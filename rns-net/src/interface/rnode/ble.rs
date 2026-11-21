//! RNodes over Bluetooth Low Energy (`port = ble://...`), as upstream's
//! `BLEConnection`: the device's Nordic UART service carries the same KISS
//! stream as a serial port.
//!
//! The target is named in the port: `ble://` alone takes the first bonded
//! RNode found, `ble://AA:BB:CC:DD:EE:FF` the device with that address and
//! `ble://RNode 1A2B` the device with that name. Only bonded devices are
//! connected to; pair the RNode with the host first (for example with
//! `rnodeconf --bluetooth-pair` and `bluetoothctl`).
//!
//! On Linux the connection goes through BlueZ over D-Bus (with the
//! `iface-rnode-ble` feature). The device's notifications are read from the
//! descriptor BlueZ hands over (`AcquireNotify`), so the connection is
//! served like a serial port: a loop source on the compact engine's
//! driver, a reader thread otherwise. Writes are attribute writes without
//! response, at most the connection's MTU less three bytes each, sent on
//! the D-Bus connection without waiting for BlueZ to answer.

use std::sync::{Arc, Mutex};

/// The scheme of a BLE port, matched without regard to case as upstream.
const SCHEME: &str = "ble://";

/// The Nordic UART service and its characteristics, as BlueZ writes them.
#[cfg(any(feature = "iface-rnode-ble", test))]
pub(super) const UART_SERVICE_UUID: &str = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
#[cfg(feature = "iface-rnode-ble")]
pub(super) const UART_RX_CHAR_UUID: &str = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
#[cfg(feature = "iface-rnode-ble")]
pub(super) const UART_TX_CHAR_UUID: &str = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";

/// Whether `port` names a BLE device.
pub(super) fn is_ble_port(port: &str) -> bool {
    port.get(..SCHEME.len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
}

/// Which device a BLE port asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Target {
    pub(super) name: Option<String>,
    pub(super) address: Option<String>,
}

impl Target {
    /// Read the target from a port as upstream does: nothing after the
    /// scheme is any RNode; six colon-separated fields in 17 characters
    /// are an address, anything else a name. `None` when `port` is not a
    /// BLE port.
    pub(super) fn parse(port: &str) -> Option<Target> {
        if !is_ble_port(port) {
            return None;
        }
        let rest = &port[SCHEME.len()..];
        Some(if rest.is_empty() {
            Target::default()
        } else if rest.split(':').count() == 6 && rest.chars().count() == 17 {
            Target {
                address: Some(rest.to_string()),
                ..Target::default()
            }
        } else {
            Target {
                name: Some(rest.to_string()),
                ..Target::default()
            }
        })
    }
}

/// A device seen advertising while looking for the target.
#[cfg(any(feature = "iface-rnode-ble", test))]
#[derive(Debug, Clone, Default)]
pub(super) struct Seen {
    pub(super) address: String,
    /// The name the system shows, if it knows one.
    pub(super) name: Option<String>,
    pub(super) service_uuids: Vec<String>,
    pub(super) bonded: bool,
}

/// What looking at one device found.
#[cfg(any(feature = "iface-rnode-ble", test))]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// The device to connect to.
    Target,
    /// The device asked for, which cannot be used without a bond; carries
    /// how the port named it.
    NotBonded(String),
    /// Another device.
    Other,
}

#[cfg(any(feature = "iface-rnode-ble", test))]
impl Target {
    /// Judge `seen` as upstream's scan filter does.
    pub(super) fn judge(&self, seen: &Seen) -> Verdict {
        if !seen
            .service_uuids
            .iter()
            .any(|uuid| uuid == UART_SERVICE_UUID)
        {
            return Verdict::Other;
        }
        if seen.bonded {
            if self.address.is_none() && self.name.is_none() {
                // Upstream asks for a name starting with "RNode " but then
                // takes any bonded device; a device without a name makes
                // its filter fail.
                return match seen.name {
                    Some(_) => Verdict::Target,
                    None => Verdict::Other,
                };
            }
            let address_matches = self
                .address
                .as_ref()
                .is_none_or(|address| *address == seen.address);
            let name_matches = self
                .name
                .as_ref()
                .is_none_or(|name| seen.name.as_ref() == Some(name));
            if address_matches && name_matches {
                return Verdict::Target;
            }
        } else if let Some(address) = self
            .address
            .as_ref()
            .filter(|address| **address == seen.address)
        {
            return Verdict::NotBonded(address.clone());
        } else if let Some(name) = self
            .name
            .as_ref()
            .filter(|name| seen.name.as_ref() == Some(*name))
        {
            return Verdict::NotBonded(name.clone());
        }
        Verdict::Other
    }
}

/// What a BLE interface remembers between connections.
#[derive(Debug, Default)]
pub struct LinkState {
    /// The address of the device last connected to: upstream then calls
    /// the port `ble://<address>`.
    pub(super) address: Option<String>,
    /// Whether looking for the device failed outright, which ends
    /// upstream's connection job until the next attempt starts a new one.
    pub(super) ended: bool,
}

/// Upstream's `BLEConnection.CONNECT_TIMEOUT`: how long opening waits for
/// a connection.
pub(super) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long after the last attempt upstream's connection job, which keeps
/// looking for the device between attempts, starts looking again.
pub(super) const JOB_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Shared between an interface's connections.
pub(super) type SharedLinkState = Arc<Mutex<LinkState>>;

/// Whether looking for the device failed outright, so that upstream's
/// connection job no longer looks for it between attempts.
pub(super) fn job_ended(state: &SharedLinkState) -> bool {
    crate::interface::lock_or_recover(state, "rnode ble state").ended
}

/// The port as upstream names it in its log lines: `None` until a device
/// was connected to, then `ble://<address>`.
pub(super) fn port_display(state: &SharedLinkState) -> String {
    match &crate::interface::lock_or_recover(state, "rnode ble state").address {
        Some(address) => format!("ble://{address}"),
        None => "None".to_string(),
    }
}

#[cfg(feature = "iface-rnode-ble")]
pub(super) use bluez::{open, Session};

#[cfg(feature = "iface-rnode-ble")]
mod bluez {
    use std::collections::{HashMap, HashSet};
    use std::fs::File;
    use std::io;
    use std::os::fd::RawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use dbus::arg::{prop_cast, PropMap, RefArg, Variant};
    use dbus::blocking::stdintf::org_freedesktop_dbus::{ObjectManager, Properties};
    use dbus::blocking::SyncConnection;
    use dbus::channel::{BusType, Channel};
    use dbus::{Message, Path};

    use super::{
        SharedLinkState, Target, Verdict, JOB_INTERVAL, UART_RX_CHAR_UUID, UART_TX_CHAR_UUID,
    };
    use crate::interface::lock_or_recover;

    const BLUEZ: &str = "org.bluez";
    const ADAPTER: &str = "org.bluez.Adapter1";
    const DEVICE: &str = "org.bluez.Device1";
    const CHARACTERISTIC: &str = "org.bluez.GattCharacteristic1";

    /// Upstream's `BLEConnection.SCAN_TIMEOUT`.
    const SCAN_TIMEOUT: Duration = Duration::from_secs(2);
    /// How long connecting and resolving services may take (bleak's
    /// default client timeout).
    const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
    const CALL_TIMEOUT: Duration = Duration::from_secs(5);
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    /// The smallest ATT MTU, when BlueZ does not say.
    const DEFAULT_MTU: u16 = 23;
    const ATT_WRITE_HEADER: usize = 3;

    /// A D-Bus error, worded as bleak words it.
    #[derive(Debug)]
    struct DbusError(dbus::Error);

    impl std::fmt::Display for DbusError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "[{}] {}",
                self.0.name().unwrap_or("org.freedesktop.DBus.Error.Failed"),
                self.0.message().unwrap_or("")
            )
        }
    }

    impl std::error::Error for DbusError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    /// A D-Bus error as an io::Error that keeps it.
    fn dbus_error(error: dbus::Error) -> io::Error {
        io::Error::other(DbusError(error))
    }

    /// What upstream raises when no connection came up in time.
    fn not_open() -> io::Error {
        io::Error::other("Could not open serial port")
    }

    /// A connection to an RNode over BLE: the D-Bus connection that holds
    /// it, and what writing to it needs.
    pub struct Session {
        conn: SyncConnection,
        device: Path<'static>,
        rx: Path<'static>,
        /// The most one attribute write carries.
        payload: usize,
        iface: String,
        closed: AtomicBool,
        /// The device's notifications, read while the connection closes.
        notify: File,
    }

    impl std::fmt::Debug for Session {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Session")
                .field("device", &self.device)
                .field("payload", &self.payload)
                .finish()
        }
    }

    impl Session {
        /// The D-Bus connection's descriptor, writable when queued writes
        /// can go out.
        pub fn fd(&self) -> RawFd {
            self.conn.channel().watch().fd
        }

        /// Send the start of `buf` as one attribute write without
        /// response. On the compact engine's driver this does not block:
        /// while earlier writes still wait for the bus it fails with
        /// `WouldBlock`, and the driver retries once the descriptor is
        /// writable.
        pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            if self.closed.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "the BLE device is disconnected",
                ));
            }
            let channel = self.conn.channel();
            self.pump()?;
            if channel.has_messages_to_send() {
                if crate::engine::FOLD_IO {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                channel.flush();
            }
            let n = buf.len().min(self.payload);
            let mut options = PropMap::new();
            options.insert(
                "type".to_string(),
                Variant(Box::new("command".to_string()) as Box<dyn RefArg>),
            );
            let mut message =
                Message::new_method_call(BLUEZ, &self.rx, CHARACTERISTIC, "WriteValue")
                    .map_err(io::Error::other)?
                    .append2(buf[..n].to_vec(), options);
            message.set_no_reply(true);
            channel.send(message).map_err(|()| {
                io::Error::new(io::ErrorKind::BrokenPipe, "the D-Bus connection is closed")
            })?;
            self.pump()?;
            Ok(n)
        }

        /// Move what the D-Bus connection holds without blocking, dropping
        /// what arrives (nothing is asked for).
        fn pump(&self) -> io::Result<()> {
            let channel = self.conn.channel();
            channel.read_write(Some(Duration::ZERO)).map_err(|()| {
                io::Error::new(io::ErrorKind::BrokenPipe, "the D-Bus connection is closed")
            })?;
            while channel.pop_message().is_some() {}
            Ok(())
        }

        /// Disconnect the device, as upstream's `close`, after BlueZ has
        /// taken every write sent before. Once only.
        pub fn close(&self) {
            self.close_reading(|_| {});
        }

        /// Disconnect the device as [`Self::close`] does, letting `read`
        /// read what the device answers meanwhile: upstream reads the
        /// device until its connection is gone.
        pub fn close_reading(&self, read: impl FnOnce(&mut File)) {
            if self.closed.swap(true, Ordering::Relaxed) {
                return;
            }
            log::debug!("Disconnecting BLE device from {}", self.iface);
            let device = self.conn.with_proxy(BLUEZ, &self.device, CALL_TIMEOUT);
            // Answered only once BlueZ has handled the writes before it.
            let _ = device.get::<bool>(DEVICE, "Connected");
            let started = Instant::now();
            if let Ok(mut notify) = self.notify.try_clone() {
                read(&mut notify);
            }
            std::thread::sleep(Duration::from_millis(100).saturating_sub(started.elapsed()));
            let _: Result<(), _> = device.method_call(DEVICE, "Disconnect", ());
            log::info!(
                target: crate::logging::NOTICE_TARGET,
                "BLE device for {} disconnected",
                self.iface
            );
        }

        /// Note a connection the device dropped: upstream's disconnect
        /// callback.
        pub fn lost(&self) {
            if !self.closed.swap(true, Ordering::Relaxed) {
                log::info!(
                    target: crate::logging::NOTICE_TARGET,
                    "BLE device for {} disconnected",
                    self.iface
                );
            }
        }
    }

    /// A device found, and where BlueZ keeps it.
    struct Found {
        path: Path<'static>,
        address: String,
        name: Option<String>,
    }

    impl std::fmt::Display for Found {
        /// As bleak writes a device.
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.name {
                Some(name) => write!(f, "{}: {}", self.address, name),
                None => write!(f, "{}: None", self.address),
            }
        }
    }

    /// Find and connect the device `target` names, for the interface
    /// upstream calls `iface`, looking for it for up to `budget`. Returns
    /// the notification descriptor to read and the session to write.
    pub(crate) fn open(
        target: &Target,
        iface: &str,
        state: &SharedLinkState,
        budget: Duration,
    ) -> io::Result<(File, std::sync::Arc<Session>)> {
        {
            let mut state = lock_or_recover(state, "rnode ble state");
            if state.ended {
                log::info!(
                    target: crate::logging::NOTICE_TARGET,
                    "Cleaning up previous BLE connection for {}...",
                    iface
                );
                state.ended = false;
            }
        }
        let deadline = Instant::now() + budget;
        let conn = match system_bus() {
            Ok(conn) => conn,
            Err(e) => return Err(job_ended(iface, state, e)),
        };
        let mut found: Option<Found> = None;
        loop {
            if found.is_none() {
                found = match find_device(&conn, target, iface) {
                    Ok(found) => found,
                    Err(e) => return Err(job_ended(iface, state, e)),
                };
            }
            if let Some(device) = &found {
                match connect(conn, device, iface) {
                    Ok((notify, session)) => {
                        lock_or_recover(state, "rnode ble state").address =
                            Some(device.address.clone());
                        return Ok((notify, std::sync::Arc::new(session)));
                    }
                    Err(e) => {
                        log::debug!("BLE connection to {} failed: {}", device, e);
                        log::error!(
                            "Could not connect BLE device {} for {}. Possibly missing authentication.",
                            device,
                            iface
                        );
                        return Err(not_open());
                    }
                }
            }
            if Instant::now() + JOB_INTERVAL >= deadline {
                return Err(not_open());
            }
            std::thread::sleep(JOB_INTERVAL);
        }
    }

    /// Looking for the device failed: upstream logs it and ends its
    /// connection job.
    fn job_ended(iface: &str, state: &SharedLinkState, error: io::Error) -> io::Error {
        log::error!("Error while finding BLE device for {}: {}", iface, error);
        log::debug!("BLE connection job for {} ended", iface);
        lock_or_recover(state, "rnode ble state").ended = true;
        not_open()
    }

    fn system_bus() -> io::Result<SyncConnection> {
        let mut channel = Channel::get_private(BusType::System).map_err(dbus_error)?;
        channel.set_watch_enabled(true);
        Ok(SyncConnection::from(channel))
    }

    type Objects = HashMap<Path<'static>, HashMap<String, PropMap>>;

    fn managed_objects(conn: &SyncConnection) -> io::Result<Objects> {
        conn.with_proxy(BLUEZ, "/", CALL_TIMEOUT)
            .get_managed_objects()
            .map_err(dbus_error)
    }

    /// The first powered adapter that can be central, as bleak picks it.
    fn default_adapter(objects: &Objects) -> io::Result<Path<'static>> {
        let mut adapters: Vec<(&Path<'static>, &PropMap)> = objects
            .iter()
            .filter_map(|(path, interfaces)| interfaces.get(ADAPTER).map(|props| (path, props)))
            .collect();
        adapters.sort_by(|a, b| a.0.cmp(b.0));
        if adapters.is_empty() {
            return Err(io::Error::other("No Bluetooth adapters found."));
        }
        let central: Vec<_> = adapters
            .into_iter()
            .filter(|(_, props)| {
                prop_cast::<Vec<String>>(props, "Roles")
                    .is_some_and(|roles| roles.iter().any(|role| role == "central"))
            })
            .collect();
        if central.is_empty() {
            return Err(io::Error::other(
                "No Bluetooth adapters with BLE 'central' role found.",
            ));
        }
        central
            .into_iter()
            .find(|(_, props)| prop_cast::<bool>(props, "Powered").copied() == Some(true))
            .map(|(path, _)| path.clone())
            .ok_or_else(|| {
                io::Error::other(
                    "No powered Bluetooth adapters found. Turn on Bluetooth and try again.",
                )
            })
    }

    /// What BlueZ knows of a device, as the scan filter sees it.
    fn seen(props: &PropMap) -> Option<super::Seen> {
        let address = prop_cast::<String>(props, "Address")?.clone();
        // BlueZ makes up an alias from the address when the device has
        // no name; bleak then reports none.
        let name = prop_cast::<String>(props, "Alias")
            .filter(|alias| **alias != address.replace(':', "-"))
            .cloned();
        Some(super::Seen {
            name,
            service_uuids: prop_cast::<Vec<String>>(props, "UUIDs")
                .cloned()
                .unwrap_or_default(),
            bonded: prop_cast::<bool>(props, "Bonded").copied() == Some(true),
            address,
        })
    }

    /// Scan for up to `SCAN_TIMEOUT`, as upstream's `find_target_device`,
    /// for a device advertising now (or already connected to this host,
    /// when it does not advertise).
    fn find_device(
        conn: &SyncConnection,
        target: &Target,
        iface: &str,
    ) -> io::Result<Option<Found>> {
        log::trace!("Searching for attachable BLE device for {}...", iface);
        let adapter_path = default_adapter(&managed_objects(conn)?)?;
        let adapter = conn.with_proxy(BLUEZ, &adapter_path, CALL_TIMEOUT);
        let mut filter = PropMap::new();
        filter.insert(
            "Transport".to_string(),
            Variant(Box::new("le".to_string()) as Box<dyn RefArg>),
        );
        filter.insert(
            "DuplicateData".to_string(),
            Variant(Box::new(false) as Box<dyn RefArg>),
        );
        adapter
            .method_call::<(), _, _, _>(ADAPTER, "SetDiscoveryFilter", (filter,))
            .map_err(dbus_error)?;
        // Another client may be scanning already, which serves as well.
        let started = match adapter.method_call::<(), _, _, _>(ADAPTER, "StartDiscovery", ()) {
            Ok(()) => true,
            Err(e) if e.name() == Some("org.bluez.Error.InProgress") => false,
            Err(e) => return Err(dbus_error(e)),
        };
        let prefix = format!("{}/", adapter_path);
        let deadline = Instant::now() + SCAN_TIMEOUT;
        let mut refused = HashSet::new();
        let found = loop {
            let mut found = None;
            for (path, interfaces) in managed_objects(conn)? {
                if !path.starts_with(&prefix) {
                    continue;
                }
                let Some(props) = interfaces.get(DEVICE) else {
                    continue;
                };
                let advertising = props.contains_key("RSSI")
                    || prop_cast::<bool>(props, "Connected").copied() == Some(true);
                let Some(seen) = seen(props).filter(|_| advertising) else {
                    continue;
                };
                match target.judge(&seen) {
                    Verdict::Target => {
                        found = Some(Found {
                            path: path.clone(),
                            address: seen.address,
                            name: seen.name,
                        });
                        break;
                    }
                    Verdict::NotBonded(subject) => {
                        if refused.insert(subject.clone()) {
                            log::error!(
                                "Can't connect to target device {} over BLE, device is not bonded",
                                subject
                            );
                        }
                    }
                    Verdict::Other => {}
                }
            }
            if found.is_some() || Instant::now() >= deadline {
                break found;
            }
            std::thread::sleep(POLL_INTERVAL);
        };
        if started {
            let _: Result<(), _> = adapter.method_call(ADAPTER, "StopDiscovery", ());
        }
        Ok(found)
    }

    /// Connect `device`, resolve its UART service and acquire its
    /// notifications.
    fn connect(conn: SyncConnection, device: &Found, iface: &str) -> io::Result<(File, Session)> {
        log::debug!("Connecting BLE device {} for {}...", device, iface);
        let deadline = Instant::now() + CLIENT_TIMEOUT;
        let proxy = conn.with_proxy(BLUEZ, &device.path, CLIENT_TIMEOUT);
        let result = (|| {
            proxy
                .method_call::<(), _, _, _>(DEVICE, "Connect", ())
                .map_err(dbus_error)?;
            while !proxy
                .get::<bool>(DEVICE, "ServicesResolved")
                .unwrap_or(false)
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "services were not resolved in time",
                    ));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            let (rx, tx, mtu) = uart_characteristics(&conn, &device.path)?;
            let (fd, notify_mtu): (std::os::fd::OwnedFd, u16) = conn
                .with_proxy(BLUEZ, &tx, CALL_TIMEOUT)
                .method_call(CHARACTERISTIC, "AcquireNotify", (PropMap::new(),))
                .map_err(dbus_error)?;
            let mtu = mtu.unwrap_or(if notify_mtu > 0 {
                notify_mtu
            } else {
                DEFAULT_MTU
            });
            let notify = File::from(fd);
            let tap = notify.try_clone()?;
            Ok((notify, tap, rx, mtu))
        })();
        match result {
            Ok((notify, tap, rx, mtu)) => Ok((
                notify,
                Session {
                    conn,
                    device: device.path.clone(),
                    rx,
                    payload: usize::from(mtu).saturating_sub(ATT_WRITE_HEADER).max(1),
                    iface: iface.to_string(),
                    closed: AtomicBool::new(false),
                    notify: tap,
                },
            )),
            Err(e) => {
                let _: Result<(), _> = conn
                    .with_proxy(BLUEZ, &device.path, CALL_TIMEOUT)
                    .method_call(DEVICE, "Disconnect", ());
                Err(e)
            }
        }
    }

    /// The UART service's receive and transmit characteristics under
    /// `device`, with the MTU BlueZ reports for writing.
    fn uart_characteristics(
        conn: &SyncConnection,
        device: &Path<'static>,
    ) -> io::Result<(Path<'static>, Path<'static>, Option<u16>)> {
        let prefix = format!("{}/", device);
        let mut rx = None;
        let mut tx = None;
        for (path, interfaces) in managed_objects(conn)? {
            if !path.starts_with(&prefix) {
                continue;
            }
            let Some(props) = interfaces.get(CHARACTERISTIC) else {
                continue;
            };
            match prop_cast::<String>(props, "UUID").map(|uuid| uuid.to_ascii_lowercase()) {
                Some(uuid) if uuid == UART_RX_CHAR_UUID => {
                    rx = Some((path.clone(), prop_cast::<u16>(props, "MTU").copied()))
                }
                Some(uuid) if uuid == UART_TX_CHAR_UUID => tx = Some(path.clone()),
                _ => {}
            }
        }
        match (rx, tx) {
            (Some((rx, mtu)), Some(tx)) => Ok((rx, tx, mtu)),
            _ => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the device has no UART service",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(address: &str, name: Option<&str>, bonded: bool) -> Seen {
        Seen {
            address: address.to_string(),
            name: name.map(str::to_string),
            service_uuids: vec![
                "00001801-0000-1000-8000-00805f9b34fb".to_string(),
                UART_SERVICE_UUID.to_string(),
            ],
            bonded,
        }
    }

    #[test]
    fn ble_ports_are_told_apart_as_upstream() {
        assert!(is_ble_port("ble://"));
        assert!(is_ble_port("BLE://RNode 1A2B"));
        assert!(is_ble_port("Ble://AA:BB:CC:DD:EE:FF"));
        assert!(!is_ble_port("/dev/ttyUSB0"));
        assert!(!is_ble_port("tcp:10.0.0.1"));
        assert!(!is_ble_port("ble:/"));
        assert!(!is_ble_port("blé://"));
        assert_eq!(Target::parse("/dev/ttyACM0"), None);
    }

    #[test]
    fn targets_are_read_as_upstream_reads_them() {
        assert_eq!(Target::parse("ble://"), Some(Target::default()));
        assert_eq!(
            Target::parse("ble://3C:0F:02:E6:67:01"),
            Some(Target {
                address: Some("3C:0F:02:E6:67:01".into()),
                name: None
            })
        );
        // The case of an address is kept, as upstream keeps it.
        assert_eq!(
            Target::parse("BLE://3c:0f:02:e6:67:01"),
            Some(Target {
                address: Some("3c:0f:02:e6:67:01".into()),
                name: None
            })
        );
        assert_eq!(
            Target::parse("ble://RNode 7012"),
            Some(Target {
                name: Some("RNode 7012".into()),
                address: None
            })
        );
        // Six fields but not 17 characters: a name.
        assert_eq!(
            Target::parse("ble://A:B:C:D:E:F"),
            Some(Target {
                name: Some("A:B:C:D:E:F".into()),
                address: None
            })
        );
        // 17 characters but not six fields: a name.
        assert_eq!(
            Target::parse("ble://AABB:CCDD:EEFF:0011"),
            Some(Target {
                name: Some("AABB:CCDD:EEFF:0011".into()),
                address: None
            })
        );
    }

    #[test]
    fn any_bonded_rnode_is_taken_without_a_target() {
        let any = Target::default();
        assert_eq!(
            any.judge(&seen("3C:0F:02:E6:67:01", Some("RNode 7012"), true)),
            Verdict::Target
        );
        // Upstream's filter takes any bonded UART device with a name.
        assert_eq!(
            any.judge(&seen("3C:0F:02:E6:67:01", Some("Other"), true)),
            Verdict::Target
        );
        assert_eq!(
            any.judge(&seen("3C:0F:02:E6:67:01", None, true)),
            Verdict::Other
        );
        // Not bonded: passed over, without a word.
        assert_eq!(
            any.judge(&seen("3C:0F:02:E6:67:01", Some("RNode 7012"), false)),
            Verdict::Other
        );
        // Without the UART service.
        let mut plain = seen("3C:0F:02:E6:67:01", Some("RNode 7012"), true);
        plain.service_uuids.retain(|uuid| uuid != UART_SERVICE_UUID);
        assert_eq!(any.judge(&plain), Verdict::Other);
    }

    #[test]
    fn targets_match_by_address_or_name() {
        let by_address = Target::parse("ble://3C:0F:02:E6:67:01").unwrap();
        assert_eq!(
            by_address.judge(&seen("3C:0F:02:E6:67:01", Some("RNode 7012"), true)),
            Verdict::Target
        );
        assert_eq!(
            by_address.judge(&seen("3C:0F:02:E6:67:05", Some("RNode 7012"), true)),
            Verdict::Other
        );
        assert_eq!(
            by_address.judge(&seen("3C:0F:02:E6:67:01", Some("RNode 7012"), false)),
            Verdict::NotBonded("3C:0F:02:E6:67:01".into())
        );
        // Addresses compare exactly, as upstream compares them.
        let lower = Target::parse("ble://3c:0f:02:e6:67:01").unwrap();
        assert_eq!(
            lower.judge(&seen("3C:0F:02:E6:67:01", Some("RNode 7012"), true)),
            Verdict::Other
        );

        let by_name = Target::parse("ble://RNode 7012").unwrap();
        assert_eq!(
            by_name.judge(&seen("3C:0F:02:E6:67:01", Some("RNode 7012"), true)),
            Verdict::Target
        );
        assert_eq!(
            by_name.judge(&seen("3C:0F:02:E6:67:01", Some("RNode 7013"), true)),
            Verdict::Other
        );
        assert_eq!(
            by_name.judge(&seen("3C:0F:02:E6:67:01", None, true)),
            Verdict::Other
        );
        assert_eq!(
            by_name.judge(&seen("3C:0F:02:E6:67:01", Some("RNode 7012"), false)),
            Verdict::NotBonded("RNode 7012".into())
        );
    }

    #[test]
    fn the_port_is_named_after_the_device_once_connected() {
        let state = SharedLinkState::default();
        assert_eq!(port_display(&state), "None");
        state.lock().unwrap().address = Some("3C:0F:02:E6:67:01".into());
        assert_eq!(port_display(&state), "ble://3C:0F:02:E6:67:01");
    }
}
