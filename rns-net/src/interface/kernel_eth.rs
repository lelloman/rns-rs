//! Kernel Ethernet interface: talks to `/dev/rns`, a Linux misc character
//! device exposed by the out-of-tree `krns` kernel module
//! (https://codeberg.org/ignirtoq/linux-rns). The kernel module hooks
//! Ethernet frames of the Reticulum ethertype directly via `dev_add_pack()`,
//! so this interface never sees non-Reticulum traffic and the kernel never
//! touches the normal IP stack for that ethertype.
//!
//! Not part of upstream rns-rs -- this is specific to the krns kernel module
//! and is not built by default (see the `iface-kernel-eth` feature).
//!
//! Every `read()`/`write()` on the device is exactly one whole RNS packet
//! (the kernel module strips the Ethernet header on receive and adds it on
//! send), so unlike `PipeInterface` this needs no HDLC framing.
//!
//! Always operates in the kernel module's promiscuous delivery mode
//! (`RNS_IOC_PROMISC`), matching how `rns-core`'s driver does its own
//! destination-hash routing centrally over raw frames from every interface
//! -- the same reasoning that led the reference Python implementation's
//! `KernelEthernetInterface.py` to use promiscuous mode instead of the
//! kernel module's exact-match dispatch (`RNS_IOC_REGISTER`), which exists
//! for lightweight single-destination clients instead.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::thread;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};
use crate::event::{Event, EventSender};
use crate::interface::Writer;

const RNS_DEV_PATH: &str = "/dev/rns";

// Matches rns.c's ioctl definitions exactly (RNS_IOC_MAGIC = 0xF0). Linux's
// _IOW(type, nr, size) encodes as (1 << 30) | (size << 16) | (type << 8) | nr
// -- see asm-generic/ioctl.h. The `libc` crate doesn't expose that macro
// (it's C preprocessor-only), so the encoding is reproduced directly, same
// as KernelEthernetInterface.py's `_IOW` helper on the Python side.
//
// The request parameter type isn't uniform across platforms -- libc::ioctl
// takes libc::Ioctl, which is c_ulong on x86_64-glibc but c_int on aarch64
// and/or musl targets (caught by the aarch64-unknown-linux-musl cross
// build, which x86_64-unknown-linux-gnu native testing never would have
// exercised). Using libc::Ioctl directly, rather than hardcoding one
// platform's underlying type, is the whole point of that alias existing.
const RNS_IOC_MAGIC: u32 = 0xF0;

const fn iow(nr: u32, size: u32) -> libc::Ioctl {
    ((1u32 << 30) | (size << 16) | (RNS_IOC_MAGIC << 8) | nr) as libc::Ioctl
}

const RNS_IOC_BIND_IFACE: libc::Ioctl = iow(1, libc::IFNAMSIZ as u32);
const RNS_IOC_PROMISC: libc::Ioctl = iow(3, std::mem::size_of::<libc::c_int>() as u32);

/// Maximum RNS packet size the kernel module accepts on write() (matches
/// rns.c's RNS_MAX_PACKET), plus read buffer headroom matching
/// KernelEthernetInterface.py's MAX_FRAME_SIZE.
const READ_BUF_SIZE: usize = 1536;

#[derive(Debug, Clone)]
pub struct KernelEthConfig {
    pub name: String,
    pub interface: String,
    pub interface_id: InterfaceId,
}

struct KernelEthWriter {
    fd: File,
}

impl Writer for KernelEthWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.fd.write_all(data)
    }
}

fn open_and_configure(interface: &str) -> io::Result<File> {
    let fd = OpenOptions::new().read(true).write(true).open(RNS_DEV_PATH)?;

    let mut ifname = [0u8; libc::IFNAMSIZ];
    let bytes = interface.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name too long: {}", interface),
        ));
    }
    ifname[..bytes.len()].copy_from_slice(bytes);

    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            RNS_IOC_BIND_IFACE,
            ifname.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let promisc: libc::c_int = 1;
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), RNS_IOC_PROMISC, &promisc as *const _) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}

/// Start the kernel Ethernet interface. Opens `/dev/rns`, binds it to the
/// configured physical interface, enables promiscuous delivery, and spawns
/// a reader thread. Returns the writer half.
pub fn start(config: KernelEthConfig, tx: EventSender) -> io::Result<Box<dyn Writer>> {
    let id = config.interface_id;
    let read_fd = open_and_configure(&config.interface)?;
    let write_fd = read_fd.try_clone()?;

    log::info!(
        "[{}] attached to {} bound to {}",
        config.name,
        RNS_DEV_PATH,
        config.interface
    );

    let _ = tx.send(Event::InterfaceUp(id, None, None));

    thread::Builder::new()
        .name(format!("kernel-eth-reader-{}", id.0))
        .spawn(move || reader_loop(read_fd, id, config.name, tx))?;

    Ok(Box::new(KernelEthWriter { fd: write_fd }))
}

/// Reader loop: each read() is exactly one complete RNS packet (the kernel
/// module never partial-delivers or coalesces), so frames are dispatched
/// directly with no decoder/framing step. Exits (marking the interface
/// down) on any read error, including EOF -- a closed /dev/rns is a
/// permanent condition here (module unloaded, etc.), not something worth
/// blind respawn-retrying the way PipeInterface retries a subprocess.
fn reader_loop(mut fd: File, id: InterfaceId, name: String, tx: EventSender) {
    let mut buf = [0u8; READ_BUF_SIZE];
    loop {
        match fd.read(&mut buf) {
            Ok(0) => {
                log::warn!("[{}] {} closed (EOF)", name, RNS_DEV_PATH);
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
            Ok(n) => {
                if tx
                    .send(Event::Frame {
                        interface_id: id,
                        data: buf[..n].to_vec(),
                        rssi: None,
                        snr: None,
                    })
                    .is_err()
                {
                    // Driver shut down.
                    return;
                }
            }
            Err(e) => {
                log::warn!("[{}] {} read error: {}", name, RNS_DEV_PATH, e);
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
        }
    }
}

pub struct KernelEthFactory;

impl InterfaceFactory for KernelEthFactory {
    fn type_name(&self) -> &str {
        "KernelEthernetInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let interface = params
            .get("interface")
            .ok_or_else(|| "KernelEthernetInterface requires 'interface'".to_string())?
            .clone();

        // Fail fast on an obviously-bad interface name here, rather than at
        // start() time, so config errors surface immediately.
        let _ = CString::new(interface.as_bytes())
            .map_err(|_| "interface name contains a NUL byte".to_string())?;
        if interface.len() >= libc::IFNAMSIZ {
            return Err(format!("interface name too long: {}", interface));
        }

        Ok(Box::new(KernelEthConfig {
            name: name.to_string(),
            interface,
            interface_id: id,
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        let config = *config
            .into_any()
            .downcast::<KernelEthConfig>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wrong config type"))?;

        let id = config.interface_id;
        let info = InterfaceInfo {
            id,
            name: config.name.clone(),
            mode: ctx.mode,
            gravity: ctx.gravity,
            recursive_prs: ctx.recursive_prs,
            announces_from_internal: ctx.announces_from_internal,
            announces_to_internal: ctx.announces_to_internal,
            out_capable: true,
            in_capable: true,
            // Real link speed isn't known at this layer (no negotiation, no
            // config value for it) -- leave unset rather than guess, same
            // as KernelEthernetInterface.py never setting self.bitrate.
            bitrate: None,
            airtime_profile: None,
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            // Must be set explicitly: rns_core::constants::MTU is 500 (a
            // conservative default for interfaces with no real hardware
            // MTU), not the actual 1500-byte cap rns.c enforces
            // (RNS_MAX_PACKET) on real Ethernet.
            mtu: 1500,
            ia_freq: 0.0,
            ip_freq: 0.0,
            op_freq: 0.0,
            op_samples: 0,
            started: crate::time::now(),
            // This is a genuinely shared/broadcast medium (unlike a pipe or
            // point-to-point TCP client), so respect the node's configured
            // ingress control rather than hardcoding it disabled.
            ingress_control: ctx.ingress_control,
        };

        let writer = start(config, ctx.tx)?;

        Ok(StartResult::Simple {
            id,
            info,
            writer,
            interface_type_name: "KernelEthernetInterface".to_string(),
        })
    }
}
