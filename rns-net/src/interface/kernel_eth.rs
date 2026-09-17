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

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex, OnceLock};
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

const fn ior(nr: u32, size: u32) -> libc::Ioctl {
    ((2u32 << 30) | (size << 16) | (RNS_IOC_MAGIC << 8) | nr) as libc::Ioctl
}

const RNS_IOC_BIND_IFACE: libc::Ioctl = iow(1, libc::IFNAMSIZ as u32);
const RNS_IOC_PROMISC: libc::Ioctl = iow(3, std::mem::size_of::<libc::c_int>() as u32);
const RNS_IOC_LAST_SRC_MAC: libc::Ioctl = ior(4, 6);
const RNS_IOC_LEARN_ROUTE: libc::Ioctl = iow(5, std::mem::size_of::<RouteReq>() as u32);

/// Maximum RNS packet size the kernel module accepts on write() (matches
/// rns.c's RNS_MAX_PACKET), plus read buffer headroom matching
/// KernelEthernetInterface.py's MAX_FRAME_SIZE.
const READ_BUF_SIZE: usize = 1536;

// --- Route learning ---------------------------------------------------
//
// Mirrors the reference Python implementation's KernelEthernetInterface.py:
// the kernel module never parses announces or makes trust decisions of its
// own (it has no key material to verify a signature with) -- it only ever
// caches a dest_hash -> MAC mapping that userspace, having already
// verified it for real via rns-core's normal announce processing, hands
// it. See rns.c's big comment on RNS_IOC_LEARN_ROUTE for the full
// rationale.
//
// The wiring here is necessarily more involved than Python's self-contained
// design: rns-net's Callbacks trait is registered once, at the application
// level (RnsNode::start), not per-interface, so an interface can't just
// subscribe to its own path updates the way a Python RNS.Interfaces.Interface
// can via RNS.Transport.register_announce_handler. Instead, this module
// keeps a small global registry of started KernelEthernetInterface
// instances, keyed by InterfaceId, and the application's Callbacks
// implementation calls maybe_learn_route() (below) from its
// on_path_updated_via override.

/// Matches rns.c's struct rns_route_req exactly, including the 2 bytes of
/// padding the C compiler inserts before ttl_seconds (a u32, needing
/// 4-byte alignment) -- #[repr(C)] reproduces the same layout rules a C
/// compiler uses, so this doesn't need manual byte-packing the way the
/// Python side does with struct.pack's native-mode alignment.
#[repr(C)]
struct RouteReq {
    dest_hash: [u8; 16],
    mac: [u8; 6],
    ttl_seconds: u32,
}

const RNS_FLAG_IFAC: u8 = 0x80;
const RNS_FLAG_HEADER2: u8 = 0x40;
const RNS_FLAG_PACKET_TYPE: u8 = 0x03;
const RNS_PACKET_TYPE_ANNOUNCE: u8 = 0x01;
const RNS_HEADER1_DEST_OFF: usize = 2;
const RNS_HEADER2_DEST_OFF: usize = 18;

/// Deliberately a fixed default rather than threading an exact expiry
/// through from rns-core's path table (which would need extracting
/// PathEntry::expires at the TransportAction::PathUpdated dispatch site
/// and widening on_path_updated_via's signature further) -- a learned
/// kernel-side route is naturally refreshed on every subsequent path
/// update for the same destination anyway (RNS destinations re-announce
/// periodically), and the kernel's own reaper (60s interval) reclaims
/// anything that stops being refreshed. Comfortably longer than that
/// reaper interval so an entry isn't evicted between refreshes.
const LEARNED_ROUTE_TTL_SECONDS: u32 = 3600;

/// Bound on a single interface's pending-MAC cache, mirroring the same
/// "cap it, fail open" philosophy as the kernel-side route table's own
/// RNS_ROUTE_TABLE_MAX.
const PENDING_MAC_MAX: usize = 256;

/// dest_hash -> source MAC, captured only for frames that are RNS
/// ANNOUNCEs (the only packet type that ever updates rns-core's path
/// table). A plain HashMap plus an insertion-order VecDeque gives
/// FIFO eviction without pulling in an indexmap-style dependency for
/// something this small.
#[derive(Default)]
struct PendingMacs {
    map: HashMap<[u8; 16], [u8; 6]>,
    order: VecDeque<[u8; 16]>,
}

impl PendingMacs {
    fn insert(&mut self, dest_hash: [u8; 16], mac: [u8; 6]) {
        if self.map.insert(dest_hash, mac).is_none() {
            self.order.push_back(dest_hash);
        }
        while self.order.len() > PENDING_MAC_MAX {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
    }

    fn take(&mut self, dest_hash: &[u8; 16]) -> Option<[u8; 6]> {
        let mac = self.map.remove(dest_hash)?;
        if let Some(pos) = self.order.iter().position(|h| h == dest_hash) {
            self.order.remove(pos);
        }
        Some(mac)
    }
}

/// Per-interface state needed to actually issue RNS_IOC_LEARN_ROUTE calls.
struct RouteLearner {
    // A separate fd (bound to the same interface, via RNS_IOC_BIND_IFACE)
    // for RNS_IOC_LEARN_ROUTE specifically. Doesn't need to be the
    // reader's own fd -- the kernel's route table is shared per interface,
    // not per channel -- unlike RNS_IOC_LAST_SRC_MAC below, which reads
    // *this specific channel's* last-dequeued-packet state and therefore
    // must be called on the reader's own fd, synchronously, right after
    // each read() (see reader_loop).
    learn_fd: File,
    pending_macs: Mutex<PendingMacs>,
}

fn route_learners() -> &'static Mutex<HashMap<InterfaceId, Arc<RouteLearner>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<InterfaceId, Arc<RouteLearner>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Maps an RNS packet's flags byte to the offset of its 16-byte
/// destination hash, and extracts it if the frame is long enough. Mirrors
/// rns.c's rns_dest_offset() / KernelEthernetInterface.py's
/// _parse_dest_hash() -- deliberately tiny, not a protocol
/// reimplementation.
fn parse_dest_hash(data: &[u8]) -> Option<[u8; 16]> {
    let flags = *data.first()?;
    if flags & RNS_FLAG_IFAC != 0 {
        // Same limitation as the kernel and Python sides: ifac_size is
        // per-interface out-of-band config, so the dest_hash offset isn't
        // recoverable from the wire alone.
        return None;
    }
    let dest_off = if flags & RNS_FLAG_HEADER2 != 0 {
        RNS_HEADER2_DEST_OFF
    } else {
        RNS_HEADER1_DEST_OFF
    };
    let hash_slice = data.get(dest_off..dest_off + 16)?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(hash_slice);
    Some(hash)
}

/// Called by the application's Callbacks::on_path_updated_via override
/// (see the module-level comment above) once rns-core has fully processed
/// and verified an announce and updated its path table. A no-op if
/// `interface` isn't a KernelEthernetInterface, or if no ANNOUNCE for
/// `dest_hash` was recently seen on it.
pub fn maybe_learn_route(interface: InterfaceId, dest_hash: [u8; 16]) {
    let learner = match route_learners().lock().unwrap().get(&interface) {
        Some(l) => l.clone(),
        None => return,
    };

    let mac = match learner.pending_macs.lock().unwrap().take(&dest_hash) {
        Some(m) => m,
        None => return,
    };

    let req = RouteReq {
        dest_hash,
        mac,
        ttl_seconds: LEARNED_ROUTE_TTL_SECONDS,
    };
    let ret = unsafe {
        libc::ioctl(
            learner.learn_fd.as_raw_fd(),
            RNS_IOC_LEARN_ROUTE,
            &req as *const RouteReq as *const libc::c_void,
        )
    };
    if ret != 0 {
        log::debug!(
            "krns route-learning ioctl failed for interface {}: {}",
            interface.0,
            io::Error::last_os_error(),
        );
    } else {
        log::trace!(target: crate::logging::PATHING_LOG_TARGET,
            "krns learned route {:02x?} -> {:02x?} on interface {}",
            &dest_hash[..4],
            mac,
            interface.0,
        );
    }
}

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
    let learn_fd = read_fd.try_clone()?;

    let learner = Arc::new(RouteLearner {
        learn_fd,
        pending_macs: Mutex::new(PendingMacs::default()),
    });
    route_learners().lock().unwrap().insert(id, learner.clone());

    log::info!(
        "[{}] attached to {} bound to {}",
        config.name,
        RNS_DEV_PATH,
        config.interface
    );

    let _ = tx.send(Event::InterfaceUp(id, None, None));

    thread::Builder::new()
        .name(format!("kernel-eth-reader-{}", id.0))
        .spawn(move || reader_loop(read_fd, id, config.name, tx, learner))?;

    Ok(Box::new(KernelEthWriter { fd: write_fd }))
}

/// Reader loop: each read() is exactly one complete RNS packet (the kernel
/// module never partial-delivers or coalesces), so frames are dispatched
/// directly with no decoder/framing step. Exits (marking the interface
/// down) on any read error, including EOF -- a closed /dev/rns is a
/// permanent condition here (module unloaded, etc.), not something worth
/// blind respawn-retrying the way PipeInterface retries a subprocess.
fn reader_loop(
    mut fd: File,
    id: InterfaceId,
    name: String,
    tx: EventSender,
    learner: Arc<RouteLearner>,
) {
    let mut buf = [0u8; READ_BUF_SIZE];
    loop {
        match fd.read(&mut buf) {
            Ok(0) => {
                log::warn!("[{}] {} closed (EOF)", name, RNS_DEV_PATH);
                route_learners().lock().unwrap().remove(&id);
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
            Ok(n) => {
                let data = &buf[..n];
                remember_announce_mac(&fd, data, &learner);

                if tx
                    .send(Event::Frame {
                        interface_id: id,
                        data: data.to_vec(),
                        rssi: None,
                        snr: None,
                    })
                    .is_err()
                {
                    // Driver shut down.
                    route_learners().lock().unwrap().remove(&id);
                    return;
                }
            }
            Err(e) => {
                log::warn!("[{}] {} read error: {}", name, RNS_DEV_PATH, e);
                route_learners().lock().unwrap().remove(&id);
                let _ = tx.send(Event::InterfaceDown(id));
                return;
            }
        }
    }
}

/// Captures this frame's source MAC via RNS_IOC_LAST_SRC_MAC *before*
/// rns-core gets a chance to process it -- rns-core verifies and applies
/// announces asynchronously (see rns-core/src/transport/announce_verify_queue.rs),
/// so by the time maybe_learn_route() is eventually called (from a
/// different thread, once path_table is actually updated), this reader
/// loop may have already moved on to later frames. RNS_IOC_LAST_SRC_MAC
/// reads a single mutable "most recently read" slot on the kernel side --
/// only safe to read here, synchronously, immediately after the read()
/// that produced this exact frame, which is exactly what this function
/// does. Only bothers for ANNOUNCEs, the only packet type that ever
/// updates the path table.
fn remember_announce_mac(fd: &File, data: &[u8], learner: &RouteLearner) {
    if data.first().map(|b| b & RNS_FLAG_PACKET_TYPE) != Some(RNS_PACKET_TYPE_ANNOUNCE) {
        return;
    }
    let Some(dest_hash) = parse_dest_hash(data) else {
        return;
    };

    let mut mac = [0u8; 6];
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            RNS_IOC_LAST_SRC_MAC,
            mac.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if ret != 0 {
        log::debug!(
            "krns could not read announce source MAC: {}",
            io::Error::last_os_error(),
        );
        return;
    }

    learner.pending_macs.lock().unwrap().insert(dest_hash, mac);
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
