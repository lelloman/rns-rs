//! Safe wrappers for the operating system calls rns-net makes through
//! `libc` outside its dedicated modules (`poll`, `serial`, the driver's
//! tick source). Each function states what the caller may rely on; the
//! unsafe code they need is here and nowhere else in those modules.
#![allow(unsafe_code, reason = "the crate's libc calls, behind safe wrappers")]

use std::ffi::{CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;

/// Make `fd` non-blocking, for the driver loop to read or write it. This
/// changes the open file, which every duplicate of the descriptor shares.
/// A descriptor that is not open makes it fail with `EBADF`.
pub(crate) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl(F_GETFL) takes no pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK == 0
        // SAFETY: fcntl(F_SETFL) takes no pointers.
        && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether `fd` is a socket.
pub(crate) fn is_socket(fd: RawFd) -> bool {
    // SAFETY: fstat writes into a zeroed stat the call owns.
    unsafe {
        let mut stat: libc::stat = std::mem::zeroed();
        // 32-bit Android stores `st_mode` wider than `mode_t`; the type bits fit either way.
        libc::fstat(fd, &mut stat) == 0
            && (stat.st_mode as libc::mode_t) & libc::S_IFMT == libc::S_IFSOCK
    }
}

/// Take an exclusive `flock` on `file` without waiting: false when another
/// open file description holds a lock on it.
pub(crate) fn try_lock_exclusive(file: &std::fs::File) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: the fd belongs to `file`, borrowed for the call; flock takes
    // no pointers.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// Rename `source` to `destination`, failing with `AlreadyExists` instead of
/// replacing a file there (`renameat2` with `RENAME_NOREPLACE`).
#[cfg(target_os = "linux")]
pub(crate) fn rename_no_replace(source: &CStr, destination: &CStr) -> io::Result<()> {
    // SAFETY: both pointers come from live `CStr`s, NUL-terminated and valid
    // for the call; AT_FDCWD needs no open fd.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Ask Linux to back a large buffer's capacity with huge pages. Filling it
/// then takes one page fault per 2 MiB instead of one per 4 KiB.
#[cfg(target_os = "linux")]
pub(crate) fn advise_huge_pages(buffer: &Vec<u8>) {
    const HUGE_PAGE: usize = 2 << 20;
    if buffer.capacity() < 2 * HUGE_PAGE {
        return;
    }
    let start = buffer.as_ptr() as usize;
    let aligned = start.next_multiple_of(HUGE_PAGE);
    let len = (start + buffer.capacity()).saturating_sub(aligned) / HUGE_PAGE * HUGE_PAGE;
    if len == 0 {
        return;
    }
    // SAFETY: the range lies within the buffer's own allocation, and the
    // advice changes only how the kernel backs it, not its contents.
    unsafe {
        libc::madvise(aligned as *mut libc::c_void, len, libc::MADV_HUGEPAGE);
    }
}

/// Lower the calling thread's scheduling priority by `increment` (`nice`;
/// per thread on Linux). Failure leaves it as it was.
#[cfg(target_family = "unix")]
pub(crate) fn nice(increment: i32) {
    // SAFETY: `nice` takes a plain integer; no memory is involved.
    unsafe {
        libc::nice(increment);
    }
}

/// Set the calling thread's niceness. A thread may only raise its own, so
/// a value below the current one fails harmlessly.
#[cfg(target_os = "linux")]
pub(crate) fn set_thread_niceness(niceness: i32) {
    // SAFETY: gettid and setpriority take no pointers.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        let _ = libc::setpriority(libc::PRIO_PROCESS, tid, niceness);
    }
}

/// One address of a network interface, as `getifaddrs` lists it.
pub(crate) struct InterfaceAddress {
    pub(crate) name: CString,
    pub(crate) flags: u32,
    /// The address, when it is IPv4 or IPv6.
    pub(crate) addr: Option<IpAddr>,
    /// Its netmask, when it is IPv4 or IPv6.
    pub(crate) netmask: Option<IpAddr>,
}

/// Every address of this host's network interfaces (`getifaddrs`), empty
/// when the list cannot be read.
pub(crate) fn interface_addresses() -> Vec<InterfaceAddress> {
    let mut addresses = Vec::new();
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes the head of a list it allocates.
    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return addresses;
    }
    let mut current = ifaddrs;
    while !current.is_null() {
        // SAFETY: a non-null node of the list getifaddrs returned, valid
        // until the freeifaddrs below; `ifa_name` is the NUL-terminated name
        // the kernel sets on every entry, and the sockaddr pointers are null
        // or point to sockaddrs of the family they hold.
        unsafe {
            let ifa = &*current;
            current = ifa.ifa_next;
            addresses.push(InterfaceAddress {
                name: CStr::from_ptr(ifa.ifa_name).to_owned(),
                flags: ifa.ifa_flags,
                addr: sockaddr_ip(ifa.ifa_addr),
                netmask: sockaddr_ip(ifa.ifa_netmask),
            });
        }
    }
    // SAFETY: the list getifaddrs returned, freed once and not used after.
    unsafe { libc::freeifaddrs(ifaddrs) };
    addresses
}

/// The IP address in `sa`, if it is IPv4 or IPv6.
///
/// # Safety
/// `sa` must be null or point to a valid `sockaddr` of the family it claims.
unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: `sa` points to a valid sockaddr (the caller's contract).
    match i32::from(unsafe { (*sa).sa_family }) {
        libc::AF_INET => {
            // SAFETY: the family says this is a sockaddr_in.
            let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this is a sockaddr_in6.
            let sin6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// The index of the network interface named `name`, or 0 when there is none.
#[cfg(feature = "iface-auto")]
pub(crate) fn interface_index(name: &CStr) -> u32 {
    // SAFETY: `name` is a live NUL-terminated string.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

/// `read(2)` into `buf`: the bytes read, 0 at end of file, or a negative
/// value with the error in `errno` (`io::Error::last_os_error`).
#[cfg(any(
    stream_read_ifaces,
    feature = "iface-rnode",
    all(feature = "iface-weave", target_os = "linux")
))]
#[inline]
pub(crate) fn read(fd: RawFd, buf: &mut [u8]) -> isize {
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes for the call.
    unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }
}

/// `recv(2)` into `buf` with `flags`, returning as [`read`] does.
#[cfg(stream_read_ifaces)]
#[inline]
pub(crate) fn recv(fd: RawFd, buf: &mut [u8], flags: libc::c_int) -> isize {
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes for the call.
    unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), flags) }
}

/// `poll(2)` for input on `fd`, waiting at most `timeout_ms` (negative:
/// forever): the descriptor's `revents`, 0 on timeout. An invalid
/// descriptor shows as `POLLNVAL`.
#[cfg(any(
    feature = "iface-serial",
    feature = "iface-kiss",
    feature = "iface-rnode",
    all(feature = "iface-weave", target_os = "linux")
))]
pub(crate) fn poll_in(fd: RawFd, timeout_ms: libc::c_int) -> io::Result<libc::c_short> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a live, exclusively borrowed `pollfd` and the count is 1.
    if unsafe { libc::poll(&mut pfd, 1, timeout_ms) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pfd.revents)
}
