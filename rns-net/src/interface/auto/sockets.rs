//! The discovery, unicast and data sockets.

use super::*;

pub(super) fn create_multicast_recv_socket(
    mcast_ip: &Ipv6Addr,
    port: u16,
    if_index: u32,
    underlay_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    crate::interface::apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;

    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;

    // Bind to [::]:port on the specific interface
    let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, if_index);
    socket.bind(&bind_addr.into())?;

    // Join multicast group on the specific interface
    socket.join_multicast_v6(mcast_ip, if_index)?;

    socket.set_nonblocking(false)?;
    let std_socket: UdpSocket = socket.into();
    std_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(std_socket)
}

pub(super) fn create_unicast_recv_socket(
    link_local: &str,
    port: u16,
    if_index: u32,
    underlay_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let ip: Ipv6Addr = link_local
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad IPv6: {}", e)))?;

    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    crate::interface::apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;

    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;

    let bind_addr = SocketAddrV6::new(ip, port, 0, if_index);
    socket.bind(&bind_addr.into())?;

    socket.set_nonblocking(false)?;
    let std_socket: UdpSocket = socket.into();
    std_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(std_socket)
}

pub(super) fn create_data_recv_socket(
    link_local: &str,
    port: u16,
    if_index: u32,
    underlay_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let ip: Ipv6Addr = link_local
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad IPv6: {}", e)))?;

    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    crate::interface::apply_underlay_mark(socket.as_raw_fd(), underlay_mark)?;

    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;

    let bind_addr = SocketAddrV6::new(ip, port, 0, if_index);
    socket.bind(&bind_addr.into())?;

    socket.set_nonblocking(false)?;
    let std_socket: UdpSocket = socket.into();
    std_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(std_socket)
}

/// Get the raw file descriptor from a UdpSocket (for setsockopt).
#[cfg(unix)]
pub(super) fn socket_fd(socket: &UdpSocket) -> i32 {
    use std::os::unix::io::AsRawFd;
    socket.as_raw_fd()
}

#[cfg(not(unix))]
pub(super) fn socket_fd(_socket: &UdpSocket) -> i32 {
    0
}
