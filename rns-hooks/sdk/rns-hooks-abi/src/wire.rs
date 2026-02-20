/// Action tag bytes used in the binary encoding between guest and host.
pub const TAG_SEND_ON_INTERFACE: u8 = 0;
pub const TAG_BROADCAST: u8 = 1;
pub const TAG_DELIVER_LOCAL: u8 = 2;
pub const TAG_ANNOUNCE_RECEIVED: u8 = 3;
pub const TAG_PATH_UPDATED: u8 = 4;
pub const TAG_FORWARD_LOCAL_CLIENTS: u8 = 5;
pub const TAG_FORWARD_PLAIN_BROADCAST: u8 = 6;
pub const TAG_CACHE_ANNOUNCE: u8 = 7;
pub const TAG_TUNNEL_SYNTHESIZE: u8 = 8;
pub const TAG_TUNNEL_ESTABLISHED: u8 = 9;
