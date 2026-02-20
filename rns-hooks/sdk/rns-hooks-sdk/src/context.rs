// Re-export all shared ABI context types and constants.
pub use rns_hooks_abi::context::*;

/// Read the variable-length packet data that follows the packet context header.
///
/// # Safety
/// The caller must ensure the arena memory is valid and `ctx.data_len` bytes
/// are readable at `ARENA_BASE + ctx.data_offset`.
pub unsafe fn packet_data(ctx: &PacketContext) -> &[u8] {
    let base = ARENA_BASE as *const u8;
    let start = base.add(ctx.data_offset as usize);
    core::slice::from_raw_parts(start, ctx.data_len as usize)
}
