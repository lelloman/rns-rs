pub const VERDICT_CONTINUE: u32 = 0;
pub const VERDICT_DROP: u32 = 1;
pub const VERDICT_MODIFY: u32 = 2;
pub const VERDICT_HALT: u32 = 3;

/// Result returned to the host after hook execution.
///
/// Layout matches `HookResult` in the host crate byte-for-byte.
#[repr(C)]
pub struct HookResult {
    pub verdict: u32,
    pub modified_data_offset: u32,
    pub modified_data_len: u32,
    pub inject_actions_offset: u32,
    pub inject_actions_count: u32,
    pub log_offset: u32,
    pub log_len: u32,
}

impl HookResult {
    pub fn continue_result() -> Self {
        HookResult {
            verdict: VERDICT_CONTINUE,
            modified_data_offset: 0,
            modified_data_len: 0,
            inject_actions_offset: 0,
            inject_actions_count: 0,
            log_offset: 0,
            log_len: 0,
        }
    }

    pub fn drop_result() -> Self {
        HookResult {
            verdict: VERDICT_DROP,
            modified_data_offset: 0,
            modified_data_len: 0,
            inject_actions_offset: 0,
            inject_actions_count: 0,
            log_offset: 0,
            log_len: 0,
        }
    }

    pub fn modify_result(data_offset: u32, data_len: u32) -> Self {
        HookResult {
            verdict: VERDICT_MODIFY,
            modified_data_offset: data_offset,
            modified_data_len: data_len,
            inject_actions_offset: 0,
            inject_actions_count: 0,
            log_offset: 0,
            log_len: 0,
        }
    }
}
