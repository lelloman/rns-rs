//! The verdict and result a hook returns.

/// Verdict returned by a hook program.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Pass through normally.
    Continue = 0,
    /// Block the packet/action.
    Drop = 1,
    /// Replace with modified data.
    Modify = 2,
    /// Stop hook chain — no further hooks at this point are executed.
    Halt = 3,
}

impl Verdict {
    /// Convert from a raw `u32` discriminant. Returns `None` for invalid values.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Verdict::Continue),
            1 => Some(Verdict::Drop),
            2 => Some(Verdict::Modify),
            3 => Some(Verdict::Halt),
            _ => None,
        }
    }
}

/// [`Verdict::Continue`] as the raw value of [`HookResult::verdict`].
pub const VERDICT_CONTINUE: u32 = Verdict::Continue as u32;
/// [`Verdict::Drop`] as the raw value of [`HookResult::verdict`].
pub const VERDICT_DROP: u32 = Verdict::Drop as u32;
/// [`Verdict::Modify`] as the raw value of [`HookResult::verdict`].
pub const VERDICT_MODIFY: u32 = Verdict::Modify as u32;
/// [`Verdict::Halt`] as the raw value of [`HookResult::verdict`].
pub const VERDICT_HALT: u32 = Verdict::Halt as u32;

/// Result returned from a hook invocation.
///
/// Laid out as `#[repr(C)]` for direct reading across hook ABI boundaries:
/// three little-endian `u32`s, 12 bytes. Hooks inject actions and log
/// through the `inject_action` and `log` host functions, not through the
/// result.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookResult {
    /// Verdict as `u32` discriminant (see [`Verdict`]).
    pub verdict: u32,
    /// Address in the WASM guest's linear memory of the replacement bytes
    /// for a `Modify` verdict. Native hooks pass the bytes through
    /// [`RnsNativeHostApi::set_modified_data`](crate::native::RnsNativeHostApi::set_modified_data)
    /// instead, and the host ignores this field for them.
    pub modified_data_offset: u32,
    /// Length of modified data. 0 if no modification.
    pub modified_data_len: u32,
}

const _: () = assert!(core::mem::size_of::<HookResult>() == 12);

impl HookResult {
    /// Whether this result drops the packet/action.
    pub fn is_drop(&self) -> bool {
        self.verdict == Verdict::Drop as u32
    }

    /// Create a `Continue` result with no modifications.
    pub fn continue_result() -> Self {
        HookResult {
            verdict: Verdict::Continue as u32,
            modified_data_offset: 0,
            modified_data_len: 0,
        }
    }

    /// Create a `Drop` result.
    pub fn drop_result() -> Self {
        HookResult {
            verdict: Verdict::Drop as u32,
            modified_data_offset: 0,
            modified_data_len: 0,
        }
    }

    /// Create a `Modify` result pointing at modified data.
    pub fn modify_result(data_offset: u32, data_len: u32) -> Self {
        HookResult {
            verdict: Verdict::Modify as u32,
            modified_data_offset: data_offset,
            modified_data_len: data_len,
        }
    }
}
