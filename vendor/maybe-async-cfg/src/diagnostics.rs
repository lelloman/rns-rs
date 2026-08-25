// The upstream 0.2.4 transformer uses proc-macro-error only to turn internal
// syn errors into compiler diagnostics. Panicking from a procedural macro
// retains the same fail-fast behavior without pulling in the unmaintained
// diagnostic crate; valid macro expansion is unchanged.

macro_rules! abort {
    ($error:expr) => {{
        crate::diagnostics::abort_fail($error)
    }};
    ($span:expr, $($message:tt)*) => {{
        let _ = $span;
        crate::diagnostics::abort_fail(format_args!($($message)*))
    }};
}

macro_rules! emit_error {
    ($error:expr) => {{
        crate::diagnostics::emit_fail($error)
    }};
}

pub(crate) fn abort_fail(error: impl std::fmt::Display) -> ! {
    panic!("{error}")
}

pub(crate) fn emit_fail(error: impl std::fmt::Display) {
    panic!("{error}")
}

pub(crate) use abort;
pub(crate) use emit_error;
