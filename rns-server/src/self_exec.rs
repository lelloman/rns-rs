use std::path::PathBuf;

pub fn resolve_self_exec() -> Result<PathBuf, String> {
    let proc_self = PathBuf::from("/proc/self/exe");
    if proc_self.exists() {
        return Ok(proc_self);
    }

    std::env::current_exe().map_err(|err| format!("failed to resolve current executable: {}", err))
}

pub fn self_exec_display() -> &'static str {
    "/proc/self/exe"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_exec_prefers_proc_self_exe_or_falls_back_to_existing_path() {
        let resolved = resolve_self_exec().unwrap();
        assert!(
            resolved == PathBuf::from("/proc/self/exe") || resolved.exists(),
            "unexpected self exec path: {}",
            resolved.display()
        );
    }
}
