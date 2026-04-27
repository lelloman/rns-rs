#![cfg(all(feature = "native", target_os = "linux"))]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use rns_hooks::{HookBackend, HookContext, HookManager, NullEngine, Verdict};

#[test]
fn native_hook_loads_and_executes() {
    let lib_path = build_native_fixture();
    let manager = HookManager::new().expect("manager");
    let mut program = manager
        .load_file_backend("native-test".into(), &lib_path, 0, HookBackend::Native)
        .expect("load native hook");

    assert_eq!(program.backend_name(), "native");

    let exec = manager
        .execute_program(&mut program, &HookContext::Tick, &NullEngine, 0.0, None)
        .expect("native hook result");
    let result = exec.hook_result.expect("hook result");
    assert_eq!(Verdict::from_u32(result.verdict), Some(Verdict::Continue));
    assert!(exec.injected_actions.is_empty());
    assert!(exec.provider_events.is_empty());
    assert!(exec.modified_data.is_none());
}

fn build_native_fixture() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rns-hooks-native-test-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("create fixture dir");

    let source = dir.join("native_hook.c");
    let lib_path = dir.join(format!(
        "libnative_hook.{}",
        std::env::consts::DLL_EXTENSION
    ));
    fs::write(
        &source,
        r#"
#include <stddef.h>
#include <stdint.h>

typedef struct HookResult {
    uint32_t verdict;
    uint32_t modified_data_offset;
    uint32_t modified_data_len;
    uint32_t inject_actions_offset;
    uint32_t inject_actions_count;
    uint32_t log_offset;
    uint32_t log_len;
} HookResult;

typedef struct RnsNativeHostApi RnsNativeHostApi;

int rns_hook_abi_version(void) {
    return 1;
}

int rns_hook_on_call(
    const uint8_t *ctx,
    size_t ctx_len,
    const RnsNativeHostApi *host_api,
    HookResult *result
) {
    (void)host_api;
    if (ctx == NULL || ctx_len < 4 || result == NULL) {
        return -1;
    }
    uint32_t ctx_type =
        ((uint32_t)ctx[0]) |
        ((uint32_t)ctx[1] << 8) |
        ((uint32_t)ctx[2] << 16) |
        ((uint32_t)ctx[3] << 24);
    if (ctx_type != 2) {
        return -2;
    }
    result->verdict = 0;
    result->modified_data_offset = 0;
    result->modified_data_len = 0;
    result->inject_actions_offset = 0;
    result->inject_actions_count = 0;
    result->log_offset = 0;
    result->log_len = 0;
    return 0;
}
"#,
    )
    .expect("write fixture source");

    let output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source)
        .arg("-o")
        .arg(&lib_path)
        .output()
        .expect("run cc");
    assert!(
        output.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    lib_path
}
