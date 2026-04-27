use rns_hooks::{
    register_builtin_hook, BuiltinHookCall, BuiltinHookHost, HookContext, HookManager, NullEngine,
    Verdict,
};

#[test]
fn builtin_hook_loads_and_executes_from_registry() {
    let id = format!("test.builtin.{}", std::process::id());
    register_builtin_hook(id.clone(), continue_on_tick).expect("register built-in hook");

    let manager = HookManager::new().expect("manager");
    let mut program = manager
        .load_builtin("builtin-test".into(), id, 0)
        .expect("load built-in hook");

    assert_eq!(program.backend_name(), "builtin");

    let exec = manager
        .execute_program(&mut program, &HookContext::Tick, &NullEngine, 0.0, None)
        .expect("built-in hook result");
    let result = exec.hook_result.expect("hook result");
    assert_eq!(Verdict::from_u32(result.verdict), Some(Verdict::Continue));
}

fn continue_on_tick(
    call: BuiltinHookCall<'_>,
    _host: &mut BuiltinHookHost,
) -> Result<rns_hooks::HookResult, rns_hooks::HookError> {
    assert!(matches!(call.ctx, HookContext::Tick));
    Ok(rns_hooks::HookResult::continue_result())
}
