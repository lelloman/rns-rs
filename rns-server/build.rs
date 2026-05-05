#[path = "build_common.rs"]
mod build_common;

fn main() {
    build_common::emit_git_rerun_inputs();
    build_common::emit_full_version();
}
