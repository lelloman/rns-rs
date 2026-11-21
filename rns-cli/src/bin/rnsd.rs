//! rnsd - the Reticulum daemon: runs a node from the config directory until
//! it is signalled to stop.

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> std::process::ExitCode {
    rns_cli::rnsd::main_entry()
}
