use crate::args::Args;

/// Run `rnpath` with its options, reporting itself as `rns-ctl path`.
pub fn run(args: Args) {
    rns_cli::rnpath_command::run_with_args(args, "rns-ctl path", "rns-ctl");
}
