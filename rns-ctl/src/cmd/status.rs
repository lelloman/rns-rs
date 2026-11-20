use crate::args::Args;

/// Run `rnstatus` with its options, reporting itself as `rns-ctl status`.
pub fn run(args: Args) {
    rns_cli::rnstatus::run_with_args(args, "rns-ctl status", "rns-ctl");
}
