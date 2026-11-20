use crate::args::Args;

/// Run `rnid` with its options, reporting itself as `rns-ctl id`.
pub fn run(args: Args) {
    rns_cli::rnid::run_with_args(args, "rns-ctl id", "rns-ctl");
}
