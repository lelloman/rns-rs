use crate::args::Args;

/// Run `rnprobe` with its options, reporting itself as `rns-ctl probe`.
pub fn run(args: Args) {
    rns_cli::rnprobe::run_with_args(args, "rns-ctl probe", "rns-ctl");
}
