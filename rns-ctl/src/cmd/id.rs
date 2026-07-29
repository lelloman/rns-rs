use crate::args::Args;

pub fn run(args: Args) {
    rns_cli::rnid_command::run_with_args(args, "rns-ctl id", "rns-ctl");
}
