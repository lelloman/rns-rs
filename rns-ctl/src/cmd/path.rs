use crate::args::Args;

pub fn run(args: Args) {
    rns_cli::rnpath_command::run_with_args(args, "rns-ctl path", "rns-ctl");
}
