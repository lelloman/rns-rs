use crate::args::Args;

pub fn run(args: Args) {
    rns_cli::rnstatus_command::run_with_args(args, "rns-ctl status", "rns-ctl");
}
