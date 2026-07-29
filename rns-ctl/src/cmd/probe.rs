use crate::args::Args;

pub fn run(args: Args) {
    rns_cli::rnprobe_command::run_with_args(args, "rns-ctl probe", "rns-ctl");
}
