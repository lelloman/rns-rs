use crate::args::Args;

pub fn run(args: Args) {
    rns_cli::rnsd::main_entry_from_named(args, "rns-ctl daemon", "rns-ctl");
}
