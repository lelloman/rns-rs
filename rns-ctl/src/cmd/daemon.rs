use crate::args::Args;

/// Run the node daemon with `rnsd`'s options until it is shut down.
pub fn run(args: Args) {
    rns_cli::rnsd::main_entry_from_named(args, "rns-ctl daemon", "rns-ctl");
}
