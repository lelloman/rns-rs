fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.first().is_some_and(|arg| arg == "release") {
        args.remove(0);
        rns_git::release_cli::main(args)
    } else if args.first().is_some_and(|arg| arg == "work") {
        args.remove(0);
        rns_git::work_cli::main(args)
    } else if args.first().is_some_and(|arg| arg == "perms") {
        args.remove(0);
        rns_git::perms_cli::main(args)
    } else if args.first().is_some_and(|arg| arg == "create") {
        args.remove(0);
        rns_git::create_cli::main(args)
    } else if args.first().is_some_and(|arg| arg == "fork") {
        args.remove(0);
        rns_git::clone_cli::main(rns_git::clone_cli::CloneCommand::Fork, args)
    } else if args.first().is_some_and(|arg| arg == "sync") {
        args.remove(0);
        rns_git::sync_cli::main(args)
    } else if args.first().is_some_and(|arg| arg == "mirror") {
        args.remove(0);
        rns_git::clone_cli::main(rns_git::clone_cli::CloneCommand::Mirror, args)
    } else {
        rns_git::server::main(args)
    };
    if let Err(err) = result {
        eprintln!("rngit: {err}");
        std::process::exit(1);
    }
}
