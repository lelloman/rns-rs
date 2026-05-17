fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.first().is_some_and(|arg| arg == "release") {
        args.remove(0);
        rns_git::release_cli::main(args)
    } else if args.first().is_some_and(|arg| arg == "work") {
        args.remove(0);
        rns_git::work_cli::main(args)
    } else if args.first().is_some_and(|arg| arg == "create") {
        args.remove(0);
        rns_git::create_cli::main(args)
    } else {
        rns_git::server::main(args)
    };
    if let Err(err) = result {
        eprintln!("rngit: {err}");
        std::process::exit(1);
    }
}
