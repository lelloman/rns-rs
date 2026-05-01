fn main() {
    env_logger::init();
    if let Err(err) = rns_git::server::main(std::env::args().skip(1)) {
        eprintln!("rngit: {err}");
        std::process::exit(1);
    }
}
