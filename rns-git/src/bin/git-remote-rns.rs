fn main() {
    env_logger::init();
    if let Err(err) = rns_git::client::main(std::env::args().skip(1)) {
        eprintln!("git-remote-rns: {err}");
        std::process::exit(1);
    }
}
