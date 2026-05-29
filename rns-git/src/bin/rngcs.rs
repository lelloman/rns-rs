fn main() {
    if let Err(err) = rns_git::commitsigs::main(std::env::args().skip(1)) {
        eprintln!("rngcs: {err}");
        std::process::exit(1);
    }
}
