//! rngcs - signs and verifies git commits with a Reticulum identity, as
//! git's `gpg.ssh.program`.

fn main() {
    if let Err(err) = rns_git::commitsigs::main(std::env::args().skip(1)) {
        eprintln!("rngcs: {err}");
        std::process::exit(1);
    }
}
