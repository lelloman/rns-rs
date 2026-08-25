# maybe-async-cfg compatibility backport

This directory vendors the MIT-licensed `maybe-async-cfg` 0.2.4 macro
implementation from upstream commit
`384f6bd800420a8f42993271e5d7907848d29da9`. SSD1306 0.10 pins that exact
version because 0.2.5 produces incompatible sync/async expansions.

The local patch preserves the 0.2.4 transformation implementation and replaces
its `proc-macro-error` diagnostic calls with fail-fast procedural-macro
diagnostics. This removes the unmaintained crate covered by
RUSTSEC-2024-0370 without adopting 0.2.5's incompatible transformer behavior.

Remove this directory and the `[patch.crates-io]` entry in
`rns-esp32/Cargo.toml` once SSD1306 publishes a release compatible with a
maintained macro stack.
