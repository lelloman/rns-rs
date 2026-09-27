# Contributing to rns-rs

## Authorship and provenance

rns-rs is an independent reimplementation of Reticulum's reference
implementation (RNS). It is **not** a clean-room design: it is a derivative
work distributed under the [Reticulum License](LICENSE). Contributions are
accepted under the same license, and the original copyright and permission
notice must be preserved in copies and substantial portions of the project.

Development makes substantial use of machine (LLM) assistance under human
direction and review. This is stated deliberately: assistance is welcome, but
the human contributor remains the agent of the work. By submitting a change you
confirm that:

- you have reviewed and understand it, and can answer for it;
- it is your own submission and you have the right to submit it;
- it does not remove or weaken attribution to the reference implementation;
- where substantial machine assistance was used, that is stated in the pull
  request description.

Do not describe the project as "ground-up", clean-room, or otherwise
independent of the reference implementation. It is a port of RNS, and it says
so.

## Development

See the [Developer Checks](README.md#developer-checks) section of the README
for the standard validation commands: `cargo test --workspace`,
`bash scripts/lint-host.sh`, `cargo fmt --check`, and the Docker end-to-end
suites. New behavior should come with focused tests, and protocol-facing
changes should be validated against the Python reference where applicable.

## License conditions

The Reticulum License conditions apply to the project and to contributions:

- the software must not be used in systems designed to purposefully harm human
  beings;
- it must not be used, directly or indirectly, in the creation of an artificial
  intelligence, machine learning, or language model training dataset;
- the copyright and permission notice must be included in all copies and
  substantial portions of the software.
