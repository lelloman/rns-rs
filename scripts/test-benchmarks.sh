#!/usr/bin/env bash
set -euo pipefail

# Criterion's test mode executes every benchmark once. This catches API and
# feature incompatibilities without performing a full statistical benchmark.
cargo bench -p rns-core --bench transport_hot_paths -- --test
cargo bench -p rns-net --bench link_dispatch -- --test
cargo bench -p rns-net --bench shared_client_replay -- --test
cargo bench -p rns-hooks --bench hook_dispatch -- --test
