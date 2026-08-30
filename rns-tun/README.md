# rntun

`rntun` carries validated IPv4 packets over authenticated Reticulum Links. Each
process starts a private `RnsNode`; it does not connect to `rnsd` or reuse the
normal Reticulum state directory.

The Linux binary currently supports:

```text
rntun check    --config /etc/rntun/config.toml
rntun identity --config /etc/rntun/config.toml
rntun listen   --config /etc/rntun/config.toml
rntun connect  <destination-hash> --config /etc/rntun/config.toml
rntun status   --config /etc/rntun/config.toml [--json]
rntun cleanup  --config /etc/rntun/config.toml
```

Linux setup requires `/dev/net/tun`, `CAP_NET_ADMIN`, and (for `SO_MARK`)
`CAP_NET_ADMIN`. Full-tunnel DNS requires `systemd-resolved` and `resolvectl`.
Network changes are made by direct `ip`/`resolvectl` process invocation (never
through a shell) and recorded in a mode-0600 ownership journal. `cleanup`
replays only the exact inverse operations in that journal.

Gateway forwarding, firewall policy, and NAT are deliberately operator-owned.
`rntun` does not enable forwarding or masquerading.

The privileged Linux acceptance suite creates separate client, gateway, and
remote-target containers with real TUN devices. It covers split and full routes,
gateway NAT, DNS-address delivery, resolver selection, IPv6 blocking, Link-loss
reconnect, fail-closed behavior, orderly teardown, crash reconciliation, and
partial-setup rollback:

```bash
./tests/docker/rntun/run.sh
```

The resolver command path uses a deterministic `resolvectl` facade inside the
container; validation against a host running real systemd-resolved remains a
separate release test.

See [`../docs/rntun-design.md`](../docs/rntun-design.md) for the protocol and
security model.
