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

See [`../docs/rntun-design.md`](../docs/rntun-design.md) for the protocol and
security model.
