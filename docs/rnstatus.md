# rnstatus

`rnstatus` displays interface and transport statistics from a local `rnsd`
instance or, with `-R`, from a remote transport instance.

```text
Usage: rnstatus [OPTIONS] [FILTER]

Options:
  --config PATH, -c PATH  Path to config directory
  -a                      Show all interfaces
  -j                      JSON output
  -s SORT                 Sort by: rate, traffic, rx, tx, prx, ptx
  -r                      Reverse sort order
  -t                      Show traffic totals
  -l                      Show link count
  -A                      Show announce statistics
  -P, --pr-stats          Show path request statistics
  -B, --burst             Only show interfaces with active burst limiting
  -b, --blocked-ips       Show blocked IPs per interface
  -q, --queues            Show inbound queue pressure statistics
  -d                      Show discovered interfaces
  -D                      Show discovered interfaces with config entries
  -m                      Monitor mode (loop)
  -I SECONDS              Monitor interval (default: 1.0)
  -R HASH                 Query remote transport identity via management link
  -i PATH                 Identity file for remote management
  -w SECONDS              Timeout for remote queries
  -v                      Increase verbosity
  --version               Print version and exit
  --help, -h              Print this help
```

An optional `FILTER` limits output to interface names containing the supplied
text. Queue statistics report total, data, announce, path-request, and
ingress-limited queue occupancy, and append cumulative drop counts when they
are nonzero. Backbone listener burst lines include the number of affected child
interfaces when that count is available.

For remote status, `-R HASH` requires the management identity selected with
`-i PATH`, and the remote transport must authorize that identity.
