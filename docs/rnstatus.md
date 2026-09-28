# rnstatus

`rnstatus` displays and controls interfaces on a local `rnsd` instance, or
displays statistics from a remote transport instance with `-R`.

```text
Usage: rnstatus [OPTIONS] [FILTER]

Options:
  --config PATH, -c PATH  Path to config directory
  --attach NAME           Attach a configured interface
  --detach NAME           Detach a running interface
  --reload NAME           Reload a running interface from config
  -a                      Show all interfaces
  -j                      JSON output
  -s SORT                 Sort by: rate, traffic, rx, tx, prx, ptx,
                          arxc, atxc, prxc, ptxc, vio, ifac, flt
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

`--attach` reads the named interface from the current config file, including
sections marked disabled. `--reload` detaches it and reads that section again,
so edits take effect without restarting `rnsd`. Local, I2P, and shared-instance
interfaces cannot be detached. Set `enable_interface_management = no` in
`[reticulum]` to disallow these commands through the shared-instance RPC port.

For example, after editing an interface section named `Backbone`, run
`rnstatus --reload Backbone`. Use `rnstatus --attach Backbone` to start it when
it is not running, or `rnstatus --detach Backbone` to stop it.

Discovered-interface views (`-d` and `-D`) show the announcing stack's
implementation and version as `Running` in the table or `Stack` in the detail
view. Older announcements without both fields show `Unknown`.

An optional `FILTER` limits output to interface names containing the supplied
text. Queue statistics report total, data, announce, path-request, and
ingress-limited queue occupancy, and append cumulative drop counts when they
are nonzero. Backbone listener burst lines include the number of affected child
interfaces when that count is available.

With `-A` or `-P`, each interface includes cumulative incoming and outgoing
packet counts as well as byte totals, current rates, and frequencies. The
`arxc`, `atxc`, `prxc`, and `ptxc` sort keys order interfaces by those announce
and path-request counts. `vio`, `ifac`, and `flt` sort by protocol, IFAC, and
duplicate-filter violations respectively.

For remote status, `-R HASH` requires the management identity selected with
`-i PATH`, and the remote transport must authorize that identity.
