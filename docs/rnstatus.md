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
  -s SORT                 Sort by: rate, traffic, rx, tx, frx, ftx,
                          frxs, ftxs, prx, ptx, arxc, atxc, afrxc, prxc, ptxc,
                          pvs, ivs, flt
  -r                      Reverse sort order
  -t                      Show traffic totals
  -l                      Show link count
  -A                      Show announce statistics
  -P, --pr-stats          Show path request statistics
  -F, --filter-stats      Show filtered traffic statistics
  -T, --tunnels           Show tunnel information
  -B, --burst             Only show interfaces with active burst limiting
  -b, --blocked-ips       Show blocked IPs per interface
  -q, --queues            Show inbound queue pressure statistics
  -d                      Show discovered interfaces
  -D                      Show discovered interfaces with config entries
  --show-stale            Include stale discovery entries
  --show-unknown          Include discovery entries without version info
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

`--detach` also takes a tunnel id, as `-T` shows it without the angle
brackets. It names the interface a remote node's tunnel is attached to, such
as one client of a server interface, or the interface this node synthesized
that tunnel on. A spawned client interface has its connection closed. A
configured interface is detached as by its name.

With `-T`, each interface shows a `Tunnel ID` line: the tunnel a connected
transport node synthesized over it, else the one this node synthesized over
it when dialing out, else `None`. A `Rem.Tr.ID` line follows with the
transport identity of the node that synthesized a tunnel over the interface,
or `Unknown`. TCP clients, Backbone clients and outbound I2P peers synthesize a
tunnel each time they connect, so the remote side keeps their paths across
reconnects. Tunnels are only accepted over TCP, Backbone and I2P connections,
one per connection, and a connection whose tunnel synthesis carries a bad
signature is torn down.

Discovered-interface views (`-d` and `-D`) show the announcing stack's
implementation and version as `Running` in the table or `Stack` in the detail
view. Older announcements without both fields show `Unknown`. By default, stale
entries and entries without implementation/version information are hidden; pass
`--show-stale` and/or `--show-unknown` to include them.

An optional `FILTER` limits output to interface names containing the supplied
text. Queue statistics report total, data, announce, path-request, and
ingress-limited queue occupancy, and append cumulative drop counts when they
are nonzero. Backbone listener burst lines include the number of affected child
interfaces when that count is available.

With `-A` or `-P`, each interface includes cumulative incoming and outgoing
packet counts as well as byte totals, current rates, and frequencies. The
`arxc`, `atxc`, `prxc`, and `ptxc` sort keys order interfaces by those announce
and path-request counts. The announce total line ends with the number of
filtered announces when there are any, and the `afrxc` sort key orders by it.
An announce is filtered when ingress control drops it or uses it to replace an
announce it already holds, when `required_destinations_only` rejects its type,
or when its identity is blackholed or its stamp fails. `pvs`, `ivs`, and `flt` sort by protocol, IFAC, and
duplicate-filter violations respectively. A `Hop Limit` line counts frames
dropped because their hop count reached the transport hop limiter configured
with `[filter] hop_limiter`; these are reported separately from protocol
violations and appear only when nonzero. With the default limiter of 128 the
line stays empty: hop counts of 128 and above are malformed and counted as
protocol violations, as upstream.

With `-F`, each interface shows a `Filtered` line, and with `-t` the totals
do too (upstream `134dc677`): the bytes and current rate of received frames
dropped before transport processed them. Those are frames failing IFAC, too
large, malformed, over the hop limiter or caught by the packet filter;
announces dropped while the interface's held announces are full, of a
blocked or not allowed destination type, failing to unpack or verify, from
a blackholed identity, without a required stamp, or held by ingress control;
and path requests that are duplicates, fail a required stamp or join one
already in flight. A filtered frame is moved out of the received bytes and
packets. The `frx`, `ftx`, `frxs` and `ftxs` sort keys order interfaces by
filtered bytes and rates. As upstream, nothing is counted as filtered on
transmit, so the outbound figures stay zero.

For remote status, `-R HASH` requires the management identity selected with
`-i PATH`, and the remote transport must authorize that identity.
