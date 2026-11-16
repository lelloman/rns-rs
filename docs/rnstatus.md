# rnstatus

`rnstatus` displays and controls interfaces on a local `rnsd` instance, or
displays statistics from a remote transport instance with `-R`.

The status display is upstream's, byte for byte: the same lines, order,
number formatting and quirks, rendered from the same statistics. The tests
check it against upstream's own output (`tests/fixtures/rnstatus`, generated
by `tests/generate_rnstatus_fixtures.py`). One difference is inherent: upstream's
`rnstatus` connects to the shared instance as a client, so with `-a` it also
lists its own `LocalInterface` and counts itself as a served program, while
this one asks over RPC only.

```text
usage: rnstatus [-h] [--config CONFIG] [--version] [--attach name]
                [--detach name] [--reload name] [-a] [-A] [-P] [-F] [-l] [-B]
                [-b] [-t] [-T] [-p] [-q] [-z] [-s SORT] [-r] [-j] [-R hash]
                [-i path] [-w seconds] [-d] [-D] [--show-stale]
                [--show-unknown] [-m] [-I seconds] [-v]
                [filter]

Reticulum Network Stack Status

positional arguments:
  filter                only display interfaces with names including filter

options:
  -h, --help            show this help message and exit
  --config CONFIG       path to alternative Reticulum config directory
  --version             show program's version number and exit
  --attach name         Attach interface by name
  --detach name         Detach interface by name
  --reload name         Reload interface by name
  -a, --all             show all interfaces
  -A, --announce-stats  show announce stats
  -P, --pr-stats        show path request stats
  -F, --filter-stats    show filtered traffic stats
  -l, --link-stats      show link stats
  -B, --burst           only show interfaces with active bursts
  -b, --blocked-ips     show blocked IPs per interface
  -t, --totals          display traffic totals
  -T, --tunnels         display tunnel information
  -p, --pps             display packets per second in totals
  -q, --queues          display queue stats
  -z, --profiling       display live profiling results
  -s SORT, --sort SORT  sort interfaces by [rate, traffic, rx, tx, rxs, txs,
                        frx, ftx, anns, arx, atx, arxc, atxc, afrxc, held,
                        prx, ptx, prxc, ptxc, pvs, ivs, flt, txdrp, txdrb,
                        txbuf]
  -r, --reverse         reverse sorting
  -j, --json            output in JSON format
  -R hash               transport identity hash of remote instance to get
                        status from
  -i path               path to identity used for remote management
  -w seconds            timeout before giving up on remote queries
  -d, --discovered      list discovered interfaces
  -D                    show details and config entries for discovered
                        interfaces
  --show-stale          show stale discovery entries
  --show-unknown        show discovery entries without version info
  -m, --monitor         continuously monitor status
  -I seconds, --monitor-interval seconds
                        refresh interval for monitor mode (default: 1)
  -v, --verbose
```

Also accepted, not listed: `-c PATH` for `--config` and `--identity PATH`
for `-i`.

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
`--show-stale` and/or `--show-unknown` to include them. The views are upstream's,
byte for byte, `-j` included (fixtures `discovered_*` in
`tests/fixtures/rnstatus`). The list comes from the instance's
`discovered_interfaces` RPC call; an instance without it, such as upstream's,
is read from its stored records, as upstream's `rnstatus` always does.

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
duplicate-filter violations respectively. Frames dropped because their hop
count reached the transport hop limiter (`[filter] hop_limiter`) are counted
separately from protocol violations, as `hop_limiter_hits` in `-j` output;
upstream's display has no line for them. With the default limiter of 128 the
count stays zero: hop counts of 128 and above are malformed and counted as
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
packets. A held announce's frame is counted again when ingress control
releases it: as received if it is then accepted, as filtered if not
(upstream `29dc449a`). The `frx`, `ftx`, `frxs` and `ftxs` sort keys order interfaces by
filtered bytes and rates. As upstream, nothing is counted as filtered on
transmit, so the outbound figures stay zero.

For remote status, `-R HASH` requires the management identity selected with
`-i PATH`, and the remote transport must authorize that identity.
