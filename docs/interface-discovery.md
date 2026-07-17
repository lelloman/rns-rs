# Interface discovery locations

Discoverable Backbone and TCP server interfaces can advertise a static
location with `latitude`, `longitude`, and `height`. Alternatively,
`location_cmd` can resolve a changing location immediately before every due
announce:

```ini
[interfaces]
  [[Mobile Backbone]]
    type = BackboneInterface
    enabled = yes
    interface_mode = internal
    listen_ip = 0.0.0.0
    listen_port = 4242
    discoverable = yes
    discovery_name = Mobile Backbone
    reachable_on = backbone.example.net
    location_cmd = ~/bin/reticulum-location
```

On Unix, `location_cmd` must name an executable regular file. A leading `~/`
is expanded to the current home directory. The executable is started directly,
without a shell or arguments, inherits the node environment, and receives null
standard input and standard error. Windows does not support `location_cmd` and
suppresses the affected announce.

The command must exit successfully within five seconds and write no more than
4096 bytes of UTF-8 standard output. Its output is exactly one line containing
three comma-separated numbers:

```text
45.4642,9.1900,122.5
```

The fields are latitude (`-90..=90` degrees), longitude (`-180..=180`
degrees), and height above mean sea level (`-4000..=1000000` metres). All
three values must be finite. Command coordinates override static coordinates
for that announce only; they do not modify the configured values. A missing,
invalid, oversized, timed-out, or unsuccessful command suppresses that
announce without a static fallback. Resolution is retried at the normal
announce interval.

Backbone and TCP server discovery settings can also be changed at runtime.
The nullable keys are `backbone.<name>.location_cmd` and
`tcp_server.<name>.location_cmd`; setting either key to `null` clears the
command, and resetting it restores the startup value.
