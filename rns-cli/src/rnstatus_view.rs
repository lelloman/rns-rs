//! `rnstatus`'s status display, ported statement by statement from
//! upstream's `RNS/Utilities/rnstatus.py` (`program_setup`, from
//! `if stats != None:`) so the output matches it byte for byte, quirks
//! included. `render` is split into one helper per output section, each
//! keeping upstream's statement order; keep them parallel to upstream's
//! when changing them.

use rns_net::pickle::PickleValue;

use crate::pyfmt::{
    self, hexrep, len, pad, prettyfrequency, prettyhexrep, prettyshorttime_tight, prettysize,
    prettyspeed, prettytime, str_of, truthy, Num,
};

// Upstream's `Interface.MODE_*`.
const MODE_POINT_TO_POINT: i64 = 0x02;
const MODE_ACCESS_POINT: i64 = 0x03;
const MODE_ROAMING: i64 = 0x04;
const MODE_BOUNDARY: i64 = 0x05;
const MODE_GATEWAY: i64 = 0x06;
const MODE_INTERNAL: i64 = 0x07;

/// The display switches of upstream's `program_setup`.
#[derive(Clone, Debug, Default)]
pub struct ViewOptions {
    /// `-a`
    pub dispall: bool,
    /// The positional filter.
    pub name_filter: Option<String>,
    /// `-A`
    pub astats: bool,
    /// `-P`
    pub pstats: bool,
    /// `-l`
    pub lstats: bool,
    /// `-s`
    pub sorting: Option<String>,
    /// `-r`
    pub sort_reverse: bool,
    /// `-t`
    pub traffic_totals: bool,
    /// `-B`
    pub burst_filter: bool,
    /// `-b`
    pub blocked_ips: bool,
    /// `-q`
    pub queue_stats: bool,
    /// `-p`
    pub pps: bool,
    /// `-F`
    pub fstats: bool,
    /// `-T`
    pub tstats: bool,
}

/// What a status query returned besides the stats themselves.
#[derive(Clone, Debug, Default)]
pub struct Extras<'a> {
    /// Entries in the link table, for `-l`.
    pub link_count: Option<Num>,
    /// How many of those links are active; shown when nonzero.
    pub active_link_count: Option<Num>,
    /// The instance's profiling results, shown when present and truthy.
    pub profiling_results: Option<&'a PickleValue>,
}

fn get<'a>(dict: &'a PickleValue, key: &str) -> Option<&'a PickleValue> {
    dict.get(key)
}

fn has(dict: &PickleValue, key: &str) -> bool {
    dict.get(key).is_some()
}

/// `d[key] != None` (a missing key reads as `None` instead of raising).
fn not_none(dict: &PickleValue, key: &str) -> bool {
    present(dict, key).is_some()
}

/// `d[key]` when it is there and not `None`.
fn present<'a>(dict: &'a PickleValue, key: &str) -> Option<&'a PickleValue> {
    dict.get(key)
        .filter(|value| !matches!(value, PickleValue::None))
}

fn num(dict: &PickleValue, key: &str) -> Num {
    dict.get(key).and_then(Num::of).unwrap_or(Num::Int(0))
}

fn opt_num(dict: &PickleValue, key: &str) -> Option<Num> {
    dict.get(key).and_then(Num::of)
}

fn s(dict: &PickleValue, key: &str) -> String {
    dict.get(key).map(str_of).unwrap_or_else(|| "None".into())
}

fn name_of(dict: &PickleValue) -> &str {
    dict.get("name").and_then(|v| v.as_str()).unwrap_or("")
}

fn bytes_of<'a>(dict: &'a PickleValue, key: &str) -> Option<&'a [u8]> {
    match dict.get(key) {
        Some(PickleValue::Bytes(b)) => Some(b),
        _ => None,
    }
}

/// `100.0 * a / b` clamped as upstream's flow percentages are, or 0.0 when
/// either is falsy.
fn flow_pct(dict: &PickleValue, part: &str, whole: &str) -> f64 {
    if truthy(get(dict, whole)) && truthy(get(dict, part)) {
        f64::min(100.0, (num(dict, part).f() / num(dict, whole).f()) * 100.0)
    } else {
        0.0
    }
}

fn sort_key_name(sorting: &str) -> Option<&'static str> {
    Some(match sorting {
        "rate" | "bitrate" => "bitrate",
        "rx" => "rxb",
        "tx" => "txb",
        "frx" => "frxb",
        "ftx" => "ftxb",
        "rxs" => "rxs",
        "txs" => "txs",
        "frxs" => "frxs",
        "ftxs" => "ftxs",
        "traffic" => "traffic",
        "anns" | "announces" => "anns",
        "arx" => "incoming_announce_frequency",
        "atx" => "outgoing_announce_frequency",
        "arxc" => "arxc",
        "atxc" => "atxc",
        "afrxc" => "afrxc",
        "prx" => "incoming_pr_frequency",
        "ptx" => "outgoing_pr_frequency",
        "prxc" => "prxc",
        "ptxc" => "ptxc",
        "held" => "held_announces",
        "pvs" => "protocol_violations",
        "ivs" => "ifac_violations",
        "flt" => "packet_filter_hits",
        "gravity" | "g" => "gravity",
        "txdrp" => "txdrp",
        "txdrb" => "txdrb",
        "txbuf" => "txbuffered",
        _ => return None,
    })
}

fn sort_value(iface: &PickleValue, key: &str) -> f64 {
    match key {
        "traffic" => num(iface, "rxb").f() + num(iface, "txb").f(),
        "anns" => {
            num(iface, "incoming_announce_frequency").f()
                + num(iface, "outgoing_announce_frequency").f()
        }
        key => num(iface, key).f(),
    }
}

/// Upstream's interfaces hidden without `-a`.
fn hidden_without_all(name: &str, iface: &PickleValue) -> bool {
    name.starts_with("LocalInterface[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("BackboneInterface[Client on")
        || name.starts_with("AutoInterfacePeer[")
        || name.starts_with("WeaveInterfacePeer[")
        || name.starts_with("I2PInterfacePeer[Connected peer")
        || unconnectable_i2p(name, iface)
}

fn unconnectable_i2p(name: &str, iface: &PickleValue) -> bool {
    name.starts_with("I2PInterface[")
        && matches!(
            get(iface, "i2p_connectable"),
            Some(PickleValue::Bool(false))
        )
}

/// Upstream's `print(...)`: the formatted line and a newline onto `$out`.
macro_rules! outln {
    ($out:expr) => { $out.push('\n') };
    ($out:expr, $($arg:tt)*) => {{ $out.push_str(&format!($($arg)*)); $out.push('\n'); }};
}

/// The status display for `stats` (upstream's `get_interface_stats()`
/// result), as upstream prints it; `now` stands in for `time.time()`.
pub fn render(stats: &PickleValue, opts: &ViewOptions, extras: &Extras<'_>, now: f64) -> String {
    let mut out = String::new();

    for ifstat in sorted_interfaces(stats, opts) {
        if interface_shown(ifstat, opts) {
            render_interface(&mut out, ifstat, opts, now);
        }
    }

    let lstr = link_table_str(stats, opts, extras);
    if opts.traffic_totals {
        render_totals(&mut out, stats, opts);
    }
    if opts.queue_stats {
        render_queue_pressure(&mut out, stats);
    }
    if let Some(results) = extras.profiling_results.filter(|r| truthy(Some(r))) {
        outln!(
            out,
            "\n Profiling    :\n{}",
            format_profiling_results(results)
        );
    }
    render_instance_footer(&mut out, stats, &lstr);

    outln!(out, "");
    out
}

/// The interfaces in display order: as listed, or sorted by `-s`.
fn sorted_interfaces<'a>(stats: &'a PickleValue, opts: &ViewOptions) -> Vec<&'a PickleValue> {
    let mut interfaces: Vec<&PickleValue> = match get(stats, "interfaces") {
        Some(PickleValue::List(list)) => list.iter().collect(),
        _ => Vec::new(),
    };
    if let Some(sorting) = opts.sorting.as_deref() {
        if let Some(key) = sort_key_name(&sorting.to_lowercase()) {
            // Python's stable sort, descending unless reversed.
            interfaces.sort_by(|a, b| {
                let (a, b) = (sort_value(a, key), sort_value(b, key));
                let ord = a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal);
                if opts.sort_reverse {
                    ord
                } else {
                    ord.reverse()
                }
            });
        }
    }
    interfaces
}

/// Whether `-a`, `-B` and the name filter let `ifstat` through.
fn interface_shown(ifstat: &PickleValue, opts: &ViewOptions) -> bool {
    let name = name_of(ifstat);
    if !opts.dispall && hidden_without_all(name, ifstat) {
        return false;
    }
    if unconnectable_i2p(name, ifstat) {
        return false;
    }
    if !opts.burst_filter {
        match opts.name_filter.as_deref() {
            Some(filter) if !filter.is_empty() => {
                name.to_lowercase().contains(&filter.to_lowercase())
            }
            _ => true,
        }
    } else {
        let burst_act = has(ifstat, "burst_active")
            && has(ifstat, "pr_burst_active")
            && (truthy(get(ifstat, "burst_active")) || truthy(get(ifstat, "pr_burst_active")));
        let nfilt = opts
            .name_filter
            .as_deref()
            .filter(|f| !f.is_empty())
            .is_some_and(|f| name.to_lowercase().contains(&f.to_lowercase()));
        burst_act || nfilt
    }
}

/// One interface's block, preceded by a blank line.
fn render_interface(out: &mut String, ifstat: &PickleValue, opts: &ViewOptions, now: f64) {
    let name = name_of(ifstat);
    outln!(out, "");

    let (mut clients, clients_string) = clients_str(name, ifstat, opts);
    render_interface_header(out, ifstat, name, clients.is_some(), &clients_string);
    render_tunnel(out, ifstat, opts);
    render_device(out, ifstat, now);
    render_link(out, ifstat);
    render_announce_queues(out, ifstat, opts);

    let columns = FlowColumns::new(ifstat, opts, name, &mut clients);

    render_violations(out, ifstat);
    if truthy(get(ifstat, "packet_filter_hits")) {
        outln!(out, "    Flt. Hits : {}", s(ifstat, "packet_filter_hits"));
    }
    if columns.psr {
        render_path_requests(out, ifstat, &columns, now);
    }
    if columns.asr {
        render_announces(out, ifstat, opts, &columns, now);
    }
    render_traffic(out, ifstat, opts, columns.rxb_str, columns.txb_str);
}

/// The client count and upstream's `clients_string` for it (with `-b`'s
/// blocked addresses appended), or `None` when the interface reports no
/// clients.
fn clients_str(name: &str, ifstat: &PickleValue, opts: &ViewOptions) -> (Option<Num>, String) {
    let mut clients_string = String::new();
    if !not_none(ifstat, "clients") {
        return (None, clients_string);
    }
    let count = num(ifstat, "clients");
    if name.starts_with("Shared Instance[") {
        let cnum = (count.f() as i64 - 1).max(0);
        let spec_str = if cnum == 1 { " program" } else { " programs" };
        clients_string = format!("Serving   : {cnum}{spec_str}");
    } else if name.starts_with("I2PInterface[") {
        if matches!(
            get(ifstat, "i2p_connectable"),
            Some(PickleValue::Bool(true))
        ) {
            let spec_str = if count == Num::Int(1) {
                " connected I2P endpoint"
            } else {
                " connected I2P endpoints"
            };
            clients_string = format!("Peers     : {}{spec_str}", count.str());
        }
    } else {
        clients_string = format!("Clients   : {}", count.str());
        if has(ifstat, "blocked_ips") && num(ifstat, "blocked_ips").f() > 0.0 {
            // Upstream's precedence makes this always plural.
            clients_string += &format!("\n    Blocked   : {} IPs", s(ifstat, "blocked_ips"));
        }
    }
    if opts.blocked_ips {
        if let Some(PickleValue::List(list)) = get(ifstat, "blocked_ip_list") {
            for bip in list {
                clients_string += &format!("\n                {}", str_of(bip));
            }
        }
    }
    (Some(count), clients_string)
}

/// The interface's name, source, network, status, clients and mode lines.
fn render_interface_header(
    out: &mut String,
    ifstat: &PickleValue,
    name: &str,
    has_clients: bool,
    clients_string: &str,
) {
    let mut ss = String::from(if truthy(get(ifstat, "status")) {
        "Up"
    } else {
        "Down"
    });
    if has(ifstat, "gravity") && truthy(get(ifstat, "gravity")) {
        ss += &format!(", gravity {}", s(ifstat, "gravity"));
    }

    let mut modestr = String::from(match num(ifstat, "mode") {
        Num::Int(MODE_ACCESS_POINT) => "Access Point",
        Num::Int(MODE_POINT_TO_POINT) => "Point-to-Point",
        Num::Int(MODE_ROAMING) => "Roaming",
        Num::Int(MODE_BOUNDARY) => "Boundary",
        Num::Int(MODE_GATEWAY) => "Gateway",
        Num::Int(MODE_INTERNAL) => "Internal",
        _ => "Full",
    });
    if has(ifstat, "announces_to_internal") && truthy(get(ifstat, "announces_to_internal")) {
        modestr += " (a>i)";
    }

    outln!(out, " {}", s(ifstat, "name"));

    if not_none(ifstat, "autoconnect_source") {
        outln!(
            out,
            "    Source    : Auto-connect via <{}>",
            s(ifstat, "autoconnect_source")
        );
    }
    if not_none(ifstat, "ifac_netname") {
        outln!(out, "    Network   : {}", s(ifstat, "ifac_netname"));
    }

    outln!(out, "    Status    : {ss}");

    if has_clients && !clients_string.is_empty() {
        outln!(out, "    {clients_string}");
    }

    if !(name.starts_with("Shared Instance[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("LocalInterface["))
    {
        outln!(out, "    Mode      : {modestr}");
    }

    if truthy(get(ifstat, "txdrp")) {
        outln!(
            out,
            "    TX Drops  : {} ({})",
            s(ifstat, "txdrp"),
            prettysize(num(ifstat, "txdrb").f(), "B")
        );
    }

    if not_none(ifstat, "bitrate") {
        outln!(
            out,
            "    Rate      : {}, MTU {}",
            speed_str(num(ifstat, "bitrate").f()),
            s(ifstat, "mtu")
        );
    }
}

/// `-T`: the tunnel id and, for an interface with a tunnel, what the
/// remote transport node reported.
fn render_tunnel(out: &mut String, ifstat: &PickleValue, opts: &ViewOptions) {
    // Upstream b7a93b9b: the tunnel id as plain hex, then for an
    // interface with a tunnel what the remote transport node reported.
    // Upstream indexes these keys directly; a missing key reads as
    // `None` here, as from an instance that predates them.
    let tunnel_id = bytes_of(ifstat, "tunnel_id").filter(|b| !b.is_empty());
    if opts.tstats {
        let tid = tunnel_id.map(hexrep).unwrap_or_else(|| "None".into());
        outln!(out, "    Tunnel ID : {tid}");
    }
    if !(opts.tstats && tunnel_id.is_some()) {
        return;
    }
    let rid = match bytes_of(ifstat, "remote_transport_id") {
        Some(b) if !b.is_empty() => prettyhexrep(b),
        _ => "Unknown".into(),
    };
    outln!(out, "    Rem.Tr.ID : {rid}");

    let impl_str = if truthy(get(ifstat, "rem_impl")) {
        s(ifstat, "rem_impl")
    } else {
        "Unknown implementation".into()
    };
    let vers_str = match get(ifstat, "rem_vers") {
        Some(PickleValue::List(components)) if !components.is_empty() => format!(
            " {}",
            components.iter().map(str_of).collect::<Vec<_>>().join(".")
        ),
        _ => ", unknown version".into(),
    };
    outln!(out, "    Rem.Vers. : {impl_str}{vers_str}");

    let cost = |key: &str, label: &str| {
        if not_none(ifstat, key) {
            format!(
                "{label} {}",
                crate::format::prettycost(Some(num(ifstat, key).f()))
            )
        } else {
            format!("{label} ?")
        }
    };
    outln!(
        out,
        "    Rem.Csts. : {}, {}",
        cost("rem_dst_cost", "Dst"),
        cost("rem_pr_cost", "PR")
    );
}

/// The radio and device readings: noise floor, CPU, memory, battery,
/// airtime, channel load and switch ids.
fn render_device(out: &mut String, ifstat: &PickleValue, now: f64) {
    if has(ifstat, "noise_floor") {
        render_noise_floor(out, ifstat, now);
    }

    if has(ifstat, "cpu_load") {
        if not_none(ifstat, "cpu_load") {
            outln!(out, "    CPU load  : {} %", s(ifstat, "cpu_load"));
        } else {
            outln!(out, "    CPU load  : Unknown");
        }
    }
    if has(ifstat, "cpu_temp") {
        if not_none(ifstat, "cpu_temp") {
            outln!(out, "    CPU temp  : {}°C", s(ifstat, "cpu_temp"));
        } else {
            // Upstream's label.
            outln!(out, "    CPU load  : Unknown");
        }
    }
    if has(ifstat, "mem_load") {
        // Upstream tests cpu_load here.
        if not_none(ifstat, "cpu_load") {
            outln!(out, "    Mem usage : {} %", s(ifstat, "mem_load"));
        } else {
            outln!(out, "    Mem usage : Unknown");
        }
    }

    if not_none(ifstat, "battery_percent") {
        if let Some(bpi) = opt_num(ifstat, "battery_percent") {
            outln!(
                out,
                "    Battery   : {}% ({})",
                bpi.f().trunc() as i64,
                s(ifstat, "battery_state")
            );
        }
    }

    if has(ifstat, "airtime_short") && has(ifstat, "airtime_long") {
        outln!(
            out,
            "    Airtime   : {}% (15s), {}% (1h)",
            s(ifstat, "airtime_short"),
            s(ifstat, "airtime_long")
        );
    }
    if has(ifstat, "channel_load_short") && has(ifstat, "channel_load_long") {
        outln!(
            out,
            "    Ch. Load  : {}% (15s), {}% (1h)",
            s(ifstat, "channel_load_short"),
            s(ifstat, "channel_load_long")
        );
    }

    for (key, label) in [
        ("switch_id", "Switch ID"),
        ("endpoint_id", "Endpoint "),
        ("via_switch_id", "Via      "),
    ] {
        if has(ifstat, key) {
            if not_none(ifstat, key) {
                outln!(out, "    {label} : {}", s(ifstat, key));
            } else {
                outln!(out, "    {label} : Unknown");
            }
        }
    }
}

/// The noise floor line, with the interference reading when reported.
fn render_noise_floor(out: &mut String, ifstat: &PickleValue, now: f64) {
    let nstr = if !has(ifstat, "interference") {
        String::new()
    } else {
        let mut lstr = String::from(", no interference");
        if has(ifstat, "interference_last_ts") && has(ifstat, "interference_last_dbm") {
            let lago = now - num(ifstat, "interference_last_ts").f();
            lstr = format!(
                "\n    Intrfrnc. : {} dBm {} ago",
                s(ifstat, "interference_last_dbm"),
                prettytime(Num::Float(lago), true)
            );
        }
        if truthy(get(ifstat, "interference")) {
            format!("\n    Intrfrnc. : {} dBm", s(ifstat, "interference"))
        } else {
            lstr
        }
    };
    if not_none(ifstat, "noise_floor") {
        outln!(
            out,
            "    Noise Fl. : {} dBm{nstr}",
            s(ifstat, "noise_floor")
        );
    } else {
        outln!(out, "    Noise Fl. : Unknown");
    }
}

/// Reachable peers, I2P tunnel state, IFAC and I2P address.
fn render_link(out: &mut String, ifstat: &PickleValue) {
    if not_none(ifstat, "peers") {
        outln!(out, "    Peers     : {} reachable", s(ifstat, "peers"));
    }
    if not_none(ifstat, "tunnelstate") {
        outln!(out, "    I2P       : {}", s(ifstat, "tunnelstate"));
    }

    if let Some(sig) = bytes_of(ifstat, "ifac_signature") {
        let tail = &sig[sig.len().saturating_sub(5)..];
        outln!(
            out,
            "    Access    : {}-bit IFAC by <…{}>",
            num(ifstat, "ifac_size").f() as i64 * 8,
            hexrep(tail)
        );
    }

    if not_none(ifstat, "i2p_b32") {
        outln!(out, "    I2P B32   : {}", s(ifstat, "i2p_b32"));
    }
}

/// `-A`: queued and held announce counts, when nonzero.
fn render_announce_queues(out: &mut String, ifstat: &PickleValue, opts: &ViewOptions) {
    for (key, label) in [
        ("announce_queue", "Queued   "),
        ("held_announces", "Held     "),
    ] {
        if opts.astats && not_none(ifstat, key) && num(ifstat, key).f() > 0.0 {
            let aqn = num(ifstat, key);
            let plural = if aqn == Num::Int(1) { "" } else { "s" };
            outln!(out, "    {label} : {} announce{plural}", aqn.str());
        }
    }
}

/// The announce (`-A`) and path request (`-P`) frequency columns and the
/// traffic byte counts, padded to a common width.
struct FlowColumns {
    /// Incoming and outgoing announce frequencies.
    iaf: String,
    oaf: String,
    /// Incoming and outgoing path request frequencies.
    ipf: String,
    opf: String,
    rxb_str: String,
    txb_str: String,
    /// The per-client and share-of-flow suffix for announces.
    pc_str: String,
    /// The same for path requests.
    rpc_str: String,
    /// Whether the announce lines are shown.
    asr: bool,
    /// Whether the path request lines are shown.
    psr: bool,
}

impl FlowColumns {
    /// The columns for `ifstat`; may fall back to its peer count for
    /// `clients`, as upstream does.
    fn new(
        ifstat: &PickleValue,
        opts: &ViewOptions,
        name: &str,
        clients: &mut Option<Num>,
    ) -> Self {
        let mut rxb_str = format!("↓{}", prettysize(num(ifstat, "rxb").f(), "B"));
        let mut txb_str = format!("↑{}", prettysize(num(ifstat, "txb").f(), "B"));

        let both_flows =
            has(ifstat, "prxs") && has(ifstat, "rxs") && has(ifstat, "ptxs") && has(ifstat, "txs");
        let is_shared = name.starts_with("Shared Instance[");

        let (mut iaf, mut oaf, mut pc_str) = (String::new(), String::new(), String::new());
        let asr = opts.astats && not_none(ifstat, "incoming_announce_frequency");
        if asr {
            let (oan, ian);
            (oan, ian, pc_str) = frequencies(
                ifstat,
                clients,
                is_shared,
                both_flows,
                ["outgoing_announce_frequency", "incoming_announce_frequency"],
                ["arxs", "atxs"],
            );
            oaf = prettyfrequency(oan, 1, true);
            iaf = prettyfrequency(ian, 1, true);
        }

        let (mut ipf, mut opf, mut rpc_str) = (String::new(), String::new(), String::new());
        let psr = opts.pstats && not_none(ifstat, "incoming_pr_frequency");
        if psr {
            let (opn, ipn);
            (opn, ipn, rpc_str) = frequencies(
                ifstat,
                clients,
                is_shared,
                both_flows,
                ["outgoing_pr_frequency", "incoming_pr_frequency"],
                ["prxs", "ptxs"],
            );
            if opts.astats {
                opf = format!("↑{}", prettyfrequency(opn, 1, true));
                ipf = format!("↓{}", prettyfrequency(ipn, 1, true));
            } else {
                opf = format!("{}↑", prettyfrequency(opn, 1, true));
                ipf = format!("{}↓", prettyfrequency(ipn, 1, true));
            }
        }

        let amlen = len(&iaf).max(len(&oaf));
        pad(&mut iaf, amlen);
        iaf.push('↓');
        pad(&mut oaf, amlen);
        oaf.push('↑');
        let mlen = [&iaf, &oaf, &rxb_str, &txb_str, &ipf, &opf]
            .iter()
            .map(|s| len(s))
            .max()
            .unwrap_or(0)
            .max(10);
        for s in [
            &mut iaf,
            &mut oaf,
            &mut ipf,
            &mut opf,
            &mut rxb_str,
            &mut txb_str,
        ] {
            pad(s, mlen);
        }

        FlowColumns {
            iaf,
            oaf,
            ipf,
            opf,
            rxb_str,
            txb_str,
            pc_str,
            rpc_str,
            asr,
            psr,
        }
    }
}

/// The outgoing frequency under `keys[0]` (less the instance's own share on
/// a shared instance), the incoming one under `keys[1]`, and the suffix
/// with the per-client (or, lacking clients, per-peer) rate and, when all
/// flows are reported, the `flow_keys` shares of the rx and tx flow.
fn frequencies(
    ifstat: &PickleValue,
    clients: &mut Option<Num>,
    is_shared: bool,
    both_flows: bool,
    [out_key, in_key]: [&str; 2],
    [rx_key, tx_key]: [&str; 2],
) -> (Num, Num, String) {
    let freq = |key: &str| opt_num(ifstat, key).unwrap_or(Num::Int(0));
    let outgoing = match *clients {
        Some(c) if is_shared && c.f() > 0.0 => {
            let n = freq(out_key);
            Num::Float(n.f() - (n.f() / c.f()))
        }
        _ => freq(out_key),
    };
    let incoming = freq(in_key);
    let mut cspec = "c";
    if clients.is_none() && truthy(get(ifstat, "peers")) {
        *clients = Some(num(ifstat, "peers"));
        cspec = "p";
    }
    let mut suffix = match *clients {
        Some(c) if c.f() > 0.0 => format!(
            " {}/{cspec}",
            prettyfrequency(Num::Float(freq(out_key).f() / c.f()), 1, true)
        ),
        _ => String::new(),
    };
    if both_flows {
        let pctstr = format!(
            "(↓{}% / ↑{}% of flow)",
            flow_pct(ifstat, rx_key, "rxs") as i64,
            flow_pct(ifstat, tx_key, "txs") as i64
        );
        suffix = if suffix.is_empty() {
            pctstr
        } else {
            format!("{suffix} {pctstr}")
        };
    }
    (outgoing, incoming, suffix)
}

/// The violation counts, when any.
fn render_violations(out: &mut String, ifstat: &PickleValue) {
    if !(has(ifstat, "protocol_violations") && has(ifstat, "ifac_violations")) {
        return;
    }
    let pv = s(ifstat, "protocol_violations");
    let iv = get(ifstat, "ifac_violations");
    if truthy(get(ifstat, "protocol_violations")) || truthy(iv) {
        let pvstr = format!("{pv} protocol{}", if truthy(iv) { ", " } else { "" });
        let ivstr = if truthy(iv) {
            format!("{} IFAC", s(ifstat, "ifac_violations"))
        } else {
            String::new()
        };
        outln!(out, "    Violatns. : {pvstr}{ivstr}");
    }
}

/// `-P`: the path request lines.
fn render_path_requests(out: &mut String, ifstat: &PickleValue, cols: &FlowColumns, now: f64) {
    let FlowColumns {
        ipf, opf, rpc_str, ..
    } = cols;
    let pburst_str = burst_str(
        ifstat,
        ["pr_burst_active", "pr_burst_count", "pr_burst_activated"],
        "",
        now,
    );
    if truthy(get(ifstat, "prxc")) && truthy(get(ifstat, "ptxc")) {
        outln!(
            out,
            "    Path Rqs. : {}↓ {}↑ total",
            s(ifstat, "prxc"),
            s(ifstat, "ptxc")
        );
        outln!(out, "                {opf} {rpc_str}");
    } else {
        outln!(out, "    Path Rqs. : {opf} {rpc_str}");
    }
    outln!(out, "                {ipf}  {pburst_str}");
}

/// `-A`: the announce lines.
fn render_announces(
    out: &mut String,
    ifstat: &PickleValue,
    opts: &ViewOptions,
    cols: &FlowColumns,
    now: f64,
) {
    let FlowColumns {
        iaf, oaf, pc_str, ..
    } = cols;
    let art_str = announce_rate_str(ifstat, opts);
    let burst_str = burst_str(
        ifstat,
        ["burst_active", "burst_count", "burst_activated"],
        " ",
        now,
    );
    if truthy(get(ifstat, "arxc")) && truthy(get(ifstat, "atxc")) {
        let f_str = if truthy(get(ifstat, "afrxc")) {
            format!(", {} filtered", s(ifstat, "afrxc"))
        } else {
            String::new()
        };
        outln!(
            out,
            "    Announces : {}↓ {}↑ total{f_str}",
            s(ifstat, "arxc"),
            s(ifstat, "atxc")
        );
        outln!(out, "                {oaf} {pc_str}");
    } else {
        outln!(out, "    Announces : {oaf} {pc_str}");
    }
    outln!(out, "                {iaf} {art_str}{burst_str}");
}

/// The announce rate target, penalty and grace, as far as they are set.
fn announce_rate_str(ifstat: &PickleValue, opts: &ViewOptions) -> String {
    let art = opts
        .astats
        .then(|| get(ifstat, "announce_rate_target"))
        .flatten();
    let arp = opts
        .astats
        .then(|| get(ifstat, "announce_rate_penalty"))
        .flatten();
    let arg = opts
        .astats
        .then(|| get(ifstat, "announce_rate_grace"))
        .flatten();
    let arp_set = !matches!(arp, None | Some(PickleValue::None));
    let pt =
        |v: Option<&PickleValue>| prettytime(v.and_then(Num::of).unwrap_or(Num::Int(0)), false);
    if truthy(art) && arp_set && truthy(arg) {
        format!(
            "(t:{}/p:{}/g:{})",
            pt(art),
            pt(arp),
            arg.map(str_of).unwrap_or_default()
        )
    } else if truthy(art) && arp_set {
        format!("(t:{}/p:{})", pt(art), pt(arp))
    } else if truthy(art) {
        format!("(t:{})", pt(art))
    } else {
        String::new()
    }
}

/// `{lead}burst [on N ]for T` for an active burst under the `[active,
/// count, activated]` keys, or nothing.
fn burst_str(
    ifstat: &PickleValue,
    [active, count, activated]: [&str; 3],
    lead: &str,
    now: f64,
) -> String {
    if !(has(ifstat, active) && truthy(get(ifstat, active))) {
        return String::new();
    }
    let bcstr = if has(ifstat, count) && truthy(get(ifstat, count)) {
        format!("on {} ", s(ifstat, count))
    } else {
        String::new()
    };
    let for_str = prettytime(Num::Float(now - num(ifstat, activated).f()), false);
    format!("{lead}burst {bcstr}for {for_str}")
}

/// The traffic lines (from the padded byte counts) and, with `-F`, the
/// filtered traffic lines.
fn render_traffic(
    out: &mut String,
    ifstat: &PickleValue,
    opts: &ViewOptions,
    mut rxstat: String,
    mut txstat: String,
) {
    if has(ifstat, "rxs") && has(ifstat, "txs") {
        rxstat += &format!("  {}", prettyspeed(num(ifstat, "rxs").f()));
        txstat += &format!("  {}", prettyspeed(num(ifstat, "txs").f()));
    }
    if truthy(get(ifstat, "txbuffered")) {
        let stlstr = if truthy(get(ifstat, "txstalled")) {
            ", stalled"
        } else {
            ""
        };
        txstat += &format!(
            " ({} waiting{stlstr})",
            prettysize(num(ifstat, "txbuffered").f(), "B")
        );
    }
    outln!(out, "    Traffic   : {txstat}\n                {rxstat}");

    if opts.fstats {
        let mut frxstat = format!("↓{}", prettysize(num(ifstat, "frxb").f(), "B"));
        let mut ftxstat = format!("↑{}", prettysize(num(ifstat, "ftxb").f(), "B"));
        if has(ifstat, "frxs") && has(ifstat, "ftxs") {
            frxstat += &format!("  {}", prettyspeed(num(ifstat, "frxs").f()));
            ftxstat += &format!("  {}", prettyspeed(num(ifstat, "ftxs").f()));
        }
        outln!(out, "    Filtered  : {ftxstat}\n                {frxstat}");
    }
}

/// `-l`: the link table entry count, or empty.
fn link_table_str(stats: &PickleValue, opts: &ViewOptions, extras: &Extras<'_>) -> String {
    let mut lstr = String::new();
    if let (Some(link_count), true) = (extras.link_count, opts.lstats) {
        let ms = if link_count == Num::Int(1) {
            "y"
        } else {
            "ies"
        };
        lstr = if not_none(stats, "transport_id") {
            format!(", {} entr{ms} in link table", link_count.str())
        } else {
            format!(" {} entr{ms} in link table", link_count.str())
        };
        if let Some(active) = extras.active_link_count.filter(|n| !n.is_zero()) {
            lstr = format!("{lstr} ({} active)", active.str());
        }
    }
    lstr
}

/// `-t`: the instance's traffic totals, with `-F`'s filtered totals and
/// `-P`/`-A`'s path request and announce totals.
fn render_totals(out: &mut String, stats: &PickleValue, opts: &ViewOptions) {
    let mut rxb_str = format!("↓{}", prettysize(num(stats, "rxb").f(), "B"));
    let mut txb_str = format!("↑{}", prettysize(num(stats, "txb").f(), "B"));
    equalize(&mut rxb_str, &mut txb_str);
    let mut rxstat = format!("{rxb_str}  {}", prettyspeed(num(stats, "rxs").f()));
    let mut txstat = format!("{txb_str}  {}", prettyspeed(num(stats, "txs").f()));

    if (opts.pstats || opts.astats)
        && has(stats, "prxs")
        && has(stats, "ptxs")
        && has(stats, "arxs")
        && has(stats, "atxs")
    {
        append_data_share(stats, &mut rxstat, &mut txstat);
    }

    if opts.pps {
        let rpps = prettysize(num(stats, "rxpps").f(), "pps");
        let tpps = prettysize(num(stats, "txpps").f(), "pps");
        rxstat = format!("{rxstat}, {rpps}");
        txstat = format!("{txstat}, {tpps}");
    }

    outln!(out, "\n Totals       : {txstat}\n                {rxstat}");

    if opts.fstats {
        let mut frxstat = format!("↓{}", prettysize(num(stats, "frxb").f(), "B"));
        let mut ftxstat = format!("↑{}", prettysize(num(stats, "ftxb").f(), "B"));
        equalize(&mut frxstat, &mut ftxstat);
        if has(stats, "frxs") && has(stats, "ftxs") {
            frxstat += &format!("  {}", prettyspeed(num(stats, "frxs").f()));
            ftxstat += &format!("  {}", prettyspeed(num(stats, "ftxs").f()));
        }
        outln!(
            out,
            "\n Filtered     : {ftxstat}\n                {frxstat}"
        );
    }

    for (enabled, prefix, label) in [
        (opts.pstats, "p", " Path Rqs.    "),
        (opts.astats, "a", " Announces    "),
    ] {
        if enabled {
            render_control_totals(out, stats, prefix, label);
        }
    }
}

/// Appends the share and rate of the totals that is data, not announces
/// or path requests.
fn append_data_share(stats: &PickleValue, rxstat: &mut String, txstat: &mut String) {
    let parxs = num(stats, "prxs").f() + num(stats, "arxs").f();
    let patxs = num(stats, "ptxs").f() + num(stats, "atxs").f();
    let rxs = num(stats, "rxs").f();
    let txs = num(stats, "txs").f();
    let drxpct = if rxs != 0.0 {
        100.0 - f64::min(100.0, (parxs / rxs) * 100.0)
    } else {
        100.0
    };
    let dtxpct = if txs != 0.0 {
        100.0 - f64::min(100.0, (patxs / txs) * 100.0)
    } else {
        100.0
    };
    let drxs = rxs * (drxpct / 100.0);
    let dtxs = txs * (dtxpct / 100.0);
    if rxs > 0.0 {
        *rxstat = format!("{rxstat}, {}% data ({})", drxpct as i64, prettyspeed(drxs));
    }
    if txs > 0.0 {
        *txstat = format!("{txstat}, {}% data ({})", dtxpct as i64, prettyspeed(dtxs));
    }
}

/// The path request (`prefix` "p") or announce ("a") totals, when the
/// instance reports them.
fn render_control_totals(out: &mut String, stats: &PickleValue, prefix: &str, label: &str) {
    let key = |suffix: &str| format!("{prefix}{suffix}");
    if !(has(stats, &key("rxb"))
        && has(stats, &key("txb"))
        && has(stats, &key("rxs"))
        && has(stats, &key("txs")))
    {
        return;
    }
    let mut rb = format!("↓{}", prettysize(num(stats, &key("rxb")).f(), "B"));
    let mut tb = format!("↑{}", prettysize(num(stats, &key("txb")).f(), "B"));
    equalize(&mut rb, &mut tb);
    let rpct = flow_pct(stats, &key("rxs"), "rxs");
    let tpct = flow_pct(stats, &key("txs"), "txs");
    let rf = prettyfrequency(opt_num(stats, &key("rxf")).unwrap_or(Num::Int(0)), 2, false);
    let tf = prettyfrequency(opt_num(stats, &key("txf")).unwrap_or(Num::Int(0)), 2, false);
    let rstat = format!(
        "{rb}  {}, {}% of flow, {rf}",
        prettyspeed(num(stats, &key("rxs")).f()),
        rpct as i64
    );
    let tstat = format!(
        "{tb}  {}, {}% of flow, {tf}",
        prettyspeed(num(stats, &key("txs")).f()),
        tpct as i64
    );
    outln!(out, "\n{label}: {tstat}\n                {rstat}");
}

/// `-q`: the ingress queue pressures.
fn render_queue_pressure(out: &mut String, stats: &PickleValue) {
    let dropped = |key: &str| {
        if truthy(get(stats, key)) {
            format!(", {} dropped", s(stats, key))
        } else {
            String::new()
        }
    };
    let pressure = |key: &str| python_round_pct(num(stats, key));
    outln!(
        out,
        "\n Qu. Pressure : {}% total, {} pkts{}",
        pressure("tqpressure"),
        s(stats, "rxqt"),
        dropped("rxqtd")
    );
    for (pkey, label, qkey, dkey) in [
        ("dqpressure", "data", "rxqd", "rxqdd"),
        ("aqpressure", "announce", "rxqa", "rxqad"),
        ("pqpressure", "path request", "rxqp", "rxqpd"),
        ("ilqpressure", "ingress limiter", "rxqil", "rxqild"),
    ] {
        outln!(
            out,
            "                {}% {label}, {} pkts{}",
            pressure(pkey),
            s(stats, qkey),
            dropped(dkey)
        );
    }
}

/// The transport instance, network identity, probe responder and uptime
/// lines with `lstr` appended; or `lstr` alone without a transport id.
fn render_instance_footer(out: &mut String, stats: &PickleValue, lstr: &str) {
    if not_none(stats, "transport_id") {
        if let Some(tid) = bytes_of(stats, "transport_id") {
            outln!(out, "\n Transport Instance {} running", prettyhexrep(tid));
        }
        if let Some(nid) = bytes_of(stats, "network_id") {
            outln!(out, " Network Identity   {}", prettyhexrep(nid));
        }
        if let Some(pr) = bytes_of(stats, "probe_responder") {
            outln!(out, " Probe responder at {} active", prettyhexrep(pr));
        }
        if let Some(uptime) = opt_num(stats, "transport_uptime") {
            outln!(out, " Uptime is {}{lstr}", prettytime(uptime, false));
        }
    } else if !lstr.is_empty() {
        outln!(out, "\n{lstr}");
    }
}

/// `f"{round(x*100.0, 1)}"`.
fn python_round_pct(x: Num) -> String {
    crate::format::python_float(pyfmt::round_float(x.f() * 100.0, 1))
}

/// Pad the shorter of two strings to the other's length.
fn equalize(a: &mut String, b: &mut String) {
    let (la, lb) = (len(a), len(b));
    if la > lb {
        pad(b, la);
    } else {
        pad(a, lb);
    }
}

/// rnstatus's own `speed_str` (`%3.2f`, lower-case `k`).
pub fn speed_str(num: f64) -> String {
    let mut num = num;
    for unit in ["", "k", "M", "G", "T", "P", "E", "Z"] {
        if num.abs() < 1000.0 {
            return format!("{num:.2} {unit}bps");
        }
        num /= 1000.0;
    }
    format!("{num:.2} Ybps")
}

/// `RNS.Profiler.format_results(results)`.
pub fn format_profiling_results(results: &PickleValue) -> String {
    let PickleValue::Dict(entries) = results else {
        return String::new();
    };
    let pst = |stats: &PickleValue, key: &str| match stats.get(key).and_then(Num::of) {
        Some(n) => prettyshorttime_tight(n.f()),
        None => "-----".into(),
    };

    fn tag_results(
        tag: &PickleValue,
        level: usize,
        pst: &dyn Fn(&PickleValue, &str) -> String,
    ) -> String {
        let ind = "  ".repeat(level);
        let name = s(tag, "name");
        let mut out = format!(" {ind}{name}\n");
        let Some(all) = get(tag, "stats_all") else {
            return out;
        };
        let threads = num(all, "threads");
        out += &format!(
            " {ind}  Samples  : {} from {} thread{}\n",
            s(all, "count"),
            threads.str(),
            if threads.f() > 1.0 { "s" } else { "" }
        );
        if !matches!(all, PickleValue::None) {
            out += &format!(
                " {ind}              {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15}\n",
                "Mean", "Median", "Min", "Max", "St. dev", "Total"
            );
        }
        for (key, label) in [
            ("stats_all", "  Stats    "),
            ("stats_1m", "   0-1m    "),
            ("stats_5m", "   1-5m    "),
            ("stats_30m", "  5-30m    "),
            ("stats_60m", " 30-60m    "),
        ] {
            if let Some(stats) = get(tag, key).filter(|v| !matches!(v, PickleValue::None)) {
                out += &format!(
                    " {ind}{label}: ({:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15})\n",
                    pst(stats, "mean"),
                    pst(stats, "median"),
                    pst(stats, "min"),
                    pst(stats, "max"),
                    pst(stats, "stdev"),
                    pst(stats, "sum"),
                );
            }
        }
        out
    }

    fn recursive(
        tag: &PickleValue,
        entries: &[(PickleValue, PickleValue)],
        level: usize,
        pst: &dyn Fn(&PickleValue, &str) -> String,
    ) -> String {
        let mut out = tag_results(tag, level + 1, pst) + "\n";
        let name = get(tag, "name");
        for (_, sub) in entries {
            if get(sub, "super") == name {
                out += &recursive(sub, entries, level + 1, pst);
            }
        }
        out
    }

    let mut out = String::new();
    for (_, tag) in entries {
        if !not_none(tag, "super") {
            out += &recursive(tag, entries, 0, &pst);
        }
    }
    out
}

/// `f"{n:,}"` of a Python number.
fn thousands(n: Num) -> String {
    let text = n.str();
    if text.contains('e') || text.contains("inf") || text.contains("nan") {
        return text;
    }
    let (sign, rest) = text
        .strip_prefix('-')
        .map_or(("", text.as_str()), |r| ("-", r));
    let (whole, fraction) = rest
        .split_once('.')
        .map_or((rest, None), |(w, f)| (w, Some(f)));
    let mut grouped = String::new();
    for (i, c) in whole.chars().enumerate() {
        if i > 0 && (whole.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(c);
    }
    match fraction {
        Some(f) => format!("{sign}{grouped}.{f}"),
        None => format!("{sign}{grouped}"),
    }
}

fn cost(value: Option<&PickleValue>) -> String {
    // RNS.prettycost: "n" unless an int or a float (bool is neither).
    match value {
        Some(PickleValue::Int(n)) => crate::format::prettycost(Some(*n as f64)),
        Some(PickleValue::Float(f)) => crate::format::prettycost(Some(*f)),
        _ => crate::format::prettycost(None),
    }
}

/// `round(x, 4)` of a coordinate, printed with `str()`.
fn coordinate(value: &PickleValue) -> String {
    match Num::of(value) {
        Some(n) => pyfmt::round(n, 4).str(),
        None => str_of(value),
    }
}

/// The discovered interfaces view (`-d`, or `-D` for `details`), from
/// upstream-shaped records ([`upstream_discovery_record`]).
pub fn render_discovered(
    ifs: &[PickleValue],
    details: bool,
    name_filter: Option<&str>,
    show_stale: bool,
    show_unknown: bool,
    now: f64,
) -> String {
    let mut out = String::from("\n");
    macro_rules! p {
        ($($arg:tt)*) => {{ out.push_str(&format!($($arg)*)); out.push('\n'); }};
    }
    let filtered_ifs: Vec<&PickleValue> = ifs
        .iter()
        .filter(|i| match name_filter.filter(|f| !f.is_empty()) {
            Some(f) => name_of(i).to_lowercase().contains(&f.to_lowercase()),
            None => true,
        })
        .collect();
    let has_impl_info = |i: &PickleValue| {
        has(i, "impl_name")
            && has(i, "version")
            && truthy(get(i, "impl_name"))
            && truthy(get(i, "version"))
    };
    let impl_str = |i: &PickleValue| {
        if has_impl_info(i) {
            format!("{} {}", s(i, "impl_name"), s(i, "version"))
        } else {
            "Unknown".to_string()
        }
    };
    let status_of = |i: &PickleValue| s(i, "status");

    if details {
        for (idx, i) in filtered_ifs.iter().copied().enumerate() {
            let status = status_of(i);
            let status_display = match status.as_str() {
                "available" => "Available".to_string(),
                "unknown" => "Unknown".to_string(),
                "stale" => "Stale".to_string(),
                other => other.to_string(),
            };
            if status == "stale" && !show_stale {
                continue;
            }
            if !has_impl_info(i) && !show_unknown {
                continue;
            }
            let dago = now - num(i, "discovered").f();
            let hago = now - num(i, "last_heard").f();
            let transport_str = if truthy(get(i, "transport")) {
                "Enabled"
            } else {
                "Disabled"
            };
            let has_cost_info = has(i, "dst_cost") && has(i, "pr_cost");
            let location = if let (Some(latitude), Some(longitude)) =
                (present(i, "latitude"), present(i, "longitude"))
            {
                let height = if not_none(i, "height") {
                    format!(", {}m h", s(i, "height"))
                } else {
                    String::new()
                };
                format!(
                    "{}, {}{height}",
                    coordinate(latitude),
                    coordinate(longitude)
                )
            } else {
                "Unknown".to_string()
            };
            let lxmf_addr = get(i, "operator_lxmf_address");
            let transport_id = get(i, "transport_id");
            let network = (has(i, "transport_id")
                && has(i, "network_id")
                && get(i, "transport_id") != get(i, "network_id"))
            .then(|| get(i, "network_id"))
            .flatten();

            if idx > 0 {
                p!("\n{}\n", "=".repeat(47));
            }
            if let Some(network) = network.filter(|value| truthy(Some(value))) {
                p!("Network   ID : {}", str_of(network));
            }
            if let Some(transport_id) = transport_id.filter(|value| truthy(Some(value))) {
                p!("Transport ID : {}", str_of(transport_id));
            }
            if let Some(lxmf_addr) = lxmf_addr.filter(|value| truthy(Some(value))) {
                p!("LXMF address : {}", str_of(lxmf_addr));
            }
            p!("Name         : {}", s(i, "name"));
            p!("Type         : {}", s(i, "type"));
            p!("Stack        : {}", impl_str(i));
            p!("Status       : {status_display}");
            p!("Transport    : {transport_str}");
            p!("Stamp Value  : {}", cost(get(i, "value")));
            if has_cost_info {
                p!(
                    "Costs        : Dst {}, PR {}",
                    cost(get(i, "dst_cost")),
                    cost(get(i, "pr_cost"))
                );
            }
            let hops = s(i, "hops");
            p!(
                "Distance     : {hops} hop{}",
                if num(i, "hops") == Num::Int(1) {
                    ""
                } else {
                    "s"
                }
            );
            p!("Discovered   : {} ago", prettytime(Num::Float(dago), true));
            p!("Last Heard   : {} ago", prettytime(Num::Float(hago), true));
            p!("Location     : {location}");
            for (key, label) in [
                ("frequency", "Frequency    "),
                ("bandwidth", "Bandwidth    "),
            ] {
                if has(i, key) {
                    let value = opt_num(i, key).map(thousands).unwrap_or_else(|| s(i, key));
                    p!("{label}: {value} Hz");
                }
            }
            for (key, label) in [
                ("sf", "Sprd. Factor "),
                ("cr", "Coding Rate  "),
                ("modulation", "Modulation   "),
                ("reachable_on", "Address      "),
                ("port", "Port         "),
            ] {
                if has(i, key) {
                    p!("{label}: {}", s(i, key));
                }
            }
            p!("\nConfiguration Entry:");
            // Upstream gives up on the entry when it has none.
            if let Some(PickleValue::String(entry)) = get(i, "config_entry") {
                for line in entry.split('\n') {
                    p!("  {line}");
                }
            }
        }
    } else {
        p!(
            "{:<25} {:<10}   {:<10} {:<12} {:<7} {:<16} {:<15}",
            "Name",
            "Type",
            "Status",
            "Last Heard",
            "Value",
            "Running",
            "Location"
        );
        p!("{}", "-".repeat(110));
        for i in filtered_ifs {
            let full = name_of(i);
            let name = if len(full) > 24 {
                format!("{}…", full.chars().take(24).collect::<String>())
            } else {
                full.to_string()
            };
            let mut impl_str = impl_str(i);
            if len(&impl_str) > 16 {
                impl_str = format!("{}…", impl_str.chars().take(15).collect::<String>());
            }
            let if_type = s(i, "type").replace("Interface", "");
            let status = status_of(i);
            let status_display = match status.as_str() {
                "available" => "✓ Available".to_string(),
                "unknown" => "? Unknown".to_string(),
                "stale" => "× Stale".to_string(),
                other => other.to_string(),
            };
            if status == "stale" && !show_stale {
                continue;
            }
            if !has_impl_info(i) && !show_unknown {
                continue;
            }
            let diff = now - num(i, "last_heard").f();
            let last_heard_display = if diff < 60.0 {
                "Just now".to_string()
            } else if diff < 3600.0 {
                format!("{}m ago", (diff / 60.0) as i64)
            } else if diff < 86400.0 {
                format!("{}h ago", (diff / 3600.0) as i64)
            } else {
                format!("{}d ago", (diff / 86400.0) as i64)
            };
            let value = cost(get(i, "value"));
            let location = if let (Some(latitude), Some(longitude)) =
                (present(i, "latitude"), present(i, "longitude"))
            {
                format!("{}, {}", coordinate(latitude), coordinate(longitude))
            } else {
                "N/A".to_string()
            };
            p!(
                "{name:<25} {if_type:<10} {status_display:<12} {last_heard_display:<12} {value:<7} {impl_str:<16} {location:<15}"
            );
        }
    }
    out
}

/// `-d -j`: upstream's empty line, then `json.dumps` of the records with
/// their bytes as plain hex.
pub fn render_discovered_json(ifs: &[PickleValue]) -> String {
    format!(
        "\n{}\n",
        crate::format::python_json(&PickleValue::List(ifs.to_vec()))
    )
}

fn key(name: &str) -> PickleValue {
    PickleValue::String(name.into())
}

/// A discovered interface from the `discovered_interfaces` RPC as upstream's
/// `list_discovered_interfaces()` returns it: its keys, in its order, ids as
/// hex strings, and the type-specific keys only for their types.
pub fn upstream_discovery_record(rpc: &PickleValue) -> PickleValue {
    let field = |name: &str| get(rpc, name).cloned().unwrap_or(PickleValue::None);
    let hex = |name: &str| match get(rpc, name) {
        Some(PickleValue::Bytes(b)) => PickleValue::String(hexrep(b)),
        Some(other) => other.clone(),
        None => PickleValue::None,
    };
    let mut record = Vec::new();
    let mut push = |name: &str, value: PickleValue| record.push((key(name), value));
    for name in ["type", "impl_name", "version", "transport", "name"] {
        push(name, field(name));
    }
    push("received", field("last_heard"));
    push("stamp", field("stamp"));
    push("value", field("value"));
    push("transport_id", hex("transport_id"));
    push("network_id", hex("network_id"));
    for name in [
        "dst_cost",
        "pr_cost",
        "hops",
        "latitude",
        "longitude",
        "height",
    ] {
        push(name, field(name));
    }
    for name in ["ifac_netname", "ifac_netkey"] {
        if let Some(PickleValue::String(v)) = get(rpc, name) {
            if !v.is_empty() {
                push(name, PickleValue::String(v.clone()));
            }
        }
    }
    let type_keys: &[&str] = match s(rpc, "type").as_str() {
        "BackboneInterface" | "TCPServerInterface" => &["reachable_on", "port"],
        "I2PInterface" => &["reachable_on"],
        "RNodeInterface" => &["frequency", "bandwidth", "sf", "cr"],
        "WeaveInterface" => &["frequency", "bandwidth", "channel", "modulation"],
        "KISSInterface" => &["frequency", "bandwidth", "modulation"],
        _ => &[],
    };
    for name in type_keys {
        push(name, field(name));
    }
    if not_none(rpc, "config_entry") {
        push("config_entry", field("config_entry"));
    }
    push("discovery_hash", field("discovery_hash"));
    if not_none(rpc, "operator_lxmf_address") {
        push("operator_lxmf_address", field("operator_lxmf_address"));
    }
    for name in ["discovered", "last_heard", "heard_count", "status"] {
        push(name, field(name));
    }
    let status_code = match s(rpc, "status").as_str() {
        "available" => 1000,
        "unknown" => 100,
        _ => 0,
    };
    push("status_code", PickleValue::Int(status_code));
    PickleValue::Dict(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options_from(value: &PickleValue) -> ViewOptions {
        let flag = |key: &str| truthy(value.get(key));
        let text = |key: &str| value.get(key).and_then(|v| v.as_str()).map(str::to_string);
        ViewOptions {
            dispall: flag("dispall"),
            name_filter: text("name_filter"),
            astats: flag("astats"),
            pstats: flag("pstats"),
            lstats: flag("lstats"),
            sorting: text("sorting"),
            sort_reverse: flag("sort_reverse"),
            traffic_totals: flag("traffic_totals"),
            burst_filter: flag("burst_filter"),
            blocked_ips: flag("blocked_ips"),
            queue_stats: flag("queue_stats"),
            pps: flag("pps"),
            fstats: flag("fstats"),
            tstats: flag("tstats"),
        }
    }

    /// Every case in `tests/fixtures/rnstatus` (from
    /// `tests/generate_rnstatus_fixtures.py`, upstream's own rnstatus)
    /// renders exactly as upstream printed it.
    #[test]
    fn rnstatus_view_matches_upstream() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/rnstatus");
        let mut cases: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "pickle"))
            .collect();
        cases.sort();
        assert!(cases.len() >= 20, "fixtures missing in {}", dir.display());
        let mut failures = Vec::new();
        for path in cases {
            let inputs = rns_net::pickle::decode(&std::fs::read(&path).unwrap()).unwrap();
            let expected = std::fs::read_to_string(path.with_extension("txt")).unwrap();
            let now = inputs.get("now").and_then(Num::of).unwrap().f();
            let options = inputs.get("options").unwrap();
            let rendered = if let Some(PickleValue::List(records)) = inputs.get("discovered") {
                let flag = |key: &str| truthy(options.get(key));
                if flag("json") {
                    render_discovered_json(records)
                } else {
                    render_discovered(
                        records,
                        flag("config_entries"),
                        options.get("name_filter").and_then(|v| v.as_str()),
                        flag("show_stale"),
                        flag("show_unknown"),
                        now,
                    )
                }
            } else {
                let profiling = inputs
                    .get("profiling")
                    .filter(|v| !matches!(v, PickleValue::None));
                let extras = Extras {
                    link_count: inputs.get("link_count").and_then(Num::of),
                    active_link_count: inputs.get("active_link_count").and_then(Num::of),
                    profiling_results: profiling,
                };
                render(
                    inputs.get("stats").unwrap(),
                    &options_from(options),
                    &extras,
                    now,
                )
            };
            if rendered != expected {
                let line = rendered
                    .lines()
                    .zip(expected.lines())
                    .position(|(a, b)| a != b)
                    .unwrap_or_else(|| rendered.lines().count().min(expected.lines().count()));
                failures.push(format!(
                    "{}: line {}\n  rust:     {:?}\n  upstream: {:?}",
                    path.file_stem().unwrap().to_string_lossy(),
                    line + 1,
                    rendered.lines().nth(line),
                    expected.lines().nth(line)
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
