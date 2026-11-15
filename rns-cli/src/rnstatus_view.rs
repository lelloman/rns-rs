//! `rnstatus`'s status display, ported statement by statement from
//! upstream's `RNS/Utilities/rnstatus.py` (`program_setup`, from
//! `if stats != None:`) so the output matches it byte for byte, quirks
//! included. Keep the structure parallel to upstream's when changing it.

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
    pub link_count: Option<Num>,
    pub active_link_count: Option<Num>,
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
    !matches!(dict.get(key), None | Some(PickleValue::None))
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

/// The status display for `stats` (upstream's `get_interface_stats()`
/// result), as upstream prints it; `now` stands in for `time.time()`.
pub fn render(stats: &PickleValue, opts: &ViewOptions, extras: &Extras<'_>, now: f64) -> String {
    let mut out = String::new();
    macro_rules! p {
        () => { out.push('\n') };
        ($($arg:tt)*) => {{ out.push_str(&format!($($arg)*)); out.push('\n'); }};
    }

    let empty = Vec::new();
    let mut interfaces: Vec<&PickleValue> = match get(stats, "interfaces") {
        Some(PickleValue::List(list)) => list.iter().collect(),
        _ => empty.iter().collect(),
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

    for ifstat in interfaces {
        let name = name_of(ifstat);
        if !opts.dispall && hidden_without_all(name, ifstat) {
            continue;
        }
        if unconnectable_i2p(name, ifstat) {
            continue;
        }
        let show_if = if !opts.burst_filter {
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
        };
        if !show_if {
            continue;
        }

        p!("");

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

        let mut clients: Option<Num> = None;
        let mut clients_string = String::new();
        if not_none(ifstat, "clients") {
            let count = num(ifstat, "clients");
            clients = Some(count);
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
                    clients_string +=
                        &format!("\n    Blocked   : {} IPs", s(ifstat, "blocked_ips"));
                }
            }
            if opts.blocked_ips {
                if let Some(PickleValue::List(list)) = get(ifstat, "blocked_ip_list") {
                    for bip in list {
                        clients_string += &format!("\n                {}", str_of(bip));
                    }
                }
            }
        }

        p!(" {}", s(ifstat, "name"));

        if not_none(ifstat, "autoconnect_source") {
            p!(
                "    Source    : Auto-connect via <{}>",
                s(ifstat, "autoconnect_source")
            );
        }
        if not_none(ifstat, "ifac_netname") {
            p!("    Network   : {}", s(ifstat, "ifac_netname"));
        }

        p!("    Status    : {ss}");

        if clients.is_some() && !clients_string.is_empty() {
            p!("    {clients_string}");
        }

        if !(name.starts_with("Shared Instance[")
            || name.starts_with("TCPInterface[Client")
            || name.starts_with("LocalInterface["))
        {
            p!("    Mode      : {modestr}");
        }

        if truthy(get(ifstat, "txdrp")) {
            p!(
                "    TX Drops  : {} ({})",
                s(ifstat, "txdrp"),
                prettysize(num(ifstat, "txdrb").f(), "B")
            );
        }

        if not_none(ifstat, "bitrate") {
            p!(
                "    Rate      : {}, MTU {}",
                speed_str(num(ifstat, "bitrate").f()),
                s(ifstat, "mtu")
            );
        }

        if opts.tstats && has(ifstat, "tunnel_id") {
            let tid = match bytes_of(ifstat, "tunnel_id") {
                Some(b) if !b.is_empty() => prettyhexrep(b),
                _ => "None".into(),
            };
            p!("    Tunnel ID : {tid}");
        }
        if opts.tstats && has(ifstat, "remote_transport_id") {
            let rid = match bytes_of(ifstat, "remote_transport_id") {
                Some(b) if !b.is_empty() => prettyhexrep(b),
                _ => "Unknown".into(),
            };
            p!("    Rem.Tr.ID : {rid}");
        }

        if has(ifstat, "noise_floor") {
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
                p!("    Noise Fl. : {} dBm{nstr}", s(ifstat, "noise_floor"));
            } else {
                p!("    Noise Fl. : Unknown");
            }
        }

        if has(ifstat, "cpu_load") {
            if not_none(ifstat, "cpu_load") {
                p!("    CPU load  : {} %", s(ifstat, "cpu_load"));
            } else {
                p!("    CPU load  : Unknown");
            }
        }
        if has(ifstat, "cpu_temp") {
            if not_none(ifstat, "cpu_temp") {
                p!("    CPU temp  : {}°C", s(ifstat, "cpu_temp"));
            } else {
                // Upstream's label.
                p!("    CPU load  : Unknown");
            }
        }
        if has(ifstat, "mem_load") {
            // Upstream tests cpu_load here.
            if not_none(ifstat, "cpu_load") {
                p!("    Mem usage : {} %", s(ifstat, "mem_load"));
            } else {
                p!("    Mem usage : Unknown");
            }
        }

        if not_none(ifstat, "battery_percent") {
            if let Some(bpi) = opt_num(ifstat, "battery_percent") {
                p!(
                    "    Battery   : {}% ({})",
                    bpi.f().trunc() as i64,
                    s(ifstat, "battery_state")
                );
            }
        }

        if has(ifstat, "airtime_short") && has(ifstat, "airtime_long") {
            p!(
                "    Airtime   : {}% (15s), {}% (1h)",
                s(ifstat, "airtime_short"),
                s(ifstat, "airtime_long")
            );
        }
        if has(ifstat, "channel_load_short") && has(ifstat, "channel_load_long") {
            p!(
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
                    p!("    {label} : {}", s(ifstat, key));
                } else {
                    p!("    {label} : Unknown");
                }
            }
        }

        if not_none(ifstat, "peers") {
            p!("    Peers     : {} reachable", s(ifstat, "peers"));
        }
        if not_none(ifstat, "tunnelstate") {
            p!("    I2P       : {}", s(ifstat, "tunnelstate"));
        }

        if let Some(sig) = bytes_of(ifstat, "ifac_signature") {
            let tail = &sig[sig.len().saturating_sub(5)..];
            p!(
                "    Access    : {}-bit IFAC by <…{}>",
                num(ifstat, "ifac_size").f() as i64 * 8,
                hexrep(tail)
            );
        }

        if not_none(ifstat, "i2p_b32") {
            p!("    I2P B32   : {}", s(ifstat, "i2p_b32"));
        }

        for (key, label) in [
            ("announce_queue", "Queued   "),
            ("held_announces", "Held     "),
        ] {
            if opts.astats && not_none(ifstat, key) && num(ifstat, key).f() > 0.0 {
                let aqn = num(ifstat, key);
                let plural = if aqn == Num::Int(1) { "" } else { "s" };
                p!("    {label} : {} announce{plural}", aqn.str());
            }
        }

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
        let art_str = if truthy(art) && arp_set && truthy(arg) {
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
        };

        let mut burst_str = String::new();
        if has(ifstat, "burst_active") && truthy(get(ifstat, "burst_active")) {
            let bcstr = if has(ifstat, "burst_count") && truthy(get(ifstat, "burst_count")) {
                format!("on {} ", s(ifstat, "burst_count"))
            } else {
                String::new()
            };
            let for_str = prettytime(Num::Float(now - num(ifstat, "burst_activated").f()), false);
            burst_str = format!(" burst {bcstr}for {for_str}");
        }
        let mut pburst_str = String::new();
        if has(ifstat, "pr_burst_active") && truthy(get(ifstat, "pr_burst_active")) {
            let prbcstr = if has(ifstat, "pr_burst_count") && truthy(get(ifstat, "pr_burst_count"))
            {
                format!("on {} ", s(ifstat, "pr_burst_count"))
            } else {
                String::new()
            };
            let for_str = prettytime(
                Num::Float(now - num(ifstat, "pr_burst_activated").f()),
                false,
            );
            pburst_str = format!("burst {prbcstr}for {for_str}");
        }

        let mut rxb_str = format!("↓{}", prettysize(num(ifstat, "rxb").f(), "B"));
        let mut txb_str = format!("↑{}", prettysize(num(ifstat, "txb").f(), "B"));

        let both_flows =
            has(ifstat, "prxs") && has(ifstat, "rxs") && has(ifstat, "ptxs") && has(ifstat, "txs");
        let is_shared = name.starts_with("Shared Instance[");
        let freq = |key: &str| opt_num(ifstat, key).unwrap_or(Num::Int(0));
        let minus_own = |n: Num, clients: Option<Num>| match clients {
            Some(c) if is_shared && c.f() > 0.0 => Num::Float(n.f() - (n.f() / c.f())),
            _ => n,
        };

        let (mut iaf, mut oaf, mut pc_str) = (String::new(), String::new(), String::new());
        let mut asr = false;
        if opts.astats && not_none(ifstat, "incoming_announce_frequency") {
            let oan = minus_own(freq("outgoing_announce_frequency"), clients);
            let ian = freq("incoming_announce_frequency");
            oaf = prettyfrequency(oan, 1, true);
            iaf = prettyfrequency(ian, 1, true);
            let mut cspec = "c";
            if clients.is_none() && truthy(get(ifstat, "peers")) {
                clients = Some(num(ifstat, "peers"));
                cspec = "p";
            }
            pc_str = match clients {
                Some(c) if c.f() > 0.0 => format!(
                    " {}/{cspec}",
                    prettyfrequency(
                        Num::Float(freq("outgoing_announce_frequency").f() / c.f()),
                        1,
                        true
                    )
                ),
                _ => String::new(),
            };
            if both_flows {
                let apctstr = format!(
                    "(↓{}% / ↑{}% of flow)",
                    flow_pct(ifstat, "arxs", "rxs") as i64,
                    flow_pct(ifstat, "atxs", "txs") as i64
                );
                pc_str = if pc_str.is_empty() {
                    apctstr
                } else {
                    format!("{pc_str} {apctstr}")
                };
            }
            asr = true;
        }

        let (mut ipf, mut opf, mut rpc_str) = (String::new(), String::new(), String::new());
        let mut psr = false;
        if opts.pstats && not_none(ifstat, "incoming_pr_frequency") {
            let opn = minus_own(freq("outgoing_pr_frequency"), clients);
            let ipn = freq("incoming_pr_frequency");
            if opts.astats {
                opf = format!("↑{}", prettyfrequency(opn, 1, true));
                ipf = format!("↓{}", prettyfrequency(ipn, 1, true));
            } else {
                opf = format!("{}↑", prettyfrequency(opn, 1, true));
                ipf = format!("{}↓", prettyfrequency(ipn, 1, true));
            }
            let mut cspec = "c";
            if clients.is_none() && truthy(get(ifstat, "peers")) {
                clients = Some(num(ifstat, "peers"));
                cspec = "p";
            }
            rpc_str = match clients {
                Some(c) if c.f() > 0.0 => format!(
                    " {}/{cspec}",
                    prettyfrequency(
                        Num::Float(freq("outgoing_pr_frequency").f() / c.f()),
                        1,
                        true
                    )
                ),
                _ => String::new(),
            };
            if both_flows {
                let ppctstr = format!(
                    "(↓{}% / ↑{}% of flow)",
                    flow_pct(ifstat, "prxs", "rxs") as i64,
                    flow_pct(ifstat, "ptxs", "txs") as i64
                );
                rpc_str = if rpc_str.is_empty() {
                    ppctstr
                } else {
                    format!("{rpc_str} {ppctstr}")
                };
            }
            psr = true;
        }

        if !asr {
            iaf.clear();
            oaf.clear();
        }
        if !psr {
            ipf.clear();
            opf.clear();
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

        if has(ifstat, "protocol_violations") && has(ifstat, "ifac_violations") {
            let pv = s(ifstat, "protocol_violations");
            let iv = get(ifstat, "ifac_violations");
            if truthy(get(ifstat, "protocol_violations")) || truthy(iv) {
                let pvstr = format!("{pv} protocol{}", if truthy(iv) { ", " } else { "" });
                let ivstr = if truthy(iv) {
                    format!("{} IFAC", s(ifstat, "ifac_violations"))
                } else {
                    String::new()
                };
                p!("    Violatns. : {pvstr}{ivstr}");
            }
        }

        if truthy(get(ifstat, "packet_filter_hits")) {
            p!("    Flt. Hits : {}", s(ifstat, "packet_filter_hits"));
        }

        if psr {
            if truthy(get(ifstat, "prxc")) && truthy(get(ifstat, "ptxc")) {
                p!(
                    "    Path Rqs. : {}↓ {}↑ total",
                    s(ifstat, "prxc"),
                    s(ifstat, "ptxc")
                );
                p!("                {opf} {rpc_str}");
            } else {
                p!("    Path Rqs. : {opf} {rpc_str}");
            }
            p!("                {ipf}  {pburst_str}");
        }

        if asr {
            if truthy(get(ifstat, "arxc")) && truthy(get(ifstat, "atxc")) {
                let f_str = if truthy(get(ifstat, "afrxc")) {
                    format!(", {} filtered", s(ifstat, "afrxc"))
                } else {
                    String::new()
                };
                p!(
                    "    Announces : {}↓ {}↑ total{f_str}",
                    s(ifstat, "arxc"),
                    s(ifstat, "atxc")
                );
                p!("                {oaf} {pc_str}");
            } else {
                p!("    Announces : {oaf} {pc_str}");
            }
            p!("                {iaf} {art_str}{burst_str}");
        }

        let mut rxstat = rxb_str;
        let mut txstat = txb_str;
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
        p!("    Traffic   : {txstat}\n                {rxstat}");

        if opts.fstats {
            let mut frxstat = format!("↓{}", prettysize(num(ifstat, "frxb").f(), "B"));
            let mut ftxstat = format!("↑{}", prettysize(num(ifstat, "ftxb").f(), "B"));
            if has(ifstat, "frxs") && has(ifstat, "ftxs") {
                frxstat += &format!("  {}", prettyspeed(num(ifstat, "frxs").f()));
                ftxstat += &format!("  {}", prettyspeed(num(ifstat, "ftxs").f()));
            }
            p!("    Filtered  : {ftxstat}\n                {frxstat}");
        }
    }

    let has_transport_id = not_none(stats, "transport_id");
    let mut lstr = String::new();
    if let (Some(link_count), true) = (extras.link_count, opts.lstats) {
        let ms = if link_count == Num::Int(1) {
            "y"
        } else {
            "ies"
        };
        lstr = if has_transport_id {
            format!(", {} entr{ms} in link table", link_count.str())
        } else {
            format!(" {} entr{ms} in link table", link_count.str())
        };
        if let Some(active) = extras.active_link_count.filter(|n| !n.is_zero()) {
            lstr = format!("{lstr} ({} active)", active.str());
        }
    }

    if opts.traffic_totals {
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
                rxstat = format!("{rxstat}, {}% data ({})", drxpct as i64, prettyspeed(drxs));
            }
            if txs > 0.0 {
                txstat = format!("{txstat}, {}% data ({})", dtxpct as i64, prettyspeed(dtxs));
            }
        }

        if opts.pps {
            let rpps = prettysize(num(stats, "rxpps").f(), "pps");
            let tpps = prettysize(num(stats, "txpps").f(), "pps");
            rxstat = format!("{rxstat}, {rpps}");
            txstat = format!("{txstat}, {tpps}");
        }

        p!("\n Totals       : {txstat}\n                {rxstat}");

        if opts.fstats {
            let mut frxstat = format!("↓{}", prettysize(num(stats, "frxb").f(), "B"));
            let mut ftxstat = format!("↑{}", prettysize(num(stats, "ftxb").f(), "B"));
            equalize(&mut frxstat, &mut ftxstat);
            if has(stats, "frxs") && has(stats, "ftxs") {
                frxstat += &format!("  {}", prettyspeed(num(stats, "frxs").f()));
                ftxstat += &format!("  {}", prettyspeed(num(stats, "ftxs").f()));
            }
            p!("\n Filtered     : {ftxstat}\n                {frxstat}");
        }

        for (enabled, prefix, label) in [
            (opts.pstats, "p", " Path Rqs.    "),
            (opts.astats, "a", " Announces    "),
        ] {
            let key = |suffix: &str| format!("{prefix}{suffix}");
            if enabled
                && has(stats, &key("rxb"))
                && has(stats, &key("txb"))
                && has(stats, &key("rxs"))
                && has(stats, &key("txs"))
            {
                let mut rb = format!("↓{}", prettysize(num(stats, &key("rxb")).f(), "B"));
                let mut tb = format!("↑{}", prettysize(num(stats, &key("txb")).f(), "B"));
                equalize(&mut rb, &mut tb);
                let rpct = flow_pct(stats, &key("rxs"), "rxs");
                let tpct = flow_pct(stats, &key("txs"), "txs");
                let rf =
                    prettyfrequency(opt_num(stats, &key("rxf")).unwrap_or(Num::Int(0)), 2, false);
                let tf =
                    prettyfrequency(opt_num(stats, &key("txf")).unwrap_or(Num::Int(0)), 2, false);
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
                p!("\n{label}: {tstat}\n                {rstat}");
            }
        }
    }

    if opts.queue_stats {
        let dropped = |key: &str| {
            if truthy(get(stats, key)) {
                format!(", {} dropped", s(stats, key))
            } else {
                String::new()
            }
        };
        let pressure = |key: &str| python_round_pct(num(stats, key));
        p!(
            "\n Qu. Pressure : {}% total, {} pkts{}",
            pressure("tqpressure"),
            s(stats, "rxqt"),
            dropped("rxqtd")
        );
        p!(
            "                {}% data, {} pkts{}",
            pressure("dqpressure"),
            s(stats, "rxqd"),
            dropped("rxqdd")
        );
        p!(
            "                {}% announce, {} pkts{}",
            pressure("aqpressure"),
            s(stats, "rxqa"),
            dropped("rxqad")
        );
        p!(
            "                {}% path request, {} pkts{}",
            pressure("pqpressure"),
            s(stats, "rxqp"),
            dropped("rxqpd")
        );
        p!(
            "                {}% ingress limiter, {} pkts{}",
            pressure("ilqpressure"),
            s(stats, "rxqil"),
            dropped("rxqild")
        );
    }

    if let Some(results) = extras.profiling_results.filter(|r| truthy(Some(r))) {
        p!("\n Profiling    :\n{}", format_profiling_results(results));
    }

    if has_transport_id {
        if let Some(tid) = bytes_of(stats, "transport_id") {
            p!("\n Transport Instance {} running", prettyhexrep(tid));
        }
        if let Some(nid) = bytes_of(stats, "network_id") {
            p!(" Network Identity   {}", prettyhexrep(nid));
        }
        if let Some(pr) = bytes_of(stats, "probe_responder") {
            p!(" Probe responder at {} active", prettyhexrep(pr));
        }
        if let Some(uptime) = opt_num(stats, "transport_uptime") {
            p!(" Uptime is {}{lstr}", prettytime(uptime, false));
        }
    } else if !lstr.is_empty() {
        p!("\n{lstr}");
    }

    p!("");
    out
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
            let profiling = inputs
                .get("profiling")
                .filter(|v| !matches!(v, PickleValue::None));
            let extras = Extras {
                link_count: inputs.get("link_count").and_then(Num::of),
                active_link_count: inputs.get("active_link_count").and_then(Num::of),
                profiling_results: profiling,
            };
            let now = inputs.get("now").and_then(Num::of).unwrap().f();
            let rendered = render(
                inputs.get("stats").unwrap(),
                &options_from(inputs.get("options").unwrap()),
                &extras,
                now,
            );
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
