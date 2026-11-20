//! Memory statistics for the log.

use super::*;

impl Driver {
    /// Read RSS from /proc/self/statm (Linux only).
    pub(crate) fn rss_mb() -> Option<f64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(rss_pages as f64 * 4096.0 / (1024.0 * 1024.0))
    }

    pub(crate) fn parse_proc_kib(contents: &str, key: &str) -> Option<u64> {
        contents.lines().find_map(|line| {
            let value = line.strip_prefix(key)?;
            value.split_whitespace().next()?.parse().ok()
        })
    }

    pub(crate) fn proc_status_mb() -> Option<(f64, f64, f64, f64)> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let vm_rss = Self::parse_proc_kib(&status, "VmRSS:")? as f64 / 1024.0;
        let vm_hwm = Self::parse_proc_kib(&status, "VmHWM:")? as f64 / 1024.0;
        let vm_data = Self::parse_proc_kib(&status, "VmData:")? as f64 / 1024.0;
        let vm_swap = Self::parse_proc_kib(&status, "VmSwap:").unwrap_or(0) as f64 / 1024.0;
        Some((vm_rss, vm_hwm, vm_data, vm_swap))
    }

    pub(crate) fn smaps_rollup_mb() -> Option<MemoryRollup> {
        let smaps = std::fs::read_to_string("/proc/self/smaps_rollup").ok()?;
        let rss_kib = Self::parse_proc_kib(&smaps, "Rss:")?;
        let anon_kib = Self::parse_proc_kib(&smaps, "Anonymous:")?;
        let shared_clean_kib = Self::parse_proc_kib(&smaps, "Shared_Clean:").unwrap_or(0);
        let shared_dirty_kib = Self::parse_proc_kib(&smaps, "Shared_Dirty:").unwrap_or(0);
        let private_clean_kib = Self::parse_proc_kib(&smaps, "Private_Clean:").unwrap_or(0);
        let private_dirty_kib = Self::parse_proc_kib(&smaps, "Private_Dirty:").unwrap_or(0);
        let swap_kib = Self::parse_proc_kib(&smaps, "Swap:").unwrap_or(0);
        let file_est_kib = rss_kib.saturating_sub(anon_kib);
        Some((
            rss_kib as f64 / 1024.0,
            anon_kib as f64 / 1024.0,
            file_est_kib as f64 / 1024.0,
            shared_clean_kib as f64 / 1024.0,
            shared_dirty_kib as f64 / 1024.0,
            private_clean_kib as f64 / 1024.0,
            private_dirty_kib as f64 / 1024.0,
            swap_kib as f64 / 1024.0,
        ))
    }

    /// Log sizes of all major collections for memory growth diagnostics.
    pub(crate) fn log_memory_stats(&self) {
        let rss = Self::rss_mb()
            .map(|v| format!("{:.1}", v))
            .unwrap_or_else(|| "N/A".into());
        let (vm_rss, vm_hwm, vm_data, vm_swap) = Self::proc_status_mb()
            .map(|(rss, hwm, data, swap)| {
                (
                    format!("{rss:.1}"),
                    format!("{hwm:.1}"),
                    format!("{data:.1}"),
                    format!("{swap:.1}"),
                )
            })
            .unwrap_or_else(|| ("N/A".into(), "N/A".into(), "N/A".into(), "N/A".into()));
        let (
            smaps_rss,
            smaps_anon,
            smaps_file_est,
            smaps_shared_clean,
            smaps_shared_dirty,
            smaps_private_clean,
            smaps_private_dirty,
            smaps_swap,
        ) = Self::smaps_rollup_mb()
            .map(
                |(
                    rss,
                    anon,
                    file_est,
                    shared_clean,
                    shared_dirty,
                    private_clean,
                    private_dirty,
                    swap,
                )| {
                    (
                        format!("{rss:.1}"),
                        format!("{anon:.1}"),
                        format!("{file_est:.1}"),
                        format!("{shared_clean:.1}"),
                        format!("{shared_dirty:.1}"),
                        format!("{private_clean:.1}"),
                        format!("{private_dirty:.1}"),
                        format!("{swap:.1}"),
                    )
                },
            )
            .unwrap_or_else(|| {
                (
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                    "N/A".into(),
                )
            });
        // At notice level, so the default log level keeps it: the daily VPS
        // report reads it from the journal.
        log::info!(
            target: crate::logging::NOTICE_TARGET,
            "MEMSTATS rss_mb={} vmrss_mb={} vmhwm_mb={} vmdata_mb={} vmswap_mb={} smaps_rss_mb={} smaps_anon_mb={} smaps_file_est_mb={} smaps_shared_clean_mb={} smaps_shared_dirty_mb={} smaps_private_clean_mb={} smaps_private_dirty_mb={} smaps_swap_mb={} known_dest={} known_dest_cap_evict={} path={} path_cap_evict={} announce={} reverse={}              link={} held_ann={} hashlist={} sig_cache={} ann_verify_q={} rate_lim={} blackhole={} tunnel={} ann_q_ifaces={} ann_q_nonempty={} ann_q_entries={} ann_q_bytes={} ann_q_iface_drop={}              pr_tags={} disc_pr={} sent_pkt={} completed={} local_dest={}              shared_ann={} lm_links={} hp_sessions={} proof_strat={}",
            rss,
            vm_rss,
            vm_hwm,
            vm_data,
            vm_swap,
            smaps_rss,
            smaps_anon,
            smaps_file_est,
            smaps_shared_clean,
            smaps_shared_dirty,
            smaps_private_clean,
            smaps_private_dirty,
            smaps_swap,
            self.known.entries.len(),
            self.known.cap_evict_count,
            self.engine.path_table_count(),
            self.engine.path_destination_cap_evict_count(),
            self.engine.announce_table_count(),
            self.engine.reverse_table_count(),
            self.engine.link_table_count(),
            self.engine.held_announces_count(),
            self.engine.packet_hashlist_len(),
            self.engine.announce_sig_cache_len(),
            self.announce_verify_queue
                .lock()
                .map(|queue| queue.len())
                .unwrap_or(0),
            self.engine.rate_limiter_count(),
            self.engine.blackholed_count(),
            self.engine.tunnel_count(),
            self.engine.announce_queue_count(),
            self.engine.nonempty_announce_queue_count(),
            self.engine.queued_announce_count(),
            self.engine.queued_announce_bytes(),
            self.engine.announce_queue_interface_cap_drop_count(),
            self.engine.discovery_pr_tags_count(),
            self.engine.discovery_path_requests_count(),
            self.proofs.sent_packets.len(),
            self.proofs.completed.len(),
            self.local_destinations.len(),
            self.shared_announces.len(),
            self.link_manager.link_count(),
            self.holepunch_manager.session_count(),
            self.proofs.strategies.len(),
        );
    }
}
