use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct LogStore {
    dir: PathBuf,
}

impl LogStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn process_log_path(&self, process: &str) -> PathBuf {
        self.dir.join(format!("{process}.log"))
    }

    pub fn append_line(&self, process: &str, stream: &str, line: &str) -> Result<(), String> {
        fs::create_dir_all(&self.dir)
            .map_err(|err| format!("failed to create log dir {}: {}", self.dir.display(), err))?;
        let path = self.process_log_path(process);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| format!("failed to open process log {}: {}", path.display(), err))?;
        writeln!(file, "{} [{}] {}", unix_timestamp_secs(), stream, line)
            .map_err(|err| format!("failed to append process log {}: {}", path.display(), err))
    }
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_store_appends_process_output() {
        let dir = std::env::temp_dir().join(format!("rns-server-logs-{}", std::process::id()));
        let store = LogStore::new(dir.clone());

        store.append_line("rnsd", "stdout", "started").unwrap();
        store.append_line("rnsd", "stderr", "warning").unwrap();

        let body = std::fs::read_to_string(store.process_log_path("rnsd")).unwrap();
        assert!(body.contains("[stdout] started"));
        assert!(body.contains("[stderr] warning"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn process_log_path_is_per_process() {
        let store = LogStore::new(PathBuf::from("/tmp/rns/logs"));
        assert_eq!(
            store.process_log_path("rns-statsd"),
            std::path::Path::new("/tmp/rns/logs/rns-statsd.log")
        );
    }
}
