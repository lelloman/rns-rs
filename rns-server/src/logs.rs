use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_ARCHIVES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogPolicy {
    pub max_file_bytes: u64,
    pub max_archives: usize,
}

impl Default for LogPolicy {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_archives: DEFAULT_MAX_ARCHIVES,
        }
    }
}

#[derive(Clone)]
pub struct LogStore {
    dir: PathBuf,
    policy: LogPolicy,
    write_lock: Arc<Mutex<()>>,
}

impl LogStore {
    pub fn new(dir: PathBuf) -> Self {
        Self::with_policy(dir, LogPolicy::default())
    }

    pub fn with_policy(dir: PathBuf, policy: LogPolicy) -> Self {
        Self {
            dir,
            policy,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn process_log_path(&self, process: &str) -> PathBuf {
        self.dir.join(format!("{process}.log"))
    }

    pub fn append_line(&self, process: &str, stream: &str, line: &str) -> Result<(), String> {
        let rendered = format!("{} [{}] {}\n", unix_timestamp_secs(), stream, line);
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| "durable log write lock is poisoned".to_string())?;

        fs::create_dir_all(&self.dir)
            .map_err(|err| format!("failed to create log dir {}: {}", self.dir.display(), err))?;
        let path = self.process_log_path(process);
        let current_len = path.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        if current_len > 0
            && current_len.saturating_add(rendered.len() as u64) > self.policy.max_file_bytes
        {
            self.rotate(&path, current_len)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| format!("failed to open process log {}: {}", path.display(), err))?;
        file.write_all(rendered.as_bytes())
            .map_err(|err| format!("failed to append process log {}: {}", path.display(), err))
    }

    fn rotate(&self, active_path: &Path, active_len: u64) -> Result<(), String> {
        if self.policy.max_archives == 0 || active_len > self.policy.max_file_bytes {
            remove_if_present(active_path)?;
            return Ok(());
        }

        remove_if_present(&archive_path(active_path, self.policy.max_archives))?;
        for index in (1..self.policy.max_archives).rev() {
            let source = archive_path(active_path, index);
            if source.exists() {
                let destination = archive_path(active_path, index + 1);
                fs::rename(&source, &destination).map_err(|err| {
                    format!(
                        "failed to rotate process log {} to {}: {}",
                        source.display(),
                        destination.display(),
                        err
                    )
                })?;
            }
        }

        let first_archive = archive_path(active_path, 1);
        fs::rename(active_path, &first_archive).map_err(|err| {
            format!(
                "failed to rotate process log {} to {}: {}",
                active_path.display(),
                first_archive.display(),
                err
            )
        })
    }
}

fn archive_path(active_path: &Path, index: usize) -> PathBuf {
    let mut path = active_path.as_os_str().to_os_string();
    path.push(format!(".{index}"));
    PathBuf::from(path)
}

fn remove_if_present(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "failed to prune process log {}: {}",
            path.display(),
            err
        )),
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

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rns-server-logs-{name}-{}-{}",
            std::process::id(),
            unix_timestamp_secs()
        ))
    }

    #[test]
    fn log_store_appends_process_output() {
        let dir = test_dir("append");
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

    #[test]
    fn rotates_and_prunes_old_archives() {
        let dir = test_dir("rotate");
        let store = LogStore::with_policy(
            dir.clone(),
            LogPolicy {
                max_file_bytes: 50,
                max_archives: 2,
            },
        );

        for index in 0..8 {
            store
                .append_line("rnsd", "stderr", &format!("message-{index}"))
                .unwrap();
        }

        let active = store.process_log_path("rnsd");
        assert!(active.exists());
        assert!(archive_path(&active, 1).exists());
        assert!(archive_path(&active, 2).exists());
        assert!(!archive_path(&active, 3).exists());
        assert!(active.metadata().unwrap().len() <= 50);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn drops_preexisting_oversized_log_instead_of_archiving_it() {
        let dir = test_dir("oversized");
        fs::create_dir_all(&dir).unwrap();
        let active = dir.join("rnsd.log");
        fs::write(&active, vec![b'x'; 256]).unwrap();
        let store = LogStore::with_policy(
            dir.clone(),
            LogPolicy {
                max_file_bytes: 64,
                max_archives: 2,
            },
        );

        store.append_line("rnsd", "stderr", "new-line").unwrap();

        let body = fs::read_to_string(&active).unwrap();
        assert!(body.contains("new-line"));
        assert!(body.len() < 64);
        assert!(!archive_path(&active, 1).exists());

        let _ = std::fs::remove_dir_all(dir);
    }
}
