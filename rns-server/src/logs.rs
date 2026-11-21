use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default size, in bytes, at which an active process log is rotated.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Default number of rotated archives kept per process.
pub const DEFAULT_MAX_ARCHIVES: usize = 4;

/// Rotation limits for supervised-process logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogPolicy {
    /// Size in bytes an active log may reach; a write that would exceed it
    /// rotates the file first.
    pub max_file_bytes: u64,
    /// Rotated files kept per process (`<name>.log.1` is the newest). Zero
    /// keeps none: a full log is deleted instead of archived.
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

/// Why a line could not be written to a process log.
#[derive(Debug)]
pub(crate) enum LogWriteError {
    /// Another writer panicked while holding the write lock.
    LockPoisoned,
    /// The log directory could not be created.
    CreateDir { path: PathBuf, source: io::Error },
    /// The active log could not be opened.
    Open { path: PathBuf, source: io::Error },
    /// The line could not be appended to the active log.
    Append { path: PathBuf, source: io::Error },
    /// A log could not be renamed to its next archive.
    Rotate {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    /// A log past the retention limit could not be deleted.
    Prune { path: PathBuf, source: io::Error },
}

impl fmt::Display for LogWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogWriteError::LockPoisoned => f.write_str("durable log write lock is poisoned"),
            LogWriteError::CreateDir { path, source } => {
                write!(f, "failed to create log dir {}: {}", path.display(), source)
            }
            LogWriteError::Open { path, source } => {
                write!(
                    f,
                    "failed to open process log {}: {}",
                    path.display(),
                    source
                )
            }
            LogWriteError::Append { path, source } => {
                write!(
                    f,
                    "failed to append process log {}: {}",
                    path.display(),
                    source
                )
            }
            LogWriteError::Rotate { from, to, source } => write!(
                f,
                "failed to rotate process log {} to {}: {}",
                from.display(),
                to.display(),
                source
            ),
            LogWriteError::Prune { path, source } => {
                write!(
                    f,
                    "failed to prune process log {}: {}",
                    path.display(),
                    source
                )
            }
        }
    }
}

impl std::error::Error for LogWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LogWriteError::LockPoisoned => None,
            LogWriteError::CreateDir { source, .. }
            | LogWriteError::Open { source, .. }
            | LogWriteError::Append { source, .. }
            | LogWriteError::Rotate { source, .. }
            | LogWriteError::Prune { source, .. } => Some(source),
        }
    }
}

/// Directory of per-process log files, shared across clones.
#[derive(Clone)]
pub(crate) struct LogStore {
    dir: PathBuf,
    policy: LogPolicy,
    write_lock: Arc<Mutex<()>>,
}

impl LogStore {
    #[cfg(test)]
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self::with_policy(dir, LogPolicy::default())
    }

    pub(crate) fn with_policy(dir: PathBuf, policy: LogPolicy) -> Self {
        Self {
            dir,
            policy,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) fn process_log_path(&self, process: &str) -> PathBuf {
        self.dir.join(format!("{process}.log"))
    }

    /// Appends `line` with a Unix timestamp and the `stream` label,
    /// rotating first if the file would exceed the policy size.
    pub(crate) fn append_line(
        &self,
        process: &str,
        stream: &str,
        line: &str,
    ) -> Result<(), LogWriteError> {
        let rendered = format!("{} [{}] {}\n", unix_timestamp_secs(), stream, line);
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| LogWriteError::LockPoisoned)?;

        fs::create_dir_all(&self.dir).map_err(|source| LogWriteError::CreateDir {
            path: self.dir.clone(),
            source,
        })?;
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
            .map_err(|source| LogWriteError::Open {
                path: path.clone(),
                source,
            })?;
        file.write_all(rendered.as_bytes())
            .map_err(|source| LogWriteError::Append { path, source })
    }

    fn rotate(&self, active_path: &Path, active_len: u64) -> Result<(), LogWriteError> {
        if self.policy.max_archives == 0 || active_len > self.policy.max_file_bytes {
            remove_if_present(active_path)?;
            return Ok(());
        }

        remove_if_present(&archive_path(active_path, self.policy.max_archives))?;
        for index in (1..self.policy.max_archives).rev() {
            let source = archive_path(active_path, index);
            if source.exists() {
                let destination = archive_path(active_path, index + 1);
                if let Err(err) = fs::rename(&source, &destination) {
                    return Err(LogWriteError::Rotate {
                        from: source,
                        to: destination,
                        source: err,
                    });
                }
            }
        }

        let first_archive = archive_path(active_path, 1);
        fs::rename(active_path, &first_archive).map_err(|source| LogWriteError::Rotate {
            from: active_path.to_path_buf(),
            to: first_archive,
            source,
        })
    }
}

fn archive_path(active_path: &Path, index: usize) -> PathBuf {
    let mut path = active_path.as_os_str().to_os_string();
    path.push(format!(".{index}"));
    PathBuf::from(path)
}

fn remove_if_present(path: &Path) -> Result<(), LogWriteError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(LogWriteError::Prune {
            path: path.to_path_buf(),
            source,
        }),
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
    fn log_write_errors_keep_their_messages() {
        let path = || PathBuf::from("/var/log/rns/rnsd.log");
        let io = || io::Error::other("denied");
        let cases = [
            (
                LogWriteError::LockPoisoned.to_string(),
                "durable log write lock is poisoned",
            ),
            (
                LogWriteError::CreateDir {
                    path: PathBuf::from("/var/log/rns"),
                    source: io(),
                }
                .to_string(),
                "failed to create log dir /var/log/rns: denied",
            ),
            (
                LogWriteError::Open {
                    path: path(),
                    source: io(),
                }
                .to_string(),
                "failed to open process log /var/log/rns/rnsd.log: denied",
            ),
            (
                LogWriteError::Append {
                    path: path(),
                    source: io(),
                }
                .to_string(),
                "failed to append process log /var/log/rns/rnsd.log: denied",
            ),
            (
                LogWriteError::Rotate {
                    from: path(),
                    to: PathBuf::from("/var/log/rns/rnsd.log.1"),
                    source: io(),
                }
                .to_string(),
                "failed to rotate process log /var/log/rns/rnsd.log to /var/log/rns/rnsd.log.1: denied",
            ),
            (
                LogWriteError::Prune {
                    path: path(),
                    source: io(),
                }
                .to_string(),
                "failed to prune process log /var/log/rns/rnsd.log: denied",
            ),
        ];
        for (actual, expected) in cases {
            assert_eq!(actual, expected);
        }
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
