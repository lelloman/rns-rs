//! The readiness file a supervised sidecar writes once it is serving, so
//! its supervisor (`rns-server`) knows when it is up and when it drains.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A readiness file operation that failed: what was done, on which path,
/// and the I/O error.
#[derive(Debug)]
pub struct ReadyFileError {
    action: &'static str,
    path: PathBuf,
    source: io::Error,
}

impl fmt::Display for ReadyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to {} {}: {}",
            self.action,
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for ReadyFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// A readiness file through which a sidecar process tells its supervisor it
/// is up. The file is deleted when this is dropped.
pub struct ReadyFile {
    path: PathBuf,
}

impl ReadyFile {
    /// Starts with no readiness file when `path` is `None`. Otherwise removes
    /// any stale file at `path`, so the supervisor does not see an old status
    /// before this process reports one; fails when that removal fails.
    pub fn new(path: Option<&str>) -> Result<Option<Self>, ReadyFileError> {
        let Some(path) = path else {
            return Ok(None);
        };
        let ready_file = Self {
            path: PathBuf::from(path),
        };
        ready_file.clear()?;
        Ok(Some(ready_file))
    }

    /// Writes the `ready` status for `process`, with a free-text `detail`.
    /// Creates missing parent directories. The error names the path and the
    /// I/O failure.
    pub fn mark_ready(&self, process: &str, detail: &str) -> Result<(), ReadyFileError> {
        self.write_status(process, "ready", detail)
    }

    /// Writes the `draining` status: the process is shutting down. Errors as
    /// [`ReadyFile::mark_ready`].
    pub fn mark_draining(&self, process: &str, detail: &str) -> Result<(), ReadyFileError> {
        self.write_status(process, "draining", detail)
    }

    fn write_status(
        &self,
        process: &str,
        status: &str,
        detail: &str,
    ) -> Result<(), ReadyFileError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|source| ReadyFileError {
                action: "create readiness dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let body = format!(
            "version=1\nstatus={}\nprocess={}\npid={}\ntimestamp_ms={}\ndetail={}\n",
            status,
            process,
            std::process::id(),
            now_unix_ms(),
            escape_value(detail),
        );
        fs::write(&self.path, body).map_err(|source| ReadyFileError {
            action: "write readiness file",
            path: self.path.clone(),
            source,
        })
    }

    /// Removes the file; a file that is already gone is not an error.
    pub fn clear(&self) -> Result<(), ReadyFileError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(ReadyFileError {
                action: "remove readiness file",
                path: self.path.clone(),
                source,
            }),
        }
    }

    /// Where the file is written.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ReadyFile {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn escape_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_file_lifecycle_writes_and_clears_contract_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("sentineld.ready");
        let path_string = path.display().to_string();
        let ready_file = ReadyFile::new(Some(&path_string))
            .unwrap()
            .expect("ready file should be configured");

        ready_file
            .mark_ready(
                "rns-sentineld",
                "hooks loaded and provider bridge connected",
            )
            .unwrap();

        let body = fs::read_to_string(ready_file.path()).unwrap();
        assert!(body.contains("version=1"));
        assert!(body.contains("status=ready"));
        assert!(body.contains("process=rns-sentineld"));
        assert!(body.contains("detail=hooks loaded and provider bridge connected"));

        ready_file.clear().unwrap();
        assert!(!ready_file.path().exists());
    }

    #[test]
    fn ready_file_can_report_draining_state() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("statsd.ready");
        let path_string = path.display().to_string();
        let ready_file = ReadyFile::new(Some(&path_string))
            .unwrap()
            .expect("ready file should be configured");

        ready_file
            .mark_draining("rns-statsd", "stopping ingest and flushing stats database")
            .unwrap();

        let body = fs::read_to_string(ready_file.path()).unwrap();
        assert!(body.contains("status=draining"));
        assert!(body.contains("process=rns-statsd"));
        assert!(body.contains("detail=stopping ingest and flushing stats database"));
    }

    #[test]
    fn ready_file_new_clears_stale_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("statsd.ready");
        fs::write(&path, "stale").unwrap();

        let path_string = path.display().to_string();
        let ready_file = ReadyFile::new(Some(&path_string))
            .unwrap()
            .expect("ready file should be configured");

        assert!(!ready_file.path().exists());
    }
}
