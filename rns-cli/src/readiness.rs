use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ReadyFile {
    path: PathBuf,
}

impl ReadyFile {
    pub fn new(path: Option<&str>) -> Result<Option<Self>, String> {
        let Some(path) = path else {
            return Ok(None);
        };
        let ready_file = Self {
            path: PathBuf::from(path),
        };
        ready_file.clear()?;
        Ok(Some(ready_file))
    }

    pub fn mark_ready(&self, process: &str, detail: &str) -> Result<(), String> {
        self.write_status(process, "ready", detail)
    }

    pub fn mark_draining(&self, process: &str, detail: &str) -> Result<(), String> {
        self.write_status(process, "draining", detail)
    }

    fn write_status(&self, process: &str, status: &str, detail: &str) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "failed to create readiness dir {}: {}",
                    parent.display(),
                    err
                )
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
        fs::write(&self.path, body).map_err(|err| {
            format!(
                "failed to write readiness file {}: {}",
                self.path.display(),
                err
            )
        })
    }

    pub fn clear(&self) -> Result<(), String> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!(
                "failed to remove readiness file {}: {}",
                self.path.display(),
                err
            )),
        }
    }

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
