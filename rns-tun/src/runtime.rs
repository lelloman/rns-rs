//! Reticulum integration runtime.
//!
//! The portable protocol and session engines do not depend on this module's
//! worker topology. Runtime construction is added incrementally with the
//! private-node APIs in rns-net.

use std::sync::{Arc, Mutex};

use crate::status::RuntimeStatus;

/// The live [`RuntimeStatus`], shared between the worker that updates it and
/// the status server. Clones share the same status. A poisoned lock is
/// recovered, not propagated.
#[derive(Clone)]
pub struct SharedStatus(pub Arc<Mutex<RuntimeStatus>>);
impl SharedStatus {
    /// Share `status`.
    pub fn new(status: RuntimeStatus) -> Self {
        Self(Arc::new(Mutex::new(status)))
    }
    /// A copy of the current status.
    pub fn snapshot(&self) -> RuntimeStatus {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
    /// Change the status under the lock.
    pub fn update(&self, update: impl FnOnce(&mut RuntimeStatus)) {
        update(&mut self.0.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

/// The status Unix socket: a client writes one JSON [`StatusRequest`] line
/// and reads back one JSON [`RuntimeStatus`] line.
///
/// [`StatusRequest`]: crate::status::StatusRequest
#[cfg(unix)]
pub mod status_socket {
    use std::fs;
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use super::SharedStatus;
    use crate::status::{RuntimeStatus, StatusRequest};

    /// Serves status queries from a background thread until dropped. Drop
    /// stops the thread (within about 50 ms) and removes the socket file.
    pub struct StatusServer {
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        path: PathBuf,
    }

    impl StatusServer {
        /// Bind the socket at `path` with mode 0600, creating parent
        /// directories, and start serving `status`. A stale socket file is
        /// replaced; one with a live listener fails with
        /// [`io::ErrorKind::AddrInUse`]. Requests longer than 512 bytes or
        /// not a valid status request get no answer.
        pub fn start(path: PathBuf, status: SharedStatus) -> io::Result<Self> {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            if path.exists() {
                // Unix socket pathnames survive an unclean process exit. Only
                // replace the pathname when it no longer has a live listener;
                // a successful connection still means another rntun owns it.
                match UnixStream::connect(&path) {
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrInUse,
                            format!("status socket already exists: {}", path.display()),
                        ))
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                        ) =>
                    {
                        fs::remove_file(&path)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            let listener = UnixListener::bind(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            }
            listener.set_nonblocking(true)?;
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let thread = thread::spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let mut request_line = String::new();
                            let valid = BufReader::new(&mut stream)
                                .take(513)
                                .read_line(&mut request_line)
                                .ok()
                                .filter(|size| *size <= 512)
                                .and_then(|_| {
                                    serde_json::from_str::<StatusRequest>(&request_line).ok()
                                })
                                .is_some_and(|request| {
                                    request.schema_version == 1 && request.command == "status"
                                });
                            if valid {
                                let response = status.snapshot();
                                if serde_json::to_writer(&mut stream, &response).is_ok() {
                                    let _ = stream.write_all(b"\n");
                                }
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(50));
                        }
                        Err(_) => break,
                    }
                }
            });
            Ok(Self {
                stop,
                thread: Some(thread),
                path,
            })
        }
    }

    impl Drop for StatusServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            let _ = fs::remove_file(&self.path);
        }
    }

    /// Ask the server at `path` for its status. Blocks until the server
    /// answers or closes the connection.
    pub fn query(path: &Path) -> io::Result<RuntimeStatus> {
        let mut stream = UnixStream::connect(path)?;
        let request = StatusRequest {
            schema_version: 1,
            command: "status".into(),
        };
        serde_json::to_writer(&mut stream, &request).map_err(io::Error::other)?;
        stream.write_all(b"\n")?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        serde_json::from_str(&line).map_err(io::Error::other)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn serves_bounded_status_request() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("status.sock");
            let status = SharedStatus::new(RuntimeStatus {
                mode: "client".into(),
                lifecycle: "active".into(),
                ..Default::default()
            });
            let _server = StatusServer::start(path.clone(), status).unwrap();
            let response = query(&path).unwrap();
            assert_eq!(response.mode, "client");
            assert_eq!(response.lifecycle, "active");
        }

        #[test]
        fn replaces_stale_socket_but_not_live_server() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("status.sock");
            let stale = UnixListener::bind(&path).unwrap();
            drop(stale);
            let status = SharedStatus::new(RuntimeStatus::default());
            let server = StatusServer::start(path.clone(), status.clone()).unwrap();
            assert_eq!(query(&path).unwrap().schema_version, 1);
            let error = match StatusServer::start(path, status) {
                Ok(_) => panic!("a second live status server must be rejected"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
            drop(server);
        }
    }
}
