//! Running a command: the child process, its exec plan, its pipes and
//! their readers, and the bound on buffered output.

#![allow(unsafe_code, reason = "OS calls through libc and signal handlers")]

use super::*;

#[derive(Debug)]
pub(super) struct OutputBudget {
    pub(super) state: Mutex<OutputBudgetState>,
    pub(super) available: Condvar,
}

#[derive(Debug, Default)]
pub(super) struct OutputBudgetState {
    pub(super) buffered: usize,
    pub(super) closed: bool,
}

impl OutputBudget {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(OutputBudgetState::default()),
            available: Condvar::new(),
        }
    }

    pub(super) fn reserve(&self, bytes: usize) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !state.closed && state.buffered.saturating_add(bytes) > PROCESS_OUTPUT_BUFFER_MAX {
            state = self
                .available
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        if state.closed {
            return false;
        }
        state.buffered += bytes;
        true
    }

    pub(super) fn release(&self, bytes: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.buffered = state.buffered.saturating_sub(bytes);
        self.available.notify_all();
    }

    pub(super) fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed = true;
        self.available.notify_all();
    }

    #[cfg(test)]
    pub(super) fn buffered(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .buffered
    }
}

/// A program running for a session. Its parent-side descriptors are shared
/// with the reader threads, so each is closed only when the last user is
/// done with it, never under a thread still reading it. The waiter thread
/// reaps the pid; `reaped` tells `terminate` not to signal it after that.
pub(super) struct ChildProcess {
    pub(super) pid: libc::pid_t,
    pub(super) reaped: Arc<Mutex<bool>>,
    pub(super) stdin_fd: Option<Arc<OwnedFd>>,
    pub(super) stdout_fd: Option<Arc<OwnedFd>>,
    pub(super) stderr_fd: Option<Arc<OwnedFd>>,
    pub(super) output_budget: Arc<OutputBudget>,
}

impl ChildProcess {
    pub(super) fn spawn(
        link_id: [u8; 16],
        argv: &[String],
        env_overrides: &[(&str, String)],
        flags: &ExecuteCommand,
        event_tx: mpsc::Sender<RnshEvent>,
    ) -> io::Result<Self> {
        if argv.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty command"));
        }

        let use_pty = !(flags.pipe_stdin && flags.pipe_stdout && flags.pipe_stderr);
        let mut pty_master = None;
        let mut pty_child = None;
        if use_pty {
            let mut master: libc::c_int = -1;
            let mut child: libc::c_int = -1;
            // SAFETY: `master` and `child` are live locals `openpty` writes the two descriptors
            // into; the name, termios and winsize arguments may be null.
            let rc = unsafe {
                libc::openpty(
                    &mut master,
                    &mut child,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            pty_master = Some(master);
            pty_child = Some(child);
        }

        let stdin_pipe = if flags.pipe_stdin {
            Some(pipe_pair()?)
        } else {
            None
        };
        let stdout_pipe = if flags.pipe_stdout {
            Some(pipe_pair()?)
        } else {
            None
        };
        let stderr_pipe = if flags.pipe_stderr {
            Some(pipe_pair()?)
        } else {
            None
        };

        let child_stdin = stdin_pipe.map(|p| p.0).or(pty_child).unwrap_or(-1);
        let parent_stdin = stdin_pipe.map(|p| p.1).or(pty_master).unwrap_or(-1);
        let parent_stdout = stdout_pipe.map(|p| p.0).or(pty_master).unwrap_or(-1);
        let child_stdout = stdout_pipe.map(|p| p.1).or(pty_child).unwrap_or(-1);
        let parent_stderr = stderr_pipe.map(|p| p.0).or(pty_master).unwrap_or(-1);
        let child_stderr = stderr_pipe.map(|p| p.1).or(pty_child).unwrap_or(-1);

        // Everything the child needs is built here: between fork and exec
        // the child of a multithreaded process may only make
        // async-signal-safe calls, and allocating is not one.
        let mut exec = ExecPlan::new(argv, env_overrides);
        // SAFETY: `fork` takes no arguments; the child branch below only makes async-signal-safe
        // calls with data (`exec`, the fds) prepared before the fork.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: in the forked child only async-signal-safe calls run: `setsid`, `dup2` of
            // descriptors opened above (never -1: with `use_pty` false all three streams are
            // pipes, otherwise the pty child fills the gaps), `ioctl(TIOCSCTTY)` on a stdio fd
            // that is the pty, `close`, `execve` via the prepared `ExecPlan`, and `_exit`. `exec` is
            // only borrowed here and never dropped in the child.
            unsafe {
                if use_pty {
                    libc::setsid();
                }
                libc::dup2(child_stdin, 0);
                libc::dup2(child_stdout, 1);
                libc::dup2(child_stderr, 2);
                if use_pty {
                    let tty_fd = if !flags.pipe_stdin {
                        0
                    } else if !flags.pipe_stdout {
                        1
                    } else {
                        2
                    };
                    #[allow(
                        clippy::useless_conversion,
                        reason = "the ioctl request type differs between Linux and macOS"
                    )]
                    libc::ioctl(tty_fd, libc::TIOCSCTTY.into(), 0);
                }
                for fd in 3..1024 {
                    libc::close(fd);
                }
                // Borrowed, not moved: `exec` must not be dropped (freeing is
                // not async-signal-safe); _exit leaves it as it is.
                if let Some(exec) = exec.as_mut() {
                    exec.exec();
                }
                libc::_exit(255);
            }
        }

        close_unique(&[
            pty_child,
            stdin_pipe.map(|p| p.0),
            stdout_pipe.map(|p| p.1),
            stderr_pipe.map(|p| p.1),
        ]);

        // The parent's ends, each owned once: the pty master may serve
        // several streams.
        let mut owned: Vec<Arc<OwnedFd>> = Vec::new();
        let mut own = |fd: RawFd| -> Option<Arc<OwnedFd>> {
            if fd < 0 {
                return None;
            }
            if let Some(shared) = owned.iter().find(|o| o.as_raw_fd() == fd) {
                return Some(shared.clone());
            }
            // SAFETY: `fd` is a parent-side pipe end or the pty master,
            // opened above, used by nothing else; this is its only owner.
            let fd = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
            owned.push(fd.clone());
            Some(fd)
        };
        let stdin_fd = own(parent_stdin);
        let stdout_fd = own(parent_stdout);
        let stderr_fd = own(parent_stderr);

        let output_budget = Arc::new(OutputBudget::new());
        let mut reader_handles = Vec::new();
        if let Some(fd) = &stdout_fd {
            reader_handles.push(spawn_reader(
                link_id,
                STREAM_STDOUT,
                fd.clone(),
                event_tx.clone(),
                output_budget.clone(),
            ));
        }
        if let Some(fd) = stderr_fd
            .as_ref()
            .filter(|fd| !stdout_fd.as_ref().is_some_and(|out| Arc::ptr_eq(fd, out)))
        {
            reader_handles.push(spawn_reader(
                link_id,
                STREAM_STDERR,
                fd.clone(),
                event_tx.clone(),
                output_budget.clone(),
            ));
        }
        let reaped = Arc::new(Mutex::new(false));
        spawn_waiter(link_id, pid, reaped.clone(), reader_handles, event_tx);

        Ok(ChildProcess {
            pid,
            reaped,
            stdin_fd,
            stdout_fd,
            stderr_fd,
            output_budget,
        })
    }

    pub(super) fn write_stdin(&self, data: &[u8]) {
        if let Some(fd) = &self.stdin_fd {
            let _ = write_all_fd(fd.as_raw_fd(), data);
        }
    }

    pub(super) fn close_stdin(&mut self) {
        let Some(fd) = self.stdin_fd.take() else {
            return;
        };
        let shared = [&self.stdout_fd, &self.stderr_fd]
            .into_iter()
            .flatten()
            .any(|other| Arc::ptr_eq(&fd, other));
        if shared {
            // The pty: end of input is ^D, and the descriptor stays open.
            let _ = write_all_fd(fd.as_raw_fd(), b"\x04");
            self.stdin_fd = Some(fd);
        }
        // Otherwise the stdin pipe's write end closes as `fd` drops.
    }

    pub(super) fn set_winsize(&self, size: &WindowSize) {
        let Some(fd) = self.stdout_fd.as_ref().or(self.stdin_fd.as_ref()) else {
            return;
        };
        let ws = libc::winsize {
            ws_row: size.rows.unwrap_or(0),
            ws_col: size.cols.unwrap_or(0),
            ws_xpixel: size.hpix.unwrap_or(0),
            ws_ypixel: size.vpix.unwrap_or(0),
        };
        // SAFETY: `fd` is open while this struct holds its Arc, and `ws` is a live local
        // `winsize` that TIOCSWINSZ only reads.
        unsafe {
            libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws);
        }
    }

    pub(super) fn terminate(&mut self) {
        let reaped = self.reaped.lock().unwrap_or_else(|p| p.into_inner());
        if !*reaped {
            // SAFETY: `kill` takes no pointers. While `reaped` is false and its lock is held
            // the waiter cannot reap the child, so `pid` still names it (a zombie at worst),
            // never a reused pid.
            unsafe {
                libc::kill(self.pid, libc::SIGTERM);
            }
        }
        drop(reaped);
        self.close_stdin();
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        // The readers stop at their next chunk; each descriptor closes when
        // its last user, this struct or a reader, lets it go.
        self.output_budget.close();
    }
}

/// A program to exec in a forked child, prepared before the fork: the
/// candidate paths execvp would try, argv, and the environment with the
/// overrides applied. `exec` only makes async-signal-safe calls.
pub(super) struct ExecPlan {
    pub(super) candidates: Vec<CString>,
    pub(super) _argv: Vec<CString>,
    pub(super) argv: Vec<*const libc::c_char>,
    /// `sh <path> <args...>` for a file without a valid executable header,
    /// as execvp runs it; slot 1 is filled with the candidate in the child.
    pub(super) sh_argv: Vec<*const libc::c_char>,
    pub(super) _envp: Vec<CString>,
    pub(super) envp: Vec<*const libc::c_char>,
}

pub(super) const EXEC_SHELL: &std::ffi::CStr = c"/bin/sh";

impl ExecPlan {
    /// None when an argument holds a NUL byte: such a command cannot run.
    pub(super) fn new(argv: &[String], env_overrides: &[(&str, String)]) -> Option<Self> {
        use std::os::unix::ffi::OsStrExt;

        let args = argv
            .iter()
            .map(|arg| CString::new(arg.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        let program = argv.first()?;
        let candidates = if program.contains('/') {
            vec![args.first()?.clone()]
        } else {
            let path = std::env::var_os("PATH");
            let path = path
                .as_deref()
                .map_or(b"/bin:/usr/bin".as_slice(), |p| p.as_bytes());
            path.split(|&b| b == b':')
                .filter_map(|dir| {
                    let mut full = if dir.is_empty() {
                        b".".to_vec()
                    } else {
                        dir.to_vec()
                    };
                    full.push(b'/');
                    full.extend_from_slice(program.as_bytes());
                    CString::new(full).ok()
                })
                .collect()
        };

        let mut env: Vec<(Vec<u8>, Vec<u8>)> = std::env::vars_os()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        for (key, value) in env_overrides {
            if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
                continue;
            }
            match env.iter_mut().find(|(k, _)| k == key.as_bytes()) {
                Some(entry) => entry.1 = value.as_bytes().to_vec(),
                None => env.push((key.as_bytes().to_vec(), value.as_bytes().to_vec())),
            }
        }
        let envs: Vec<CString> = env
            .into_iter()
            .filter_map(|(mut k, v)| {
                k.push(b'=');
                k.extend_from_slice(&v);
                CString::new(k).ok()
            })
            .collect();

        let null_terminated = |strings: &[CString]| {
            strings
                .iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect::<Vec<_>>()
        };
        let argv_ptrs = null_terminated(&args);
        let mut sh_argv = vec![EXEC_SHELL.as_ptr(), std::ptr::null()];
        sh_argv.extend(argv_ptrs.iter().skip(1));
        let envp = null_terminated(&envs);
        Some(ExecPlan {
            candidates,
            _argv: args,
            argv: argv_ptrs,
            sh_argv,
            _envp: envs,
            envp,
        })
    }

    /// Replace the process image as execvp would: try each candidate in
    /// turn, run a file without an executable header with /bin/sh. Returns
    /// only when every attempt failed.
    ///
    /// # Safety
    /// Call only in a forked child that will `_exit` if this returns.
    pub(super) unsafe fn exec(&mut self) {
        for path in &self.candidates {
            // SAFETY: `path`, `argv` and `envp` point into CStrings and null-terminated pointer
            // vectors owned by `self`, built before the fork; `execve` is async-signal-safe.
            unsafe { libc::execve(path.as_ptr(), self.argv.as_ptr(), self.envp.as_ptr()) };
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOEXEC) => {
                    #[allow(
                        clippy::indexing_slicing,
                        reason = "sh_argv starts with the shell and this slot; execve below relies on it"
                    )]
                    {
                        self.sh_argv[1] = path.as_ptr();
                    }
                    // SAFETY: as above; `sh_argv` is null-terminated and slot 1 now points at
                    // `path`, which `self.candidates` keeps alive.
                    unsafe {
                        libc::execve(
                            EXEC_SHELL.as_ptr(),
                            self.sh_argv.as_ptr(),
                            self.envp.as_ptr(),
                        )
                    };
                    return;
                }
                Some(libc::ENOENT | libc::ENOTDIR | libc::EACCES | libc::ESTALE) => continue,
                _ => return,
            }
        }
    }
}

pub(super) fn pipe_pair() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [-1; 2];
    // SAFETY: `fds` is a live local array of two c_ints, the room `pipe` writes into.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

pub(super) fn close_unique(fds: &[Option<RawFd>]) {
    let mut seen = HashSet::new();
    for fd in fds.iter().flatten().copied() {
        if fd >= 0 && seen.insert(fd) {
            // SAFETY: callers pass descriptors they own and give up; `seen` makes each one closed
            // only once here.
            unsafe {
                libc::close(fd);
            }
        }
    }
}

pub(super) fn spawn_reader(
    link_id: [u8; 16],
    stream_id: u16,
    fd: Arc<OwnedFd>,
    event_tx: mpsc::Sender<RnshEvent>,
    output_budget: Arc<OutputBudget>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: `buf` is a live local of `buf.len()` bytes; `fd` stays open while this
            // thread holds its Arc.
            let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                let bytes = n as usize;
                if !output_budget.reserve(bytes) {
                    break;
                }
                if event_tx
                    .send(RnshEvent::ProcessOutput {
                        link_id,
                        stream_id,
                        data: buf.get(..bytes).unwrap_or_default().to_vec(),
                        budget: output_budget.clone(),
                    })
                    .is_err()
                {
                    output_budget.release(bytes);
                    break;
                }
            } else {
                break;
            }
        }
    })
}

pub(super) fn spawn_waiter(
    link_id: [u8; 16],
    pid: libc::pid_t,
    reaped: Arc<Mutex<bool>>,
    reader_handles: Vec<std::thread::JoinHandle<()>>,
    event_tx: mpsc::Sender<RnshEvent>,
) {
    std::thread::spawn(move || {
        // Wait for the exit without reaping, then reap under the lock
        // `terminate` takes: the pid is never signalled once it may be reused.
        loop {
            // SAFETY: an all-zero siginfo_t is a valid value for this plain C struct.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: `info` is a live local waitid writes into; `pid` is our child.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if rc == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
        let mut reaped = reaped.lock().unwrap_or_else(|p| p.into_inner());
        let mut status = 0;
        // SAFETY: `status` is a live local `c_int` waitpid writes into; `pid` is the forked
        // child, reaped only here.
        let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
        *reaped = true;
        drop(reaped);
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            255
        };
        for handle in reader_handles {
            let _ = handle.join();
        }
        let _ = event_tx.send(RnshEvent::ProcessExited { link_id, code });
    });
}

pub(super) fn write_all_fd(fd: RawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        // SAFETY: `data` is a live slice and `write` reads at most `data.len()` bytes from it;
        // the caller passes a descriptor it owns.
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // write reports at most data.len() bytes written.
        data = data.get(n as usize..).unwrap_or_default();
    }
    Ok(())
}
