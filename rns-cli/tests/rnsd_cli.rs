use std::fs;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// `rnsd -i` keeps upstream's console lifecycle: prompts on stdout, the
/// console's messages on stderr, and the end of its input stops rnsd with
/// status 0.
#[test]
fn interactive_rnsd_stops_at_the_end_of_its_input() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("config"),
        "[reticulum]\n  share_instance = No\n[logging]\n  loglevel = 2\n",
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rnsd"))
        .args(["--config", dir.path().to_str().unwrap(), "-i"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start rnsd -i");
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"print(1)\n\n").unwrap();
    }

    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("rnsd -i did not stop at the end of its input");
        }
        thread::sleep(Duration::from_millis(50));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child.stdout.unwrap().read_to_string(&mut stdout).unwrap();
    child.stderr.unwrap().read_to_string(&mut stderr).unwrap();

    assert_eq!(status.code(), Some(0), "stderr:\n{stderr}");
    assert_eq!(stdout, ">>> >>> >>> ");
    assert!(
        stderr.ends_with(
            "Python statements cannot be run by this rnsd\n\nnow exiting InteractiveConsole...\n"
        ),
        "{stderr}"
    );
}
