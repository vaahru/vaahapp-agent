//! Small helpers: time, files, and running commands with a hard timeout.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

pub fn exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// Finds an executable in the usual system dirs (systemd units have a minimal PATH).
pub fn which(name: &str) -> Option<String> {
    for dir in ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let p = format!("{dir}/{name}");
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    None
}

/// Runs a command and returns its stdout. `None` on spawn failure or timeout (the child is killed).
/// A non-zero exit still returns stdout, because some tools (yum check-update) use exit codes as data.
pub fn run(cmd: &str, args: &[&str], timeout: Duration) -> Option<(i32, String)> {
    let mut child = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take()?;
    let reader = thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let s = reader.join().unwrap_or_default();
                return Some((status.code().unwrap_or(-1), s));
            }
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Local time as "YYYY-MM-DD HH:MM:SS", the one --since format every journalctl accepts
/// (systemd 219 on CentOS 7 rejects ISO "T" and "@epoch" forms).
#[allow(deprecated)] // libc flags time_t on musl because it became 64-bit in musl 1.2; we only pass it through
pub fn local_time(ts: i64) -> String {
    let t = ts as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

pub fn log(msg: &str) {
    // journald adds timestamps; keep lines short and plain.
    eprintln!("{msg}");
}
