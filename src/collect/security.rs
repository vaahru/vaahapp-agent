//! Security signals: failed SSH logins, fail2ban bans, OOM kills, reboot-required, pending updates.
//! Each source degrades to `None` when the tool or log is missing.

use crate::report::Security;
use crate::util::{exists, local_time, now, read, run, which};
use std::collections::BTreeMap;
use std::time::Duration;

const F2B_EVERY: i64 = 300;
const UPDATES_EVERY: i64 = 3600;

/// Lines that mark one failed SSH attempt (password or unknown user; key-only boxes log the latter).
pub fn count_ssh_failed(log: &str) -> u64 {
    log.lines().filter(|l| l.contains("Failed password") || l.contains("Invalid user ")).count() as u64
}

/// "Out of memory: Kill process" (old kernels) / "Killed process" (new). The newer extra
/// "oom-kill:constraint=..." line describes the same event, so it is not counted.
pub fn count_oom(log: &str) -> u64 {
    log.lines().filter(|l| l.contains("Out of memory: Kill")).count() as u64
}

pub fn parse_vmstat_oom(s: &str) -> Option<u64> {
    s.lines().find(|l| l.starts_with("oom_kill ")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
}

/// `fail2ban-client status` → jail names.
pub fn parse_f2b_jails(s: &str) -> Vec<String> {
    s.lines()
        .find(|l| l.contains("Jail list:"))
        .and_then(|l| l.split_once("Jail list:"))
        .map(|(_, v)| v.split(',').map(|j| j.trim().to_string()).filter(|j| !j.is_empty()).collect())
        .unwrap_or_default()
}

/// `fail2ban-client status <jail>` → currently banned count.
pub fn parse_f2b_banned(s: &str) -> Option<u64> {
    s.lines().find(|l| l.contains("Currently banned:")).and_then(|l| l.rsplit(':').next()?.trim().parse().ok())
}

/// `apt-get -s upgrade` → (total, security). Security = the origin in parentheses mentions "security".
pub fn parse_apt_sim(s: &str) -> (u64, u64) {
    let inst: Vec<&str> = s.lines().filter(|l| l.starts_with("Inst ")).collect();
    let sec = inst.iter().filter(|l| l.to_lowercase().contains("security")).count();
    (inst.len() as u64, sec as u64)
}

/// `yum -q check-update` → package lines ("name.arch  version  repo"), stopping at "Obsoleting".
pub fn parse_yum_check(s: &str) -> u64 {
    s.lines()
        .take_while(|l| !l.starts_with("Obsoleting"))
        .filter(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() == 3 && f[0].contains('.') && !l.starts_with(' ')
        })
        .count() as u64
}

enum SshSource {
    Journal(String),
    File(String),
    None,
}

pub struct SecurityCollector {
    ssh: SshSource,
    ssh_offset: u64,
    last_ts: i64,
    oom_counter: Option<u64>,
    f2b: Option<BTreeMap<String, u64>>,
    f2b_at: i64,
    updates: (Option<u64>, Option<u64>, Option<bool>),
    updates_at: i64,
}

impl SecurityCollector {
    pub fn new() -> Self {
        let ssh = if let Some(j) = which("journalctl") {
            // Use the journal only if it actually holds sshd lines (journald may be volatile/empty).
            let since = local_time(now() - 7 * 86400);
            match run(&j, &["-t", "sshd", "-t", "sshd-session", "--since", &since, "-n", "1", "-q", "--no-pager"], Duration::from_secs(15)) {
                Some((_, out)) if !out.trim().is_empty() => SshSource::Journal(j),
                _ => file_source(),
            }
        } else {
            file_source()
        };
        let ssh_offset = match &ssh {
            SshSource::File(p) => std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
            _ => 0,
        };
        SecurityCollector {
            ssh,
            ssh_offset,
            last_ts: now(),
            oom_counter: read("/proc/vmstat").and_then(|s| parse_vmstat_oom(&s)),
            f2b: None,
            f2b_at: 0,
            updates: (None, None, None),
            updates_at: 0,
        }
    }

    pub fn collect(&mut self) -> Security {
        let ts = now();
        let since = local_time(self.last_ts);
        let until = local_time(ts - 1);
        let ssh_failed = match &self.ssh {
            SshSource::Journal(j) => run(j, &["-t", "sshd", "-t", "sshd-session", "--since", &since, "--until", &until, "-o", "cat", "-q", "--no-pager"], Duration::from_secs(20))
                .map(|(_, o)| count_ssh_failed(&o)),
            SshSource::File(p) => self.read_new(p.clone()).map(|s| count_ssh_failed(&s)),
            SshSource::None => None,
        };
        let oom_kills = match read("/proc/vmstat").and_then(|s| parse_vmstat_oom(&s)) {
            Some(c) => {
                let d = self.oom_counter.map(|p| c.saturating_sub(p));
                self.oom_counter = Some(c);
                d.or(Some(0))
            }
            None => which("journalctl").and_then(|j| {
                run(&j, &["-k", "--since", &since, "--until", &until, "-o", "cat", "-q", "--no-pager"], Duration::from_secs(20))
                    .map(|(_, o)| count_oom(&o))
            }),
        };
        self.last_ts = ts;
        if ts - self.f2b_at >= F2B_EVERY {
            self.f2b = fail2ban();
            self.f2b_at = ts;
        }
        if ts - self.updates_at >= UPDATES_EVERY {
            self.updates = updates();
            self.updates_at = ts;
        }
        Security {
            ssh_failed,
            f2b_banned: self.f2b.clone(),
            oom_kills,
            reboot_required: self.updates.2,
            updates_total: self.updates.0,
            updates_security: self.updates.1,
        }
    }

    /// New bytes in an auth log since the last read; a shrunk file means it was rotated.
    fn read_new(&mut self, path: String) -> Option<String> {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&path).ok()?;
        let len = f.metadata().ok()?.len();
        if len < self.ssh_offset {
            self.ssh_offset = 0;
        }
        // Cap one read at 8 MB so a log flood cannot balloon memory.
        let start = self.ssh_offset.max(len.saturating_sub(8 << 20));
        f.seek(SeekFrom::Start(start)).ok()?;
        let mut buf = Vec::new();
        f.take(len - start).read_to_end(&mut buf).ok()?;
        self.ssh_offset = len;
        Some(String::from_utf8_lossy(&buf).into_owned())
    }
}

fn file_source() -> SshSource {
    for p in ["/var/log/auth.log", "/var/log/secure"] {
        if exists(p) {
            return SshSource::File(p.to_string());
        }
    }
    SshSource::None
}

fn fail2ban() -> Option<BTreeMap<String, u64>> {
    let fc = which("fail2ban-client")?;
    let t = Duration::from_secs(10);
    let (_, out) = run(&fc, &["status"], t)?;
    let mut m = BTreeMap::new();
    for jail in parse_f2b_jails(&out) {
        if let Some(n) = run(&fc, &["status", &jail], t).and_then(|(_, o)| parse_f2b_banned(&o)) {
            m.insert(jail, n);
        }
    }
    Some(m)
}

/// (total, security, reboot_required)
fn updates() -> (Option<u64>, Option<u64>, Option<bool>) {
    let t = Duration::from_secs(120);
    if let Some(apt) = which("apt-get") {
        let res = run(&apt, &["-s", "-q", "-o", "Debug::NoLocking=1", "upgrade"], t).map(|(_, o)| parse_apt_sim(&o));
        let reboot = Some(exists("/var/run/reboot-required"));
        return (res.map(|r| r.0), res.map(|r| r.1), reboot);
    }
    let yum = which("dnf").or_else(|| which("yum"));
    if let Some(y) = yum {
        // exit 100 = updates available, 0 = none, anything else = error (dead repos on EOL boxes).
        let total = run(&y, &["-q", "-C", "check-update"], t).and_then(|(c, o)| match c {
            0 => Some(0),
            100 => Some(parse_yum_check(&o)),
            _ => None,
        });
        let reboot = which("needs-restarting")
            .and_then(|n| run(&n, &["-r"], Duration::from_secs(30)))
            .map(|(c, _)| c == 1);
        return (total, None, reboot);
    }
    (None, None, None)
}
