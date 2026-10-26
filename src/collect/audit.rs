//! Security baseline audit: the checks an admin runs on first login to a server, repeated every 6 h.
//! Each check returns pass / warn / fail / na plus the observed value. Nothing is changed on the server.

use crate::report::AuditItem;
use crate::util::{exists, now, read, run, which};
use std::time::Duration;

const EVERY: i64 = 6 * 3600;
/// Services that should never listen on a public address (databases, caches, Docker API, panels).
const RISKY_PORTS: &[u16] = &[2375, 2376, 3306, 5432, 6379, 9200, 11211, 27017, 5984, 8086, 9000];

fn item(id: &str, status: &str, value: impl Into<String>) -> AuditItem {
    AuditItem { id: id.into(), status: status.into(), value: value.into() }
}

/// `sshd -T` output → lowercase key → value.
pub fn sshd_value<'a>(t: &'a str, key: &str) -> Option<&'a str> {
    t.lines().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(' ')).map(str::trim))
}

pub fn ssh_checks(t: &str) -> Vec<AuditItem> {
    let mut out = Vec::new();
    match sshd_value(t, "permitrootlogin") {
        Some("yes") => out.push(item("ssh_root_login", "fail", "yes")),
        Some(v) => out.push(item("ssh_root_login", "pass", v)),
        None => out.push(item("ssh_root_login", "na", "")),
    }
    match sshd_value(t, "passwordauthentication") {
        Some("yes") => out.push(item("ssh_password_auth", "warn", "yes")),
        Some(v) => out.push(item("ssh_password_auth", "pass", v)),
        None => out.push(item("ssh_password_auth", "na", "")),
    }
    if let Some(n) = sshd_value(t, "maxauthtries").and_then(|v| v.parse::<u32>().ok()) {
        out.push(item("ssh_max_auth_tries", if n > 4 { "warn" } else { "pass" }, n.to_string()));
    }
    out
}

/// Public TCP listeners from /proc/net/tcp{,6}: state 0A (LISTEN) on 0.0.0.0 or ::.
pub fn public_listeners(tcp: &str, tcp6: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for (s, any) in [(tcp, "00000000"), (tcp6, "00000000000000000000000000000000")] {
        for l in s.lines().skip(1) {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 4 || f[3] != "0A" {
                continue;
            }
            if let Some((addr, port)) = f[1].split_once(':') {
                if addr == any {
                    if let Ok(p) = u16::from_str_radix(port, 16) {
                        ports.push(p);
                    }
                }
            }
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

/// `docker ps --format '{{.Names}} {{.Ports}}'` → "name:port" published on all interfaces,
/// excluding 80/443 (a web edge is supposed to publish those).
pub fn docker_public(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in s.lines() {
        let Some((name, ports)) = l.split_once(' ') else { continue };
        for p in ports.split(", ") {
            let Some(host) = p.split("->").next() else { continue };
            if let Some(port) = host.strip_prefix("0.0.0.0:").or_else(|| host.strip_prefix(":::")) {
                if port != "80" && port != "443" {
                    out.push(format!("{name}:{port}"));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn extra_uid0(passwd: &str) -> Vec<String> {
    passwd.lines().filter_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 3 && f[2] == "0" && f[0] != "root").then(|| f[0].to_string())
    }).collect()
}

pub fn empty_passwords(shadow: &str) -> Vec<String> {
    shadow.lines().filter_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 1 && f[1].is_empty()).then(|| f[0].to_string())
    }).collect()
}

pub fn has_security_source(sources: &str) -> bool {
    sources.lines().map(str::trim).filter(|l| !l.starts_with('#')).any(|l| l.contains("security"))
}

fn firewall() -> AuditItem {
    let t = Duration::from_secs(10);
    if let Some(ufw) = which("ufw") {
        if let Some((_, o)) = run(&ufw, &["status"], t) {
            if o.contains("Status: active") {
                return item("firewall", "pass", "ufw active");
            }
        }
    }
    if let Some(fc) = which("firewall-cmd") {
        if let Some((0, o)) = run(&fc, &["--state"], t) {
            if o.trim() == "running" {
                return item("firewall", "pass", "firewalld running");
            }
        }
    }
    if let Some(nft) = which("nft") {
        if let Some((_, o)) = run(&nft, &["list", "chains"], t) {
            if o.lines().any(|l| l.contains("hook input") && l.contains("policy drop")) {
                return item("firewall", "pass", "nftables input policy drop");
            }
        }
    }
    if let Some(ipt) = which("iptables") {
        if let Some((_, o)) = run(&ipt, &["-S", "INPUT"], t) {
            if o.lines().any(|l| l == "-P INPUT DROP" || l == "-P INPUT REJECT") {
                return item("firewall", "pass", "iptables INPUT policy drop");
            }
            if o.lines().any(|l| l.contains("-j DROP") || l.contains("-j REJECT")) {
                return item("firewall", "warn", "iptables rules, but INPUT policy ACCEPT");
            }
        }
    }
    item("firewall", "fail", "no active firewall found")
}

fn service_active(name: &str) -> Option<bool> {
    let sc = which("systemctl")?;
    run(&sc, &["is-active", name], Duration::from_secs(5)).map(|(_, o)| o.trim() == "active")
}

fn auto_updates() -> AuditItem {
    if let Some(ac) = which("apt-config") {
        let on = run(&ac, &["dump", "APT::Periodic::Unattended-Upgrade"], Duration::from_secs(10))
            .map(|(_, o)| o.contains("\"1\""))
            .unwrap_or(false);
        let installed = which("unattended-upgrade").is_some();
        return match (installed, on) {
            (true, true) => item("auto_updates", "pass", "unattended-upgrades on"),
            (true, false) => item("auto_updates", "warn", "unattended-upgrades installed but off"),
            _ => item("auto_updates", "warn", "unattended-upgrades not installed"),
        };
    }
    for unit in ["dnf-automatic.timer", "dnf-automatic-install.timer", "yum-cron"] {
        if service_active(unit) == Some(true) {
            return item("auto_updates", "pass", unit);
        }
    }
    item("auto_updates", "warn", "no automatic updates found")
}

fn time_sync() -> AuditItem {
    let Some(td) = which("timedatectl") else { return item("time_sync", "na", "") };
    let (_, o) = run(&td, &["status"], Duration::from_secs(10)).unwrap_or_default();
    // "System clock synchronized: yes" (new) / "NTP synchronized: yes" (systemd 219).
    if o.lines().any(|l| l.contains("synchronized: yes")) {
        item("time_sync", "pass", "synchronized")
    } else if o.is_empty() {
        item("time_sync", "na", "")
    } else {
        item("time_sync", "warn", "clock not synchronized")
    }
}

pub fn run_all() -> Vec<AuditItem> {
    let mut out = Vec::new();
    match which("sshd").and_then(|s| run(&s, &["-T"], Duration::from_secs(10))) {
        Some((0, t)) => out.extend(ssh_checks(&t)),
        _ => out.push(item("ssh_root_login", "na", "sshd -T unavailable")),
    }
    out.push(firewall());
    out.push(match (which("fail2ban-client").is_some(), service_active("fail2ban")) {
        (true, Some(true)) => item("fail2ban", "pass", "active"),
        (true, _) => item("fail2ban", "fail", "installed but not running"),
        _ => item("fail2ban", "warn", "not installed"),
    });
    out.push(auto_updates());
    if which("apt-get").is_some() {
        let mut src = read("/etc/apt/sources.list").unwrap_or_default();
        if let Ok(d) = std::fs::read_dir("/etc/apt/sources.list.d") {
            for e in d.flatten() {
                src.push_str(&std::fs::read_to_string(e.path()).unwrap_or_default());
            }
        }
        out.push(if has_security_source(&src) { item("security_repo", "pass", "present") } else { item("security_repo", "fail", "no -security apt source") });
    }
    if let Some((total, swap)) = read("/proc/meminfo").and_then(|m| crate::collect::sys::parse_meminfo(&m)).map(|m| (m.0, m.2)) {
        let small = total <= 8 << 30;
        out.push(match (small, swap > 0) {
            (_, true) => item("swap", "pass", format!("{} MB", swap >> 20)),
            (true, false) => item("swap", "warn", "no swap with ≤ 8 GB RAM"),
            (false, false) => item("swap", "pass", "none (RAM > 8 GB)"),
        });
    }
    out.push(time_sync());
    let ports = public_listeners(&read("/proc/net/tcp").unwrap_or_default(), &read("/proc/net/tcp6").unwrap_or_default());
    let risky: Vec<String> = ports.iter().filter(|p| RISKY_PORTS.contains(p)).map(|p| p.to_string()).collect();
    let all: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    out.push(if risky.is_empty() {
        item("public_ports", "pass", all.join(","))
    } else {
        item("public_ports", "warn", format!("risky on 0.0.0.0: {} (all: {})", risky.join(","), all.join(",")))
    });
    if let Some(d) = which("docker") {
        if let Some((0, o)) = run(&d, &["ps", "--format", "{{.Names}} {{.Ports}}"], Duration::from_secs(10)) {
            let p = docker_public(&o);
            out.push(if p.is_empty() { item("docker_ports", "pass", "") } else { item("docker_ports", "warn", format!("published on all interfaces (bypasses ufw): {}", p.join(", "))) });
        }
    }
    let uid0 = extra_uid0(&read("/etc/passwd").unwrap_or_default());
    out.push(if uid0.is_empty() { item("uid0_accounts", "pass", "root only") } else { item("uid0_accounts", "fail", uid0.join(",")) });
    if exists("/etc/shadow") {
        let e = empty_passwords(&read("/etc/shadow").unwrap_or_default());
        out.push(if e.is_empty() { item("empty_passwords", "pass", "") } else { item("empty_passwords", "fail", e.join(",")) });
    }
    out
}

pub struct AuditCollector {
    at: i64,
}

impl AuditCollector {
    pub fn new() -> Self {
        AuditCollector { at: 0 }
    }

    pub fn collect(&mut self) -> Option<Vec<AuditItem>> {
        let ts = now();
        if self.at != 0 && ts - self.at < EVERY {
            return None;
        }
        self.at = ts;
        Some(run_all())
    }
}
