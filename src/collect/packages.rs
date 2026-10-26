//! Installed package inventory for the server's CVE scan. Sent on start, daily, and soon after the
//! package database changes. Only names and versions leave the server — no file contents.

use crate::report::Packages;
use crate::util::{now, read, run, which};
use std::time::{Duration, SystemTime};

const EVERY: i64 = 86400;

/// `dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n'`
pub fn parse_dpkg(s: &str) -> Vec<[String; 4]> {
    let mut out: Vec<[String; 4]> = s
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 5 || !f[4].starts_with("ii") {
                return None;
            }
            let src = if f[2].is_empty() { f[0] } else { f[2] };
            let srcv = if f[3].is_empty() { f[1] } else { f[3] };
            Some([f[0].to_string(), f[1].to_string(), src.to_string(), srcv.to_string()])
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n'`.
/// The source name is the SRPM file name without "-version-release.src.rpm".
pub fn parse_rpm(s: &str) -> Vec<[String; 4]> {
    let mut out: Vec<[String; 4]> = s
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 3 || f[0] == "gpg-pubkey" {
                return None;
            }
            let srpm = f[2].trim_end_matches(".src.rpm");
            // name-version-release: strip the last two dash-separated fields.
            let mut parts: Vec<&str> = srpm.rsplitn(3, '-').collect();
            parts.reverse();
            let src = if parts.len() == 3 { parts[0].to_string() } else { f[0].to_string() };
            Some([f[0].to_string(), f[1].to_string(), src, f[1].to_string()])
        })
        .collect();
    out.sort();
    out
}

pub fn os_release_field(s: &str, key: &str) -> String {
    s.lines()
        .find(|l| l.starts_with(&format!("{key}=")))
        .map(|l| l[key.len() + 1..].trim().trim_matches('"').to_string())
        .unwrap_or_default()
}

fn db_mtime() -> Option<SystemTime> {
    ["/var/lib/dpkg/status", "/var/lib/rpm/Packages", "/var/lib/rpm/rpmdb.sqlite"]
        .iter()
        .filter_map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        .max()
}

pub struct PackagesCollector {
    sent_at: i64,
    sent_mtime: Option<SystemTime>,
}

impl PackagesCollector {
    pub fn new() -> Self {
        PackagesCollector { sent_at: 0, sent_mtime: None }
    }

    /// Returns the inventory when it is due: first call, daily, or once the package DB changed and
    /// has been quiet for a minute (so a running apt upgrade is not reported half-way).
    pub fn collect(&mut self) -> Option<Packages> {
        let ts = now();
        let mtime = db_mtime();
        let changed = mtime != self.sent_mtime
            && mtime.and_then(|m| m.elapsed().ok()).map(|e| e.as_secs() >= 60).unwrap_or(false);
        if self.sent_at != 0 && ts - self.sent_at < EVERY && !changed {
            return None;
        }
        let p = inventory()?;
        self.sent_at = ts;
        self.sent_mtime = mtime;
        Some(p)
    }
}

pub fn inventory() -> Option<Packages> {
    let osr = read("/etc/os-release").unwrap_or_default();
    let t = Duration::from_secs(60);
    let (manager, items) = if let Some(dq) = which("dpkg-query") {
        let (_, out) = run(&dq, &["-W", "-f", "${Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"], t)?;
        ("dpkg", parse_dpkg(&out))
    } else if let Some(rpm) = which("rpm") {
        let (_, out) = run(&rpm, &["-qa", "--qf", "%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"], t)?;
        ("rpm", parse_rpm(&out))
    } else {
        return None;
    };
    Some(Packages {
        manager: manager.into(),
        os_id: os_release_field(&osr, "ID"),
        os_version: os_release_field(&osr, "VERSION_ID"),
        os_codename: os_release_field(&osr, "VERSION_CODENAME"),
        items,
    })
}
