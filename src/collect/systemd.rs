//! Key systemd services and failed units.

use crate::report::Service;
use crate::util::{run, which};
use std::time::Duration;

/// Unit name prefixes reported automatically when the unit is loaded on this host.
const KEY_UNITS: &[&str] = &[
    "nginx", "apache2", "httpd", "php", "mariadb", "mysql", "mysqld", "postgresql", "redis", "memcached",
    "docker", "containerd", "caddy", "haproxy", "varnish", "fail2ban", "ssh", "sshd", "cron", "crond",
    "chronyd", "chrony", "systemd-timesyncd", "ntp", "ntpsec", "postfix", "exim4", "tailscaled",
    "sing-box", "tinyproxy", "wg-quick@", "awg-quick@", "clp-agent", "clp-nginx", "proftpd", "pure-ftpd",
];

/// Parses `systemctl list-units --type=service --all --no-legend --plain`:
/// `UNIT LOAD ACTIVE SUB DESCRIPTION...`. Some versions prefix failed units with "●".
pub fn parse_list_units(s: &str) -> Vec<(String, String, String, String)> {
    s.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace().filter(|x| *x != "●" && *x != "*");
            Some((f.next()?.to_string(), f.next()?.to_string(), f.next()?.to_string(), f.next()?.to_string()))
        })
        .collect()
}

pub fn is_key_unit(name: &str, extra: &[String]) -> bool {
    let base = name.strip_suffix(".service").unwrap_or(name);
    if extra.iter().any(|e| e == name || e == base) {
        return true;
    }
    KEY_UNITS.iter().any(|k| {
        if k.ends_with('@') {
            return base.starts_with(k);
        }
        // "php" matches php8.3-fpm / php-fpm; others must match the whole name or name@instance.
        if *k == "php" {
            return base.starts_with("php") && base.ends_with("fpm");
        }
        // Exact name, or the name followed by @instance / -suffix / version (redis-server, postgresql@16-main).
        base == *k
            || (base.starts_with(k)
                && base[k.len()..].starts_with(|c: char| c == '@' || c == '-' || c == '.' || c.is_ascii_digit()))
    })
}

/// (key services, failed units). `None` when systemd is not running.
pub fn collect(extra: &[String]) -> Option<(Vec<Service>, Vec<String>)> {
    if !crate::util::exists("/run/systemd/system") {
        return None;
    }
    let sc = which("systemctl")?;
    let (_, out) = run(&sc, &["list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"], Duration::from_secs(10))?;
    let mut services = Vec::new();
    let mut failed = Vec::new();
    for (name, load, active, sub) in parse_list_units(&out) {
        if active == "failed" {
            failed.push(name.clone());
        }
        if load == "loaded" && is_key_unit(&name, extra) {
            services.push(Service { name, active, sub });
        }
    }
    services.sort_by(|a, b| a.name.cmp(&b.name));
    failed.sort();
    Some((services, failed))
}
