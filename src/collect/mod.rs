//! Collectors. Everything that needs root (journal, fail2ban, package managers, docker socket,
//! sshd -T, /etc/shadow) lives here, so a future non-root mode only has to touch this module.

pub mod audit;
pub mod disk;
pub mod docker;
pub mod net;
pub mod packages;
pub mod security;
pub mod sys;
pub mod systemd;

use crate::config::Config;
use crate::report::{Host, Report};
use crate::util::now;

const HOST_EVERY: i64 = 86400;

pub struct Collector {
    sys: sys::SysCollector,
    net: net::NetCollector,
    sec: security::SecurityCollector,
    pkgs: packages::PackagesCollector,
    audit: audit::AuditCollector,
    extra_units: Vec<String>,
    interval: u64,
    host_at: i64,
    last_host: Option<Host>,
}

impl Collector {
    pub fn new(cfg: &Config) -> Self {
        Collector {
            sys: sys::SysCollector::new(),
            net: net::NetCollector::new(),
            sec: security::SecurityCollector::new(),
            pkgs: packages::PackagesCollector::new(),
            audit: audit::AuditCollector::new(),
            extra_units: cfg.services.clone(),
            interval: cfg.interval,
            host_at: 0,
            last_host: None,
        }
    }

    pub fn collect(&mut self) -> Report {
        let ts = now();
        // Host info on start, once a day, and whenever it changes (kernel upgrade + reboot).
        let host = sys::host();
        let changed = self
            .last_host
            .as_ref()
            .map(|h| h.kernel != host.kernel || h.boot_time.abs_diff(host.boot_time) > 120)
            .unwrap_or(true);
        let host = if changed || ts - self.host_at >= HOST_EVERY {
            self.host_at = ts;
            self.last_host = Some(host.clone());
            Some(host)
        } else {
            None
        };
        let units = systemd::collect(&self.extra_units);
        Report {
            v: 1,
            agent: env!("CARGO_PKG_VERSION").to_string(),
            ts,
            interval: self.interval,
            host,
            sys: self.sys.collect(),
            disks: disk::collect(),
            net: self.net.collect(),
            services: units.as_ref().map(|u| u.0.clone()),
            failed_units: units.map(|u| u.1),
            containers: docker::collect(),
            security: Some(self.sec.collect()),
            packages: self.pkgs.collect(),
            audit: self.audit.collect(),
        }
    }
}
