//! Report payload, see docs/PROTOCOL.md. Every collector field is optional.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Report {
    pub v: u32,
    pub agent: String,
    /// Base URL the agent is currently sending to (shows "via relay" in the dashboard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Whether self-update is enabled (auto_update in agent.toml).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update: Option<bool>,
    pub ts: i64,
    pub interval: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Host>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sys: Option<Sys>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disks: Option<Vec<Disk>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net: Option<Vec<Net>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_units: Option<Vec<String>>,
    /// `None` = docker not installed; `Some(vec![])` = docker without containers.
    pub containers: Option<Vec<Container>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<Security>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packages: Option<Packages>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<Vec<AuditItem>>,
    /// Discovered websites (collect/sites.rs); only when the list changed or once a day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sites: Option<Vec<Site>>,
}

/// A domain this server's web server is configured for. server: nginx | apache | caddy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Site {
    pub domain: String,
    pub server: String,
    pub tls: bool,
    pub wildcard: bool,
}

/// Installed packages. `items` = [name, version, source package, source version].
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Packages {
    pub manager: String,
    pub os_id: String,
    pub os_version: String,
    pub os_codename: String,
    pub items: Vec<[String; 4]>,
}

/// One security baseline check. status: pass | warn | fail | na.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuditItem {
    pub id: String,
    pub status: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct Host {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub cpu_model: String,
    pub cpu_count: u32,
    pub boot_time: i64,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Sys {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iowait_pct: Option<f64>,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub procs: u32,
    pub uptime: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Disk {
    pub mount: String,
    pub fs: String,
    pub total: u64,
    pub used: u64,
    pub avail: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Net {
    pub iface: String,
    pub rx_bps: u64,
    pub tx_bps: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Service {
    pub name: String,
    pub active: String,
    pub sub: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Container {
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Security {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_failed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub f2b_banned: Option<BTreeMap<String, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_kills: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reboot_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updates_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updates_security: Option<u64>,
}
