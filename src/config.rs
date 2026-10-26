//! /etc/vaahapp/agent.toml

use serde::Deserialize;

pub const DEFAULT_PATH: &str = "/etc/vaahapp/agent.toml";
pub const DEFAULT_SPOOL: &str = "/var/lib/vaahapp/spool.jsonl";

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    /// Base URL of the server, e.g. https://app.vaah.ru
    pub url: String,
    /// Per-server token from registration.
    pub token: String,
    #[serde(default = "default_interval")]
    pub interval: u64,
    /// Extra systemd units to report besides the auto-detected ones.
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default = "default_spool")]
    pub spool: String,
    /// Extra server URLs to fail over to, after `url` and before the signed list.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Signed endpoint list (see endpoints.rs). "" disables it.
    #[serde(default = "default_endpoints_url")]
    pub endpoints_url: String,
    /// Opt-in: let vaahapp-agent-update.timer install newer signed releases (update.rs). Off by default.
    #[serde(default)]
    pub auto_update: bool,
    /// Website discovery (collect/sites.rs): domain names from nginx/Apache/Caddy configs. On by default.
    #[serde(default = "default_true")]
    pub discover_sites: bool,
}

fn default_true() -> bool {
    true
}

fn default_endpoints_url() -> String {
    crate::endpoints::DEFAULT_URL.to_string()
}

fn default_interval() -> u64 {
    60
}

fn default_spool() -> String {
    DEFAULT_SPOOL.to_string()
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        let mut c: Config = toml::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))?;
        c.url = c.url.trim_end_matches('/').to_string();
        c.urls = c.urls.iter().map(|u| u.trim_end_matches('/').to_string()).filter(|u| !u.is_empty()).collect();
        if c.token.trim().is_empty() {
            return Err(format!("{path}: token is empty"));
        }
        if c.interval < 10 {
            c.interval = 10;
        }
        Ok(c)
    }
}
