//! Website discovery: which domains this server's web servers are configured for.
//!
//! Reads (read-only): `nginx -T`, `apachectl -S`, the host's /etc/caddy/Caddyfile and Caddyfiles
//! mounted into running Caddy containers (caddy.rs). Sends only the domain names, which web server
//! has them, and whether TLS is configured. No paths, no other configuration.
//! Turn off with `discover_sites = false` in agent.toml.

use super::caddy;
use crate::report::Site;
use crate::util::{now, run, which};
use std::collections::BTreeMap;
use std::time::Duration;

/// Re-read the configs this often; send when the list changed, and at least once a day.
const CHECK_EVERY: i64 = 1800;
const SEND_EVERY: i64 = 86400;
const MAX_SITES: usize = 500;

pub struct SitesCollector {
    enabled: bool,
    checked_at: i64,
    sent_at: i64,
    last: Vec<Site>,
}

impl SitesCollector {
    pub fn new(enabled: bool) -> Self {
        SitesCollector { enabled, checked_at: 0, sent_at: 0, last: vec![] }
    }

    pub fn collect(&mut self) -> Option<Vec<Site>> {
        let ts = now();
        if !self.enabled || (self.checked_at != 0 && ts - self.checked_at < CHECK_EVERY) {
            return None;
        }
        self.checked_at = ts;
        let found = discover();
        if found == self.last && ts - self.sent_at < SEND_EVERY {
            return None;
        }
        self.sent_at = ts;
        self.last = found.clone();
        Some(found)
    }
}

/// All web servers on this host, merged (one row per domain; TLS if any server has it).
pub fn discover() -> Vec<Site> {
    let mut all: Vec<Site> = vec![];
    if let Some(bin) = which("nginx") {
        if let Some((_, out)) = run(&bin, &["-T"], Duration::from_secs(20)) {
            all.extend(parse_nginx(&out));
        }
    }
    for name in ["apache2ctl", "apachectl", "httpd"] {
        if let Some(bin) = which(name) {
            if let Some((_, out)) = run(&bin, &["-S"], Duration::from_secs(20)) {
                all.extend(parse_apache(&out));
                break;
            }
        }
    }
    all.extend(caddy::discover());
    merge(all)
}

pub fn merge(all: Vec<Site>) -> Vec<Site> {
    let mut by: BTreeMap<String, Site> = BTreeMap::new();
    for s in all {
        // TLS if any block has it; a wildcard only if the plain name never appears on its own.
        by.entry(s.domain.clone())
            .and_modify(|e| {
                e.tls |= s.tls;
                e.wildcard &= s.wildcard;
            })
            .or_insert(s);
    }
    by.into_values().take(MAX_SITES).collect()
}

/// A usable domain: lower-cased, no regex / placeholder / IP / localhost / bare "_". Wildcards are
/// reported without the "*." and flagged.
fn clean(name: &str) -> Option<(String, bool)> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() || n == "_" || n.starts_with('~') || n.contains(['{', '}', '$', '/', '"', '\'']) {
        return None;
    }
    let (n, wildcard) = match n.strip_prefix("*.").or_else(|| n.strip_prefix('.')) {
        Some(rest) => (rest.to_string(), true),
        None => (n, false),
    };
    if !n.contains('.') || n == "localhost" || n.ends_with(".localhost") || n.ends_with(".local") || n.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') {
        return None;
    }
    Some((n, wildcard))
}

pub fn site(name: &str, server: &str, tls: bool) -> Option<Site> {
    clean(name).map(|(domain, wildcard)| Site { domain, server: server.to_string(), tls, wildcard })
}

/// `nginx -T`: server blocks at the top of a file or directly in `http {}` (not `stream {}`).
pub fn parse_nginx(conf: &str) -> Vec<Site> {
    // Tokens: words, "{", "}", ";". Comments (# … end of line) are dropped.
    let mut tokens: Vec<String> = vec![];
    for line in conf.lines() {
        let line = line.find('#').map_or(line, |i| &line[..i]);
        let mut word = String::new();
        for c in line.chars() {
            if c == '{' || c == '}' || c == ';' || c.is_whitespace() {
                if !word.is_empty() {
                    tokens.push(std::mem::take(&mut word));
                }
                if !c.is_whitespace() {
                    tokens.push(c.to_string());
                }
            } else {
                word.push(c);
            }
        }
        if !word.is_empty() {
            tokens.push(word);
        }
    }
    let mut out = vec![];
    let mut stack: Vec<String> = vec![];
    let mut stmt: Vec<String> = vec![];
    // Open server block: (stack depth inside it, names, tls)
    let mut cur: Option<(usize, Vec<String>, bool)> = None;
    for t in tokens {
        match t.as_str() {
            "{" => {
                let name = stmt.first().cloned().unwrap_or_default();
                let parent = stack.last().map(String::as_str).unwrap_or("");
                if name == "server" && (parent.is_empty() || parent == "http") && cur.is_none() {
                    cur = Some((stack.len() + 1, vec![], false));
                }
                stack.push(name);
                stmt.clear();
            }
            "}" => {
                if cur.as_ref().is_some_and(|(d, _, _)| *d == stack.len()) {
                    let (_, names, tls) = cur.take().unwrap();
                    out.extend(names.iter().filter_map(|n| site(n, "nginx", tls)));
                }
                stack.pop();
                stmt.clear();
            }
            ";" => {
                if let Some((depth, names, tls)) = cur.as_mut() {
                    if *depth == stack.len() {
                        match stmt.first().map(String::as_str) {
                            Some("server_name") => names.extend(stmt[1..].iter().cloned()),
                            Some("listen") => {
                                if stmt[1..].iter().any(|x| x == "ssl" || x == "quic" || x == "443" || x.ends_with(":443")) {
                                    *tls = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                stmt.clear();
            }
            _ => stmt.push(t),
        }
    }
    out
}

/// `apachectl -S`: "port 443 namevhost example.com (…)", "*:443 example.com (…)", "alias www.example.com".
pub fn parse_apache(out: &str) -> Vec<Site> {
    let mut sites = vec![];
    let mut port = 0u16;
    for line in out.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = w.iter().position(|x| *x == "namevhost") {
            port = i.checked_sub(1).and_then(|j| w[j].parse().ok()).unwrap_or(0);
            if let Some(name) = w.get(i + 1) {
                sites.extend(site(name, "apache", port == 443));
            }
        } else if w.first() == Some(&"alias") {
            if let Some(name) = w.get(1) {
                sites.extend(site(name, "apache", port == 443));
            }
        } else if w.len() >= 3 && w[0].contains(':') && w[2].starts_with('(') {
            // "*:443   example.com (/etc/apache2/sites-enabled/x.conf:1)": the only vhost on that address.
            port = w[0].rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0);
            sites.extend(site(w[1], "apache", port == 443));
        }
    }
    sites
}
