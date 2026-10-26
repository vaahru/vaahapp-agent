//! Website discovery: which domains this server's web servers are configured for.
//!
//! Reads the configuration files directly (nothing is executed; `nginx -T` / `apachectl -S` would
//! need write access the hardened service does not have): nginx.conf and Apache's main config with
//! their includes, the host's /etc/caddy/Caddyfile and Caddyfiles mounted into running Caddy
//! containers (caddy.rs). Sends only the domain names, which web server has them, and whether TLS is
//! configured. No paths, no other configuration. Turn off with `discover_sites = false`.

use super::caddy;
use crate::report::Site;
use crate::util::now;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    for main in ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf"] {
        if Path::new(main).exists() {
            let dir = Path::new(main).parent().unwrap_or(Path::new("/"));
            let text = read_with_includes(Path::new(main), dir, false, 0);
            all.extend(parse_nginx(&text));
            break;
        }
    }
    for (main, root) in [("/etc/apache2/apache2.conf", "/etc/apache2"), ("/etc/httpd/conf/httpd.conf", "/etc/httpd")] {
        if Path::new(main).exists() {
            let text = read_with_includes(Path::new(main), Path::new(root), true, 0);
            all.extend(parse_apache_conf(&text));
            break;
        }
    }
    all.extend(caddy::discover());
    merge(all)
}

/// A file followed by the files its include directives name (nginx `include x;`, Apache `Include` /
/// `IncludeOptional`), each appended after the file. Relative paths resolve against `root`; a `*` in
/// the last path component is expanded. Depth-limited.
pub fn read_with_includes(file: &Path, root: &Path, apache: bool, depth: usize) -> String {
    let Ok(text) = std::fs::read_to_string(file) else { return String::new() };
    let mut out = text.clone();
    if depth >= 6 {
        return out;
    }
    for line in text.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        let mut w = l.split_whitespace();
        let (Some(k), Some(arg)) = (w.next(), w.next()) else { continue };
        let is_inc = if apache { k.eq_ignore_ascii_case("include") || k.eq_ignore_ascii_case("includeoptional") } else { k == "include" };
        if !is_inc {
            continue;
        }
        let arg = arg.trim_end_matches(';').trim_matches('"');
        let p = if arg.starts_with('/') { PathBuf::from(arg) } else { root.join(arg) };
        for f in glob(&p) {
            if f.is_file() {
                out.push('\n');
                out.push_str(&read_with_includes(&f, root, apache, depth + 1));
            } else if apache && f.is_dir() {
                // Apache: "Include dir" includes every file in it.
                for g in glob(&f.join("*")) {
                    out.push('\n');
                    out.push_str(&read_with_includes(&g, root, apache, depth + 1));
                }
            }
        }
    }
    out
}

/// Files matching a path whose last component may contain one `*` (sorted).
pub fn glob(p: &Path) -> Vec<PathBuf> {
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
    let Some((pre, suf)) = name.split_once('*') else { return if p.exists() { vec![p.to_path_buf()] } else { vec![] } };
    let parent = p.parent().unwrap_or(Path::new("/"));
    let mut files: Vec<PathBuf> = std::fs::read_dir(parent)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|f| f.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(pre) && n.ends_with(suf) && !n.starts_with('.')))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
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

/// Apache config text (main file + includes): `ServerName` / `ServerAlias` inside `<VirtualHost …>`;
/// TLS when the vhost listens on :443 or has `SSLEngine on`.
pub fn parse_apache_conf(text: &str) -> Vec<Site> {
    let mut sites = vec![];
    // Open vhost: (names, tls)
    let mut cur: Option<(Vec<String>, bool)> = None;
    for line in text.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        let low = l.to_ascii_lowercase();
        if low.starts_with("<virtualhost") {
            let tls = low.trim_end_matches('>').split_whitespace().skip(1).any(|a| a.ends_with(":443"));
            cur = Some((vec![], tls));
        } else if low.starts_with("</virtualhost") {
            if let Some((names, tls)) = cur.take() {
                sites.extend(names.iter().filter_map(|n| site(n, "apache", tls)));
            }
        } else if let Some((names, tls)) = cur.as_mut() {
            let mut w = l.split_whitespace();
            match w.next().map(|k| k.to_ascii_lowercase()).as_deref() {
                Some("servername") => names.extend(w.next().map(|n| n.split(':').next().unwrap_or(n).to_string())),
                Some("serveralias") => names.extend(w.map(str::to_string)),
                Some("sslengine") if low.ends_with(" on") => *tls = true,
                _ => {}
            }
        }
    }
    sites
}
