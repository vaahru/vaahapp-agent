//! Caddy part of website discovery (sites.rs): site addresses of the host's /etc/caddy/Caddyfile and
//! of Caddyfiles bind-mounted into running Caddy containers, following `import` globs.

use super::sites::site;
use crate::report::Site;
use crate::util::{run, which};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn discover() -> Vec<Site> {
    let mut files: Vec<(PathBuf, Vec<(String, String)>)> = vec![];
    if Path::new("/etc/caddy/Caddyfile").exists() {
        files.push((PathBuf::from("/etc/caddy/Caddyfile"), vec![]));
    }
    files.extend(container_caddyfiles());
    files.iter().flat_map(|(f, mounts)| parse_file(f, mounts, 0)).collect()
}

/// `mounts` maps container paths to host paths when the file belongs to a container.
fn parse_file(file: &Path, mounts: &[(String, String)], depth: usize) -> Vec<Site> {
    let Ok(text) = std::fs::read_to_string(file) else { return vec![] };
    let dir = file.parent().unwrap_or(Path::new("/"));
    let (mut sites, imports) = parse(&text);
    if depth < 3 {
        for imp in imports {
            for f in expand_import(&imp, dir, mounts) {
                sites.extend(parse_file(&f, mounts, depth + 1));
            }
        }
    }
    sites
}

/// Sites of one Caddyfile text (top-level site blocks) and its top-level `import` arguments.
/// Snippets `(name) {`, the global options block `{` and placeholders are skipped.
pub fn parse(text: &str) -> (Vec<Site>, Vec<String>) {
    let mut sites = vec![];
    let mut imports = vec![];
    let mut depth = 0i32;
    for raw in text.lines() {
        let line = match raw.find('#') {
            Some(i) if i == 0 || raw.as_bytes()[i - 1].is_ascii_whitespace() => &raw[..i],
            _ => raw,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        if depth == 0 {
            if let Some(arg) = line.strip_prefix("import ") {
                imports.push(arg.split_whitespace().next().unwrap_or("").to_string());
            } else if line.ends_with('{') && !line.starts_with('(') && line != "{" {
                for a in line.trim_end_matches('{').split([',', ' ']).filter(|a| !a.is_empty()) {
                    let (tls, host) = match (a.strip_prefix("http://"), a.strip_prefix("https://")) {
                        (Some(h), _) => (false, h),
                        (_, Some(h)) => (true, h),
                        _ => (true, a),
                    };
                    let host = host.split('/').next().unwrap_or("");
                    let (host, tls) = match host.rsplit_once(':') {
                        Some((h, "80")) => (h, false),
                        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, tls),
                        _ => (host, tls),
                    };
                    sites.extend(site(host, "caddy", tls));
                }
            }
        }
        depth = (depth + line.matches('{').count() as i32 - line.matches('}').count() as i32).max(0);
    }
    (sites, imports)
}

/// Files for an import: relative to the Caddyfile's dir; absolute container paths mapped to the host;
/// a `*` in the file name expanded.
pub fn expand_import(arg: &str, dir: &Path, mounts: &[(String, String)]) -> Vec<PathBuf> {
    let p = if mounts.is_empty() {
        if arg.starts_with('/') { PathBuf::from(arg) } else { dir.join(arg) }
    } else {
        // Container: relative imports are relative to /etc/caddy inside it; map through the longest mount.
        let cpath = if arg.starts_with('/') { arg.to_string() } else { format!("/etc/caddy/{arg}") };
        let best = mounts
            .iter()
            .filter(|(c, _)| cpath == *c || cpath.starts_with(&format!("{}/", c.trim_end_matches('/'))))
            .max_by_key(|(c, _)| c.len());
        match best {
            Some((c, h)) => PathBuf::from(format!("{h}{}", &cpath[c.len()..])),
            None => return vec![],
        }
    };
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
    let Some((pre, suf)) = name.split_once('*') else { return vec![p] };
    let parent = p.parent().unwrap_or(Path::new("/"));
    let mut files: Vec<PathBuf> = std::fs::read_dir(parent)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|f| f.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(pre) && n.ends_with(suf)))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

/// Running containers whose image contains "caddy": their Caddyfile on the host and their mounts.
fn container_caddyfiles() -> Vec<(PathBuf, Vec<(String, String)>)> {
    let Some(docker) = which("docker") else { return vec![] };
    let Some((0, ps)) = run(&docker, &["ps", "--format", "{{.ID}} {{.Image}}"], Duration::from_secs(10)) else { return vec![] };
    let mut out = vec![];
    for line in ps.lines() {
        let mut w = line.split_whitespace();
        let (Some(id), Some(image)) = (w.next(), w.next()) else { continue };
        if !image.contains("caddy") {
            continue;
        }
        let Some((0, js)) = run(&docker, &["inspect", "--format", "{{json .Mounts}}", id], Duration::from_secs(10)) else { continue };
        let mounts: Vec<(String, String)> = serde_json::from_str::<Vec<serde_json::Value>>(js.trim())
            .unwrap_or_default()
            .iter()
            .filter_map(|m| Some((m["Destination"].as_str()?.to_string(), m["Source"].as_str()?.to_string())))
            .collect();
        let host = mounts.iter().find_map(|(c, h)| match c.as_str() {
            "/etc/caddy/Caddyfile" => Some(PathBuf::from(h)),
            "/etc/caddy" => Some(Path::new(h).join("Caddyfile")),
            _ => None,
        });
        if let Some(f) = host {
            out.push((f, mounts));
        }
    }
    out
}
