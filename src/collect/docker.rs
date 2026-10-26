//! Docker containers via the docker CLI (works with every engine version we run).

use crate::report::Container;
use crate::util::{run, which};
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
struct PsLine {
    #[serde(rename = "Names", default)]
    names: String,
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "State", default)]
    state: String,
    #[serde(rename = "Status", default)]
    status: String,
}

/// One JSON object per line from `docker ps -a --format '{{json .}}'`. Old engines have no State
/// field, so it is derived from Status ("Up 3 days", "Exited (0) ...", "Restarting ...").
pub fn parse_ps(s: &str) -> Vec<Container> {
    let mut out: Vec<Container> = s
        .lines()
        .filter_map(|l| serde_json::from_str::<PsLine>(l.trim()).ok())
        .map(|p| {
            let state = if !p.state.is_empty() {
                p.state.to_lowercase()
            } else if p.status.starts_with("Up") {
                "running".into()
            } else if p.status.starts_with("Restarting") {
                "restarting".into()
            } else if p.status.starts_with("Created") {
                "created".into()
            } else {
                "exited".into()
            };
            Container { name: p.names, image: p.image, state, status: p.status }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// `None` when docker is not installed or the daemon does not answer.
pub fn collect() -> Option<Vec<Container>> {
    let docker = which("docker")?;
    let (code, out) = run(&docker, &["ps", "-a", "--no-trunc", "--format", "{{json .}}"], Duration::from_secs(10))?;
    if code != 0 {
        return None;
    }
    Some(parse_ps(&out))
}
