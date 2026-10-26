//! Opt-in self-update (`auto_update = true` in agent.toml), run by the vaahapp-agent-update.timer.
//!
//! 1. Fetch `<endpoint>/dl/agent/release.json`: a manifest signed with the same ed25519 key as the
//!    endpoint list (public key compiled into this binary). Unsigned, tampered, expired or older
//!    manifests are refused: an update is never forced by whoever controls the server or a relay.
//! 2. Download the binary for this architecture and check its sha256 against the signed manifest.
//! 3. Check the new binary runs (`--version`), swap it in (old one kept as `.old`), restart the
//!    service and send a test report. If that fails, put the old binary back and restart again.

use crate::endpoints::{verify_signed, PUBLIC_KEY};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::process::Command;
use std::time::Duration;

pub const BIN: &str = "/usr/local/bin/vaahapp-agent";
const MAX_BINARY: u64 = 32 << 20;

#[derive(Deserialize, Debug)]
pub struct Release {
    pub v: u32,
    pub kind: String,
    pub version: String,
    pub expires: i64,
    /// arch ("x86_64", "aarch64") -> sha256 hex of `vaahapp-agent-<arch>`
    pub files: HashMap<String, String>,
}

/// Verifies a signed release manifest.
pub fn verify_release(raw: &str, public_key_b64: &str, now: i64) -> Result<Release, String> {
    let payload = verify_signed(raw, public_key_b64)?;
    let r: Release = serde_json::from_slice(&payload).map_err(|e| format!("bad manifest: {e}"))?;
    if r.v != 1 || r.kind != "release" {
        return Err("not a release manifest".into());
    }
    if r.expires < now {
        return Err("manifest expired".into());
    }
    if parse(&r.version).is_none() {
        return Err(format!("bad version {:?}", r.version));
    }
    Ok(r)
}

fn parse(v: &str) -> Option<Vec<u64>> {
    let p: Option<Vec<u64>> = v.trim().split('.').map(|x| x.parse().ok()).collect();
    p.filter(|p| !p.is_empty() && p.len() <= 4)
}

/// True when `candidate` is a strictly newer version than `current` ("0.3.0" > "0.2.2").
pub fn newer(current: &str, candidate: &str) -> bool {
    match (parse(current), parse(candidate)) {
        (Some(a), Some(b)) => b > a,
        _ => false,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn arch() -> &'static str {
    std::env::consts::ARCH
}

/// One update attempt over the given endpoints (in failover order). Returns a status line.
pub fn run(agent: &ureq::Agent, endpoints: &[String], now: i64) -> Result<String, String> {
    let mut last = String::from("no endpoints");
    let mut found = None;
    for base in endpoints {
        let raw = agent
            .get(&format!("{base}/dl/agent/release.json"))
            .timeout(Duration::from_secs(30))
            .call()
            .map_err(|e| e.to_string())
            .and_then(|r| r.into_string().map_err(|e| e.to_string()));
        match raw.and_then(|raw| verify_release(&raw, PUBLIC_KEY, now)) {
            Ok(r) => {
                found = Some((base.clone(), r));
                break;
            }
            Err(e) => last = format!("{base}: {e}"),
        }
    }
    let (base, rel) = found.ok_or(last)?;
    let current = env!("CARGO_PKG_VERSION");
    if !newer(current, &rel.version) {
        return Ok(format!("up to date ({current})"));
    }
    let want = rel.files.get(arch()).ok_or_else(|| format!("no build for {} in {}", arch(), rel.version))?;

    let mut bin = Vec::new();
    agent
        .get(&format!("{base}/dl/agent/vaahapp-agent-{}", arch()))
        .timeout(Duration::from_secs(300))
        .call()
        .map_err(|e| format!("download: {e}"))?
        .into_reader()
        .take(MAX_BINARY)
        .read_to_end(&mut bin)
        .map_err(|e| format!("download: {e}"))?;
    if sha256_hex(&bin) != want.to_lowercase() {
        return Err("downloaded binary does not match the signed checksum".into());
    }

    let new = format!("{BIN}.new");
    let old = format!("{BIN}.old");
    write_exec(&new, &bin)?;
    let out = Command::new(&new).arg("--version").output().map_err(|e| format!("run new binary: {e}"))?;
    if !String::from_utf8_lossy(&out.stdout).contains(&rel.version) {
        let _ = std::fs::remove_file(&new);
        return Err("new binary reports a different version".into());
    }
    std::fs::copy(BIN, &old).map_err(|e| format!("backup: {e}"))?;
    std::fs::rename(&new, BIN).map_err(|e| format!("swap: {e}"))?;
    restart();
    std::thread::sleep(Duration::from_secs(5));
    let ok = Command::new(BIN).arg("--test").status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        let _ = std::fs::rename(&old, BIN);
        restart();
        return Err(format!("{} failed its test report: rolled back to {current}", rel.version));
    }
    Ok(format!("updated {current} -> {}", rel.version))
}

fn write_exec(path: &str, data: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, data).map_err(|e| format!("write {path}: {e}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(|e| format!("chmod {path}: {e}"))
}

fn restart() {
    let _ = Command::new("systemctl").args(["restart", "vaahapp-agent"]).status();
}
