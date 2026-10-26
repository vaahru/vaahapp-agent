//! Signed endpoint list: lets the server address change without touching installed agents.
//!
//! The list is a JSON file `{"payload": base64(json), "sig": base64(ed25519)}` published in this
//! repository. The agent accepts it only if the signature verifies with the public key compiled in
//! below, the list has not expired, and every endpoint is https. A tampered or stale file is ignored,
//! and the configured `url` is always tried first, so the list can add routes but never remove the
//! one the admin configured.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use std::time::Duration;

/// Public half of the vaahapp endpoint-signing key (private half never leaves the vaahapp owner).
pub const PUBLIC_KEY: &str = "hFa43Ki+zg8yJcLA1DJaN6X607CKQ2+uM/we4Lwgljs=";
/// Where the signed list is published (override with `endpoints_url` in agent.toml; "" = off).
pub const DEFAULT_URL: &str =
    "https://raw.githubusercontent.com/vaahru/vaahapp-agent/main/endpoints.json";
pub const CACHE: &str = "/var/lib/vaahapp/endpoints.json";
pub const REFRESH_SECS: i64 = 6 * 3600;

#[derive(Deserialize)]
struct Signed {
    payload: String,
    sig: String,
}

#[derive(Deserialize)]
struct Payload {
    v: u32,
    expires: i64,
    endpoints: Vec<String>,
}

/// Verifies a signed list and returns its endpoints (trailing slashes trimmed).
pub fn verify(raw: &str, public_key_b64: &str, now: i64) -> Result<Vec<String>, String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let s: Signed = serde_json::from_str(raw).map_err(|e| format!("bad json: {e}"))?;
    let key_bytes: [u8; 32] = b64
        .decode(public_key_b64)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or("bad public key")?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| "bad public key")?;
    let payload = b64.decode(&s.payload).map_err(|_| "bad payload encoding")?;
    let sig_bytes: [u8; 64] = b64.decode(&s.sig).ok().and_then(|x| x.try_into().ok()).ok_or("bad signature encoding")?;
    key.verify(&payload, &Signature::from_bytes(&sig_bytes)).map_err(|_| "signature does not verify")?;
    let p: Payload = serde_json::from_slice(&payload).map_err(|e| format!("bad payload: {e}"))?;
    if p.v != 1 {
        return Err(format!("unsupported version {}", p.v));
    }
    if p.expires < now {
        return Err("list expired".into());
    }
    let list: Vec<String> = p
        .endpoints
        .into_iter()
        .filter(|u| u.starts_with("https://") && !u.contains(char::is_whitespace))
        .map(|u| u.trim_end_matches('/').to_string())
        .collect();
    if list.is_empty() {
        return Err("no usable endpoints".into());
    }
    Ok(list)
}

/// Fetches the list (falls back to the cached copy) and returns verified endpoints, or empty.
pub fn load(agent: &ureq::Agent, url: &str, now: i64) -> Vec<String> {
    if !url.is_empty() {
        let fetched = agent
            .get(url)
            .timeout(Duration::from_secs(20))
            .call()
            .ok()
            .and_then(|r| r.into_string().ok());
        if let Some(raw) = fetched {
            match verify(&raw, PUBLIC_KEY, now) {
                Ok(list) => {
                    let _ = std::fs::write(CACHE, &raw);
                    return list;
                }
                Err(e) => crate::util::log(&format!("endpoint list rejected: {e}")),
            }
        }
    }
    std::fs::read_to_string(CACHE)
        .ok()
        .and_then(|raw| verify(&raw, PUBLIC_KEY, now).ok())
        .unwrap_or_default()
}
