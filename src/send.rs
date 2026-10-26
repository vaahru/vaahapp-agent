//! Delivery with endpoint failover and an on-disk spool: reports that could not be delivered anywhere
//! are appended as JSON lines and re-sent oldest first.

use crate::report::Report;
use crate::util::{log, now};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::Duration;

/// 24 h of one-minute reports.
const SPOOL_MAX: usize = 1440;
const BATCH: usize = 60;
/// While on a fallback endpoint, try the primary again this often.
const PRIMARY_RETRY: i64 = 3600;
/// Filtered routes (e.g. some networks to Cloudflare) drop single connections at random, so a failed
/// pass over all endpoints is repeated a few times within one report interval.
const PASSES: usize = 3;
const PASS_PAUSE: Duration = Duration::from_secs(3);
/// No new pass starts after this, so a send stays well inside a 60 s interval.
const PASS_BUDGET: Duration = Duration::from_secs(30);

pub enum Outcome {
    Ok,
    /// Network error, 5xx or 401: keep for later.
    Retry(String),
    /// 400: the server will never accept this batch.
    Drop(String),
}

pub struct Sender {
    pub agent: ureq::Agent,
    /// Configured URLs first (url, then urls), then the signed list. Base URLs, no trailing slash.
    configured: Vec<String>,
    candidates: Vec<String>,
    current: usize,
    primary_tried: i64,
    auth: String,
    spool: String,
}

/// Errors where another endpoint may succeed: no connection, timeouts, and gateway/5xx answers
/// (a relay that cannot reach the server). A 401/403/404 means the endpoint is the server itself.
fn try_next(o: &Outcome) -> bool {
    match o {
        Outcome::Retry(e) => !(e.starts_with("HTTP 401") || e.starts_with("HTTP 403") || e.starts_with("HTTP 404")),
        _ => false,
    }
}

impl Sender {
    pub fn new(urls: Vec<String>, token: &str, spool: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("vaahapp-agent/", env!("CARGO_PKG_VERSION")))
            .resolver(crate::resolve::V4First)
            .build();
        Sender {
            agent,
            candidates: urls.clone(),
            configured: urls,
            current: 0,
            primary_tried: now(),
            auth: format!("Bearer {}", token.trim()),
            spool: spool.to_string(),
        }
    }

    /// Adds the signed-list endpoints after the configured ones (deduplicated, order kept).
    pub fn set_signed(&mut self, list: Vec<String>) {
        let keep = self.candidates.get(self.current).cloned();
        let mut c = self.configured.clone();
        for u in list {
            if !c.contains(&u) {
                c.push(u);
            }
        }
        self.current = keep.and_then(|k| c.iter().position(|u| *u == k)).unwrap_or(0);
        self.candidates = c;
    }

    pub fn current_url(&self) -> &str {
        &self.candidates[self.current]
    }

    fn post_to(&self, base: &str, reports: &[Report]) -> Outcome {
        let body = serde_json::json!({ "reports": reports });
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        if gz.write_all(body.to_string().as_bytes()).is_err() {
            return Outcome::Drop("gzip failed".into());
        }
        let Ok(bytes) = gz.finish() else { return Outcome::Drop("gzip failed".into()) };
        match self
            .agent
            .post(&format!("{base}/api/agent/v1/report"))
            .set("Authorization", &self.auth)
            .set("Content-Type", "application/json")
            .set("Content-Encoding", "gzip")
            .send_bytes(&bytes)
        {
            Ok(_) => Outcome::Ok,
            Err(ureq::Error::Status(400, r)) => Outcome::Drop(format!("400 {}", r.into_string().unwrap_or_default())),
            Err(ureq::Error::Status(code, _)) => Outcome::Retry(format!("HTTP {code}")),
            Err(e) => Outcome::Retry(e.to_string()),
        }
    }

    /// Delivers with up to PASSES passes over the endpoints while failures are network-type.
    pub fn post(&mut self, reports: &[Report]) -> Outcome {
        let start = std::time::Instant::now();
        let mut o = self.pass(reports);
        for _ in 1..PASSES {
            if !try_next(&o) || start.elapsed() + PASS_PAUSE >= PASS_BUDGET {
                break;
            }
            std::thread::sleep(PASS_PAUSE);
            o = self.pass(reports);
        }
        o
    }

    /// Posts to the current endpoint; on a network-type failure walks the other candidates and sticks
    /// with the first that works. Periodically returns to the primary.
    fn pass(&mut self, reports: &[Report]) -> Outcome {
        if self.current != 0 && now() - self.primary_tried >= PRIMARY_RETRY {
            self.primary_tried = now();
            if let o @ Outcome::Ok = self.post_to(&self.candidates[0].clone(), reports) {
                log(&format!("back on primary endpoint {}", self.candidates[0]));
                self.current = 0;
                return o;
            }
        }
        let first = self.post_to(&self.candidates[self.current].clone(), reports);
        if !try_next(&first) {
            return first;
        }
        let n = self.candidates.len();
        for step in 1..n {
            let i = (self.current + step) % n;
            let o = self.post_to(&self.candidates[i].clone(), reports);
            if let Outcome::Ok = o {
                log(&format!("switched endpoint {} -> {}", self.candidates[self.current], self.candidates[i]));
                self.current = i;
                if i != 0 {
                    self.primary_tried = now();
                }
                return o;
            }
        }
        first
    }

    /// Sends the current report; on success also drains the spool.
    pub fn deliver(&mut self, report: Report) {
        match self.post(std::slice::from_ref(&report)) {
            Outcome::Ok => self.drain(),
            Outcome::Retry(e) => {
                log(&format!("send failed on all endpoints, spooled: {e}"));
                self.append(&report);
            }
            Outcome::Drop(e) => log(&format!("report rejected: {e}")),
        }
    }

    fn load(&self) -> Vec<Report> {
        fs::read_to_string(&self.spool)
            .map(|s| s.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
            .unwrap_or_default()
    }

    fn save(&self, reports: &[Report]) {
        if reports.is_empty() {
            let _ = fs::remove_file(&self.spool);
            return;
        }
        let tmp = format!("{}.tmp", self.spool);
        let data: String = reports.iter().filter_map(|r| serde_json::to_string(r).ok()).map(|l| l + "\n").collect();
        if fs::write(&tmp, data).is_ok() {
            let _ = fs::rename(&tmp, &self.spool);
        }
    }

    fn append(&self, report: &Report) {
        let mut all = self.load();
        all.push(report.clone());
        if all.len() > SPOOL_MAX {
            let cut = all.len() - SPOOL_MAX;
            all.drain(..cut);
            self.save(&all);
            return;
        }
        if let Some(dir) = std::path::Path::new(&self.spool).parent() {
            let _ = fs::create_dir_all(dir);
        }
        if let (Ok(mut f), Ok(line)) = (OpenOptions::new().create(true).append(true).open(&self.spool), serde_json::to_string(report)) {
            let _ = writeln!(f, "{line}");
        }
    }

    fn drain(&mut self) {
        let mut pending = self.load();
        if pending.is_empty() {
            return;
        }
        log(&format!("sending {} spooled reports", pending.len()));
        while !pending.is_empty() {
            let n = pending.len().min(BATCH);
            match self.post(&pending[..n]) {
                Outcome::Ok | Outcome::Drop(_) => {
                    pending.drain(..n);
                }
                Outcome::Retry(e) => {
                    log(&format!("spool resend failed: {e}"));
                    break;
                }
            }
        }
        self.save(&pending);
    }
}
