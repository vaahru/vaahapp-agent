//! Network throughput per interface from /proc/net/dev (virtual container links skipped).

use crate::report::Net;
use crate::util::read;
use std::collections::HashMap;
use std::time::Instant;

const SKIP_PREFIX: &[&str] = &["lo", "veth", "docker", "br-", "virbr", "cni", "flannel", "vnet", "kube"];

pub fn parse_netdev(s: &str) -> HashMap<String, (u64, u64)> {
    let mut m = HashMap::new();
    for line in s.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else { continue };
        let name = name.trim();
        if SKIP_PREFIX.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let v: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if v.len() >= 9 {
            m.insert(name.to_string(), (v[0], v[8]));
        }
    }
    m
}

pub struct NetCollector {
    prev: HashMap<String, (u64, u64)>,
    at: Instant,
}

impl NetCollector {
    pub fn new() -> Self {
        NetCollector { prev: read("/proc/net/dev").map(|s| parse_netdev(&s)).unwrap_or_default(), at: Instant::now() }
    }

    pub fn collect(&mut self) -> Option<Vec<Net>> {
        let cur = parse_netdev(&read("/proc/net/dev")?);
        let secs = self.at.elapsed().as_secs_f64();
        let mut out: Vec<Net> = Vec::new();
        if secs >= 1.0 {
            for (iface, (rx, tx)) in &cur {
                if let Some((prx, ptx)) = self.prev.get(iface) {
                    // A counter reset (reboot of the interface) gives a negative delta: skip once.
                    if rx >= prx && tx >= ptx {
                        out.push(Net {
                            iface: iface.clone(),
                            rx_bps: ((rx - prx) as f64 / secs) as u64,
                            tx_bps: ((tx - ptx) as f64 / secs) as u64,
                        });
                    }
                }
            }
        }
        out.sort_by(|a, b| a.iface.cmp(&b.iface));
        self.prev = cur;
        self.at = Instant::now();
        Some(out)
    }
}
