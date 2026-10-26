//! CPU, load, memory, swap, process count, uptime and host identity from /proc.

use crate::report::{Host, Sys};
use crate::util::{now, read};

/// Aggregate CPU jiffies from the first line of /proc/stat.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CpuTimes {
    pub total: u64,
    pub idle: u64,
    pub iowait: u64,
}

pub fn parse_cpu(stat: &str) -> Option<CpuTimes> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    if v.len() < 4 {
        return None;
    }
    // user nice system idle iowait irq softirq steal (guest is already inside user)
    let total: u64 = v.iter().take(8).sum();
    let iowait = v.get(4).copied().unwrap_or(0);
    Some(CpuTimes { total, idle: v[3] + iowait, iowait })
}

/// (busy %, iowait %) between two samples.
pub fn cpu_pct(prev: CpuTimes, cur: CpuTimes) -> Option<(f64, f64)> {
    let dt = cur.total.checked_sub(prev.total)?;
    if dt == 0 {
        return None;
    }
    let didle = cur.idle.saturating_sub(prev.idle);
    let dio = cur.iowait.saturating_sub(prev.iowait);
    let busy = 100.0 * (dt.saturating_sub(didle)) as f64 / dt as f64;
    Some((round1(busy), round1(100.0 * dio as f64 / dt as f64)))
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// MemTotal / MemAvailable / SwapTotal / SwapFree in bytes. Older kernels without MemAvailable
/// fall back to MemFree + Buffers + Cached.
pub fn parse_meminfo(s: &str) -> Option<(u64, u64, u64, u64)> {
    let get = |key: &str| -> Option<u64> {
        s.lines()
            .find(|l| l.starts_with(key) && l[key.len()..].starts_with(':'))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|x| x.parse::<u64>().ok())
            .map(|kb| kb * 1024)
    };
    let total = get("MemTotal")?;
    let avail = match get("MemAvailable") {
        Some(a) => a,
        None => get("MemFree")? + get("Buffers").unwrap_or(0) + get("Cached").unwrap_or(0),
    };
    let swap_total = get("SwapTotal").unwrap_or(0);
    let swap_free = get("SwapFree").unwrap_or(0);
    Some((total, total.saturating_sub(avail), swap_total, swap_total.saturating_sub(swap_free)))
}

pub fn parse_loadavg(s: &str) -> Option<(f64, f64, f64)> {
    let mut it = s.split_whitespace().map(|x| x.parse::<f64>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

fn proc_count() -> u32 {
    std::fs::read_dir("/proc")
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
                .count() as u32
        })
        .unwrap_or(0)
}

pub fn uptime() -> u64 {
    read("/proc/uptime")
        .and_then(|s| s.split_whitespace().next().and_then(|x| x.parse::<f64>().ok()))
        .map(|f| f as u64)
        .unwrap_or(0)
}

pub struct SysCollector {
    prev: Option<CpuTimes>,
}

impl SysCollector {
    pub fn new() -> Self {
        let prev = read("/proc/stat").and_then(|s| parse_cpu(&s));
        SysCollector { prev }
    }

    pub fn collect(&mut self) -> Option<Sys> {
        let (mem_total, mem_used, swap_total, swap_used) = parse_meminfo(&read("/proc/meminfo")?)?;
        let (load1, load5, load15) = read("/proc/loadavg").and_then(|s| parse_loadavg(&s)).unwrap_or_default();
        let cur = read("/proc/stat").and_then(|s| parse_cpu(&s));
        let pct = match (self.prev, cur) {
            (Some(p), Some(c)) => cpu_pct(p, c),
            _ => None,
        };
        if cur.is_some() {
            self.prev = cur;
        }
        Some(Sys {
            cpu_pct: pct.map(|p| p.0),
            iowait_pct: pct.map(|p| p.1),
            load1,
            load5,
            load15,
            mem_total,
            mem_used,
            swap_total,
            swap_used,
            procs: proc_count(),
            uptime: uptime(),
        })
    }
}

pub fn parse_os_release(s: &str) -> Option<String> {
    s.lines()
        .find(|l| l.starts_with("PRETTY_NAME="))
        .map(|l| l["PRETTY_NAME=".len()..].trim().trim_matches('"').to_string())
}

pub fn parse_cpuinfo(s: &str) -> (String, u32) {
    let count = s.lines().filter(|l| l.starts_with("processor")).count() as u32;
    let model = s
        .lines()
        .find(|l| l.starts_with("model name") || l.starts_with("Hardware") || l.starts_with("Model"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    (model, count)
}

pub fn host() -> Host {
    let trim = |p: &str| read(p).map(|s| s.trim().to_string()).unwrap_or_default();
    let (cpu_model, mut cpu_count) = read("/proc/cpuinfo").map(|s| parse_cpuinfo(&s)).unwrap_or_default();
    if cpu_count == 0 {
        cpu_count = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);
    }
    Host {
        hostname: trim("/proc/sys/kernel/hostname"),
        os: read("/etc/os-release").and_then(|s| parse_os_release(&s)).unwrap_or_else(|| "Linux".into()),
        kernel: trim("/proc/sys/kernel/osrelease"),
        arch: std::env::consts::ARCH.to_string(),
        cpu_model,
        cpu_count,
        boot_time: now() - uptime() as i64,
    }
}
