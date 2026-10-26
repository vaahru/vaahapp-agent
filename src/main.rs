//! vaahapp-agent: collects server metrics every interval and pushes them to the vaahapp server.
//!
//!   vaahapp-agent [--config /etc/vaahapp/agent.toml]   run (systemd)
//!   vaahapp-agent --once                               print one report as JSON, send nothing
//!   vaahapp-agent --test                               collect and send one report, report the result
//!   vaahapp-agent --audit                              print the security baseline audit
//!   vaahapp-agent --packages                           print the package inventory sent for CVE scans
//!   vaahapp-agent --sites                              print the websites found in nginx/Apache/Caddy configs
//!   vaahapp-agent --self-update                        install a newer signed release (only if auto_update = true)
//!   vaahapp-agent --version

mod collect;
mod config;
mod endpoints;
mod report;
mod resolve;
mod send;
mod update;
mod util;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_sites;

use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("vaahapp-agent {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let path = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| config::DEFAULT_PATH.to_string());

    if args.iter().any(|a| a == "--audit") {
        for i in collect::audit::run_all() {
            println!("{:<20} {:<5} {}", i.id, i.status, i.value);
        }
        return;
    }
    if args.iter().any(|a| a == "--sites") {
        // Exactly what website discovery would send (even if discover_sites = false in the config).
        for s in collect::sites::discover() {
            println!("{:<40} {:<7} {}{}", s.domain, s.server, if s.tls { "tls" } else { "-" }, if s.wildcard { " wildcard" } else { "" });
        }
        return;
    }
    if args.iter().any(|a| a == "--packages") {
        match collect::packages::inventory() {
            Some(p) => {
                use std::io::Write;
                // writeln! instead of println!: a closed pipe (`| head`) must end quietly, not panic.
                let mut out = std::io::stdout().lock();
                let _ = writeln!(out, "{} {} {} ({}), {} packages", p.manager, p.os_id, p.os_version, p.os_codename, p.items.len());
                for i in &p.items {
                    if writeln!(out, "{}\t{}\t{}\t{}", i[0], i[1], i[2], i[3]).is_err() {
                        break;
                    }
                }
            }
            None => println!("no dpkg or rpm found"),
        }
        return;
    }

    if args.iter().any(|a| a == "--once") {
        let cfg = config::Config::load(&path).unwrap_or(config::Config {
            url: String::new(),
            token: "-".into(),
            interval: 60,
            services: vec![],
            spool: config::DEFAULT_SPOOL.into(),
            urls: vec![],
            endpoints_url: String::new(),
            auto_update: false,
            discover_sites: true,
        });
        let mut c = collect::Collector::new(&cfg);
        // Wait so the rate-based fields (cpu, net) have a baseline.
        thread::sleep(Duration::from_secs(2));
        println!("{}", serde_json::to_string_pretty(&c.collect()).unwrap_or_default());
        return;
    }

    let cfg = match config::Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            util::log(&format!("config error: {e}"));
            std::process::exit(2);
        }
    };
    let mut urls = vec![cfg.url.clone()];
    urls.extend(cfg.urls.iter().filter(|u| **u != cfg.url).cloned());
    let mut sender = send::Sender::new(urls, &cfg.token, &cfg.spool);
    let mut endpoints_at = util::now();
    sender.set_signed(endpoints::load(&sender.agent, &cfg.endpoints_url, endpoints_at));
    let mut collector = collect::Collector::new(&cfg);

    if args.iter().any(|a| a == "--self-update") {
        if !cfg.auto_update {
            println!("auto_update is off in {path}: nothing to do");
            return;
        }
        match update::run(&sender.agent, &sender.ordered(), util::now()) {
            Ok(msg) => util::log(&format!("self-update: {msg}")),
            Err(e) => {
                util::log(&format!("self-update failed: {e}"));
                std::process::exit(1);
            }
        }
        return;
    }

    if args.iter().any(|a| a == "--test") {
        thread::sleep(Duration::from_secs(2));
        let mut r = collector.collect();
        r.endpoint = Some(sender.current_url().to_string());
        r.auto_update = Some(cfg.auto_update);
        match sender.post(&[r]) {
            send::Outcome::Ok => println!("ok: report accepted by {}", sender.current_url()),
            send::Outcome::Retry(e) | send::Outcome::Drop(e) => {
                println!("failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    util::log(&format!("vaahapp-agent {} started, every {}s → {}", env!("CARGO_PKG_VERSION"), cfg.interval, cfg.url));
    // First report after a short baseline, then a fixed cadence that does not drift with collect time.
    thread::sleep(Duration::from_secs(5));
    let every = Duration::from_secs(cfg.interval);
    let mut next = Instant::now();
    loop {
        if util::now() - endpoints_at >= endpoints::REFRESH_SECS {
            endpoints_at = util::now();
            sender.set_signed(endpoints::load(&sender.agent, &cfg.endpoints_url, endpoints_at));
        }
        let mut r = collector.collect();
        r.endpoint = Some(sender.current_url().to_string());
        r.auto_update = Some(cfg.auto_update);
        sender.deliver(r);
        next += every;
        let now = Instant::now();
        if next <= now {
            // Collect or send took longer than the interval (e.g. a slow resend): skip ahead.
            next = now + every;
        }
        thread::sleep(next - now);
    }
}
