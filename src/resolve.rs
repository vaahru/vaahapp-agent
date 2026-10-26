//! DNS for the HTTP client: IPv4 addresses first, then IPv6, each looked up on its own.
//!
//! The static (musl) build fails a combined lookup when either the A or the AAAA query fails, and
//! many servers have no IPv6 route at all ("Network unreachable"). Separate per-family lookups keep a
//! broken AAAA answer from hiding a working IPv4 address; ureq then tries the addresses in order.

use std::ffi::CString;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

pub struct V4First;

impl ureq::Resolver for V4First {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        let Some((host, port)) = split(netloc) else { return netloc.to_socket_addrs().map(|a| a.collect()) };
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let mut out = lookup(host, port, libc::AF_INET);
        out.extend(lookup(host, port, libc::AF_INET6));
        if out.is_empty() {
            // Last resort: the system's combined lookup, which also carries its error message.
            return netloc.to_socket_addrs().map(|a| a.collect());
        }
        Ok(out)
    }
}

/// "host:port" or "[v6]:port" -> (host, port).
pub fn split(netloc: &str) -> Option<(&str, u16)> {
    let (h, p) = netloc.rsplit_once(':')?;
    Some((h.trim_start_matches('[').trim_end_matches(']'), p.parse().ok()?))
}

fn lookup(host: &str, port: u16, family: i32) -> Vec<SocketAddr> {
    let Ok(c) = CString::new(host) else { return Vec::new() };
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = family;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: valid C string and hints; the result list is freed below.
    if unsafe { libc::getaddrinfo(c.as_ptr(), std::ptr::null(), &hints, &mut res) } != 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut p = res;
    while !p.is_null() {
        // SAFETY: p walks the list getaddrinfo returned; ai_addr matches ai_family.
        let ai = unsafe { &*p };
        if !ai.ai_addr.is_null() {
            let addr = match ai.ai_family {
                libc::AF_INET => {
                    let sa = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
                    Some(SocketAddr::from((u32::from_be(sa.sin_addr.s_addr).to_be_bytes(), port)))
                }
                libc::AF_INET6 => {
                    let sa = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in6) };
                    Some(SocketAddr::from((sa.sin6_addr.s6_addr, port)))
                }
                _ => None,
            };
            if let Some(a) = addr {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
        p = ai.ai_next;
    }
    unsafe { libc::freeaddrinfo(res) };
    out
}
