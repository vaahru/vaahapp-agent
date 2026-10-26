//! Disk usage per real filesystem (one entry per device, first mount wins).

use crate::report::Disk;
use crate::util::read;
use std::collections::HashSet;
use std::ffi::CString;

const REAL_FS: &[&str] = &["ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "vfat", "ntfs", "ntfs3", "exfat"];

/// (device, mount, fs) for every real filesystem in /proc/self/mounts.
pub fn parse_mounts(s: &str) -> Vec<(String, String, String)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in s.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || !REAL_FS.contains(&f[2]) {
            continue;
        }
        let mount = unescape(f[1]);
        // Snap/docker internals and bind mounts of the same device are noise.
        // /etc/* are file bind mounts (resolv.conf, hosts) inside containers and LXC guests.
        if mount.starts_with("/snap/") || mount.starts_with("/var/lib/docker/") || mount.starts_with("/run/") || mount.starts_with("/etc/") {
            continue;
        }
        let dev = f[0].to_string();
        if !seen.insert(dev.clone()) {
            continue;
        }
        out.push((dev, mount, f[2].to_string()));
    }
    out
}

/// /proc/mounts escapes space, tab, newline and backslash as octal.
fn unescape(s: &str) -> String {
    s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
}

fn statvfs(path: &str) -> Option<(u64, u64, u64)> {
    let c = CString::new(path).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let fr = st.f_frsize as u64;
    let total = st.f_blocks as u64 * fr;
    let free = st.f_bfree as u64 * fr;
    let avail = st.f_bavail as u64 * fr;
    if total == 0 {
        return None;
    }
    Some((total, total.saturating_sub(free), avail))
}

pub fn collect() -> Option<Vec<Disk>> {
    let mounts = read("/proc/self/mounts")?;
    let disks = parse_mounts(&mounts)
        .into_iter()
        .filter_map(|(_, mount, fs)| {
            statvfs(&mount).map(|(total, used, avail)| Disk { mount, fs, total, used, avail })
        })
        .collect();
    Some(disks)
}
