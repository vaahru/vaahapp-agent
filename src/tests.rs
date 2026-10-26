//! Parser tests with output samples in the formats our servers produce.

use crate::collect::{audit, disk, docker, net, packages, security, sys, systemd};
use crate::endpoints;

// Signed with a throwaway TEST key by `vaahapp-endpoints sign` (valid until 2036). Not the real key.
const TEST_PUB: &str = "P50S/2EtYkbbwBFLj3c0rEBnSY12J1Kw76dGsVuQvSc=";
const SIGNED: &str = r#"{"payload": "eyJ2IjoxLCJpc3N1ZWQiOjE3OTI4NzU4MzIsImV4cGlyZXMiOjIxMDgyMzU4MzIsImVuZHBvaW50cyI6WyJodHRwczovL2FwcC52YWFoLnJ1IiwiaHR0cHM6Ly9yZWxheS52YWFoLnJ1LyJdfQ==",
  "sig": "R3QZ5we+av18MJRhvesXbmQcjBwmJHwTio7g2lUpXA0UrzE6l/R/wB77v2pJRjErW3ob82LvQgeyAYesKCegBg=="}"#;

#[test]
fn resolver_v4_first() {
    use crate::resolve::{split, V4First};
    use ureq::Resolver;
    assert_eq!(split("relay.vaah.ru:443"), Some(("relay.vaah.ru", 443)));
    assert_eq!(split("[::1]:8080"), Some(("::1", 8080)));
    assert_eq!(V4First.resolve("127.0.0.1:443").unwrap(), vec!["127.0.0.1:443".parse().unwrap()]);
    // "localhost" resolves from /etc/hosts; any IPv4 answer must come before IPv6 ones.
    let addrs = V4First.resolve("localhost:80").unwrap();
    assert!(!addrs.is_empty());
    let first_v6 = addrs.iter().position(|a| a.is_ipv6()).unwrap_or(addrs.len());
    assert!(addrs[first_v6..].iter().all(|a| a.is_ipv6()));
}

#[test]
fn signed_endpoint_list() {
	let now = 1_792_900_000;
	assert_eq!(endpoints::verify(SIGNED, TEST_PUB, now).unwrap(), vec!["https://app.vaah.ru", "https://relay.vaah.ru"]);
	// Wrong key (the real one) must reject a list signed by the test key.
	assert!(endpoints::verify(SIGNED, endpoints::PUBLIC_KEY, now).is_err());
	// Tampered payload: swap one character.
	let tampered = SIGNED.replacen("eyJ2Ijox", "eyJ2Ijoy", 1);
	assert!(endpoints::verify(&tampered, TEST_PUB, now).is_err());
	// Expired.
	assert_eq!(endpoints::verify(SIGNED, TEST_PUB, 2_200_000_000).unwrap_err(), "list expired");
}

#[test]
fn dpkg_inventory_uses_source_packages() {
    let s = "libssl3\t3.0.17-1~deb12u2\topenssl\t3.0.17-1~deb12u2\tii \nphp8.3-fpm\t8.3.36-1+clp-bookworm\tphp8.3\t8.3.36-1+clp-bookworm\tii \nbash\t5.2.15-2+b8\tbash\t5.2.15-2\tii \nold-pkg\t1.0\t\t\trc \nzlib1g\t1:1.2.13.dfsg-1\t\t\tii \n";
    let p = packages::parse_dpkg(s);
    assert_eq!(p.len(), 4); // "rc" (removed, config left) is skipped
    assert_eq!(p[0], ["bash".to_string(), "5.2.15-2+b8".into(), "bash".into(), "5.2.15-2".into()]);
    assert_eq!(p[3][2], "zlib1g"); // empty source falls back to the binary package
}

#[test]
fn rpm_inventory_strips_srpm_version() {
    let s = "openssl\t1:1.0.2k-26.el7_9\topenssl-1.0.2k-26.el7_9.src.rpm\ngpg-pubkey\t0:f4a80eb5-53a7ff4b\t(none)\nphp-cli\t0:8.3.36-1.el7.mfc\tphp-8.3.36-1.el7.mfc.src.rpm\n";
    let p = packages::parse_rpm(s);
    assert_eq!(p.len(), 2);
    assert_eq!((p[0][0].as_str(), p[0][2].as_str()), ("openssl", "openssl"));
    assert_eq!((p[1][0].as_str(), p[1][2].as_str()), ("php-cli", "php"));
    assert_eq!(packages::os_release_field("ID=debian\nVERSION_ID=\"12\"\n", "VERSION_ID"), "12");
}

#[test]
fn audit_sshd_and_listeners() {
    let t = "port 22\npermitrootlogin without-password\npasswordauthentication yes\nmaxauthtries 6\n";
    let c = audit::ssh_checks(t);
    assert_eq!((c[0].status.as_str(), c[0].value.as_str()), ("pass", "without-password"));
    assert_eq!(c[1].status, "warn");
    assert_eq!((c[2].status.as_str(), c[2].value.as_str()), ("warn", "6"));
    assert_eq!(audit::ssh_checks("permitrootlogin yes\n")[0].status, "fail");

    let tcp = "  sl  local_address rem_address   st\n   0: 00000000:0CEA 00000000:0000 0A 0\n   1: 0100007F:1F90 00000000:0000 0A 0\n   2: 00000000:0016 00000000:0000 0A 0\n   3: 0A00020F:0016 0B00020F:D2F0 01 0\n";
    let tcp6 = "  sl\n   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0\n";
    assert_eq!(audit::public_listeners(tcp, tcp6), vec![22, 443, 3306]);

    let d = "edge-caddy 0.0.0.0:80->80/tcp, :::80->80/tcp, 0.0.0.0:443->443/tcp\nshop-api-1 0.0.0.0:18090->8090/tcp, [::]:18090->8090/tcp\ndb 127.0.0.1:15432->5432/tcp\n";
    assert_eq!(audit::docker_public(d), vec!["shop-api-1:18090"]);
}

#[test]
fn audit_accounts_and_sources() {
    assert_eq!(audit::extra_uid0("root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\nuser:x:1000:1000::/home/user:/bin/bash\n"), vec!["toor"]);
    assert_eq!(audit::empty_passwords("root:$6$abc:1::\nnopw::1::\nlocked:!:1::\n"), vec!["nopw"]);
    assert!(audit::has_security_source("deb http://deb.debian.org/debian bookworm main\ndeb http://security.debian.org/debian-security bookworm-security main\n"));
    assert!(!audit::has_security_source("deb http://mirror.yandex.ru/debian bookworm main\n# deb http://security.debian.org bookworm-security main\n"));
}

#[test]
fn cpu_percent_between_samples() {
    let a = sys::parse_cpu("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4\n").unwrap();
    let b = sys::parse_cpu("cpu  150 0 150 880 20 0 0 0 0 0\n").unwrap();
    let (busy, io) = sys::cpu_pct(a, b).unwrap();
    assert_eq!(busy, 50.0); // 100 busy of 200 jiffies
    assert_eq!(io, 10.0);
}

#[test]
fn meminfo_with_and_without_memavailable() {
    let m = "MemTotal:        4000000 kB\nMemFree:  500000 kB\nMemAvailable:  1000000 kB\nBuffers: 1 kB\nSwapTotal: 2000000 kB\nSwapFree: 1500000 kB\n";
    assert_eq!(sys::parse_meminfo(m), Some((4_096_000_000, 3_072_000_000, 2_048_000_000, 512_000_000)));
    let old = "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 100 kB\nCached: 200 kB\n";
    assert_eq!(sys::parse_meminfo(old), Some((1_024_000, 614_400, 0, 0)));
}

#[test]
fn os_release_and_cpuinfo() {
    assert_eq!(sys::parse_os_release("NAME=\"CentOS Linux\"\nPRETTY_NAME=\"CentOS Linux 7 (Core)\"\n").as_deref(), Some("CentOS Linux 7 (Core)"));
    let (model, n) = sys::parse_cpuinfo("processor\t: 0\nmodel name\t: Intel Xeon\nprocessor\t: 1\nmodel name\t: Intel Xeon\n");
    assert_eq!((model.as_str(), n), ("Intel Xeon", 2));
}

#[test]
fn mounts_keep_real_fs_once_per_device() {
    let m = "/dev/mapper/vg-root / ext4 rw 0 0\nproc /proc proc rw 0 0\ntmpfs /run tmpfs rw 0 0\n/dev/vda1 /boot ext2 rw 0 0\n/dev/mapper/vg-root /var/lib/docker/overlay ext4 rw 0 0\n/dev/mapper/vg-root /srv/bind ext4 rw 0 0\n/dev/loop1 /snap/core24/1 squashfs ro 0 0\n/dev/sdb1 /mnt/my\\040disk xfs rw 0 0\n";
    let got: Vec<String> = disk::parse_mounts(m).into_iter().map(|x| x.1).collect();
    assert_eq!(got, vec!["/", "/boot", "/mnt/my disk"]);
}

#[test]
fn netdev_skips_virtual_links() {
    let s = "Inter-|   Receive\n face |bytes packets errs drop fifo frame compressed multicast|bytes\n    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n  eth0: 5000 10 0 0 0 0 0 0 7000 12 0 0 0 0 0 0\nveth12ab: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\nbr-5f: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n";
    let m = net::parse_netdev(s);
    assert_eq!(m.len(), 1);
    assert_eq!(m["eth0"], (5000, 7000));
}

#[test]
fn systemd_units_and_key_filter() {
    let out = "nginx.service loaded active running A high performance web server\n\u{25cf} php8.3-fpm.service loaded failed failed The PHP 8.3 FastCGI\nphpsessionclean.service loaded inactive dead Clean php session files\nredis-server.service loaded active running Advanced key-value store\npostgresql@16-main.service loaded active running PostgreSQL\nsshd-keygen.service loaded inactive dead keys\nfoo.service not-found inactive dead foo.service\n";
    let units = systemd::parse_list_units(out);
    assert_eq!(units[1], ("php8.3-fpm.service".into(), "loaded".into(), "failed".into(), "failed".into()));
    let extra = vec!["myapp".to_string()];
    assert!(systemd::is_key_unit("nginx.service", &extra));
    assert!(systemd::is_key_unit("php8.3-fpm.service", &extra));
    assert!(!systemd::is_key_unit("phpsessionclean.service", &extra));
    assert!(systemd::is_key_unit("redis-server.service", &extra));
    assert!(systemd::is_key_unit("postgresql@16-main.service", &extra));
    assert!(systemd::is_key_unit("awg-quick@awg0.service", &extra));
    assert!(systemd::is_key_unit("myapp.service", &extra));
    assert!(!systemd::is_key_unit("getty@tty1.service", &extra));
}

#[test]
fn docker_ps_new_and_old_engines() {
    let s = "{\"Names\":\"edge-caddy\",\"Image\":\"caddy:2.10-alpine\",\"State\":\"running\",\"Status\":\"Up 3 days\"}\n{\"Names\":\"old\",\"Image\":\"x\",\"Status\":\"Exited (0) 2 hours ago\"}\nnot json\n";
    let c = docker::parse_ps(s);
    assert_eq!(c.len(), 2);
    assert_eq!((c[0].name.as_str(), c[0].state.as_str()), ("edge-caddy", "running"));
    assert_eq!(c[1].state, "exited");
}

#[test]
fn ssh_and_oom_counts() {
    let log = "Failed password for root from 1.2.3.4 port 22 ssh2\nInvalid user admin from 5.6.7.8 port 4242\nFailed password for invalid user admin from 5.6.7.8 port 4242 ssh2\nAccepted publickey for user from 9.9.9.9\n";
    assert_eq!(security::count_ssh_failed(log), 3);
    let k = "Out of memory: Killed process 123 (nginx)\nOut of memory: Kill process 99 (php-fpm) score 10\noom-kill:constraint=CONSTRAINT_NONE,task=mariadbd,pid=1\n";
    assert_eq!(security::count_oom(k), 2);
    assert_eq!(security::parse_vmstat_oom("pgfault 1\noom_kill 7\n"), Some(7));
}

#[test]
fn fail2ban_output() {
    let st = "Status\n|- Number of jail:\t3\n`- Jail list:\tnginx-flood, nginx-wp-login, sshd\n";
    assert_eq!(security::parse_f2b_jails(st), vec!["nginx-flood", "nginx-wp-login", "sshd"]);
    let j = "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t3\n`- Actions\n   |- Currently banned:\t12\n   |- Total banned:\t400\n";
    assert_eq!(security::parse_f2b_banned(j), Some(12));
}

#[test]
fn apt_and_yum_updates() {
    let apt = "Reading package lists...\nInst libssl3 [3.0.1] (3.0.2 Debian-Security:12/stable-security [amd64])\nInst curl [7.1] (7.2 Debian:12.7/stable [amd64])\nConf libssl3 (3.0.2 Debian-Security:12/stable-security [amd64])\n";
    assert_eq!(security::parse_apt_sim(apt), (2, 1));
    let yum = "\nkernel.x86_64    3.10.0-1160.119.1.el7    updates\nopenssl.x86_64   1:1.0.2k-26.el7_9        updates\nObsoleting Packages\nfoo.noarch 1 base\n";
    assert_eq!(security::parse_yum_check(yum), 2);
}
