# vaahapp-agent

The open-source monitoring agent for [vaahapp](https://app.vaah.ru). It runs on your Linux server,
collects health and security data once a minute and **pushes** it over HTTPS to the vaahapp server.

This repository exists so you can see exactly what the agent does on your machine before you install it.

- One static binary (Rust, musl), about 2 MB. No runtime dependencies, no OpenSSL.
- Linux x86_64 and aarch64 with systemd. Built to run on old systems too (static binary, no glibc
  dependency); tested on Debian 12, Ubuntu 24.04 and CentOS 7.
- **Outbound only**: it opens no listening port.
- **Read-only**: it never runs anything the server sends. There is no remote command channel and no
  auto-update. It changes nothing on your server apart from its own spool file.

## What it collects

| Data | Source | How often |
|---|---|---|
| CPU %, iowait, load, RAM, swap, process count, uptime | `/proc` | every report |
| Disk usage per real filesystem | `/proc/self/mounts` + `statvfs` | every report |
| Network throughput per interface (container veths skipped) | `/proc/net/dev` | every report |
| State of key services (nginx, php-fpm, databases, docker, ssh, fail2ban…) and every failed unit | `systemctl list-units` | every report |
| Docker containers: name, image, state | `docker ps -a` | every report |
| Failed SSH login count (no usernames or IPs) | journal (`sshd`) or `/var/log/auth.log` / `secure` | every report |
| OOM-killer count | `/proc/vmstat`, or the kernel journal | every report |
| fail2ban currently-banned count per jail | `fail2ban-client status` | 5 min |
| Pending updates (and how many are security updates), reboot required | `apt-get -s upgrade` / `yum -C check-update` | hourly |
| Installed package names and versions, for the CVE scan | `dpkg-query -W` / `rpm -qa` | daily, and after packages change |
| Security baseline audit (see below) | see below | every 6 h |
| Hostname, OS, kernel, CPU model and count, boot time | `/proc`, `/etc/os-release` | start, daily, on change |

**Never collected:** file contents, environment variables, process command lines, user names (except the
names of extra UID-0 accounts or accounts without a password, when the audit finds them), passwords, keys,
logs, or your website data.

The exact payload is documented in [PROTOCOL.md](PROTOCOL.md). To see it yourself:

```sh
vaahapp-agent --once       # one full report as JSON; sends nothing
vaahapp-agent --audit      # the baseline audit
vaahapp-agent --packages   # the package list used for the CVE scan
```

## Security baseline audit

Read-only checks. Each one reports pass / warn / fail with the observed value:

| Check | Looks at |
|---|---|
| `ssh_root_login`, `ssh_password_auth`, `ssh_max_auth_tries` | `sshd -T` |
| `firewall` | ufw, firewalld, nftables input policy, or iptables INPUT policy |
| `fail2ban` | installed and running |
| `auto_updates` | unattended-upgrades / dnf-automatic / yum-cron |
| `security_repo` | an apt `-security` source is configured |
| `swap` | swap present when RAM ≤ 8 GB |
| `time_sync` | `timedatectl` |
| `public_ports` | TCP listeners on 0.0.0.0 / :: (`/proc/net/tcp*`); databases, caches and Docker API flagged |
| `docker_ports` | containers published on all interfaces (Docker bypasses ufw) |
| `uid0_accounts`, `empty_passwords` | `/etc/passwd`, `/etc/shadow` (only the account names are reported) |

## Why it runs as root

Several sources need root: the journal, `fail2ban-client`, the docker socket, `sshd -T` and
`/etc/shadow`. The systemd unit limits what root can do:
- `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only` and `PrivateTmp`
- writes allowed only to `/var/lib/vaahapp`
- `MemoryMax=64M` and `CPUQuota=10%`

All privileged reads live in [`src/collect/`](src/collect/).

## Install

Register the server in the vaahapp dashboard. It shows a one-line command like this:

```sh
curl -fsSL https://app.vaah.ru/install.sh | sudo sh -s -- --url https://app.vaah.ru --token vah_…
```

[`install.sh`](install.sh) does the following:
- checks the system first (`--check` runs only the checks)
- downloads the binary for your architecture and verifies its SHA-256
- writes `/etc/vaahapp/agent.toml` (mode 600)
- installs and starts the `vaahapp-agent` systemd service, then sends a test report

Upgrade: `--upgrade`. Remove everything: `--uninstall`.

Config `/etc/vaahapp/agent.toml`:

```toml
url = "https://app.vaah.ru"
token = "vah_…"
interval = 60
services = ["myapp"]   # optional: extra systemd units to watch
```

If the server is unreachable, reports wait in `/var/lib/vaahapp/spool.jsonl` (up to 24 h) and are sent
later, oldest first.

### Endpoints and failover

The agent tries the servers in this order and stays on the first that works:
1. `url`
2. the optional `urls = [...]` from the config
3. the **signed endpoint list** (`endpoints_url`, published in this repository as `endpoints.json`)

On a fallback it goes back to `url` once an hour.

The signed list lets the vaahapp server move without touching installed agents. The agent accepts it
only if all of these hold:
- the ed25519 signature verifies with the public key compiled into the binary
  ([`src/endpoints.rs`](src/endpoints.rs))
- the list has not expired
- every endpoint is `https://`

A tampered or stale list is ignored. The list can add routes but never removes the one you configured.
The last good copy is cached in `/var/lib/vaahapp/endpoints.json`.

## Build

Only Docker is needed:

```sh
bash build.sh        # tests + static binaries for x86_64 and aarch64 in dist/
bash build.sh test   # tests only
```

## License

MIT, see [LICENSE](LICENSE).
