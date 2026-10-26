# Agent → server protocol (v1)

The agent only pushes. There is no inbound port and no command channel.

## Request
`POST {url}/api/agent/v1/report`
- `Authorization: Bearer <server token>` (shown once at registration; the server keeps a SHA-256 hash)
- `Content-Type: application/json`, `Content-Encoding: gzip`
- Body: `{"reports": [Report, ...]}`. Normally one report; after an outage the agent sends its spool
  oldest first, up to 60 per request.

## Report
Every field except `v`, `agent` and `ts` may be missing or `null`; a missing collector never fails a report.
`endpoint` is the base URL the agent is sending to (a relay or the server itself), `auto_update` whether
self-update is switched on (both since 0.3.0).

```json
{
  "v": 1,
  "agent": "0.3.0",
  "endpoint": "https://app.vaah.ru",
  "auto_update": false,
  "ts": 1761300000,
  "interval": 60,
  "host": {
    "hostname": "aib-vm", "os": "Debian GNU/Linux 12 (bookworm)", "kernel": "6.1.0-53-amd64",
    "arch": "x86_64", "cpu_model": "Intel Xeon ...", "cpu_count": 2, "boot_time": 1760000000
  },
  "sys": {
    "cpu_pct": 12.5, "iowait_pct": 0.4, "load1": 0.31, "load5": 0.25, "load15": 0.2,
    "mem_total": 4100000000, "mem_used": 2100000000,
    "swap_total": 2147483648, "swap_used": 104857600,
    "procs": 182, "uptime": 123456
  },
  "disks": [ {"mount": "/", "fs": "ext4", "total": 31000000000, "used": 17000000000, "avail": 12500000000} ],
  "net": [ {"iface": "eth0", "rx_bps": 12000, "tx_bps": 34000} ],
  "services": [ {"name": "nginx.service", "active": "active", "sub": "running"} ],
  "failed_units": ["logrotate.service"],
  "containers": [ {"name": "edge-caddy", "image": "caddy:2.10-alpine", "state": "running", "status": "Up 3 days"} ],
  "security": {
    "ssh_failed": 14, "f2b_banned": {"sshd": 12}, "oom_kills": 0, "reboot_required": false,
    "updates_total": 3, "updates_security": 1
  }
}
```

- `ts`: unix seconds when the sample was taken. The server rejects reports older than 25 h or more than
  5 min in the future.
- `host`: sent with the first report after start and then once a day.
- `sys.cpu_pct` / `net`: rates since the previous sample, so absent in the very first report.
- `security.ssh_failed`, `oom_kills`: counts since the previous report.
- `security.f2b_banned`: refreshed every 5 min. `updates_*` and `reboot_required`: refreshed hourly.
  Between refreshes the last value is repeated.
- `containers`: `null` when docker is not installed, `[]` when it has no containers.
- `sites` (0.4.0+, unless `discover_sites = false`): the websites the nginx / Apache / Caddy config files mention, e.g.
  `[{"domain": "example.com", "server": "nginx", "tls": true, "wildcard": false}]`. Present only when the
  list changed and once a day; the server replaces its copy with each list it receives (`[]` = none).

## Response
- `200 {"ok": true, "accepted": N}`
- `401` bad or revoked token: the agent keeps the report in its spool and retries later.
- `400` malformed body: the agent drops that batch (logged), so one bad report cannot block the spool.
