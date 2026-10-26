#!/bin/sh
# vaahapp agent installer (served at <server>/install.sh). Run as root.
#
#   install:    sh install.sh --url https://app.vaah.ru --token vah_...
#               sh install.sh --url https://app.vaah.ru --config /path/agent.toml   (token inside, file moved)
#   upgrade:    sh install.sh --url https://app.vaah.ru --upgrade                   (keeps the config)
#   uninstall:  sh install.sh --uninstall
#   check only: sh install.sh --url https://app.vaah.ru --check                     (changes nothing)
#   self-update: add --auto-update (or --no-auto-update) to install/upgrade. Off unless you ask for it;
#               without either flag an upgrade keeps the current choice.
set -eu

URL=""; TOKEN=""; CONFIG=""; MODE=install; AUTO=""
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="${2%/}"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --auto-update) AUTO=true; shift ;;
    --no-auto-update) AUTO=false; shift ;;
    --upgrade) MODE=upgrade; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    --check) MODE=check; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# Pre-install compatibility check. Prints one line per item; returns 1 if a blocker was found.
precheck() {
  bad=0
  ok()   { echo "  ok    $1"; }
  warn() { echo "  warn  $1"; }
  fail() { echo "  FAIL  $1"; bad=1; }
  echo "vaahapp agent pre-install check"
  case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ok "architecture $(uname -m)" ;;
    *) fail "architecture $(uname -m) is not supported (x86_64, aarch64)" ;;
  esac
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then ok "systemd"; else fail "systemd is required"; fi
  if [ "$(id -u)" = 0 ]; then ok "running as root"; else fail "run as root (sudo)"; fi
  if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then ok "curl/wget"; else fail "curl or wget is required"; fi
  command -v sha256sum >/dev/null 2>&1 && ok "sha256sum" || fail "sha256sum is required"
  for d in /usr/local/bin /var/lib; do
    free=$(df -Pk "$d" 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -n "$free" ] && [ "$free" -gt 51200 ]; then ok "free space in $d"; else fail "less than 50 MB free in $d"; fi
  done
  if [ -n "$URL" ]; then
    hdr=$(mktemp)
    if command -v curl >/dev/null 2>&1 && curl -fsS --connect-timeout 8 -m 15 --retry 4 --retry-delay 2 -D "$hdr" -o /dev/null "$URL/healthz" 2>/dev/null; then
      ok "HTTPS to $URL"
      # Clock skew against the server's Date header (reports older than 25 h are rejected).
      sdate=$(sed -n 's/^[Dd]ate: //p' "$hdr" | tr -d '\r')
      if [ -n "$sdate" ] && s=$(date -d "$sdate" +%s 2>/dev/null); then
        skew=$(( $(date +%s) - s )); [ $skew -lt 0 ] && skew=$(( -skew ))
        if [ $skew -le 120 ]; then ok "clock within ${skew}s of the server"; else warn "clock is ${skew}s off the server: fix time sync"; fi
      fi
    elif ! command -v curl >/dev/null 2>&1 && wget -q -T 15 -t 4 -O /dev/null "$URL/healthz" 2>/dev/null; then
      ok "HTTPS to $URL"
    else
      fail "cannot reach $URL/healthz (outbound HTTPS blocked?)"
    fi
    rm -f "$hdr"
  fi
  [ -d /etc/hetrixtools ] && warn "HetrixTools agent present (both can run side by side)"
  systemctl is-active --quiet vaahapp-agent 2>/dev/null && warn "vaahapp agent already running (use --upgrade)"
  return $bad
}

if [ "$MODE" = check ]; then
  precheck && exit 0 || exit 1
fi

BIN=/usr/local/bin/vaahapp-agent
UNIT=/etc/systemd/system/vaahapp-agent.service
ETC=/etc/vaahapp
VAR=/var/lib/vaahapp

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || { echo "systemd is required" >&2; exit 1; }

if [ "$MODE" = uninstall ]; then
  systemctl disable --now vaahapp-agent vaahapp-agent-update.timer 2>/dev/null || true
  rm -f "$BIN" "$BIN.old" "$BIN.new" "$UNIT" /etc/systemd/system/vaahapp-agent-update.service /etc/systemd/system/vaahapp-agent-update.timer
  rm -rf "$ETC" "$VAR"
  systemctl daemon-reload
  echo "vaahapp agent removed"
  exit 0
fi

[ -n "$URL" ] || { echo "--url is required" >&2; exit 2; }
if [ "$MODE" = install ]; then
  precheck || { echo "pre-install check failed: nothing was installed" >&2; exit 1; }
fi
case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

fetch() { # url dest
  # Short connect timeout + retries: some networks drop single connections at random.
  if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 10 -m 180 --retry 6 --retry-delay 2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -T 15 -t 6 -O "$2" "$1"
  else echo "curl or wget is required" >&2; exit 1; fi
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fetch "$URL/dl/agent/vaahapp-agent-$ARCH" "$TMP/vaahapp-agent-$ARCH"
fetch "$URL/dl/agent/vaahapp-agent-$ARCH.sha256" "$TMP/sum"
(cd "$TMP" && sha256sum -c sum >/dev/null) || { echo "checksum mismatch, aborting" >&2; exit 1; }
install -m 0755 "$TMP/vaahapp-agent-$ARCH" "$BIN"

mkdir -p "$ETC" "$VAR"
chmod 700 "$ETC" "$VAR"
if [ "$MODE" = install ]; then
  if [ -n "$CONFIG" ]; then
    install -m 0600 "$CONFIG" "$ETC/agent.toml"
    rm -f "$CONFIG"
  elif [ -n "$TOKEN" ]; then
    umask 077
    printf 'url = "%s"\ntoken = "%s"\ninterval = 60\n# services = ["myapp"]   # extra systemd units to watch\n' "$URL" "$TOKEN" > "$ETC/agent.toml"
  elif [ ! -f "$ETC/agent.toml" ]; then
    echo "--token or --config is required" >&2; exit 2
  fi
fi

cat > "$UNIT" <<'EOF'
[Unit]
Description=vaahapp monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/vaahapp-agent --config /etc/vaahapp/agent.toml
Restart=always
RestartSec=10
Nice=10
MemoryMax=128M
CPUQuota=10%
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/var/lib/vaahapp
ProtectKernelTunables=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF

# Self-update (opt-in). The flag is stored in agent.toml so upgrades keep it.
if [ -n "$AUTO" ]; then
  if grep -q '^auto_update *=' "$ETC/agent.toml"; then
    sed -i "s/^auto_update *=.*/auto_update = $AUTO/" "$ETC/agent.toml"
  else
    printf 'auto_update = %s\n' "$AUTO" >> "$ETC/agent.toml"
  fi
fi
UPD=/etc/systemd/system/vaahapp-agent-update
if grep -q '^auto_update *= *true' "$ETC/agent.toml"; then
  # Separate oneshot unit: it must replace /usr/local/bin/vaahapp-agent, which the hardened main
  # unit cannot write. It only installs releases signed with the vaahapp key (see update.rs).
  cat > "$UPD.service" <<'EOF'
[Unit]
Description=vaahapp agent self-update (signed releases only)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vaahapp-agent --self-update --config /etc/vaahapp/agent.toml
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
TimeoutStartSec=15min
EOF
  cat > "$UPD.timer" <<'EOF'
[Unit]
Description=Daily vaahapp agent self-update check

[Timer]
OnBootSec=1h
OnUnitActiveSec=1d
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  AUTO_ON=1
else
  systemctl disable --now vaahapp-agent-update.timer >/dev/null 2>&1 || true
  rm -f "$UPD.service" "$UPD.timer"
  AUTO_ON=0
fi

systemctl daemon-reload
systemctl enable vaahapp-agent >/dev/null 2>&1
systemctl restart vaahapp-agent
if [ "$AUTO_ON" = 1 ]; then
  systemctl enable --now vaahapp-agent-update.timer >/dev/null 2>&1
  echo "self-update: on (daily, signed releases only; turn off with --upgrade --no-auto-update)"
fi
"$BIN" --version
"$BIN" --test --config "$ETC/agent.toml" || { echo "agent installed but the test report failed (see above)" >&2; exit 1; }
echo "vaahapp agent running (systemctl status vaahapp-agent)"
