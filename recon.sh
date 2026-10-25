#!/usr/bin/env bash
# ============================================================================
# gs-recon.sh - GSocket War-Game Reconnaissance & Forensic Script
# ============================================================================
# Dual-purpose script:
#   1. MONITOR  - Watch who/what kills our gs-netcat process (attacker side)
#   2. FORENSIC - Find all persistence layers (defender side)
#   3. AUDIT    - Map the lab web server (info gathering for both sides)
#   4. HUNT     - Profile attacker: who logged in, from where, what they ran
#   5. TRIPWIRE - Plant canary to detect investigation attempts
#
# ⚠️  EDUCATIONAL USE ONLY - Use on systems you own or have explicit permission
#     to test. Misuse against systems you don't own is illegal.
#
# Usage:
#   ./gs-recon.sh monitor [--pid PID] [--log FILE]    # Watch for kills (bg)
#   ./gs-recon.sh monitor --install                   # Install persistent watcher
#   ./gs-recon.sh forensic                            # Scan all persistence
#   ./gs-recon.sh audit                               # Map lab web server
#   ./gs-recon.sh hunt                                # Profile attacker activity
#   ./gs-recon.sh tripwire                            # Plant detection canaries
#   ./gs-recon.sh tripwire --check                    # Check if canaries triggered
#   ./gs-recon.sh all                                 # Run forensic+audit+hunt
#   ./gs-recon.sh --help
#
# ============================================================================

set -uo pipefail

RECON_VERSION="1.0-recon"

# ----------------------------------------------------------------------------
# COLOR & LOGGING (defined early for arg parsing)
# ----------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_CY=$'\033[1;33m'; C_CG=$'\033[1;32m'; C_CR=$'\033[1;31m'; C_CB=$'\033[1;34m'
  C_CC=$'\033[1;36m'; C_CM=$'\033[1;35m'; C_CN=$'\033[0m'; C_CW=$'\033[1;37m'; C_CD=$'\033[0;37m'
  C_BG_RED=$'\033[41;37m'; C_BG_GREEN=$'\033[42;30m'; C_BG_YELLOW=$'\033[43;30m'
else
  C_CY=""; C_CG=""; C_CR=""; C_CB=""; C_CC=""; C_CM=""; C_CN=""; C_CW=""; C_CD=""
  C_BG_RED=""; C_BG_GREEN=""; C_BG_YELLOW=""
fi

r_log()    { printf "%s[%s]%s %s\n" "$C_CB" "$(date +%H:%M:%S)" "$C_CN" "$*"; }
r_ok()     { printf "%s[+]%s %s\n" "$C_CG" "$C_CN" "$*"; }
r_warn()   { printf "%s[!]%s %s\n" "$C_CY" "$C_CN" "$*"; }
r_err()    { printf "%s[-]%s %s\n" "$C_CR" "$C_CN" "$*" >&2; }
r_step()   { printf "%s[*]%s %s...\n" "$C_CC" "$C_CN" "$*"; }
r_die()    { r_err "$*"; exit 1; }
r_section(){ printf "\n%s═══════════════════════════════════════════════════════════════%s\n" "$C_CW" "$C_CN"
             printf "%s %s %s\n" "$C_BG_YELLOW" "$*" "$C_CN"
             printf "%s═══════════════════════════════════════════════════════════════%s\n" "$C_CW" "$C_CN"; }
r_found()  { printf "  %s[FOUND]%s %s\n" "$C_BG_RED" "$C_CN" "$*"; }
r_clean()  { printf "  %s[OK]%s %s\n" "$C_BG_GREEN" "$C_CN" "$*"; }
r_info()   { printf "  %s[i]%s %s\n" "$C_CD" "$C_CN" "$*"; }

# ----------------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------------
RECON_LOG="${RECON_LOG:-/tmp/.gs-recon.log}"
RECON_TRIPWIRE_DIR="${RECON_TRIPWIRE_DIR:-/tmp/.gs-tripwire}"
RECON_AUDIT_RULES_FILE="/etc/audit/rules.d/gs-recon.rules"

# Known gs-netcat / gs-chaos artifacts
RECON_KNOWN_PATHS=(
  "/root/.local/share/gsocket/gs-netcat"
  "/root/.config/htop/gs-netcat"
  "/root/.cache/gsocket/gs-netcat"
  "/root/.local/bin/gs-netcat"
  "/usr/local/bin/gs-netcat"
  "/usr/bin/gs-netcat"
  "/usr/local/bin/.dbus-update-helper"
  "/usr/local/bin/dbus-update-helper"
)
RECON_SECRET_PATHS=(
  "/root/.gsocket-secret"
  "/root/.gsocket-port"
)
RECON_PROC_NAMES=("[kstrp]" "[watchdogd]" "[ksmd]" "[kswapd0]" "[card0-crtc8]" "[mm_percpu_wq]" "[rcu_preempt]" "[kworker]" "[raid5wq]" "[slub_flushwq]" "[netns]" "[kaluad]" "[ksoftirqd]" "[migration/0]" "-bash")
RECON_SUSPICIOUS_FILES=("gs-netcat" "gs-dbus" "gs-mount" "gs-sftp" "blitz" ".gsocket-secret" ".gsocket-port" "dbus-update.service" "dbus-update.timer" ".dbus-update-helper" "gs-dbus.service")

# ----------------------------------------------------------------------------
# ARG PARSING
# ----------------------------------------------------------------------------
RECON_MODE="${1:-help}"
shift || true
RECON_PID=""
RECON_LOGFILE="$RECON_LOG"

if [[ "$RECON_MODE" != "monitor" && "$RECON_MODE" != "tripwire" ]]; then
  for arg in "$@"; do
    case "$arg" in
      --pid) RECON_PID="${2:-}"; shift ;;
      --log) RECON_LOGFILE="${2:-}"; shift ;;
      *) ;;
    esac
  done
fi

if [[ "$RECON_MODE" == "monitor" ]]; then
  RECON_INSTALL_WATCHER=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pid) RECON_PID="${2:-}"; shift 2 ;;
      --log) RECON_LOGFILE="${2:-}"; shift 2 ;;
      --install) RECON_INSTALL_WATCHER=1; shift ;;
      *) shift ;;
    esac
  done
fi

if [[ "$RECON_MODE" == "tripwire" ]]; then
  RECON_TRIPWIRE_CHECK=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check) RECON_TRIPWIRE_CHECK=1; shift ;;
      *) shift ;;
    esac
  done
fi

# ----------------------------------------------------------------------------
# HELP
# ----------------------------------------------------------------------------
r_help() {
  cat <<EOF
gs-recon.sh v$RECON_VERSION - GSocket War-Game Recon & Forensic Script

Usage: $0 <mode> [options]

Modes:
  monitor [--pid PID] [--log FILE]   Watch who kills gs-netcat (foreground)
  monitor --install                  Install watcher as cron + log rotation
  forensic                           Scan ALL persistence (defender side)
  audit                              Map lab web server (Apache/Nginx/PHP/DB)
  hunt                               Profile attacker (logins, commands, IPs)
  tripwire                           Plant canary files to detect investigation
  tripwire --check                   Check if canaries were triggered
  all                                Run forensic + audit + hunt together
  --help                             This help

Options:
  --pid PID                          Target PID to monitor (default: autodetect)
  --log FILE                         Log file (default: $RECON_LOG)

Examples:
  # Watch who kills our gs-netcat
  $0 monitor
  # Install persistent watcher (cron every 5 min)
  $0 monitor --install
  # Investigate box comprehensively
  $0 all
  # Plant canaries, wait, check if anyone touched them
  $0 tripwire
  ... wait ...
  $0 tripwire --check
EOF
}

# ============================================================================
# MODE: MONITOR - Watch who/what kills gs-netcat
# ============================================================================

# Find gs-netcat PID (try multiple methods)
r_find_target_pid() {
  local pid=""

  # Method 1: by binary path
  for p in /proc/[0-9]*; do
    local exe
    exe=$(readlink "$p/exe" 2>/dev/null)
    [[ "$exe" == *gs-netcat* ]] && pid="${p##*/}" && break
  done

  # Method 2: by cmdline (catches disguised processes)
  if [[ -z "$pid" ]]; then
    for p in /proc/[0-9]*; do
      local cmdline
      cmdline=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
      [[ "$cmdline" == *gs-netcat* ]] && pid="${p##*/}" && break
    done
  fi

  # Method 3: by env var GSOCKET_ARGS
  if [[ -z "$pid" ]]; then
    for p in /proc/[0-9]*; do
      local env
      env=$(tr '\0' '\n' < "$p/environ" 2>/dev/null)
      [[ "$env" == *GSOCKET_ARGS* ]] && pid="${p##*/}" && break
    done
  fi

  # Method 4: by open fd to gs-netcat binary
  if [[ -z "$pid" ]]; then
    for p in /proc/[0-9]*; do
      ls -la "$p/fd/" 2>/dev/null | grep -q 'gs-netcat' && pid="${p##*/}" && break
    done
  fi

  printf '%s' "$pid"
}

r_get_pid_info() {
  local pid="$1"
  [[ -z "$pid" || ! -d "/proc/$pid" ]] && return 1

  echo "  PID: $pid"
  echo "  Comm: $(cat /proc/$pid/comm 2>/dev/null)"
  echo "  Cmdline: $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)"
  echo "  Exe: $(readlink /proc/$pid/exe 2>/dev/null)"
  echo "  CWD: $(readlink /proc/$pid/cwd 2>/dev/null)"
  echo "  Start: $(ps -o lstart= -p "$pid" 2>/dev/null)"
  echo "  Parent PID: $(ps -o ppid= -p "$pid" 2>/dev/null)"
  local ppid
  ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
  [[ -n "$ppid" && "$ppid" != "0" && "$ppid" != "1" ]] && \
    echo "  Parent Cmd: $(ps -o args= -p "$ppid" 2>/dev/null)"
  echo "  User: $(ps -o user= -p "$pid" 2>/dev/null)"
}

r_setup_auditd_kill_watch() {
  if [[ "$EUID" -ne 0 ]]; then
    r_warn "Not root - skipping auditd rules (will use ps polling only)"
    return 1
  fi
  command -v auditd >/dev/null 2>&1 || command -v auditctl >/dev/null 2>&1 || {
    r_warn "auditd not installed - using ps polling only"
    return 1
  }

  r_step "Installing auditd rules to track process kills"
  # Track execve of kill/pkill/killall
  local rules_file="$RECON_AUDIT_RULES_FILE"
  mkdir -p "$(dirname "$rules_file")" 2>/dev/null
  cat > "$rules_file" <<EOF
## gs-recon rules - track who kills our processes
# Track kill commands
-a always,exit -F arch=b64 -S kill -F a1=9 -k gs-kill-9
-a always,exit -F arch=b64 -S kill -F a1=15 -k gs-kill-15
-a always,exit -F arch=b64 -S kill -F a1=2 -k gs-kill-2
# Track execve of pkill/killall
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/pkill -k gs-pkill
-a always,exit -F arch=b64 -S execve -F path=/bin/pkill -k gs-pkill
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/killall -k gs-killall
-a always,exit -F arch=b64 -S execve -F path=/bin/kill -k gs-kill
EOF
  auditctl -R "$rules_file" 2>/dev/null || {
    r_warn "Failed to load auditd rules"
    return 1
  }
  r_ok "auditd rules installed (key: gs-kill-*, gs-pkill, gs-killall)"
  return 0
}

r_auditd_query_kills() {
  command -v ausearch >/dev/null 2>&1 || return 1
  r_step "Querying auditd for kill events"
  echo "  Recent kill (SIGKILL=9) events:"
  ausearch -k gs-kill-9 --raw 2>/dev/null | tail -20 | while read -r line; do
    echo "    $line"
  done
  echo ""
  echo "  Recent pkill invocations:"
  ausearch -k gs-pkill --raw 2>/dev/null | tail -10 | while read -r line; do
    echo "    $line"
  done
}

r_monitor_loop() {
  r_section "MONITORING MODE - Watching for process kills"
  r_log "Log file: $RECON_LOGFILE"
  mkdir -p "$(dirname "$RECON_LOGFILE")" 2>/dev/null
  : > "$RECON_LOGFILE"

  # Setup auditd if root
  r_setup_auditd_kill_watch 2>/dev/null

  # Find or use given PID
  if [[ -z "$RECON_PID" ]]; then
    r_step "Auto-detecting target PID"
    RECON_PID=$(r_find_target_pid)
    if [[ -z "$RECON_PID" ]]; then
      r_warn "No gs-netcat process found. Will keep looking..."
    else
      r_ok "Tracking PID $RECON_PID"
      r_get_pid_info "$RECON_PID" | tee -a "$RECON_LOGFILE"
    fi
  else
    r_ok "Tracking user-specified PID $RECON_PID"
    r_get_pid_info "$RECON_PID" | tee -a "$RECON_LOGFILE"
  fi

  r_log "Polling every 2 seconds. Press Ctrl-C to stop."
  echo "----------------------------------------"

  local last_pid="$RECON_PID"
  local poll_count=0
  local killed_count=0

  while true; do
    poll_count=$((poll_count + 1))

    # Check current PID alive
    if [[ -n "$last_pid" ]]; then
      if [[ ! -d "/proc/$last_pid" ]]; then
        killed_count=$((killed_count + 1))
        local kill_time
        kill_time=$(date '+%Y-%m-%d %H:%M:%S')
        r_warn "[$kill_time] PID $last_pid DISAPPEARED (killed/exit)"
        {
          echo "==============================================="
          echo "KILL EVENT #$killed_count at $kill_time"
          echo "==============================================="
          echo "Victim PID: $last_pid"
          echo ""
          echo "--- Recent logins (who) ---"
          who 2>/dev/null
          echo ""
          echo "--- Last logins (last -a -n 10) ---"
          last -a -n 10 2>/dev/null | head -15
          echo ""
          echo "--- Currently logged in users (w) ---"
          w 2>/dev/null
          echo ""
          echo "--- Active SSH sessions ---"
          ss -tnp 2>/dev/null | grep ':22 ' | head -10
          echo ""
          echo "--- Top processes by CPU (most recent activity) ---"
          ps -eo pid,user,pcpu,pmem,etime,args --sort=-pcpu 2>/dev/null | head -10
          echo ""
          echo "--- Recently spawned processes (started in last 60s) ---"
          ps -eo pid,lstart,args 2>/dev/null | awk -v now="$(date +%s)" '
            NR==1 {print; next}
            { cmd=$0; $1=""; $2=""; $3=""; $4=""; $5=""; gsub(/^ +/,"");
              "date -d \""$0"\" +%s 2>/dev/null" | getline ts
              if (ts != "" && (now - ts) < 60) print cmd
            }' | head -20
          echo ""
          echo "--- auth.log (last 30 lines) ---"
          tail -30 /var/log/auth.log 2>/dev/null || journalctl -u ssh --since "5 minutes ago" --no-pager 2>/dev/null | tail -30
          echo ""
          echo "--- syslog (last 20 lines) ---"
          tail -20 /var/log/syslog 2>/dev/null || journalctl --since "5 minutes ago" --no-pager 2>/dev/null | tail -20
          echo ""
          echo "--- auditd kill events (if available) ---"
          ausearch -k gs-kill-9 --start recent 2>/dev/null | tail -15
          echo ""
          echo "--- Connections to/from this host (active) ---"
          ss -tnp 2>/dev/null | head -20
          echo ""
          echo "--- Recent command history (all users) ---"
          for h in /root/.bash_history /home/*/.bash_history; do
            [[ -f "$h" ]] && echo ">>> $h" && tail -10 "$h"
          done
          echo ""
          echo "==============================================="
          echo ""
        } >> "$RECON_LOGFILE"

        r_warn "Evidence logged to: $RECON_LOGFILE"
        r_warn "Looking for respawn..."

        # Wait and see if it respawns
        sleep 5
        local new_pid
        new_pid=$(r_find_target_pid)
        if [[ -n "$new_pid" ]]; then
          r_ok "[$(date '+%H:%M:%S')] Respawned as PID $new_pid"
          r_get_pid_info "$new_pid" | tee -a "$RECON_LOGFILE"
          last_pid="$new_pid"
        else
          r_warn "Not respawned yet. Will keep polling."
          last_pid=""
        fi
      fi
    else
      # Try to find again
      local new_pid
      new_pid=$(r_find_target_pid)
      if [[ -n "$new_pid" ]]; then
        r_ok "[$(date '+%H:%M:%S')] Detected new PID $new_pid"
        r_get_pid_info "$new_pid" | tee -a "$RECON_LOGFILE"
        last_pid="$new_pid"
      fi
    fi

    sleep 2
  done
}

r_monitor_install() {
  r_section "INSTALLING PERSISTENT WATCHER"
  [[ "$EUID" -ne 0 ]] && r_die "Must be root to install watcher"

  local script_path
  script_path=$(readlink -f "$0" 2>/dev/null || echo "$0")
  local watcher_script="/usr/local/bin/.gs-watcher"
  cat > "$watcher_script" <<EOF
#!/bin/bash
# GSocket watcher - logs kills to $RECON_LOGFILE
LOGFILE="$RECON_LOGFILE"
mkdir -p "\$(dirname "\$LOGFILE")"
TARGET_PID=""
for p in /proc/[0-9]*; do
  exe=\$(readlink "\$p/exe" 2>/dev/null)
  [[ "\$exe" == *gs-netcat* ]] && TARGET_PID="\${p##*/}" && break
done
if [[ -z "\$TARGET_PID" ]]; then
  for p in /proc/[0-9]*; do
    cmdline=\$(tr '\\0' ' ' < "\$p/cmdline" 2>/dev/null)
    [[ "\$cmdline" == *gs-netcat* || "\$cmdline" == *gsocket* ]] && TARGET_PID="\${p##*/}" && break
  done
fi
if [[ -z "\$TARGET_PID" ]]; then exit 0; fi
if [[ ! -d "/proc/\$TARGET_PID" ]]; then
  echo "[\$(date '+%Y-%m-%d %H:%M:%S')] gs-netcat PID \$TARGET_PID killed" >> "\$LOGFILE"
  {
    echo "--- Snapshot ---"
    ps -eo pid,user,etime,args --sort=-start_time 2>/dev/null | head -15
    w 2>/dev/null
    ss -tnp 2>/dev/null | grep ':22 ' | head -5
    tail -10 /var/log/auth.log 2>/dev/null
  } >> "\$LOGFILE"
fi
EOF
  chmod 755 "$watcher_script"
  r_ok "Watcher script: $watcher_script"

  # Install cron every 5 min
  ( crontab -l 2>/dev/null | grep -v "$watcher_script"; echo "*/5 * * * * $watcher_script 2>/dev/null" ) | crontab -
  r_ok "Cron installed (every 5 min)"

  # Install systemd timer as well (redundant)
  cat > /etc/systemd/system/gs-watcher.service <<EOF
[Unit]
Description=System Activity Reporter
After=network.target

[Service]
Type=oneshot
ExecStart=$watcher_script
EOF
  cat > /etc/systemd/system/gs-watcher.timer <<EOF
[Unit]
Description=System Activity Reporter timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload 2>/dev/null
  systemctl enable --now gs-watcher.timer 2>/dev/null
  r_ok "Systemd timer installed (every 5 min)"

  # Setup auditd rules
  r_setup_auditd_kill_watch

  r_ok "Watcher installed. Logs at: $RECON_LOGFILE"
  r_info "View logs:    tail -f $RECON_LOGFILE"
  r_info "Uninstall:    rm $watcher_script /etc/systemd/system/gs-watcher.* && crontab -l | grep -v gs-watcher | crontab -"
}

# ============================================================================
# MODE: FORENSIC - Find all gs-chaos persistence layers
# ============================================================================

r_forensic_mode() {
  r_section "FORENSIC SCAN - Detecting all persistence layers"
  local total_findings=0

  # ---- 1. Binary files ----
  r_step "[1/11] Scanning for gs-netcat binary files"
  local found_any=0
  for p in "${RECON_KNOWN_PATHS[@]}"; do
    if [[ -e "$p" ]]; then
      r_found "$p"
      ls -la "$p" 2>/dev/null
      total_findings=$((total_findings + 1))
      found_any=1
    fi
  done
  # Find by name in common dirs
  for d in /root /home /tmp /var/tmp /dev/shm /usr/local /opt; do
    find "$d" -maxdepth 4 -type f \( -name 'gs-netcat' -o -name 'gs-dbus' -o -name '.gsocket*' -o -name 'dbus-update*' -o -name 'gs-dbus*' \) 2>/dev/null | while read -r p; do
      r_found "$p"
      ls -la "$p" 2>/dev/null
      file "$p" 2>/dev/null | head -1
    done
  done
  [[ $found_any -eq 0 ]] && r_clean "No known binary files found"

  # ---- 2. Secret files ----
  r_step "[2/11] Scanning for secret/port files"
  for p in "${RECON_SECRET_PATHS[@]}"; do
    if [[ -f "$p" ]]; then
      r_found "$p (content: $(cat "$p" 2>/dev/null | head -c 50))"
      total_findings=$((total_findings + 1))
    fi
  done
  for h in /root /home/*; do
    for f in "$h/.gsocket-secret" "$h/.gsocket-port"; do
      [[ -f "$f" ]] && r_found "$f (content: $(cat "$f" 2>/dev/null | head -c 50))" && total_findings=$((total_findings + 1))
    done
  done

  # ---- 3. Process masquerading ----
  r_step "[3/11] Scanning for masqueraded processes"
  local kernel_thread_suspicious=0
  for p in /proc/[0-9]*; do
    local pid="${p##*/}"
    local comm exe cmdline
    comm=$(cat "$p/comm" 2>/dev/null)
    exe=$(readlink "$p/exe" 2>/dev/null)
    cmdline=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    # Real kernel threads have empty exe
    if [[ "$comm" =~ ^\[.*\]$ && -n "$exe" ]]; then
      r_found "PID $pid: comm='$comm' but exe=$exe (fake kernel thread!)"
      ps -o pid,ppid,user,lstart,args -p "$pid" 2>/dev/null
      kernel_thread_suspicious=$((kernel_thread_suspicious + 1))
      total_findings=$((total_findings + 1))
    fi
    # -bash with non-bash exe = fileless gsocket
    if [[ "$comm" == "-bash" && -n "$exe" && "$exe" != *bash ]]; then
      r_found "PID $pid: comm='-bash' but exe=$exe (likely fileless gsocket!)"
      ps -o pid,ppid,user,lstart,args -p "$pid" 2>/dev/null
      total_findings=$((total_findings + 1))
    fi
    # Anything mentioning gs-netcat/gsocket in cmdline
    if [[ "$cmdline" == *gs-netcat* || "$cmdline" == *gsocket* ]]; then
      r_found "PID $pid: cmdline contains gs-netcat/gsocket: $cmdline"
      total_findings=$((total_findings + 1))
    fi
  done
  [[ $kernel_thread_suspicious -eq 0 ]] && r_clean "No fake kernel threads"

  # ---- 4. memfd (fileless) ----
  r_step "[4/11] Scanning for memfd (fileless) processes"
  local memfd_count=0
  while read -r fd; do
    [[ -z "$fd" ]] && continue
    local pid
    pid=$(echo "$fd" | cut -d/ -f3)
    r_found "memfd at $fd (PID $pid, comm=$(cat /proc/$pid/comm 2>/dev/null))"
    ls -la "$fd" 2>/dev/null
    memfd_count=$((memfd_count + 1))
    total_findings=$((total_findings + 1))
  done < <(find /proc/*/fd/ -lname '/memfd:*' 2>/dev/null)
  [[ $memfd_count -eq 0 ]] && r_clean "No memfd processes"

  # ---- 5. Cron jobs ----
  r_step "[5/11] Scanning crontabs"
  for u in $(cut -d: -f1 /etc/passwd 2>/dev/null) root; do
    crontab -u "$u" -l 2>/dev/null | grep -iE 'gs-netcat|gsocket|kworker|dbus-update' | while read -r line; do
      r_found "cron ($u): $line"
      total_findings=$((total_findings + 1))
    done
  done
  # System cron dirs
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    ls "$d" 2>/dev/null | grep -iE 'gs-|gsocket|dbus-update' | while read -r f; do
      r_found "$d/$f"
      cat "$d/$f" 2>/dev/null | head -10
      total_findings=$((total_findings + 1))
    done
  done
  # /etc/crontab
  grep -iE 'gs-netcat|gsocket|kworker|dbus-update' /etc/crontab 2>/dev/null | while read -r line; do
    r_found "/etc/crontab: $line"
    total_findings=$((total_findings + 1))
  done

  # ---- 6. Systemd units & timers ----
  r_step "[6/11] Scanning systemd units & timers"
  systemctl list-unit-files 2>/dev/null | grep -iE 'gs-|gsocket|dbus-update|gs-watcher' | while read -r line; do
    r_found "unit: $line"
    total_findings=$((total_findings + 1))
  done
  systemctl list-timers --all 2>/dev/null | grep -iE 'gs-|gsocket|dbus-update|gs-watcher' | while read -r line; do
    r_found "timer: $line"
    total_findings=$((total_findings + 1))
  done
  # Check specific files
  for f in /etc/systemd/system/dbus-update.service /etc/systemd/system/dbus-update.timer \
           /etc/systemd/system/gs-dbus.service /etc/systemd/system/gs-watcher.service \
           /etc/systemd/system/gs-watcher.timer \
           /root/.config/systemd/user/gs-dbus.service; do
    [[ -f "$f" ]] && r_found "$f exists" && cat "$f" && total_findings=$((total_findings + 1))
  done

  # ---- 7. Shell RC files ----
  r_step "[7/11] Scanning shell RC files"
  for f in /root/.bashrc /root/.zshrc /root/.bash_profile /root/.bash_login /root/.profile \
           /home/*/.bashrc /home/*/.zshrc /home/*/.bash_profile /home/*/.bash_login /home/*/.profile; do
    [[ -f "$f" ]] || continue
    while read -r line; do
      [[ -z "$line" ]] && continue
      r_found "$f: $line"
      total_findings=$((total_findings + 1))
    done < <(grep -nE 'gs-netcat|gsocket|exec -a.*kworker|GSOCKET_ARGS' "$f" 2>/dev/null)
  done

  # ---- 8. SSH backdoors ----
  r_step "[8/11] Scanning SSH backdoors"
  for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [[ -f "$f" ]] || continue
    while read -r line; do
      [[ -z "$line" ]] && continue
      r_found "SSH key: $f"
      echo "    $line"
      total_findings=$((total_findings + 1))
    done < "$f"
  done
  # ForceCommand in sshd_config
  while read -r line; do
    r_found "sshd_config: $line"
    total_findings=$((total_findings + 1))
  done < <(grep -nE 'ForceCommand|gs-netcat|gsocket' /etc/ssh/sshd_config 2>/dev/null)

  # ---- 9. LD_PRELOAD rootkit ----
  r_step "[9/11] Scanning for LD_PRELOAD rootkit"
  if [[ -f /etc/ld.so.preload ]]; then
    r_found "/etc/ld.so.preload exists"
    cat /etc/ld.so.preload | while read -r line; do
      [[ -n "$line" ]] && r_found "preload entry: $line"
    done
    total_findings=$((total_findings + 1))
  fi
  for lib in /usr/lib/x86_64-linux-gnu/libdbus-glib.so.0 \
             /usr/lib/x86_64-linux-gnu/libdbus-2.so.0; do
    [[ -f "$lib" ]] && file "$lib" 2>/dev/null | grep -v 'shared object' >/dev/null && {
      r_found "Suspicious lib: $lib (not standard shared object)"
      ls -la "$lib"
      total_findings=$((total_findings + 1))
    }
  done

  # ---- 10. Network connections ----
  r_step "[10/11] Scanning network connections"
  ss -tnp 2>/dev/null | grep -iE 'gs-netcat|kworker' | while read -r line; do
    r_found "Net: $line"
    total_findings=$((total_findings + 1))
  done
  # Connections to GSRN endpoints (port 7350 is gsocket-specific)
  ss -tn 2>/dev/null | awk '$5 ~ /:(443|53|80|22|7350)$/ {print "  [i] "$0}' | head -10

  # ---- 11. DNS rotation script ----
  r_step "[11/11] Scanning for DNS rotation"
  for s in /usr/local/bin/.dbus-update-helper /usr/local/bin/dbus-update-helper; do
    if [[ -f "$s" ]]; then
      r_found "Rotation script: $s"
      head -10 "$s" 2>/dev/null
      total_findings=$((total_findings + 1))
    fi
  done
  # Check cron for rotation
  crontab -l 2>/dev/null | grep -iE 'rotate|dbus-update-helper' | while read -r line; do
    r_found "Rotation cron: $line"
    total_findings=$((total_findings + 1))
  done

  # ---- Summary ----
  echo ""
  r_section "FORENSIC SUMMARY"
  if [[ $total_findings -gt 0 ]]; then
    r_warn "Found $total_findings suspicious items"
  else
    r_ok "No GSocket artifacts detected - system appears clean"
  fi
}

# ============================================================================
# MODE: AUDIT - Map lab web server
# ============================================================================

r_audit_mode() {
  r_section "LAB WEB SERVER AUDIT"

  # ---- 1. OS & system info ----
  r_step "[1/12] System info"
  echo "  Hostname: $(hostname)"
  echo "  OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2- | tr -d '"')"
  echo "  Kernel: $(uname -r)"
  echo "  Uptime: $(uptime -p 2>/dev/null || uptime)"
  echo "  IP addresses:"
  ip -4 addr show 2>/dev/null | awk '/inet / {print "    "$2" on "$NF}' | head -10
  echo "  Public IP: $(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo 'unknown')"

  # ---- 2. Web servers installed ----
  r_step "[2/12] Web servers detected"
  for bin in apache2 httpd nginx lighttpd caddy traefik node python3 php; do
    local path
    path=$(command -v "$bin" 2>/dev/null)
    if [[ -n "$path" ]]; then
      local ver
      ver=$("$bin" -v 2>&1 | head -1)
      r_info "$bin: $path ($ver)"
    fi
  done
  # Apache via apachectl
  command -v apachectl >/dev/null 2>&1 && apachectl -v 2>/dev/null | head -2
  # PHP versions
  command -v php >/dev/null 2>&1 && php -v 2>/dev/null | head -1

  # ---- 3. Listening ports ----
  r_step "[3/12] Listening ports"
  ss -tlnp 2>/dev/null | awk 'NR==1 || /LISTEN/ {print "  "$0}'

  # ---- 4. Web server config files ----
  r_step "[4/12] Web server config files"
  # Apache
  for f in /etc/apache2/apache2.conf /etc/apache2/ports.conf \
           /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf; do
    [[ -f "$f" ]] && {
      r_info "Apache: $f"
      grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null | head -30 | sed 's/^/    /'
    }
  done
  # Nginx
  for f in /etc/nginx/nginx.conf /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
    [[ -f "$f" ]] && {
      r_info "Nginx: $f"
      grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null | head -30 | sed 's/^/    /'
    }
  done
  # Caddy
  for f in /etc/caddy/Caddyfile /etc/caddy/caddy.json; do
    [[ -f "$f" ]] && r_info "Caddy: $f"
  done

  # ---- 5. Document roots ----
  r_step "[5/12] Web document roots"
  # Apache vhosts
  apache2ctl -S 2>/dev/null | grep -E 'DocumentRoot|VirtualHost' | head -20
  # Nginx server roots
  grep -rE '^\s*root\s' /etc/nginx/ 2>/dev/null | head -20
  # Common defaults
  for d in /var/www/html /var/www /usr/share/nginx/html /srv/http /srv/www; do
    [[ -d "$d" ]] && {
      r_info "Document root: $d"
      ls -la "$d" 2>/dev/null | head -10 | sed 's/^/    /'
    }
  done

  # ---- 6. PHP config ----
  r_step "[6/12] PHP configuration"
  if command -v php >/dev/null 2>&1; then
    echo "  PHP version: $(php -v 2>/dev/null | head -1)"
    echo "  PHP ini: $(php --ini 2>/dev/null | grep Loaded | awk '{print $NF}')"
    echo "  Disabled functions:"
    php -i 2>/dev/null | grep 'disable_functions' | sed 's/^/    /'
    echo "  Open basedir:"
    php -i 2>/dev/null | grep 'open_basedir' | sed 's/^/    /'
    echo "  Expose PHP:"
    php -i 2>/dev/null | grep 'expose_php' | sed 's/^/    /'
    # PHP-FPM pools
    for f in /etc/php/*/fpm/pool.d/*.conf; do
      [[ -f "$f" ]] && r_info "PHP-FPM pool: $f"
    done
  fi

  # ---- 7. Databases ----
  r_step "[7/12] Databases"
  for db in mysql mariadb postgres psql mongo redis memcached sqlite3; do
    command -v "$db" >/dev/null 2>&1 && {
      r_info "$db: $(command -v $db)"
      case "$db" in
        mysql|mariadb)
          mysql --version 2>/dev/null
          ss -tln 2>/dev/null | grep ':3306 ' && r_info "  MySQL on 3306"
          [[ -f /root/.my.cnf ]] && r_found "/root/.my.cnf exists (creds!)"
          [[ -f /etc/mysql/debian.cnf ]] && r_found "/etc/mysql/debian.cnf exists"
          ;;
        postgres|psql)
          psql --version 2>/dev/null
          ss -tln 2>/dev/null | grep ':5432 ' && r_info "  PG on 5432"
          ls /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | while read -r f; do
            r_info "  pg_hba.conf: $f"
            grep -vE '^\s*#|^\s*$' "$f" | head -10 | sed 's/^/    /'
          done
          ;;
        redis)
          redis-cli INFO server 2>/dev/null | head -5
          ss -tln 2>/dev/null | grep ':6379 ' && r_info "  Redis on 6379"
          [[ -f /etc/redis/redis.conf ]] && grep -E '^(requirepass|bind)' /etc/redis/redis.conf
          ;;
      esac
    }
  done

  # ---- 8. Web apps (CMS detection) ----
  r_step "[8/12] Web applications detected"
  # WordPress
  for d in /var/www/html /var/www /usr/share/nginx/html /srv/http /srv/www; do
    [[ -d "$d/wp-includes" ]] && r_found "WordPress at $d"
    [[ -d "$d/wp-admin" ]] && r_found "WordPress admin: $d/wp-admin/"
    [[ -f "$d/wp-config.php" ]] && {
      r_found "WordPress config: $d/wp-config.php"
      grep -E "DB_|AUTH_KEY|table_prefix" "$d/wp-config.php" 2>/dev/null | sed 's/^/    /'
    }
    # Joomla
    [[ -f "$d/configuration.php" ]] && r_found "Joomla at $d"
    # Drupal
    [[ -f "$d/sites/default/settings.php" ]] && r_found "Drupal at $d"
    # Laravel
    [[ -f "$d/artisan" ]] && r_found "Laravel at $d"
    # CodeIgniter
    [[ -d "$d/application" ]] && r_found "CodeIgniter at $d"
  done
  # Find all wp-config.php
  find /var/www /home /srv -maxdepth 4 -name 'wp-config.php' 2>/dev/null | while read -r f; do
    r_found "WordPress config: $f"
  done

  # ---- 9. SSL certs (potential info leak) ----
  r_step "[9/12] SSL certificates"
  for d in /etc/letsencrypt/live /etc/ssl/certs /etc/ssl/private; do
    [[ -d "$d" ]] && find "$d" -name '*.pem' -o -name '*.crt' -o -name '*.key' 2>/dev/null | head -5 | while read -r f; do
      r_info "$f"
    done
  done
  # Certbot
  command -v certbot >/dev/null 2>&1 && certbot certificates 2>/dev/null | head -20

  # ---- 10. Docker / containers ----
  r_step "[10/12] Docker & containers"
  command -v docker >/dev/null 2>&1 && {
    r_info "Docker: $(docker --version 2>/dev/null)"
    echo "  Containers:"
    docker ps -a 2>/dev/null | head -10 | sed 's/^/    /'
    echo "  Images:"
    docker images 2>/dev/null | head -10 | sed 's/^/    /'
  }
  command -v podman >/dev/null 2>&1 && podman ps -a 2>/dev/null | head -5
  # LXC
  command -v lxc >/dev/null 2>&1 && lxc list 2>/dev/null | head -5

  # ---- 11. Important system files ----
  r_step "[11/12] System files of interest"
  for f in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/hosts /etc/resolv.conf; do
    [[ -f "$f" ]] && r_info "$f ($(stat -c '%s bytes, owner=%U mode=%a' "$f" 2>/dev/null))"
  done
  # World-writable files (excluding /tmp, /dev/shm)
  r_warn "World-writable non-tmp files (top 20):"
  find / -xdev -type f -perm -0002 ! -path '/tmp/*' ! -path '/dev/shm/*' ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20 | sed 's/^/    /'
  # SUID binaries
  r_warn "SUID binaries (top 20):"
  find / -xdev -type f -perm -4000 2>/dev/null | head -20 | sed 's/^/    /'
  # Users with login shell
  r_info "Users with login shell:"
  grep -E '/(bash|sh|zsh|fish)$' /etc/passwd 2>/dev/null | sed 's/^/    /'

  # ---- 12. Cron & scheduled tasks ----
  r_step "[12/12] Scheduled tasks (legit + suspicious)"
  echo "  User crontabs:"
  for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
    crontab -u "$u" -l 2>/dev/null | grep -v '^#' | grep -v '^$' | head -5 | while read -r line; do
      echo "    [$u] $line"
    done
  done
  echo "  /etc/crontab:"
  grep -vE '^\s*#|^\s*$' /etc/crontab 2>/dev/null | sed 's/^/    /'
  echo "  /etc/cron.d/:"
  ls /etc/cron.d/ 2>/dev/null | sed 's/^/    /'
}

# ============================================================================
# MODE: HUNT - Profile attacker activity
# ============================================================================

r_hunt_mode() {
  r_section "ATTACKER PROFILE & ACTIVITY HUNT"

  # ---- 1. Currently logged in ----
  r_step "[1/8] Currently logged in users"
  w 2>/dev/null | sed 's/^/  /'
  echo ""
  who -a 2>/dev/null | sed 's/^/  /'

  # ---- 2. Last logins (history) ----
  r_step "[2/8] Recent login history (last 30)"
  last -a -F -n 30 2>/dev/null | head -30 | sed 's/^/  /'
  echo ""
  echo "  Failed login attempts (last 20):"
  lastb -a -n 20 2>/dev/null | head -20 | sed 's/^/  /' || \
    grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20 | sed 's/^/  /'

  # ---- 3. SSH brute force indicators ----
  r_step "[3/8] SSH brute force indicators"
  grep -c 'Failed password' /var/log/auth.log 2>/dev/null | while read -r n; do
    echo "  Total failed attempts: $n"
  done
  # Top source IPs
  echo "  Top 10 source IPs of failed logins:"
  grep 'Failed password' /var/log/auth.log 2>/dev/null | \
    grep -oE 'from [0-9.]+' | awk '{print $2}' | \
    sort | uniq -c | sort -rn | head -10 | sed 's/^/    /'

  # Top usernames attempted
  echo "  Top 10 attempted usernames:"
  grep 'Failed password' /var/log/auth.log 2>/dev/null | \
    grep -oE 'for (invalid user )?[a-zA-Z0-9_-]+' | \
    sed 's/for //;s/invalid user //' | \
    sort | uniq -c | sort -rn | head -10 | sed 's/^/    /'

  # ---- 4. SSH session IPs (last successful logins) ----
  r_step "[4/8] Successful SSH logins by IP"
  grep 'Accepted' /var/log/auth.log 2>/dev/null | \
    grep -oE 'from [0-9.]+' | awk '{print $2}' | \
    sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'

  # ---- 5. User command histories ----
  r_step "[5/8] Recent command history by user"
  for h in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do
    [[ -f "$h" ]] || continue
    echo "  >>> $h (last 20 commands):"
    tail -20 "$h" 2>/dev/null | sed 's/^/    /'
  done

  # ---- 6. Recently modified files (last 24h) ----
  r_step "[6/8] Recently modified files (last 24h)"
  find / -xdev -type f -mtime -1 \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/run/*' \
    ! -path '/tmp/*' ! -path '/var/log/*' \
    2>/dev/null | head -50 | sed 's/^/  /'

  # ---- 7. Active outbound connections ----
  r_step "[7/8] Active outbound connections"
  ss -tnp 2>/dev/null | awk 'NR>1 && $1=="ESTAB" {print "  "$0}' | head -20
  echo ""
  echo "  Suspicious ports (gsocket, reverse shells):"
  ss -tnp 2>/dev/null | awk '$5 ~ /:(4444|4445|1337|7350|9001)$/ {print "  [!] "$0}'

  # ---- 8. Recently started processes ----
  r_step "[8/8] Recently started processes (last 5 min)"
  ps -eo pid,lstart,user,args --sort=-lstart 2>/dev/null | awk -v now="$(date +%s)" '
    NR==1 {print "  "$0; next}
    {
      ts_str=$2" "$3" "$4" "$5" "$6
      "date -d \""ts_str"\" +%s 2>/dev/null" | getline ts
      if (ts != "" && (now - ts) < 300) print "  "$0
    }' | head -20

  # ---- Suspicious activity summary ----
  r_section "SUSPICIOUS ACTIVITY SUMMARY"
  local susp_count=0

  # Check for many failed logins
  local fail_count
  fail_count=$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0)
  if [[ "$fail_count" -gt 50 ]]; then
    r_warn "High number of failed SSH attempts: $fail_count"
    susp_count=$((susp_count + 1))
  fi

  # Check for new users added recently
  echo "  Users created in last 7 days:"
  find /home -maxdepth 1 -type d -mtime -7 2>/dev/null | sed 's/^/    /'

  # Check sudo usage
  echo "  Recent sudo usage:"
  grep 'sudo' /var/log/auth.log 2>/dev/null | tail -10 | sed 's/^/    /'
}

# ============================================================================
# MODE: TRIPWIRE - Plant canaries to detect investigation
# ============================================================================

r_tripwire_plant() {
  r_section "PLANTING TRIPWIRES (canaries)"

  mkdir -p "$RECON_TRIPWIRE_DIR" 2>/dev/null || r_die "Cannot create tripwire dir: $RECON_TRIPWIRE_DIR"
  local marker_file="$RECON_TRIPWIRE_DIR/.marker"
  : > "$marker_file"
  echo "planted: $(date)" > "$marker_file"

  # Clear previous canary list
  : > "$RECON_TRIPWIRE_DIR/canaries.list"

  # Canary 1: fake secret file (looks valuable)
  local canary1="/root/.gsocket-secret-backup"
  if echo "TRIPWIRE_CANARY_1_BACKUP_SECRET_$(date +%s)" > "$canary1" 2>/dev/null; then
    chmod 600 "$canary1" 2>/dev/null
    echo "$canary1" >> "$RECON_TRIPWIRE_DIR/canaries.list"
    r_ok "Canary 1: $canary1 (fake secret)"
  else
    r_warn "Canary 1: cannot write $canary1 (not root?) - skipping"
  fi

  # Canary 2: fake cron job that "calls home"
  local canary2="/root/.cache/.backup-creds.txt"
  if mkdir -p "$(dirname "$canary2")" 2>/dev/null && \
     cat > "$canary2" <<EOF
# Database backup credentials
# DO NOT DELETE
db_user: root
db_pass: TRIPWIRE_CANARY_2_$(date +%s)
EOF
  then
    echo "$canary2" >> "$RECON_TRIPWIRE_DIR/canaries.list"
    r_ok "Canary 2: $canary2 (fake creds)"
  else
    r_warn "Canary 2: cannot write $canary2 - skipping"
  fi

  # Canary 3: fake history file
  local canary3="/root/.bash_history.canary"
  if cat > "$canary3" <<EOF
nmap -sS 10.0.0.0/24
hydra -L users.txt -P rockyou.txt ssh://target
cat /etc/shadow
mysql -u root -p"TRIPWIRE_CANARY_3_$(date +%s)"
EOF
  then
    echo "$canary3" >> "$RECON_TRIPWIRE_DIR/canaries.list"
    r_ok "Canary 3: $canary3 (fake history)"
  else
    r_warn "Canary 3: cannot write $canary3 - skipping"
  fi

  # Canary 4: in suspicious dir
  local canary4="/tmp/.gs-fake-canary"
  if echo "TRIPWIRE_CANARY_4_$(date +%s)" > "$canary4" 2>/dev/null; then
    chmod 600 "$canary4"
    echo "$canary4" >> "$RECON_TRIPWIRE_DIR/canaries.list"
    r_ok "Canary 4: $canary4 (hidden in /tmp)"
  fi

  # Canary 5: in authorized_keys (comment line)
  if [[ -f /root/.ssh/authorized_keys ]] && [[ -w /root/.ssh/authorized_keys ]]; then
    if ! grep -q "TRIPWIRE_CANARY" /root/.ssh/authorized_keys 2>/dev/null; then
      echo "# TRIPWIRE_CANARY_5_$(date +%s)" >> /root/.ssh/authorized_keys
      echo "/root/.ssh/authorized_keys" >> "$RECON_TRIPWIRE_DIR/canaries.list"
      r_ok "Canary 5: marker added to /root/.ssh/authorized_keys"
    fi
  fi

  # Canary 6: in user home (works as non-root)
  local canary6="$HOME/.config/.backup-token"
  if mkdir -p "$(dirname "$canary6")" 2>/dev/null && \
     echo "TRIPWIRE_CANARY_6_$(date +%s)" > "$canary6"; then
    chmod 600 "$canary6"
    echo "$canary6" >> "$RECON_TRIPWIRE_DIR/canaries.list"
    r_ok "Canary 6: $canary6 (in user home)"
  fi

  r_ok "Tripwire planted. $(wc -l < "$RECON_TRIPWIRE_DIR/canaries.list") canaries active."
  r_info "List: $RECON_TRIPWIRE_DIR/canaries.list"
  r_info "Wait for investigation, then run: $0 tripwire --check"
}

r_tripwire_check() {
  r_section "CHECKING TRIPWIRES (canaries)"
  local triggered=0

  while read -r canary; do
    [[ -z "$canary" ]] && continue
    if [[ ! -e "$canary" ]]; then
      r_found "MISSING: $canary (investigator deleted it!)"
      triggered=$((triggered + 1))
    else
      # Check if accessed (mtime vs atime)
      local atime mtime
      atime=$(stat -c '%X' "$canary" 2>/dev/null)
      mtime=$(stat -c '%Y' "$canary" 2>/dev/null)
      if [[ -n "$atime" && -n "$mtime" && "$atime" -gt "$mtime" ]]; then
        local accessed_ago=$(( $(date +%s) - atime ))
        if [[ "$accessed_ago" -lt 3600 ]]; then
          r_warn "ACCESSED: $canary (accessed ${accessed_ago}s ago)"
          triggered=$((triggered + 1))
        else
          r_info "OK: $canary (untouched)"
        fi
      fi
    fi
  done < "$RECON_TRIPWIRE_DIR/canaries.list" 2>/dev/null

  # Check authorized_keys for removed marker
  if [[ -f /root/.ssh/authorized_keys ]]; then
    if ! grep -q "TRIPWIRE_CANARY_5" /root/.ssh/authorized_keys 2>/dev/null; then
      r_found "Canary 5 missing from /root/.ssh/authorized_keys (investigator edited it!)"
      triggered=$((triggered + 1))
    fi
  fi

  if [[ $triggered -gt 0 ]]; then
    r_warn "$triggered tripwire(s) triggered - investigation detected!"
    r_info "Check who was logged in: w && last -n 20"
    r_info "Check command histories: for h in /root/.bash_history /home/*/.bash_history; do tail -20 \$h; done"
    r_info "Check auth log: grep -E 'Accepted|su:' /var/log/auth.log | tail -30"
  else
    r_ok "No tripwires triggered (or no investigation yet)"
  fi
}

# ============================================================================
# MODE: ALL
# ============================================================================

r_all_mode() {
  r_forensic_mode
  r_audit_mode
  r_hunt_mode

  r_section "COMPREHENSIVE SUMMARY"
  r_warn "All three scans complete. Review output above."
  r_info "Recommended next steps:"
  echo "  1. Investigate each [FOUND] item"
  echo "  2. For attacker side: run '$0 monitor --install' to track future kills"
  echo "  3. For defender side: clean each finding, then run '$0 forensic' again"
  echo "  4. To detect future attacks: run '$0 tripwire'"
}

# ============================================================================
# MAIN
# ============================================================================

case "$RECON_MODE" in
  monitor)
    if [[ "${RECON_INSTALL_WATCHER:-0}" == "1" ]]; then
      r_monitor_install
    else
      r_monitor_loop
    fi
    ;;
  forensic) r_forensic_mode ;;
  audit)    r_audit_mode ;;
  hunt)     r_hunt_mode ;;
  tripwire)
    if [[ "${RECON_TRIPWIRE_CHECK:-0}" == "1" ]]; then
      r_tripwire_check
    else
      r_tripwire_plant
    fi
    ;;
  all) r_all_mode ;;
  -h|--help|help) r_help ;;
  *) r_die "Unknown mode: $RECON_MODE. Use --help." ;;
esac

exit 0
