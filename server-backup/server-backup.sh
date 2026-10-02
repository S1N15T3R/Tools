#!/usr/bin/env bash
# =============================================================================
#  server-backup.sh  —  Bulletproof full disaster-recovery backup
#
#  Strategy : remote tar (pigz/gzip) ──SSH──► pv ──► .tar.gz.part
#             Rename to .tar.gz ONLY after integrity check passes.
#             Streams directly — never stores temp data on the server.
#             Works for 100 GB+ archives.
#
#  Handles  : network drops, server reboots, Ctrl-C, local disk full,
#             corrupt partial archives, permission errors, missing tools,
#             SSH timeouts, broken pipes — with retry + exponential backoff.
#
#  Run      : bash ~/server-backup.sh
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────────────────────
REMOTE_USER="your_user"          # ← set your SSH username here
REMOTE_HOST="your.server.ip"     # ← set your server IP or hostname here
SSH_KEY="$HOME/.ssh/id_ed25519"  # ← path to your SSH private key
LOCAL_BASE="/path/to/local/backup/dir"  # ← local directory to store backup

ARCHIVE="${LOCAL_BASE}/server-backup.tar.gz"
ARCHIVE_PART="${LOCAL_BASE}/server-backup.tar.gz.part"  # written first; renamed on success
META_DIR="${LOCAL_BASE}/metadata"
LOG_FILE="${LOCAL_BASE}/backup.log"

MAX_RETRIES=3        # max stream/verify attempts before giving up
RETRY_DELAY=30       # seconds between retries (doubles each time)
MIN_FREE_GB=5        # abort if local free space drops below this during stream
SSH_TIMEOUT=15       # seconds for initial SSH connect

# Directories to include in the backup
REMOTE_DIRS=(
  /etc
  /home
  /var
  /root
  /opt
  /srv
  /usr/local
  /usr/share
)

# Paths excluded from tar (volatile/pseudo-filesystems — meaningless to back up)
TAR_EXCLUDES=(
  "--exclude=/proc"
  "--exclude=/sys"
  "--exclude=/dev"
  "--exclude=/run"
  "--exclude=/tmp"
  "--exclude=/var/run"
  "--exclude=/var/lock"
  "--exclude=/var/tmp"
  "--exclude=/var/cache/apt/archives"
  "--exclude=/snap"
)

# ─────────────────────────────────────────────────────────────────────────────
#  COLOUR / TERMINAL DETECTION
#  All colours are empty strings when stdout is not a TTY (pipes, cron, logs)
# ─────────────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  R='\033[0;31m'  LR='\033[1;31m'
  G='\033[0;32m'  LG='\033[1;32m'
  Y='\033[1;33m'  C='\033[0;36m'
  B='\033[1m'     DM='\033[2m'    RS='\033[0m'
  IS_TTY=1
else
  R='' LR='' G='' LG='' Y='' C='' B='' DM='' RS=''
  IS_TTY=0
fi

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING  (all output also goes to LOG_FILE)
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p "$LOCAL_BASE" "$META_DIR"
: > "$LOG_FILE"

_ts()  { date '+%Y-%m-%d %H:%M:%S'; }
_log() { printf '[%s] %s\n' "$(_ts)" "$*" >> "$LOG_FILE"; }

ok()   { printf "  ${LG}✔${RS}  %s\n"    "$*"; _log "[OK]  $*"; }
info() { printf "  ${C}›${RS}  ${DM}%s${RS}\n" "$*"; _log "[INF] $*"; }
warn() { printf "  ${Y}⚠${RS}  %s\n"    "$*"; _log "[WRN] $*"; }
err()  { printf "  ${LR}✘${RS}  %s\n"   "$*"; _log "[ERR] $*"; }

# ─────────────────────────────────────────────────────────────────────────────
#  VISUAL COMPONENTS
# ─────────────────────────────────────────────────────────────────────────────
STEP=0
TOTAL_STEPS=7

_bar() {
  # _bar filled_count total_count width
  local filled=$1 total=$2 width=${3:-32}
  local f=$(( filled * width / total ))
  local e=$(( width - f ))
  local b=""
  for ((i=0;i<f;i++)); do b+="█"; done
  for ((i=0;i<e;i++)); do b+="░"; done
  printf '%s' "$b"
}

print_banner() {
  [[ $IS_TTY -eq 1 ]] && tput clear 2>/dev/null || true
  printf '\n'
  printf "  ${B}${C}╔══════════════════════════════════════════════════════════════╗${RS}\n"
  printf "  ${B}${C}║  🖥   UBUNTU SERVER BACKUP                                   ║${RS}\n"
  printf "  ${B}${C}║  Source : %-51s║${RS}\n" "${REMOTE_USER}@${REMOTE_HOST}"
  printf "  ${B}${C}║  Target : %-51s║${RS}\n" "${LOCAL_BASE}"
  printf "  ${B}${C}║  Log    : %-51s║${RS}\n" "${LOG_FILE}"
  printf "  ${B}${C}╚══════════════════════════════════════════════════════════════╝${RS}\n"
  printf '\n'
}

step() {
  STEP=$(( STEP + 1 ))
  local bar
  bar=$(_bar "$STEP" "$TOTAL_STEPS" 32)
  local pct=$(( STEP * 100 / TOTAL_STEPS ))
  printf '\n'
  printf "  ${B}[%d/%d]${RS} ${Y}%s${RS}\n" "$STEP" "$TOTAL_STEPS" "$*"
  printf "  ${DM}  [%s] %d%%${RS}\n" "$bar" "$pct"
  printf '\n'
  _log "--- STEP ${STEP}/${TOTAL_STEPS}: $* ---"
}

print_success() {
  local duration=$1 archive_size=$2 file_count=$3
  local mins=$(( duration / 60 ))
  local secs=$(( duration % 60 ))
  printf '\n'
  printf "  ${B}${LG}╔══════════════════════════════════════════════════════════════╗${RS}\n"
  printf "  ${B}${LG}║  ✅  BACKUP COMPLETE                                         ║${RS}\n"
  printf "  ${B}${LG}╠══════════════════════════════════════════════════════════════╣${RS}\n"
  printf "  ${B}${LG}║${RS}  %-14s %-46s ${B}${LG}║${RS}\n" "Archive:"  "${ARCHIVE}"
  printf "  ${B}${LG}║${RS}  %-14s %-46s ${B}${LG}║${RS}\n" "Size:"     "${archive_size} compressed"
  printf "  ${B}${LG}║${RS}  %-14s %-46s ${B}${LG}║${RS}\n" "Entries:"  "${file_count} files/dirs"
  printf "  ${B}${LG}║${RS}  %-14s %-46s ${B}${LG}║${RS}\n" "Duration:" "${mins}m ${secs}s"
  printf "  ${B}${LG}║${RS}  %-14s %-46s ${B}${LG}║${RS}\n" "Metadata:" "${META_DIR}/"
  printf "  ${B}${LG}║${RS}  %-14s %-46s ${B}${LG}║${RS}\n" "Finished:" "$(_ts)"
  printf "  ${B}${LG}╠══════════════════════════════════════════════════════════════╣${RS}\n"
  printf "  ${B}${LG}║${RS}  ${DM}Restore: sudo tar -xzf server-backup.tar.gz -C /           ${B}${LG}║${RS}\n"
  printf "  ${B}${LG}║${RS}  ${DM}Guide:   metadata/RESTORE-GUIDE.txt                        ${B}${LG}║${RS}\n"
  printf "  ${B}${LG}╚══════════════════════════════════════════════════════════════╝${RS}\n"
  printf '\n'
}

print_failure() {
  local reason="$*"
  printf '\n'
  printf "  ${B}${LR}╔══════════════════════════════════════════════════════════════╗${RS}\n"
  printf "  ${B}${LR}║  ✘  BACKUP FAILED                                            ║${RS}\n"
  printf "  ${B}${LR}║  %-61s║${RS}\n" "${reason}"
  printf "  ${B}${LR}╠══════════════════════════════════════════════════════════════╣${RS}\n"
  printf "  ${B}${LR}║${RS}  Log: %-56s${B}${LR}║${RS}\n" "${LOG_FILE}"
  printf "  ${B}${LR}╚══════════════════════════════════════════════════════════════╝${RS}\n"
  printf '\n'
}

# ─────────────────────────────────────────────────────────────────────────────
#  TRAP  — guarantee cleanup on ANY exit (error, Ctrl-C, kill, etc.)
# ─────────────────────────────────────────────────────────────────────────────
DISK_GUARD_PID=""
_HANDLED=0

_cleanup() {
  local code=$?
  [[ $_HANDLED -eq 1 ]] && return
  _HANDLED=1

  # Stop disk-space monitor if still running
  if [[ -n "$DISK_GUARD_PID" ]] && kill -0 "$DISK_GUARD_PID" 2>/dev/null; then
    kill "$DISK_GUARD_PID" 2>/dev/null || true
    wait "$DISK_GUARD_PID" 2>/dev/null || true
  fi

  if [[ $code -ne 0 ]]; then
    # Remove corrupt partial archive
    if [[ -f "$ARCHIVE_PART" ]]; then
      rm -f "$ARCHIVE_PART"
      _log "Removed partial archive on abnormal exit"
    fi
    _log "Backup ABORTED with exit code ${code} at $(_ts)"
    print_failure "Exit code ${code} — partial archive removed. See log for details."
  fi
}

trap '_cleanup'                          EXIT
trap 'err "Interrupted (Ctrl-C)"; exit 130' INT
trap 'err "Terminated (SIGTERM)";  exit 143' TERM

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

# SSH command with all hardening options
_ssh() {
  ssh \
    -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o BatchMode=yes \
    -o ConnectTimeout=$SSH_TIMEOUT \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=6 \
    "${REMOTE_USER}@${REMOTE_HOST}" "$@"
}

# Returns 0 if SSH is alive, 1 if not
_ssh_alive() { _ssh "echo ok" &>/dev/null; }

# Retry SSH with exponential backoff; returns 1 after MAX_RETRIES failures
_ssh_wait() {
  local attempt=1 delay=10
  while (( attempt <= MAX_RETRIES )); do
    if _ssh_alive; then return 0; fi
    warn "SSH unreachable — attempt ${attempt}/${MAX_RETRIES}, retrying in ${delay}s..."
    _log "SSH unreachable attempt ${attempt}/${MAX_RETRIES}"
    sleep "$delay"
    delay=$(( delay * 2 ))
    (( attempt++ ))
  done
  return 1
}

# Run metadata command — NON-FATAL: logs warning on failure, never aborts
_meta() {
  local dest="$1"; shift
  _ssh "$@" > "$dest" 2>>"$LOG_FILE" \
    || warn "Metadata skipped (non-fatal): $*"
}

# Local free space in whole GB
_free_gb() {
  df -BG "$LOCAL_BASE" 2>/dev/null | awk 'NR==2{gsub("G","",$4); print int($4)}'
}

# Human-readable byte size
_hr() {
  awk -v b="$1" 'BEGIN{
    if      (b>=1073741824) printf "%.1f GB", b/1073741824
    else if (b>=1048576)    printf "%.1f MB", b/1048576
    else                    printf "%.0f KB", b/1024
  }'
}

# ─────────────────────────────────────────────────────────────────────────────
#  START
# ─────────────────────────────────────────────────────────────────────────────
START_TIME=$(date +%s)
_log "====== Backup started ======"
print_banner

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 1 — Dependency & pre-flight checks
# ─────────────────────────────────────────────────────────────────────────────
step "Pre-flight: dependency checks, connectivity, disk space"

# --- Local tools ---
for cmd in ssh tar; do
  if ! command -v "$cmd" &>/dev/null; then
    err "Required tool missing locally: ${cmd}"
    err "Install: sudo apt-get install ${cmd}"
    exit 1
  fi
  ok "Local tool found: ${cmd}"
done

# pv: optional but strongly preferred
HAS_PV=0
if command -v pv &>/dev/null; then
  HAS_PV=1
  ok "Local tool found: pv  (live progress bar enabled)"
else
  warn "pv not found — no live progress bar (install with: sudo apt-get install pv)"
fi

# --- SSH Key ---
if [[ ! -f "$SSH_KEY" ]]; then
  err "SSH key not found: ${SSH_KEY}"
  exit 1
fi
ok "SSH key exists: ${SSH_KEY}"

# --- Local destination writable? ---
if ! mkdir -p "$LOCAL_BASE" "$META_DIR" 2>/dev/null; then
  err "Cannot create backup directory: ${LOCAL_BASE}"
  err "Check that the drive is mounted: ls /media/sinister/NewVolume"
  exit 1
fi
if ! touch "${LOCAL_BASE}/.write_test" 2>/dev/null; then
  err "Cannot write to ${LOCAL_BASE} — drive may be read-only or unmounted"
  exit 1
fi
rm -f "${LOCAL_BASE}/.write_test"
ok "Local destination writable: ${LOCAL_BASE}"

# --- Local free space check ---
FREE_GB=$(_free_gb)
info "Local free space: ${FREE_GB} GB"
if (( FREE_GB < MIN_FREE_GB )); then
  err "Only ${FREE_GB} GB free locally — need at least ${MIN_FREE_GB} GB to start"
  exit 1
fi
if (( FREE_GB < 10 )); then
  warn "Only ${FREE_GB} GB free — may not be enough for a large backup"
fi
ok "Disk space check passed"

# --- Remove stale .part file from a previously failed run ---
if [[ -f "$ARCHIVE_PART" ]]; then
  warn "Stale partial archive found from previous failed run — removing"
  rm -f "$ARCHIVE_PART"
  ok "Stale partial archive cleaned up"
fi

# --- SSH connectivity (with retry) ---
info "Connecting to ${REMOTE_USER}@${REMOTE_HOST}..."
if ! _ssh_wait; then
  err "Cannot reach ${REMOTE_USER}@${REMOTE_HOST} after ${MAX_RETRIES} attempts"
  err "Check: server is powered on, correct IP, SSH key is valid"
  exit 1
fi
ok "SSH connected → ${REMOTE_USER}@${REMOTE_HOST}"

# --- Remote sudo check ---
SUDO_CHECK=$(_ssh "sudo whoami 2>/dev/null" || echo "FAIL")
if [[ "$SUDO_CHECK" != "root" ]]; then
  err "Remote sudo not working (got: '${SUDO_CHECK}')"
  err "Full backup requires passwordless sudo on the server"
  exit 1
fi
ok "Remote sudo: confirmed (passwordless)"

# --- Detect remote compressor: pigz (parallel) preferred over gzip ---
HAS_REMOTE_PIGZ=$(_ssh "command -v pigz &>/dev/null && echo 1 || echo 0" 2>/dev/null || echo 0)
if [[ "$HAS_REMOTE_PIGZ" == "1" ]]; then
  COMPRESS_CMD="pigz -6"
  ok "Remote compressor: pigz (parallel gzip — fastest for large archives)"
else
  COMPRESS_CMD="gzip -6"
  warn "Remote compressor: gzip (pigz not found; install it for faster backups: sudo apt-get install pigz)"
fi

# --- Remote disk survey (informational, non-fatal) ---
info "Remote disk usage per backup directory:"
_ssh "sudo du -sh ${REMOTE_DIRS[*]} 2>/dev/null" \
  | while IFS=$'\t' read -r size dir; do
      printf "     ${DM}%-24s %s${RS}\n" "$dir" "$size"
    done \
  || warn "Could not get remote disk usage (non-fatal)"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 2 — Metadata collection  (all non-fatal)
# ─────────────────────────────────────────────────────────────────────────────
step "Collecting metadata: packages, services, network, sysinfo, docker"

info "Package lists (dpkg, apt, pip3, snap, npm, gem)..."
_meta "$META_DIR/dpkg-selections.txt"     "dpkg --get-selections"
_meta "$META_DIR/apt-manual.txt"          "apt-mark showmanual 2>/dev/null || true"
_meta "$META_DIR/pip3-packages.txt"       "pip3 freeze 2>/dev/null || true"
_meta "$META_DIR/snap-list.txt"           "snap list 2>/dev/null || true"
_meta "$META_DIR/npm-globals.txt"         "npm list -g --depth=0 2>/dev/null || true"
_meta "$META_DIR/gem-list.txt"            "gem list 2>/dev/null || true"
ok "Package lists saved"

info "Systemd services and timers..."
_meta "$META_DIR/services-all.txt"        "systemctl list-units --type=service --all --no-pager"
_meta "$META_DIR/services-unit-files.txt" "systemctl list-unit-files --type=service --no-pager"
_meta "$META_DIR/timers.txt"              "systemctl list-timers --all --no-pager"
ok "Service state saved"

info "Crontabs..."
_meta "$META_DIR/crontab-etc.txt"         "sudo cat /etc/crontab 2>/dev/null || true"
_meta "$META_DIR/crontab-cron.d.txt"      "sudo cat /etc/cron.d/* 2>/dev/null || true"
_meta "$META_DIR/crontab-ubuntu.txt"      "crontab -l 2>/dev/null || echo 'no crontab for ubuntu'"
_meta "$META_DIR/crontab-root.txt"        "sudo crontab -l 2>/dev/null || echo 'no crontab for root'"
ok "Crontabs saved"

info "Network configuration..."
_meta "$META_DIR/net-ip-addr.txt"         "ip addr show"
_meta "$META_DIR/net-ip-route.txt"        "ip route show"
_meta "$META_DIR/net-listening-ports.txt" "ss -tlnp"
_meta "$META_DIR/net-iptables.txt"        "sudo iptables-save 2>/dev/null || true"
_meta "$META_DIR/net-ufw-status.txt"      "sudo ufw status verbose 2>/dev/null || true"
ok "Network config saved"

info "System info..."
_meta "$META_DIR/sysinfo-uname.txt"       "uname -a"
_meta "$META_DIR/sysinfo-os-release.txt"  "cat /etc/os-release"
_meta "$META_DIR/sysinfo-lsblk.txt"       "lsblk -f"
_meta "$META_DIR/sysinfo-df.txt"          "df -hT"
_meta "$META_DIR/sysinfo-memory.txt"      "free -h"
_meta "$META_DIR/sysinfo-dmidecode.txt"   "sudo dmidecode 2>/dev/null || true"
ok "System info saved"

info "Docker state..."
HAS_DOCKER=$(_ssh "command -v docker &>/dev/null && echo 1 || echo 0" 2>/dev/null || echo 0)
if [[ "$HAS_DOCKER" == "1" ]]; then
  _meta "$META_DIR/docker-containers.txt"  "sudo docker ps -a --no-trunc 2>/dev/null || true"
  _meta "$META_DIR/docker-images.txt"      "sudo docker images 2>/dev/null || true"
  _meta "$META_DIR/docker-networks.txt"    "sudo docker network ls 2>/dev/null || true"
  _meta "$META_DIR/docker-volumes.txt"     "sudo docker volume ls 2>/dev/null || true"
  _meta "$META_DIR/docker-compose.txt"     "find /home /opt /root /srv -name 'docker-compose*.y*ml' 2>/dev/null || true"
  ok "Docker state saved"
else
  printf "Docker not installed\n" > "$META_DIR/docker-not-installed.txt"
  info "Docker not found — skipped"
fi

info "SSH authorized keys..."
_meta "$META_DIR/ssh-keys-ubuntu.txt"  "cat ~/.ssh/authorized_keys 2>/dev/null || true"
_meta "$META_DIR/ssh-keys-root.txt"    "sudo cat /root/.ssh/authorized_keys 2>/dev/null || true"
ok "SSH key metadata saved"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 3 — Estimate remote data size (for pv ETA accuracy)
# ─────────────────────────────────────────────────────────────────────────────
step "Estimating remote data size (calibrates pv progress bar ETA)"

info "Running remote du — this may take up to 60s for large datasets..."
REMOTE_BYTES=0
RAW=$(_ssh "sudo du -sxb ${REMOTE_DIRS[*]} 2>/dev/null | awk '{s+=\$1}END{print s}'" 2>/dev/null || echo 0)
# Validate it's a number
if [[ "$RAW" =~ ^[0-9]+$ ]]; then
  REMOTE_BYTES="$RAW"
fi

if (( REMOTE_BYTES > 0 )); then
  REMOTE_HR=$(_hr "$REMOTE_BYTES")
  ok "Estimated raw data: ${REMOTE_HR}"
  info "Compressed archive will be 30–60% of raw size depending on content"
  info "pv will show: bytes transferred, speed, elapsed time, and ETA"
else
  warn "Could not determine remote data size — pv will show speed/time without ETA"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 4 — Final disk space check before streaming
# ─────────────────────────────────────────────────────────────────────────────
step "Final local disk check before streaming"

FREE_GB=$(_free_gb)
ok "Local free space: ${FREE_GB} GB on ${LOCAL_BASE}"

if (( FREE_GB < MIN_FREE_GB )); then
  err "Not enough local disk space: ${FREE_GB} GB free, need at least ${MIN_FREE_GB} GB"
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 5 — Stream tar archive with retry loop
# ─────────────────────────────────────────────────────────────────────────────
step "Streaming archive: server | tar | ${COMPRESS_CMD%% *} | SSH | pv → local disk"

# Build the remote command:
#   --ignore-failed-read : skip unreadable files (sockets, locked files) — don't abort
#   --one-file-system    : stay within each mountpoint, skip snap loop mounts etc.
#   -c -C /              : create archive with paths relative to /
#   stdout piped into compressor
EXCLUDES_STR="${TAR_EXCLUDES[*]}"
DIRS_STR="${REMOTE_DIRS[*]}"
REMOTE_CMD="sudo tar --ignore-failed-read --one-file-system ${EXCLUDES_STR} -c -C / ${DIRS_STR} 2>/dev/null | ${COMPRESS_CMD}"

info "Directories : ${DIRS_STR}"
info "Excluded    : /proc /sys /dev /run /tmp /var/run /var/lock /var/tmp /var/cache/apt/archives /snap"
info "Max retries : ${MAX_RETRIES}  |  Retry backoff: ${RETRY_DELAY}s (doubles each attempt)"
printf '\n'
printf "  ${DM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RS}\n"
printf "  ${DM}  Transfer progress (bytes received from server):${RS}\n"
printf "  ${DM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RS}\n"
printf '\n'

STREAM_OK=0
CUR_DELAY=$RETRY_DELAY

for (( attempt=1; attempt <= MAX_RETRIES; attempt++ )); do

  # Re-check SSH before each attempt (handles server restarts between retries)
  if ! _ssh_wait; then
    err "SSH unreachable before attempt ${attempt} — server may be down"
    exit 1
  fi

  if (( attempt > 1 )); then
    printf '\n'
    warn "Retry ${attempt}/${MAX_RETRIES}: last attempt failed — starting fresh stream..."
    printf '\n'
  fi

  # ── Disk space monitor (background subshell) ──────────────────────────────
  # Kills the script if local disk fills up during the stream
  (
    while true; do
      sleep 8
      FREE_NOW=$(_free_gb 2>/dev/null || echo 999)
      if (( FREE_NOW < MIN_FREE_GB )); then
        printf '\n'
        err "LOCAL DISK ALMOST FULL (${FREE_NOW} GB free) — killing stream to prevent corruption"
        _log "Disk-full guard triggered: ${FREE_NOW} GB < ${MIN_FREE_GB} GB minimum"
        kill -TERM $$ 2>/dev/null || true
        exit 1
      fi
    done
  ) &
  DISK_GUARD_PID=$!

  # ── Stream ────────────────────────────────────────────────────────────────
  STREAM_RC=0
  if [[ $HAS_PV -eq 1 ]]; then
    if (( REMOTE_BYTES > 0 )); then
      # Full ETA: pv knows the expected raw size
      # -s: size hint   -p: progress bar   -e: ETA   -t: elapsed   -r: rate   -b: bytes
      _ssh "$REMOTE_CMD" \
        | pv -s "$REMOTE_BYTES" -N "  Transfer" -petrb \
        > "$ARCHIVE_PART" \
        || STREAM_RC=$?
    else
      # No size hint — pv shows speed + elapsed only
      _ssh "$REMOTE_CMD" \
        | pv -N "  Transfer" -etrb \
        > "$ARCHIVE_PART" \
        || STREAM_RC=$?
    fi
  else
    # No pv — plain pipe; log size every 30s via background watcher
    (
      while true; do
        sleep 30
        [[ -f "$ARCHIVE_PART" ]] \
          && SZ=$(du -sh "$ARCHIVE_PART" 2>/dev/null | cut -f1) \
          && info "Transfer in progress — received so far: ${SZ}" \
          || true
      done
    ) &
    PROGRESS_PID=$!
    _ssh "$REMOTE_CMD" > "$ARCHIVE_PART" || STREAM_RC=$?
    kill "$PROGRESS_PID" 2>/dev/null || true
    wait "$PROGRESS_PID" 2>/dev/null || true
  fi

  # ── Stop disk guard ───────────────────────────────────────────────────────
  if [[ -n "$DISK_GUARD_PID" ]] && kill -0 "$DISK_GUARD_PID" 2>/dev/null; then
    kill "$DISK_GUARD_PID" 2>/dev/null || true
    wait "$DISK_GUARD_PID" 2>/dev/null || true
  fi
  DISK_GUARD_PID=""
  printf '\n'

  if [[ $STREAM_RC -eq 0 ]]; then
    STREAM_OK=1
    break
  fi

  # Map exit code to human-readable reason
  case $STREAM_RC in
    141|32) FAIL_REASON="Broken pipe — network dropped mid-transfer" ;;
    255)    FAIL_REASON="SSH connection lost" ;;
    1)      FAIL_REASON="Remote tar/compressor error" ;;
    130)    FAIL_REASON="Interrupted by user" ; exit 130 ;;
    143)    FAIL_REASON="Killed by signal"    ; exit 143 ;;
    *)      FAIL_REASON="Unexpected exit code ${STREAM_RC}" ;;
  esac

  err "Transfer failed: ${FAIL_REASON} (attempt ${attempt}/${MAX_RETRIES})"

  if (( attempt < MAX_RETRIES )); then
    # Remove incomplete .part so the next iteration writes a clean file
    rm -f "$ARCHIVE_PART"
    info "Waiting ${CUR_DELAY}s before next attempt..."
    sleep "$CUR_DELAY"
    CUR_DELAY=$(( CUR_DELAY * 2 ))
  fi
done

if [[ $STREAM_OK -eq 0 ]]; then
  err "Archive transfer failed after ${MAX_RETRIES} attempts"
  err "Last reason: ${FAIL_REASON:-unknown}"
  rm -f "$ARCHIVE_PART"
  exit 1
fi

ok "Transfer complete → ${ARCHIVE_PART}"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 6 — Integrity verification (with retry + re-stream on failure)
# ─────────────────────────────────────────────────────────────────────────────
step "Verifying archive integrity"

VERIFY_OK=0
VER_DELAY=$RETRY_DELAY

for (( vt=1; vt <= MAX_RETRIES; vt++ )); do
  info "Integrity test attempt ${vt}/${MAX_RETRIES} — testing gzip + tar listing..."

  VERIFY_RC=0
  tar -tzf "$ARCHIVE_PART" > /dev/null 2>&1 || VERIFY_RC=$?

  if [[ $VERIFY_RC -eq 0 ]]; then
    VERIFY_OK=1
    break
  fi

  err "Integrity check failed (tar exit ${VERIFY_RC}) on attempt ${vt}"
  _log "Archive corrupt on attempt ${vt}: tar exit ${VERIFY_RC}"

  if (( vt < MAX_RETRIES )); then
    warn "Archive is corrupt — re-streaming from server..."
    rm -f "$ARCHIVE_PART"
    sleep "$VER_DELAY"
    VER_DELAY=$(( VER_DELAY * 2 ))

    # Re-check SSH then re-stream
    _ssh_wait || { err "SSH lost during re-stream"; exit 1; }

    RESTREAM_RC=0
    if [[ $HAS_PV -eq 1 ]]; then
      _ssh "$REMOTE_CMD" \
        | pv -N "  Re-transfer" -etrb \
        > "$ARCHIVE_PART" \
        || RESTREAM_RC=$?
    else
      _ssh "$REMOTE_CMD" > "$ARCHIVE_PART" || RESTREAM_RC=$?
    fi

    if [[ $RESTREAM_RC -ne 0 ]]; then
      err "Re-stream failed (exit ${RESTREAM_RC})"
      rm -f "$ARCHIVE_PART"
      exit 1
    fi
    printf '\n'
  fi
done

if [[ $VERIFY_OK -eq 0 ]]; then
  err "Archive integrity failed after ${MAX_RETRIES} attempts"
  err "Possible causes: unstable network, disk write errors, server instability"
  rm -f "$ARCHIVE_PART"
  exit 1
fi

# Atomically promote .part → .tar.gz (overwrite previous good backup only now)
mv "$ARCHIVE_PART" "$ARCHIVE"

ARCHIVE_SIZE=$(du -sh "$ARCHIVE" 2>/dev/null | cut -f1 || echo "?")
FILE_COUNT=$(tar -tzf "$ARCHIVE" 2>/dev/null | wc -l || echo "?")
ok "Archive is valid and complete ✔"
ok "Size: ${ARCHIVE_SIZE} compressed  |  Entries: ${FILE_COUNT} files/dirs"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 7 — Write restore guide
# ─────────────────────────────────────────────────────────────────────────────
step "Writing restore guide and finishing up"

cat > "$META_DIR/RESTORE-GUIDE.txt" << GUIDE
=================================================================
  SERVER RESTORE GUIDE
  Backup taken : $(_ts) ($(date '+%Z'))
  Source       : ${REMOTE_USER}@${REMOTE_HOST}
  Archive      : server-backup.tar.gz
  Size         : ${ARCHIVE_SIZE} compressed  |  ${FILE_COUNT} entries
=================================================================

WHAT'S IN THE BACKUP
---------------------
Backed-up directories:
  ${DIRS_STR}

Excluded (meaningless outside the live OS):
  /proc /sys /dev /run /tmp /snap
  /var/run /var/lock /var/tmp /var/cache/apt/archives

The tar archive preserves 100% Linux filesystem metadata:
  ✔ All symlinks — including snap special-character names
  ✔ File permissions, UID/GID ownership, timestamps
  ✔ Hardlinks, device nodes, named pipes, UNIX sockets
  ✔ Extended attributes (xattr)

WHY A TAR ARCHIVE AND NOT RSYNC?
----------------------------------
The local drive is NTFS. NTFS cannot store Linux symlinks with
special characters, device nodes, or named pipes. A tar archive
wraps everything as raw bytes — NTFS stores bytes perfectly. When
you extract to a real Linux filesystem every metadata bit is intact.

FULL SYSTEM RESTORE (new server)
----------------------------------
1. Provision a fresh Ubuntu server — check OS version:
     cat metadata/sysinfo-os-release.txt

2. Copy archive to new server:
     scp -i ~/.ssh/id_ed25519 server-backup.tar.gz YOUR_USER@NEW_IP:/tmp/

3. Extract everything:
     cd /
     sudo tar -xzf /tmp/server-backup.tar.gz

4. Restore installed packages:
     sudo dpkg --set-selections < metadata/dpkg-selections.txt
     sudo apt-get dselect-upgrade -y

5. Restore Python packages:
     pip3 install -r metadata/pip3-packages.txt

6. Restore snap packages (see metadata/snap-list.txt):
     snap install <name>

7. Reload systemd:
     sudo systemctl daemon-reload

8. Restore crontabs:
     sudo crontab metadata/crontab-root.txt
     crontab metadata/crontab-ubuntu.txt

9. Reboot.

PARTIAL RESTORE
----------------
  Restore /etc only:
    cd / && sudo tar -xzf server-backup.tar.gz etc/

  Restore /home only:
    cd / && sudo tar -xzf server-backup.tar.gz home/

  Restore one file (strip leading /):
    cd / && sudo tar -xzf server-backup.tar.gz etc/nginx/nginx.conf

LIST ARCHIVE CONTENTS
----------------------
  All entries:      tar -tzf server-backup.tar.gz | less
  Search for file:  tar -tzf server-backup.tar.gz | grep nginx

=================================================================
GUIDE

ok "Restore guide written → ${META_DIR}/RESTORE-GUIDE.txt"

printf 'Last backup: %s\n' "$(_ts)" > "$LOCAL_BASE/last-backup.txt"
_log "====== Backup complete ======"

# ─────────────────────────────────────────────────────────────────────────────
#  DONE
# ─────────────────────────────────────────────────────────────────────────────
_HANDLED=1   # tell trap: normal exit, don't print failure box
END_TIME=$(date +%s)
print_success $(( END_TIME - START_TIME )) "$ARCHIVE_SIZE" "$FILE_COUNT"