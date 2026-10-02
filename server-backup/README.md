# server-backup.sh

A bulletproof, on-demand full disaster-recovery backup script for Ubuntu servers.  
Streams a complete server snapshot over SSH directly to a local directory — no intermediate storage needed on the server. Works with any local filesystem including NTFS/exFAT.

---

## What it backs up

| Category | Contents |
|---|---|
| **Filesystem** | `/etc`, `/home`, `/var`, `/root`, `/opt`, `/srv`, `/usr/local`, `/usr/share` |
| **Excluded** | `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/snap`, `/var/cache/apt/archives` |
| **Packages** | `dpkg`, `apt`, `pip3`, `snap`, `npm`, `gem` package lists |
| **Services** | systemd unit files, service states, timers |
| **Crontabs** | root + user crontabs, `/etc/cron.d/` |
| **Network** | IP addresses, routes, iptables rules, UFW status, listening ports |
| **Docker** | Container list, images, networks, volumes, compose file locations |
| **System info** | OS release, kernel, disk layout, memory, hardware info |
| **SSH keys** | Authorized keys for root and the remote user |

All Linux filesystem metadata is preserved: **symlinks** (including special-character snap symlinks), **permissions**, **ownership (uid/gid)**, **timestamps**, **hardlinks**, **device nodes**, **named pipes**, and **extended attributes** — because the backup is a `.tar.gz` archive, not an rsync to NTFS.

---

## How it works

```
server: sudo tar (pigz/gzip) → stdout
           ↓ SSH pipe
local:  pv (progress bar + ETA) → server-backup.tar.gz.part
           ↓ integrity check (tar -tzf)
           ↓ rename to server-backup.tar.gz  ← only on success
```

- Archive is written to a `.part` file first. The final `.tar.gz` is only updated after the integrity check passes — so a previous good backup is never overwritten by a corrupt one.
- Uses **pigz** (parallel gzip) on the server when available — significantly faster for large archives.
- **pv** shows live bytes, speed, elapsed time, and ETA in the terminal.

---

## Error handling

The script handles every failure mode gracefully:

| Scenario | Behaviour |
|---|---|
| SSH unreachable (server off, network drop) | Retries 3× with exponential backoff (30s → 60s → 120s) |
| Network drops mid-stream | Detects broken pipe, retries full stream |
| Local disk fills up during transfer | Background monitor kills stream cleanly, removes `.part` |
| Corrupt archive after transfer | Auto-retries stream up to 3× before giving up |
| Ctrl-C / SIGTERM | Trap cleans up `.part` file, logs abort |
| Previous partial archive found | Removed automatically at startup |
| `pigz` not on server | Falls back to `gzip` automatically |
| `pv` not installed locally | Falls back to plain pipe with periodic size logging |
| Metadata command fails | Non-fatal warning — backup continues |

---

## Requirements

**Local machine:**
- `ssh`
- `tar`
- `pv` (optional but recommended: `sudo apt-get install pv`)

**Remote server:**
- Passwordless `sudo` for your SSH user
- `tar`
- `pigz` (optional, recommended: `sudo apt-get install pigz`)

---

## Setup

**1. Clone or download the script:**

```bash
curl -O https://raw.githubusercontent.com/S1N15T3R/personal_tools/main/server-backup/server-backup.sh
chmod +x server-backup.sh
```

**2. Edit the config section at the top of the script:**

```bash
REMOTE_USER="your_user"           # SSH username on the server
REMOTE_HOST="your.server.ip"      # Server IP or hostname
SSH_KEY="$HOME/.ssh/id_ed25519"   # Path to your SSH private key
LOCAL_BASE="/path/to/local/backup/dir"  # Where to store the backup locally
```

**3. Run it:**

```bash
bash server-backup.sh
```

---

## Output structure

```
/your/backup/dir/
├── server-backup.tar.gz      ← the full archive (verified before replacing)
├── backup.log                ← timestamped log of every step
├── last-backup.txt           ← timestamp of last successful run
└── metadata/
    ├── RESTORE-GUIDE.txt     ← step-by-step restore instructions
    ├── dpkg-selections.txt
    ├── apt-manual.txt
    ├── pip3-packages.txt
    ├── snap-list.txt
    ├── services-all.txt
    ├── net-iptables.txt
    ├── docker-containers.txt
    └── ...                   ← 30+ metadata files
```

---

## Restore

**Full system restore to a new server:**

```bash
# Copy archive to new server
scp server-backup.tar.gz your_user@NEW_IP:/tmp/

# Extract everything (preserves all permissions)
cd /
sudo tar -xzf /tmp/server-backup.tar.gz

# Restore packages
sudo dpkg --set-selections < metadata/dpkg-selections.txt
sudo apt-get dselect-upgrade -y

# Restore pip packages
pip3 install -r metadata/pip3-packages.txt

# Reload systemd
sudo systemctl daemon-reload

# Reboot
sudo reboot
```

**Partial restore (single directory):**

```bash
cd / && sudo tar -xzf server-backup.tar.gz etc/
cd / && sudo tar -xzf server-backup.tar.gz home/
```

**Restore one file:**

```bash
cd / && sudo tar -xzf server-backup.tar.gz etc/nginx/nginx.conf
```

**List archive contents:**

```bash
tar -tzf server-backup.tar.gz | less
tar -tzf server-backup.tar.gz | grep nginx
```

See `metadata/RESTORE-GUIDE.txt` inside your backup directory for the full guide.

---

## Notes

- The script never stores temporary data on the remote server — everything streams directly.
- Safe to run on NTFS, exFAT, or any local filesystem — the `.tar.gz` is just bytes.
- To schedule automatic backups, add to cron: `0 2 * * * bash /path/to/server-backup.sh >> /var/log/server-backup.log 2>&1`
