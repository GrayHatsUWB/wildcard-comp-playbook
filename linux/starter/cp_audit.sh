#!/usr/bin/env bash
#
# cp_audit.sh - Comprehensive CyberPatriot Linux audit / fix / rollback tool
#
# Distro-agnostic. Supports:
#   * Debian / Ubuntu / Mint / Kali / Pop / etc. (apt + dpkg)
#   * RHEL / Fedora / Rocky / Alma / CentOS    (dnf or yum + rpm)
#   * openSUSE / SLES                           (zypper + rpm)
#   * Arch / Manjaro / EndeavourOS              (pacman)
#
# Modes:
#   (default)        Audit only. Read-only. Color terminal output.
#   --fix            Apply safe fixes. Prompts before each change.
#                    Backs up every modified file to <file>.cpbak-<TS>
#                    and logs every action to the action log.
#   --rollback       Reverse the most recent --fix run.
#   --rollback-all   Reverse every recorded --fix action, newest first.
#   --list-backups   Show recorded actions / backups.
#   --suggest        Print ready-to-paste commands for the dangerous
#                    fixes the script will not perform automatically.
#   --preserve-logs  Snapshot logs and shell histories to ~/cp_audit_logs/
#   -h | --help      Show usage.
#
# Coverage: users, sudoers, passwords, password policy, PAM, login.defs,
# sshd, firewall (ufw/firewalld/nftables/iptables), sysctl, /proc tunables,
# critical perms, SUID/SGID, world-writable, no-owner files, services,
# scheduled jobs (cron / at / systemd timers), prohibited packages,
# package manager config, repository sanity, display managers, samba,
# apache, nginx, mysql/mariadb, postgres, vsftpd, php, /etc/hosts,
# /etc/host.conf, /etc/securetty, /etc/environment, /etc/rc.local,
# kernel module blacklists (USB/firewire/thunderbolt), aliases,
# rootkit scanners (rkhunter/chkrootkit/lynis/clamav/debsums),
# fail2ban, auditd, README parsing, forensics question detection,
# prohibited media files (full filesystem), browser/Firefox prefs,
# Seafile/Seahub score-specific checks.
#

set -u
shopt -s nullglob

############################################################
# Globals
############################################################

CP_AUDIT_VERSION="2.1"
TS="$(date +%Y%m%d-%H%M%S)"
RUN_TS="$TS"
SCRIPT_NAME="$(basename "$0")"

if [[ $EUID -eq 0 ]]; then
    LOG_DIR="/var/log/cp_audit"
else
    LOG_DIR="$HOME/.cp_audit"
fi
ACTION_LOG="$LOG_DIR/actions.log"
mkdir -p "$LOG_DIR" 2>/dev/null || true

COUNT_OK=0
COUNT_WARN=0
COUNT_BAD=0
COUNT_INFO=0
COUNT_FIXED=0
COUNT_SKIPPED=0

MODE="audit"

DISTRO_ID=""
DISTRO_FAMILY=""
DISTRO_VERSION=""
PKG_MGR=""
PKG_INSTALL_CMD=""
PKG_REMOVE_CMD=""
PKG_UPDATE_CMD=""
PKG_LIST_INSTALLED=""
SHADOW_GROUP="shadow"
ADMIN_GROUP="sudo"

############################################################
# Colors
############################################################

if [[ -t 1 ]]; then
    C_RESET=$'\e[0m'
    C_BOLD=$'\e[1m'
    C_DIM=$'\e[2m'
    C_RED=$'\e[31m'
    C_GREEN=$'\e[32m'
    C_YELLOW=$'\e[33m'
    C_BLUE=$'\e[34m'
    C_MAGENTA=$'\e[35m'
    C_CYAN=$'\e[36m'
else
    C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_MAGENTA="" C_CYAN=""
fi

############################################################
# Output helpers
############################################################

hdr() { echo; echo "${C_BOLD}${C_CYAN}═══ $* ═══${C_RESET}"; }
sub() { echo "${C_BOLD}── $* ──${C_RESET}"; }
ok()      { echo "  ${C_GREEN}[ OK  ]${C_RESET} $*";   COUNT_OK=$((COUNT_OK+1)); }
warn()    { echo "  ${C_YELLOW}[WARN ]${C_RESET} $*"; COUNT_WARN=$((COUNT_WARN+1)); }
bad()     { echo "  ${C_RED}[ BAD ]${C_RESET} $*";    COUNT_BAD=$((COUNT_BAD+1)); }
info()    { echo "  ${C_BLUE}[INFO ]${C_RESET} $*";   COUNT_INFO=$((COUNT_INFO+1)); }
note()    { echo "  ${C_DIM}       $*${C_RESET}"; }
fixed()   { echo "  ${C_MAGENTA}[FIXED]${C_RESET} $*"; COUNT_FIXED=$((COUNT_FIXED+1)); }

usage() {
    cat <<EOF
${C_BOLD}$SCRIPT_NAME${C_RESET} v$CP_AUDIT_VERSION  -  Comprehensive CyberPatriot Linux audit / fix / rollback

Usage:
  $SCRIPT_NAME                  Audit only (read-only). Default.
  $SCRIPT_NAME --fix            Apply safe fixes (prompts before each change).
  $SCRIPT_NAME --rollback       Reverse the most recent --fix run.
  $SCRIPT_NAME --rollback-all   Reverse every recorded fix, newest first.
  $SCRIPT_NAME --list-backups   List recorded actions / backups.
  $SCRIPT_NAME --suggest        Print copy-paste commands for unsafe fixes.
  $SCRIPT_NAME --preserve-logs  Snapshot system logs before any changes.
  $SCRIPT_NAME -h | --help      This help.

Run as root for full coverage.
Action log: $ACTION_LOG
EOF
}

############################################################
# Distro detection
############################################################

detect_distro() {
    if [[ -r /etc/os-release ]]; then
        local osr
        osr="$(
            # shellcheck disable=SC1091
            . /etc/os-release
            printf '%s\t%s\t%s\n' "${ID:-unknown}" "${VERSION_ID:-}" "${ID_LIKE:-}"
        )"
        DISTRO_ID="$(echo "$osr" | cut -f1)"
        DISTRO_VERSION="$(echo "$osr" | cut -f2)"
        local id_like
        id_like="$(echo "$osr" | cut -f3)"

        case "$DISTRO_ID" in
            ubuntu|debian|linuxmint|kali|pop|elementary|raspbian|devuan|parrot)
                DISTRO_FAMILY="debian" ;;
            fedora|rhel|centos|rocky|almalinux|ol|amzn|scientific)
                DISTRO_FAMILY="rhel" ;;
            opensuse*|sles|sled|suse)
                DISTRO_FAMILY="suse" ;;
            arch|manjaro|endeavouros|artix|garuda)
                DISTRO_FAMILY="arch" ;;
            *)
                case "$id_like" in
                    *debian*|*ubuntu*) DISTRO_FAMILY="debian" ;;
                    *rhel*|*fedora*|*centos*) DISTRO_FAMILY="rhel" ;;
                    *suse*) DISTRO_FAMILY="suse" ;;
                    *arch*) DISTRO_FAMILY="arch" ;;
                    *) DISTRO_FAMILY="unknown" ;;
                esac
                ;;
        esac
    else
        DISTRO_ID="unknown"
        DISTRO_FAMILY="unknown"
    fi

    if   command -v apt-get >/dev/null;    then PKG_MGR="apt"
    elif command -v dnf >/dev/null;        then PKG_MGR="dnf"
    elif command -v yum >/dev/null;        then PKG_MGR="yum"
    elif command -v zypper >/dev/null;     then PKG_MGR="zypper"
    elif command -v pacman >/dev/null;     then PKG_MGR="pacman"
    else PKG_MGR="unknown"
    fi

    case "$PKG_MGR" in
        apt)
            PKG_INSTALL_CMD="DEBIAN_FRONTEND=noninteractive apt-get install -y"
            PKG_REMOVE_CMD="DEBIAN_FRONTEND=noninteractive apt-get purge -y"
            PKG_UPDATE_CMD="DEBIAN_FRONTEND=noninteractive apt-get update"
            PKG_LIST_INSTALLED='dpkg-query -W -f="\${binary:Package}\n"'
            SHADOW_GROUP="shadow"
            ;;
        dnf)
            PKG_INSTALL_CMD="dnf install -y"
            PKG_REMOVE_CMD="dnf remove -y"
            PKG_UPDATE_CMD="dnf check-update"
            PKG_LIST_INSTALLED="rpm -qa"
            SHADOW_GROUP="root"
            ;;
        yum)
            PKG_INSTALL_CMD="yum install -y"
            PKG_REMOVE_CMD="yum remove -y"
            PKG_UPDATE_CMD="yum check-update"
            PKG_LIST_INSTALLED="rpm -qa"
            SHADOW_GROUP="root"
            ;;
        zypper)
            PKG_INSTALL_CMD="zypper --non-interactive install"
            PKG_REMOVE_CMD="zypper --non-interactive remove"
            PKG_UPDATE_CMD="zypper --non-interactive refresh"
            PKG_LIST_INSTALLED="rpm -qa"
            SHADOW_GROUP="root"
            ;;
        pacman)
            PKG_INSTALL_CMD="pacman -S --noconfirm"
            PKG_REMOVE_CMD="pacman -Rns --noconfirm"
            PKG_UPDATE_CMD="pacman -Sy"
            PKG_LIST_INSTALLED="pacman -Qq"
            SHADOW_GROUP="root"
            ;;
    esac

    case "$DISTRO_FAMILY" in
        debian) ADMIN_GROUP="sudo" ;;
        rhel|suse|arch) ADMIN_GROUP="wheel" ;;
        *) ADMIN_GROUP="sudo" ;;
    esac
}

pkg_is_installed() {
    local p="$1"
    case "$PKG_MGR" in
        apt)    dpkg -s "$p" >/dev/null 2>&1 ;;
        dnf|yum|zypper) rpm -q "$p" >/dev/null 2>&1 ;;
        pacman) pacman -Qq "$p" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

############################################################
# Action log helpers
############################################################

log_action() {
    local type="$1" target="$2" backup="${3:-}" extra="${4:-}"
    printf '%s\t%s\t%s\t%s\t%s\n' "$RUN_TS" "$type" "$target" "$backup" "$extra" >> "$ACTION_LOG"
}

backup_file() {
    local f="$1"
    if [[ ! -e "$f" ]]; then echo ""; return 0; fi
    local b="${f}.cpbak-${RUN_TS}"
    cp -a -- "$f" "$b"
    echo "$b"
}

confirm() {
    local prompt="$1"
    if [[ "$MODE" != "fix" ]]; then return 1; fi
    local ans
    read -r -p "  ${C_BOLD}${C_MAGENTA}FIX?${C_RESET} $prompt [y/N] " ans </dev/tty || return 1
    [[ "$ans" =~ ^[Yy] ]]
}

need_root_for_fix() {
    if [[ "$MODE" == "fix" && $EUID -ne 0 ]]; then
        warn "Skipping fix (need root)."
        return 1
    fi
    return 0
}

ensure_line_kv() {
    local file="$1" key="$2" value="$3" sep="${4:- }"
    local b
    b="$(backup_file "$file")"
    if [[ -z "$b" && ! -e "$file" ]]; then
        mkdir -p "$(dirname "$file")" 2>/dev/null || true
        printf '%s%s%s\n' "$key" "$sep" "$value" > "$file"
        log_action "CREATE_FILE" "$file" "" ""
    else
        if grep -qE "^[[:space:]]*#?[[:space:]]*${key}([[:space:]=]|\$)" "$file"; then
            sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}([[:space:]=]).*|${key}${sep}${value}|" "$file"
        else
            printf '%s%s%s\n' "$key" "$sep" "$value" >> "$file"
        fi
        log_action "BACKUP_FILE" "$file" "$b" ""
    fi
}

############################################################
# Log preservation (--preserve-logs and start of every fix run)
############################################################

preserve_logs() {
    hdr "Preserving system logs and shell histories"
    local snap_dir="$LOG_DIR/snapshot-$RUN_TS"
    mkdir -p "$snap_dir" 2>/dev/null || { warn "Cannot create $snap_dir"; return; }

    local sources=(
        /var/log/auth.log
        /var/log/secure
        /var/log/syslog
        /var/log/messages
        /var/log/kern.log
        /var/log/dpkg.log
        /var/log/yum.log
        /var/log/dnf.log
        /var/log/zypp/history
        /var/log/pacman.log
        /var/log/apt/history.log
        /var/log/apt/term.log
        /var/log/audit/audit.log
        /var/log/faillog
        /var/log/lastlog
        /var/log/wtmp
        /var/log/btmp
        /var/log/boot.log
    )
    local s
    for s in "${sources[@]}"; do
        if [[ -r "$s" ]]; then
            cp -a -- "$s" "$snap_dir/" 2>/dev/null && note "saved $s"
        fi
    done

    # Shell histories
    local h
    for h in /root/.bash_history /home/*/.bash_history /home/*/.zsh_history /root/.zsh_history; do
        [[ -f "$h" ]] && cp -a -- "$h" "$snap_dir/$(echo "$h" | tr / _)" 2>/dev/null
    done

    # Process tree, network state, package list
    {
        echo "=== ps -ef ==="
        ps -ef 2>/dev/null
        echo
        echo "=== ss -tulnp ==="
        ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null
        echo
        echo "=== last -20 ==="
        last 2>/dev/null | head -20
        echo
        echo "=== who ==="
        who 2>/dev/null
        echo
        echo "=== getent passwd ==="
        getent passwd
        echo
        echo "=== getent group ==="
        getent group
    } > "$snap_dir/system-state.txt" 2>/dev/null

    ok "Snapshot saved to $snap_dir"
}

############################################################
# README parser
############################################################

README_FILE=""
README_USERS=()
README_ADMINS=()

find_and_parse_readme() {
    hdr "README detection"
    local candidates=()
    local f
    for f in /home/*/Desktop/[Rr][Ee][Aa][Dd][Mm][Ee]* \
             /root/Desktop/[Rr][Ee][Aa][Dd][Mm][Ee]* \
             /home/*/[Rr][Ee][Aa][Dd][Mm][Ee]* \
             /root/[Rr][Ee][Aa][Dd][Mm][Ee]*; do
        [[ -f "$f" ]] && candidates+=("$f")
    done

    if (( ${#candidates[@]} == 0 )); then
        warn "No README found in common locations. Locate it manually."
        info "Search: sudo find / -iname 'readme*' 2>/dev/null"
        return
    fi

    README_FILE="${candidates[0]}"
    ok "Found README: $README_FILE"
    if (( ${#candidates[@]} > 1 )); then
        info "Other candidates:"
        for f in "${candidates[@]:1}"; do note "$f"; done
    fi

    info "Looking for likely user / admin lists in README (heuristic only):"
    note "Read it yourself; do not trust this parser blindly."
    grep -iE 'user|admin|account|password' "$README_FILE" 2>/dev/null | head -30 \
        | sed 's/^/         /'
}

############################################################
# CHECKS - Users / Sudo / Auth
############################################################

check_users_and_admins() {
    hdr "Users and administrators"

    sub "Immutable bit on auth files (chattr +i blocks all edits)"
    if command -v lsattr >/dev/null; then
        local f imm
        for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers; do
            [[ -e "$f" ]] || continue
            imm="$(lsattr "$f" 2>/dev/null | awk '{print $1}')"
            if [[ "$imm" =~ i ]]; then
                bad "$f has immutable bit set ($imm) — cannot edit until removed"
                if confirm "Remove immutable bit (chattr -i $f) ?"; then
                    if need_root_for_fix; then
                        chattr -i "$f" && fixed "removed +i from $f"
                    fi
                fi
            else
                ok "$f no immutable bit"
            fi
        done
    else
        warn "lsattr not available; cannot check immutable bits"
    fi

    sub "Hidden / disguised users in /etc/passwd"
    local susp
    susp="$(awk -F: '$1 ~ /^[.\-_]/ || $1 ~ /[[:space:]]/ {print $0}' /etc/passwd)"
    if [[ -z "$susp" ]]; then
        ok "No users with hidden/whitespace names."
    else
        echo "$susp" | while read -r line; do bad "suspicious user: $line"; done
    fi

    sub "Human accounts (UID 1000-60000)"
    while IFS=: read -r u _ uid _ gecos home shell; do
        if (( uid >= 1000 && uid < 60000 )); then
            note "$u  uid=$uid  shell=$shell  home=$home  gecos='$gecos'"
        fi
    done < /etc/passwd

    sub "Service accounts with login shells (UID < 1000)"
    local svc
    while IFS=: read -r u _ uid _ _ _ shell; do
        if (( uid < 1000 && uid > 0 )) && [[ "$shell" =~ (bash|sh|zsh|ksh|dash|fish)$ ]]; then
            warn "service account with login shell: $u (uid=$uid, shell=$shell)"
        fi
    done < /etc/passwd

    sub "Members of administrator groups"
    local g members
    for g in sudo wheel admin adm; do
        if getent group "$g" >/dev/null; then
            members="$(getent group "$g" | awk -F: '{print $4}')"
            info "$g: ${members:-(none)}"
        fi
    done

    sub "Members of docker group (effective root via container escape)"
    if getent group docker >/dev/null; then
        local docker_members
        docker_members="$(getent group docker | awk -F: '{print $4}')"
        if [[ -n "$docker_members" ]]; then
            warn "docker group members: $docker_members  (each is effectively root)"
        else
            ok "docker group is empty"
        fi
    fi

    sub "Members of lxd group (effective root)"
    if getent group lxd >/dev/null; then
        local lxd_members
        lxd_members="$(getent group lxd | awk -F: '{print $4}')"
        if [[ -n "$lxd_members" ]]; then
            warn "lxd group members: $lxd_members  (each is effectively root)"
        fi
    fi

    sub "UID 0 accounts (only root expected)"
    local uid0
    uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd)"
    if [[ "$uid0" == "root" ]]; then
        ok "Only root has UID 0."
    else
        bad "Multiple UID-0 accounts: $uid0"
        info "Comment them out in /etc/passwd or delete them."
    fi

    sub "Duplicate UIDs"
    local dups
    dups="$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)"
    if [[ -z "$dups" ]]; then
        ok "No duplicate UIDs."
    else
        bad "Duplicate UIDs found: $dups"
    fi

    sub "Empty passwords"
    if [[ -r /etc/shadow ]]; then
        local empty
        empty="$(awk -F: '($2 == "") {print $1}' /etc/shadow)"
        if [[ -z "$empty" ]]; then
            ok "No empty password fields."
        else
            bad "Empty password: $empty"
        fi
    else
        warn "/etc/shadow not readable (need root)."
    fi

    sub "Locked vs unlocked accounts"
    if [[ -r /etc/shadow ]]; then
        local locked unlocked
        locked="$(awk -F: '$2 ~ /^!/ || $2 == "*" {print $1}' /etc/shadow | tr '\n' ' ')"
        unlocked="$(awk -F: '$2 !~ /^!/ && $2 != "*" && $2 != "" {print $1}' /etc/shadow | tr '\n' ' ')"
        info "Locked: $locked"
        info "Unlocked (have valid hash): $unlocked"
    fi

    sub "Root login state"
    if [[ -r /etc/shadow ]]; then
        local roothash
        roothash="$(awk -F: '$1=="root" {print $2}' /etc/shadow)"
        if [[ "$roothash" =~ ^! ]] || [[ "$roothash" == "*" ]]; then
            ok "root account is locked."
        else
            warn "root account is NOT locked. Consider: sudo passwd -l root"
        fi
    fi
    local rootshell
    rootshell="$(awk -F: '$1=="root" {print $7}' /etc/passwd)"
    info "root shell: $rootshell"

    info "Cross-check users / admins against the README."
}

check_sudoers() {
    hdr "Sudoers configuration"

    if [[ ! -r /etc/sudoers ]]; then
        warn "/etc/sudoers not readable (need root)."
        return
    fi

    sub "NOPASSWD entries"
    local hits
    hits="$(grep -RInE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)"
    if [[ -z "$hits" ]]; then
        ok "No NOPASSWD entries."
    else
        local line
        while IFS= read -r line; do bad "NOPASSWD: $line"; done <<< "$hits"
    fi

    sub "!authenticate entries"
    hits="$(grep -RInE '!authenticate' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)"
    if [[ -z "$hits" ]]; then
        ok "No !authenticate entries."
    else
        local line
        while IFS= read -r line; do bad "!authenticate: $line"; done <<< "$hits"
    fi

    sub "Files in /etc/sudoers.d/"
    if [[ -d /etc/sudoers.d ]]; then
        local f
        for f in /etc/sudoers.d/*; do
            [[ -f "$f" ]] || continue
            local base
            base="$(basename "$f")"
            if [[ "$base" == "README" ]]; then
                ok "/etc/sudoers.d/README (default)"
            else
                warn "/etc/sudoers.d/$base — review (could be backdoor)"
            fi
        done
    fi

    sub "visudo syntax check"
    if command -v visudo >/dev/null && visudo -c >/dev/null 2>&1; then
        ok "visudo -c passes."
    else
        bad "visudo -c FAILS — sudoers is broken."
    fi

    sub "LD_PRELOAD preserved via sudo"
    hits="$(grep -RInE '^[[:space:]]*Defaults.*env_keep.*LD_PRELOAD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)"
    if [[ -z "$hits" ]]; then
        ok "sudo does not keep LD_PRELOAD."
    else
        bad "sudo keeps LD_PRELOAD:"
        while IFS= read -r line; do
            [[ -n "$line" ]] && echo "         $line"
        done <<< "$hits"
    fi

    sub "sudo coredumps"
    hits="$(grep -RInE '^[[:space:]]*Defaults.*!disable_coredump' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)"
    if [[ -n "$hits" ]]; then
        bad "sudo explicitly allows coredumps:"
        while IFS= read -r line; do
            [[ -n "$line" ]] && echo "         $line"
        done <<< "$hits"
    else
        hits="$(grep -RInE '^[[:space:]]*Defaults.*disable_coredump' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)"
        if [[ -n "$hits" ]]; then
            ok "sudo disable_coredump is configured."
        else
            info "No explicit sudo disable_coredump setting found. Default is usually safe, but scoring may expect an explicit directive."
        fi
    fi
}

check_password_policy() {
    hdr "Password and login policy (/etc/login.defs)"

    local f=/etc/login.defs
    [[ -r "$f" ]] || { warn "$f not readable."; return; }

    declare -A want=(
        [UMASK]="077"
        [PASS_MAX_DAYS]="90"
        [PASS_MIN_DAYS]="7"
        [PASS_WARN_AGE]="14"
        [FAILLOG_ENAB]="yes"
        [LOG_OK_LOGINS]="yes"
        [LOG_UNKFAIL_ENAB]="yes"
        [SYSLOG_SU_ENAB]="yes"
        [SYSLOG_SG_ENAB]="yes"
        [ENCRYPT_METHOD]="YESCRYPT"
    )

    local k v current
    for k in "${!want[@]}"; do
        v="${want[$k]}"
        current="$(grep -E "^[[:space:]]*${k}[[:space:]]" "$f" | awk '{print $2}' | tail -n1)"
        if [[ "$current" == "$v" ]]; then
            ok "$k = $v"
        else
            bad "$k is '${current:-unset}', want '$v'"
            if confirm "Set $k $v in $f?"; then
                if need_root_for_fix; then
                    ensure_line_kv "$f" "$k" "$v"
                    fixed "$k -> $v"
                fi
            fi
        fi
    done
}

check_pam() {
    hdr "PAM hardening"

    sub "Account lockout (faillock / pam_tally2)"
    local pam_auth=""
    for f in /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [[ -f "$f" ]] && pam_auth="$f" && break
    done

    if [[ -z "$pam_auth" ]]; then
        warn "No PAM auth file found."
    else
        if grep -qE 'pam_(tally2|faillock)\.so' "$pam_auth"; then
            ok "$pam_auth has lockout module configured."
        else
            bad "$pam_auth has no pam_tally2 or pam_faillock."
            info "Add: auth required pam_faillock.so deny=5 unlock_time=1800  (or pam_tally2.so on older)"
        fi
    fi

    sub "Password complexity (pam_pwquality / pam_cracklib)"
    local pam_pw=""
    for f in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [[ -f "$f" ]] && pam_pw="$f" && break
    done

    if [[ -z "$pam_pw" ]]; then
        warn "No PAM password file found."
    else
        if grep -qE 'pam_(pwquality|cracklib)\.so' "$pam_pw"; then
            ok "$pam_pw uses pam_pwquality or pam_cracklib."
            local line
            line="$(grep -E 'pam_(pwquality|cracklib)\.so' "$pam_pw" | head -1)"
            note "$line"
            for token in minlen= ucredit= lcredit= dcredit= ocredit= retry= difok=; do
                if echo "$line" | grep -q "$token"; then
                    note "  has $token"
                fi
            done
        else
            bad "$pam_pw lacks pam_pwquality / pam_cracklib."
            info "Add: password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"
        fi

        if grep -qE 'pam_pwhistory\.so' "$pam_pw"; then
            ok "$pam_pw has pam_pwhistory (remember)."
        else
            warn "$pam_pw lacks pam_pwhistory."
            info "Add: password required pam_pwhistory.so remember=24 use_authtok"
        fi

        if grep -qE 'pam_unix\.so.*remember' "$pam_pw"; then
            ok "pam_unix has remember=N."
        fi
    fi

    sub "/etc/security/pwquality.conf"
    if [[ -f /etc/security/pwquality.conf ]]; then
        local k v current
        declare -A pwq=(
            [minlen]="12"
            [dcredit]="-1"
            [ucredit]="-1"
            [lcredit]="-1"
            [ocredit]="-1"
            [difok]="3"
            [retry]="3"
        )
        for k in "${!pwq[@]}"; do
            v="${pwq[$k]}"
            current="$(grep -E "^[[:space:]]*${k}[[:space:]]*=" /etc/security/pwquality.conf | awk -F= '{print $2}' | xargs)"
            if [[ "$current" == "$v" ]]; then
                ok "pwquality $k = $v"
            else
                warn "pwquality $k is '${current:-unset}' (want $v)"
            fi
        done
        current="$(grep -E '^[[:space:]]*dictcheck[[:space:]]*=' /etc/security/pwquality.conf | awk -F= '{print $2}' | xargs)"
        if [[ -z "$current" || "$current" == "1" ]]; then
            ok "pwquality dictionary checks are enabled."
        else
            bad "pwquality dictcheck is '${current}', want enabled"
        fi
    else
        info "/etc/security/pwquality.conf not present."
    fi
}

############################################################
# CHECKS - SSH
############################################################

check_sshd() {
    hdr "OpenSSH (sshd_config)"

    local f=/etc/ssh/sshd_config
    if [[ ! -r "$f" ]]; then
        warn "$f not readable."
        return
    fi

    declare -A want=(
        [PermitRootLogin]="no"
        [PasswordAuthentication]="yes"
        [PubkeyAuthentication]="no"
        [PermitEmptyPasswords]="no"
        [ChallengeResponseAuthentication]="no"
        [UsePAM]="yes"
        [X11Forwarding]="no"
        [Protocol]="2"
        [ClientAliveInterval]="300"
        [ClientAliveCountMax]="0"
        [LoginGraceTime]="60"
        [MaxAuthTries]="4"
        [MaxStartups]="10:30:60"
        [MaxSessions]="2"
        [IgnoreRhosts]="yes"
        [HostbasedAuthentication]="no"
        [PermitUserEnvironment]="no"
        [AllowTcpForwarding]="no"
        [AllowAgentForwarding]="no"
        [TCPKeepAlive]="no"
        [Compression]="no"
        [UseDNS]="no"
        [LogLevel]="VERBOSE"
        [StrictModes]="yes"
        [PrintLastLog]="yes"
        [Banner]="/etc/issue.net"
    )

    local k v current
    for k in "${!want[@]}"; do
        v="${want[$k]}"
        current="$(grep -iE "^[[:space:]]*${k}[[:space:]]" "$f" | awk '{print $2}' | tail -n1)"
        if [[ "${current,,}" == "${v,,}" ]]; then
            ok "$k $v"
        else
            bad "$k is '${current:-unset}', want '$v'"
            if confirm "Set $k $v in $f?"; then
                if need_root_for_fix; then
                    ensure_line_kv "$f" "$k" "$v"
                    if command -v sshd >/dev/null && sshd -t 2>/dev/null; then
                        fixed "$k -> $v (sshd -t OK)"
                    else
                        warn "sshd -t failed."
                    fi
                fi
            fi
        fi
    done

    sub "AllowUsers / DenyUsers"
    if grep -qE '^[[:space:]]*AllowUsers[[:space:]]' "$f"; then
        ok "AllowUsers directive present."
        note "$(grep -E '^[[:space:]]*AllowUsers[[:space:]]' "$f")"
    else
        info "No AllowUsers directive (consider restricting SSH to specific users)."
    fi

    sub "Listening port"
    local port
    port="$(grep -iE '^[[:space:]]*Port[[:space:]]' "$f" | awk '{print $2}' | tail -n1)"
    info "Port: ${port:-22 (default)}"

    sub "AcceptEnv directives"
    local accept_env
    accept_env="$(grep -iE '^[[:space:]]*AcceptEnv[[:space:]]' "$f" 2>/dev/null || true)"
    if [[ -z "$accept_env" ]]; then
        ok "No active AcceptEnv directives."
    else
        bad "AcceptEnv directives present (client environment variables accepted):"
        echo "$accept_env" | sed 's/^/         /'
    fi

    info "(SSH service is NOT restarted automatically. After review:  systemctl reload sshd)"
}

############################################################
# CHECKS - Firewall
############################################################

check_firewall() {
    hdr "Firewall"

    local found_firewall=""

    if command -v ufw >/dev/null; then
        found_firewall="ufw"
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            ok "UFW is active."
            local default_in
            default_in="$(ufw status verbose 2>/dev/null | grep -i 'Default:' | awk -F'(incoming)' '{print $1}' | awk '{print $NF}')"
            info "UFW default incoming: ${default_in:-unknown}"
            if systemctl is-enabled --quiet ufw 2>/dev/null; then
                ok "UFW is enabled at boot."
            else
                bad "UFW is not enabled at boot."
            fi
            if ufw status verbose 2>/dev/null | grep -qi 'logging: on'; then
                ok "UFW logging is enabled."
            else
                bad "UFW logging is disabled."
            fi
        else
            bad "UFW is installed but inactive."
            if confirm "ufw enable ?"; then
                if need_root_for_fix; then
                    ufw --force enable >/dev/null && {
                        log_action "UFW_ENABLE" "ufw" "" ""
                        fixed "UFW enabled"
                    }
                fi
            fi
        fi
    fi

    if command -v firewall-cmd >/dev/null; then
        found_firewall="${found_firewall:+$found_firewall, }firewalld"
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            ok "firewalld is active."
        else
            bad "firewalld is installed but not active."
            if confirm "Enable & start firewalld ?"; then
                if need_root_for_fix; then
                    systemctl enable --now firewalld >/dev/null 2>&1 && {
                        log_action "SERVICE_ENABLE" "firewalld" "" ""
                        fixed "firewalld enabled"
                    }
                fi
            fi
        fi
    fi

    if command -v nft >/dev/null; then
        found_firewall="${found_firewall:+$found_firewall, }nftables"
        if nft list ruleset 2>/dev/null | grep -q .; then
            ok "nftables has rules loaded."
        else
            warn "nftables present but no ruleset loaded."
        fi
    fi

    if command -v iptables >/dev/null; then
        found_firewall="${found_firewall:+$found_firewall, }iptables"
        local rules
        rules="$(iptables -S 2>/dev/null | grep -v -- '-P ' | wc -l)"
        if (( rules > 0 )); then
            ok "iptables has $rules custom rule(s)."
        else
            info "iptables present but no custom rules."
        fi
    fi

    if [[ -z "$found_firewall" ]]; then
        bad "No firewall tooling found."
        if confirm "Install ufw via $PKG_MGR ?"; then
            if need_root_for_fix && [[ -n "$PKG_INSTALL_CMD" ]]; then
                eval "$PKG_INSTALL_CMD ufw" >/dev/null 2>&1 && fixed "ufw installed (don't forget to enable)"
            fi
        fi
    else
        info "Firewall tools present: $found_firewall"
    fi
}

############################################################
# CHECKS - Sysctl + /proc tunables
############################################################

check_sysctl() {
    hdr "Kernel / network sysctl hardening"

    declare -A want=(
        [net.ipv4.ip_forward]="0"
        [net.ipv4.conf.all.log_martians]="1"
        [net.ipv4.conf.default.log_martians]="1"
        [net.ipv4.conf.all.accept_redirects]="0"
        [net.ipv4.conf.default.accept_redirects]="0"
        [net.ipv4.conf.all.secure_redirects]="0"
        [net.ipv4.conf.default.secure_redirects]="0"
        [net.ipv4.conf.all.send_redirects]="0"
        [net.ipv4.conf.default.send_redirects]="0"
        [net.ipv4.conf.all.accept_source_route]="0"
        [net.ipv4.conf.default.accept_source_route]="0"
        [net.ipv4.conf.all.rp_filter]="1"
        [net.ipv4.conf.default.rp_filter]="1"
        [net.ipv4.icmp_echo_ignore_broadcasts]="1"
        [net.ipv4.icmp_ignore_bogus_error_responses]="1"
        [net.ipv4.tcp_syncookies]="1"
        [net.ipv4.tcp_rfc1337]="1"
        [net.ipv4.tcp_timestamps]="0"
        [net.ipv4.tcp_max_syn_backlog]="2048"
        [net.ipv4.tcp_synack_retries]="2"
        [net.ipv4.tcp_syn_retries]="5"
        [net.ipv6.conf.all.accept_redirects]="0"
        [net.ipv6.conf.default.accept_redirects]="0"
        [net.ipv6.conf.all.accept_source_route]="0"
        [net.ipv6.conf.default.accept_source_route]="0"
        [kernel.randomize_va_space]="2"
        [kernel.kexec_load_disabled]="1"
        [kernel.perf_event_paranoid]="3"
        [kernel.kptr_restrict]="2"
        [kernel.dmesg_restrict]="1"
        [kernel.sysrq]="0"
        [kernel.core_uses_pid]="1"
        [kernel.unprivileged_userns_clone]="0"
        [vm.unprivileged_userfaultfd]="0"
        [fs.suid_dumpable]="0"
        [fs.protected_hardlinks]="1"
        [fs.protected_symlinks]="1"
    )

    local persist_file="/etc/sysctl.d/99-cp-audit.conf"
    local need_persist=0
    local fixes_buffer=""

    local k v current
    for k in "${!want[@]}"; do
        v="${want[$k]}"
        current="$(sysctl -n "$k" 2>/dev/null || true)"
        if [[ -z "$current" ]]; then
            note "$k not present on this kernel"
            continue
        fi
        if [[ "$current" == "$v" ]]; then
            ok "$k = $v"
        else
            bad "$k = $current, want $v"
            if confirm "Set $k=$v ?"; then
                if need_root_for_fix; then
                    fixes_buffer+="${k} = ${v}"$'\n'
                    sysctl -w "$k=$v" >/dev/null 2>&1 && fixed "$k -> $v (live)" || warn "live set failed"
                    need_persist=1
                fi
            fi
        fi
    done

    if (( need_persist )); then
        local b
        b="$(backup_file "$persist_file")"
        printf '# Added by %s on %s\n%s' "$SCRIPT_NAME" "$RUN_TS" "$fixes_buffer" >> "$persist_file"
        if [[ -n "$b" ]]; then
            log_action "BACKUP_FILE" "$persist_file" "$b" ""
        else
            log_action "CREATE_FILE" "$persist_file" "" ""
        fi
        fixed "persisted to $persist_file"
    fi
}

############################################################
# CHECKS - Critical file perms / ownership
############################################################

check_critical_perms() {
    hdr "Critical file permissions and ownership"

    declare -A want=(
        [/etc/shadow]="640 root:${SHADOW_GROUP}"
        [/etc/gshadow]="640 root:${SHADOW_GROUP}"
        [/etc/passwd]="644 root:root"
        [/etc/group]="644 root:root"
        [/etc/ssh/sshd_config]="600 root:root"
        [/etc/sudoers]="440 root:root"
        [/etc/securetty]="600 root:root"
        [/etc/crontab]="600 root:root"
        [/etc/cron.hourly]="700 root:root"
        [/etc/cron.daily]="700 root:root"
        [/etc/cron.weekly]="700 root:root"
        [/etc/cron.monthly]="700 root:root"
        [/etc/cron.d]="700 root:root"
        [/etc/hosts.allow]="644 root:root"
        [/etc/hosts.deny]="644 root:root"
        [/boot/grub/grub.cfg]="600 root:root"
        [/boot/grub2/grub.cfg]="600 root:root"
    )

    local f mode owner group actual target_mode target_own b
    for f in "${!want[@]}"; do
        if [[ ! -e "$f" ]]; then
            note "$f does not exist"
            continue
        fi
        mode="$(stat -c '%a' "$f")"
        owner="$(stat -c '%U' "$f")"
        group="$(stat -c '%G' "$f")"
        actual="$mode $owner:$group"
        if [[ "$actual" == "${want[$f]}" ]]; then
            ok "$f -> $actual"
        else
            bad "$f -> $actual (want ${want[$f]})"
            if confirm "Fix perms on $f to ${want[$f]} ?"; then
                if need_root_for_fix; then
                    b="$(backup_file "$f")"
                    target_mode="${want[$f]%% *}"
                    target_own="${want[$f]##* }"
                    chmod "$target_mode" "$f"
                    chown "$target_own" "$f"
                    log_action "BACKUP_FILE" "$f" "$b" "perms"
                    fixed "$f -> ${want[$f]}"
                fi
            fi
        fi
    done

    sub "Home directory permissions"
    local h u
    while IFS=: read -r u _ uid _ _ home _; do
        if (( uid >= 1000 && uid < 60000 )) && [[ -d "$home" ]]; then
            mode="$(stat -c '%a' "$home")"
            if [[ "$mode" =~ ^7[0-5][0-5]$ ]] || [[ "$mode" == "750" ]]; then
                ok "$home ($u): $mode"
            else
                warn "$home ($u): $mode (consider 750)"
            fi
        fi
    done < /etc/passwd
}

check_suid_sgid() {
    hdr "SUID / SGID binaries"

    if [[ $EUID -ne 0 ]]; then
        warn "Non-root: results may be incomplete."
    fi
    sub "SUID binaries"
    local suspicious=(nano vi vim less more man find cp mv tar zip unzip ruby python python3 perl awk sed bash sh dash ksh zsh tee dd nc ncat wget curl)
    local f base flag s
    while IFS= read -r f; do
        base="$(basename "$f")"
        flag=""
        for s in "${suspicious[@]}"; do
            if [[ "$base" == "$s" ]]; then
                flag=" ${C_RED}<-- SUSPICIOUS${C_RESET}"
                break
            fi
        done
        echo "         $f$flag"
    done < <(find / -xdev -type f -perm -4000 2>/dev/null | sort)

    sub "SGID binaries"
    while IFS= read -r f; do
        echo "         $f"
    done < <(find / -xdev -type f -perm -2000 2>/dev/null | sort)
}

check_world_writable() {
    hdr "World-writable files and directories"

    sub "World-writable files (excluding /proc /sys /dev /run /tmp)"
    local results
    results="$(find / -xdev -type f -perm -0002 \
        ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' \
        ! -path '/run/*' ! -path '/tmp/*' ! -path '/var/tmp/*' 2>/dev/null || true)"
    if [[ -z "$results" ]]; then
        ok "No world-writable files outside expected dirs."
    else
        local f
        while IFS= read -r f; do warn "ww file: $f"; done <<< "$results"
    fi

    sub "World-writable directories without sticky bit"
    results="$(find / -xdev -type d -perm -0002 ! -perm -1000 \
        ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/run/*' 2>/dev/null || true)"
    if [[ -z "$results" ]]; then
        ok "No world-writable dirs missing sticky bit."
    else
        local f
        while IFS= read -r f; do bad "ww dir (no sticky): $f"; done <<< "$results"
    fi
}

check_no_owner() {
    hdr "Files with no user or no group"
    local results
    results="$(find / -xdev \( -nouser -o -nogroup \) ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null || true)"
    if [[ -z "$results" ]]; then
        ok "No orphan files."
    else
        local f
        while IFS= read -r f; do bad "orphan: $f"; done <<< "$results"
    fi
}

############################################################
# CHECKS - Services / packages
############################################################

check_services() {
    hdr "Services, listening sockets, and processes"

    if command -v systemctl >/dev/null; then
        sub "Active services"
        systemctl list-units --type=service --state=active --no-legend --no-pager 2>/dev/null \
          | awk '{print "         " $1}'
    fi

    sub "Listening sockets"
    if command -v ss >/dev/null; then
        ss -tulnp 2>/dev/null | awk 'NR>1 {print "         " $0}'
    elif command -v netstat >/dev/null; then
        netstat -tulnp 2>/dev/null | awk 'NR>2 {print "         " $0}'
    fi

    sub "Processes (top 30 by CPU)"
    ps -eo pid,user,%cpu,%mem,cmd --sort=-%cpu 2>/dev/null | head -30 | awk '{print "         " $0}'

    sub "Netcat / suspicious backdoor processes"
    local hits
    hits="$(ps -ef 2>/dev/null | grep -E '\b(nc|ncat|netcat|socat)\b' | grep -v grep || true)"
    if [[ -z "$hits" ]]; then
        ok "No netcat/socat processes running."
    else
        echo "$hits" | while read -r line; do bad "BACKDOOR?: $line"; done
    fi
}

check_prohibited_packages() {
    hdr "Commonly-prohibited packages"

    local bad_pkgs=(
        # Password crackers
        ophcrack john "john-data" hydra "hydra-gtk" hashcat fcrackzip lcrack pdfcrack rarcrack sipcrack medusa
        # Network attack tools
        "aircrack-ng|aircrack" weplab pyrit
        nmap zenmap nikto sqlmap
        "wireshark|wireshark-common|tshark" tcpdump
        "ettercap-text-only|ettercap" irpas
        # Backdoor / shell tools
        "netcat|netcat-traditional|netcat-openbsd|ncat|pnetcat" socat sock socket sbd
        # Insecure servers
        "vsftpd" "proftpd" "pure-ftpd" "ftp"
        "telnet" "telnetd" "telnet-server" "inetutils-telnetd"
        "rsh-server" "rsh-client" "rsh" "rsh-redone-server"
        nis "yp-tools" "ypbind" "ypserv"
        talk talkd
        "inetd" "openbsd-inetd" "xinetd"
        # File sharing (only if not required)
        samba "samba-common"
        # Web servers (only if not required)
        nginx "apache2|httpd" lighttpd
        # Other
        snmpd "net-snmp" "bind9|bind"
        "dovecot-core|dovecot|dovecot-imapd"
        postfix sendmail "exim4|exim"
        logkeys
        pvpgn sucrack changeme unworkable
        # Remote desktop
        "vnc4server" "vncsnapshot" "tightvncserver" "vino" "x11vnc"
        # P2P
        frostwire vuze azureus deluge transmission qbittorrent
        # Game / non-work
        nethack aisleriot "gnome-mahjongg" "2048"
        # Zeitgeist / privacy
        "zeitgeist" "zeitgeist-core" "zeitgeist-datahub"
        # NFS
        "nfs-kernel-server" "nfs-common" portmap rpcbind
    )

    info "Checking installed packages against bad list..."
    local pkgspec p alts
    for pkgspec in "${bad_pkgs[@]}"; do
        IFS='|' read -ra alts <<< "$pkgspec"
        for p in "${alts[@]}"; do
            if pkg_is_installed "$p"; then
                warn "Installed: $p   (check README; may be allowed)"
                break
            fi
        done
    done

    sub "All installed packages matching 'crack|hack' (manual review)"
    case "$PKG_MGR" in
        apt)    dpkg -l 2>/dev/null | awk '/^ii/ {print $2}' | grep -iE 'crack|hack' | grep -viE 'libcrack|cracklib' | sed 's/^/         /' || note "(none)" ;;
        dnf|yum|zypper) rpm -qa 2>/dev/null | grep -iE 'crack|hack' | grep -viE 'libcrack|cracklib' | sed 's/^/         /' || note "(none)" ;;
        pacman) pacman -Qq 2>/dev/null | grep -iE 'crack|hack' | grep -viE 'libcrack|cracklib' | sed 's/^/         /' || note "(none)" ;;
    esac
}

check_pkg_mgr_config() {
    hdr "Package manager and repository configuration"

    case "$PKG_MGR" in
        apt)
            sub "/etc/apt/sources.list and /etc/apt/sources.list.d/"
            local f
            for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
                [[ -f "$f" ]] || continue
                local lines
                lines="$(grep -vE '^[[:space:]]*(#|$)' "$f" | wc -l)"
                if (( lines > 0 )); then
                    info "$f ($lines active lines)"
                    grep -vE '^[[:space:]]*(#|$)' "$f" | sed 's/^/         /'
                fi
            done

            sub "APT auto-update / GPG verification"
            local cfg=/etc/apt/apt.conf.d/99-cp-audit
            declare -A want=(
                ['APT::Get::AllowUnauthenticated']='"false";'
                ['APT::Periodic::Update-Package-Lists']='"1";'
                ['APT::Periodic::Unattended-Upgrade']='"1";'
            )
            local k v b
            for k in "${!want[@]}"; do
                v="${want[$k]}"
                if grep -rqs "${k}" /etc/apt/apt.conf.d/ /etc/apt/apt.conf 2>/dev/null; then
                    ok "$k present in /etc/apt/."
                else
                    bad "$k not set."
                    if confirm "Append $k $v to $cfg ?"; then
                        if need_root_for_fix; then
                            b="$(backup_file "$cfg")"
                            printf '%s %s\n' "$k" "$v" >> "$cfg"
                            if [[ -n "$b" ]]; then
                                log_action "BACKUP_FILE" "$cfg" "$b" ""
                            else
                                log_action "CREATE_FILE" "$cfg" "" ""
                            fi
                            fixed "$k -> $v"
                        fi
                    fi
                fi
            done

            sub "Suspicious APT settings / hooks"
            local apt_hits
            apt_hits="$(
                grep -RInE 'AllowUnauthenticated[[:space:]]+\"?true|AllowInsecureRepositories[[:space:]]+\"?true|trusted=yes|Verify-Peer[[:space:]]+\"?false|Pre-Invoke|Post-Invoke|DPkg::Pre-Install-Pkgs' \
                    /etc/apt/apt.conf /etc/apt/apt.conf.d /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true
            )"
            if [[ -z "$apt_hits" ]]; then
                ok "No obviously malicious APT overrides found."
            else
                bad "Suspicious APT configuration detected:"
                echo "$apt_hits" | sed 's/^/         /'
            fi
            ;;
        dnf|yum)
            local f=/etc/dnf/dnf.conf
            [[ "$PKG_MGR" == "yum" ]] && f=/etc/yum.conf
            if [[ -r "$f" ]]; then
                if grep -qE '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*1' "$f"; then
                    ok "$f gpgcheck=1"
                else
                    bad "$f gpgcheck not set to 1"
                fi
            fi
            if [[ "$PKG_MGR" == "dnf" ]] && command -v systemctl >/dev/null; then
                if systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
                    ok "dnf-automatic.timer enabled."
                else
                    info "dnf-automatic.timer not enabled (auto-updates off)."
                fi
            fi
            sub "Repositories"
            ls /etc/yum.repos.d/ 2>/dev/null | sed 's/^/         /'
            ;;
        zypper)
            local f=/etc/zypp/zypp.conf
            if [[ -r "$f" ]]; then
                if grep -qE '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*1' "$f"; then
                    ok "$f gpgcheck=1"
                else
                    info "$f gpgcheck not explicitly set (zypper default is on)."
                fi
            fi
            sub "Repositories"
            zypper lr 2>/dev/null | sed 's/^/         /'
            ;;
        pacman)
            if grep -qE '^[[:space:]]*SigLevel[[:space:]]*=' /etc/pacman.conf; then
                local sl
                sl="$(grep -E '^[[:space:]]*SigLevel[[:space:]]*=' /etc/pacman.conf | head -1 | cut -d= -f2- | xargs)"
                if [[ "$sl" =~ Required ]]; then
                    ok "pacman SigLevel includes Required"
                else
                    bad "pacman SigLevel does not require signatures: $sl"
                fi
            fi
            ;;
    esac

    sub "PIP configuration"
    if [[ -f /etc/pip.conf ]] && grep -q "require-hashes" /etc/pip.conf; then
        ok "/etc/pip.conf require-hashes set."
    else
        info "/etc/pip.conf does not require hashes (only relevant if pip is used)."
    fi
}

############################################################
# CHECKS - Display managers
############################################################

check_display_manager() {
    hdr "Display manager / login screen"

    local f=/etc/lightdm/lightdm.conf
    if [[ -f "$f" ]]; then
        sub "LightDM"
        for setting in 'allow-guest=false' 'greeter-hide-users=true' 'greeter-show-manual-login=true' 'autologin-user=none'; do
            if grep -q "^${setting}" "$f" 2>/dev/null; then
                ok "$setting"
            else
                bad "missing: $setting"
                if confirm "Add $setting to $f ?"; then
                    if need_root_for_fix; then
                        local b
                        b="$(backup_file "$f")"
                        echo "$setting" >> "$f"
                        log_action "BACKUP_FILE" "$f" "$b" ""
                        fixed "added $setting"
                    fi
                fi
            fi
        done
    fi

    local gdm=""
    for cand in /etc/gdm3/greeter.dconf-defaults /etc/gdm/custom.conf /etc/gdm3/custom.conf; do
        [[ -f "$cand" ]] && gdm="$cand" && break
    done
    if [[ -n "$gdm" ]]; then
        sub "GDM ($gdm)"
        if grep -qE 'disable-user-list[[:space:]]*=[[:space:]]*true' "$gdm"; then
            ok "disable-user-list = true"
        else
            bad "GDM does not hide user list"
            if confirm "Append disable-user-list=true to $gdm ?"; then
                if need_root_for_fix; then
                    local b
                    b="$(backup_file "$gdm")"
                    printf '\n[org/gnome/login-screen]\ndisable-user-list=true\n' >> "$gdm"
                    log_action "BACKUP_FILE" "$gdm" "$b" ""
                    fixed "GDM hides user list"
                fi
            fi
        fi

        local gdm_root
        gdm_root="$(grep -iE 'allowroot|greeter-allow-root' "$gdm" 2>/dev/null || true)"
        if echo "$gdm_root" | grep -qiE '=[[:space:]]*true'; then
            bad "GDM appears to allow root in greeter:"
            echo "$gdm_root" | sed 's/^/         /'
        else
            ok "No GDM allow-root directive is enabled."
        fi
    fi

    if [[ -f /etc/sddm.conf ]] || [[ -d /etc/sddm.conf.d ]]; then
        sub "SDDM"
        info "SDDM config present; review /etc/sddm.conf and /etc/sddm.conf.d/"
    fi
}

############################################################
# CHECKS - Cron / at / systemd timers
############################################################

check_scheduled() {
    hdr "Scheduled tasks"

    sub "User crontabs"
    local d u
    for d in /var/spool/cron/crontabs /var/spool/cron; do
        [[ -d "$d" ]] || continue
        for u in "$d"/*; do
            [[ -f "$u" ]] || continue
            warn "$(basename "$u") has a crontab ($(wc -l <"$u") lines)"
            sed 's/^/         /' "$u" 2>/dev/null
        done
    done

    sub "/etc/crontab and /etc/cron.d/"
    [[ -f /etc/crontab ]] && info "/etc/crontab ($(wc -l </etc/crontab) lines)"
    if [[ -d /etc/cron.d ]]; then
        local f
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] && info "/etc/cron.d/$(basename "$f")"
        done
    fi

    sub "Suspicious cron patterns"
    local cron_hits
    cron_hits="$(
        grep -RInE 'curl|wget|nc[[:space:]]|-e|/dev/tcp|base64[[:space:]].*-d|chmod[[:space:]]+4[0-7]{3}|chattr[[:space:]]+\+i|bash[[:space:]]+-i|sh[[:space:]]+-c' \
            /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
            /var/spool/cron /var/spool/cron/crontabs 2>/dev/null || true
    )"
    if [[ -z "$cron_hits" ]]; then
        ok "No obviously malicious cron patterns found."
    else
        bad "Suspicious cron content detected:"
        echo "$cron_hits" | sed 's/^/         /'
    fi

    sub "/etc/cron.{hourly,daily,weekly,monthly}/"
    local d2
    for d2 in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [[ -d "$d2" ]] || continue
        local f
        for f in "$d2"/*; do
            [[ -f "$f" ]] && note "$f"
        done
    done

    sub "cron.allow / cron.deny / at.allow / at.deny"
    for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
        if [[ -f "$f" ]]; then
            info "$f exists: $(wc -l <"$f") lines"
        fi
    done

    sub "systemd timers"
    if command -v systemctl >/dev/null; then
        systemctl list-timers --no-legend --no-pager 2>/dev/null | head -30 | sed 's/^/         /'
    fi
}

############################################################
# CHECKS - Network configuration files
############################################################

check_network_files() {
    hdr "Network configuration files"

    sub "/etc/hosts"
    if [[ -r /etc/hosts ]]; then
        local nonloop
        nonloop="$(grep -vE '^\s*(#|$|127\.|::1|fe00|ff00|ff02)' /etc/hosts | grep -v '^127\.' || true)"
        if [[ -z "$nonloop" ]]; then
            ok "/etc/hosts has only loopback / standard entries."
        else
            warn "/etc/hosts has non-standard entries:"
            echo "$nonloop" | sed 's/^/         /'
        fi
    fi

    sub "/etc/host.conf"
    if [[ -r /etc/host.conf ]]; then
        if grep -q 'nospoof on' /etc/host.conf; then
            ok "nospoof on"
        else
            bad "/etc/host.conf missing 'nospoof on'"
            if confirm "Add 'nospoof on' to /etc/host.conf ?"; then
                if need_root_for_fix; then
                    local b
                    b="$(backup_file /etc/host.conf)"
                    echo "nospoof on" >> /etc/host.conf
                    log_action "BACKUP_FILE" "/etc/host.conf" "$b" ""
                    fixed "nospoof on"
                fi
            fi
        fi
        if grep -q 'order' /etc/host.conf; then
            ok "order directive present"
        fi
    fi

    sub "/etc/resolv.conf nameservers"
    if [[ -r /etc/resolv.conf ]]; then
        grep -E '^nameserver' /etc/resolv.conf | sed 's/^/         /'
        info "Verify nameservers are not pointing to attacker-controlled IPs."
    fi

    sub "/etc/hosts.allow and /etc/hosts.deny (TCP wrappers)"
    for f in /etc/hosts.allow /etc/hosts.deny; do
        if [[ -f "$f" ]]; then
            local lines
            lines="$(grep -vE '^\s*(#|$)' "$f" | wc -l)"
            info "$f: $lines active lines"
        fi
    done

    sub "/etc/securetty (consoles where root may log in)"
    if [[ -r /etc/securetty ]]; then
        local count
        count="$(grep -vE '^\s*(#|$)' /etc/securetty | wc -l)"
        info "$count entries"
        if (( count > 6 )); then
            warn "Many entries in /etc/securetty — consider trimming."
        fi
    fi
}

############################################################
# CHECKS - Boot / startup
############################################################

check_boot() {
    hdr "Boot and startup"

    sub "/etc/rc.local"
    if [[ -f /etc/rc.local ]]; then
        local content
        content="$(grep -vE '^\s*(#|$|exit\s+0)' /etc/rc.local || true)"
        if [[ -z "$content" ]]; then
            ok "/etc/rc.local is empty / default."
        else
            bad "/etc/rc.local has commands:"
            echo "$content" | sed 's/^/         /'
            info "Review for backdoors. Default should be empty + 'exit 0'."
        fi
    fi

    sub "/etc/profile and /etc/profile.d/"
    if [[ -d /etc/profile.d ]]; then
        local f
        for f in /etc/profile.d/*.sh; do
            [[ -f "$f" ]] && note "$(basename "$f")"
        done
    fi

    sub "Systemd startup services (enabled)"
    if command -v systemctl >/dev/null; then
        systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null \
            | head -40 | awk '{print "         " $1}'
    fi

    sub "/etc/environment"
    if [[ -r /etc/environment ]]; then
        cat /etc/environment | sed 's/^/         /'
    fi
}

############################################################
# CHECKS - Kernel modules / hardware
############################################################

check_modules() {
    hdr "Kernel module blacklists"

    sub "USB storage"
    if grep -rqs "install usb-storage /bin/true" /etc/modprobe.d/ 2>/dev/null \
       || grep -rqs "blacklist usb-storage" /etc/modprobe.d/ 2>/dev/null; then
        ok "usb-storage blacklisted"
    else
        info "usb-storage NOT blacklisted (consider blocking on critical hosts)"
    fi

    sub "Firewire / Thunderbolt"
    if grep -rqs "blacklist firewire-core" /etc/modprobe.d/ 2>/dev/null; then
        ok "firewire-core blacklisted"
    else
        info "firewire-core not blacklisted"
    fi
    if grep -rqs "blacklist thunderbolt" /etc/modprobe.d/ 2>/dev/null; then
        ok "thunderbolt blacklisted"
    else
        info "thunderbolt not blacklisted"
    fi

    sub "Loaded uncommon modules"
    local mods
    mods="$(lsmod 2>/dev/null | awk 'NR>1 {print $1}' | grep -iE 'bluetooth|firewire|thunderbolt|appletalk|dccp|sctp|rds|tipc' || true)"
    if [[ -z "$mods" ]]; then
        ok "No suspicious modules loaded."
    else
        echo "$mods" | sed 's/^/         /'
    fi
}

############################################################
# CHECKS - Aliases / shell rc files
############################################################

check_aliases() {
    hdr "Shell aliases and functions (current shell)"

    sub "Aliases (non-default)"
    local aliases
    aliases="$(alias 2>/dev/null \
        | grep -viE "alias (egrep|fgrep|grep|l|la|ll|ls)=" || true)"
    if [[ -z "$aliases" ]]; then
        ok "No suspicious aliases."
    else
        echo "$aliases" | sed 's/^/         /'
        info "Review for backdoor wrappers."
    fi

    sub "/etc/bash.bashrc, /etc/profile, ~/.bashrc"
    local f
    for f in /etc/bash.bashrc /etc/profile /root/.bashrc; do
        [[ -f "$f" ]] || continue
        local s
        s="$(stat -c '%s' "$f")"
        info "$f ($s bytes)"
    done
    info "Manually inspect ~/.bashrc, ~/.profile, ~/.bash_profile in every home dir."
}

############################################################
# CHECKS - SSH authorized_keys
############################################################

check_authorized_keys() {
    hdr "SSH authorized_keys"
    local f
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [[ -f "$f" ]] || continue
        local keys
        keys="$(grep -vE '^\s*(#|$)' "$f" | wc -l)"
        if (( keys > 0 )); then
            warn "$f has $keys key(s)"
            grep -vE '^\s*(#|$)' "$f" | awk '{print "         " $NF}'
        fi
    done
}

############################################################
# CHECKS - Forensics / prohibited files
############################################################

check_forensics_questions() {
    hdr "Forensics question files"

    local found=0 d f
    for d in /home/*/Desktop /root/Desktop; do
        [[ -d "$d" ]] || continue
        for f in "$d"/Forensic* "$d"/forensic* "$d"/FQ* "$d"/fq*; do
            [[ -e "$f" ]] || continue
            info "FQ file: $f"
            found=1
        done
    done
    (( found )) || info "No Forensics Question files found."
    cat <<'EOF'
         Common FQ patterns and how to answer:
         - Decode base64:        echo "<text>" | base64 -d
         - Find file by name:    sudo find / -name "X" 2>/dev/null
         - Find by extension:    sudo find / -iname "*.mp3" 2>/dev/null
         - User UID:             id <user>
         - SSH port:             grep -i ^Port /etc/ssh/sshd_config
         - SUID binaries:        find / -perm -4000 2>/dev/null
         - File capabilities:    getcap -r / 2>/dev/null
         - File hash:            sha256sum /path/to/file
         - Strings in binary:    strings /path/to/binary | less
         - Find by user:         find / -user <user> 2>/dev/null
         - Recently modified:    find / -mtime -7 2>/dev/null
EOF
}

check_prohibited_files() {
    hdr "Prohibited files (full filesystem scan)"

    sub "Audio files"
    find / -xdev -type f \( \
        -iname '*.mp3' -o -iname '*.m4a' -o -iname '*.flac' -o -iname '*.ogg' \
        -o -iname '*.wav' -o -iname '*.aac' -o -iname '*.wma' -o -iname '*.aiff' \
        -o -iname '*.aif' -o -iname '*.midi' -o -iname '*.mid' -o -iname '*.au' \
    \) 2>/dev/null | sed 's/^/         /' | head -50

    sub "Video files"
    find / -xdev -type f \( \
        -iname '*.mp4' -o -iname '*.mkv' -o -iname '*.avi' -o -iname '*.mov' \
        -o -iname '*.wmv' -o -iname '*.flv' -o -iname '*.m4v' -o -iname '*.webm' \
        -o -iname '*.mpg' -o -iname '*.mpeg' -o -iname '*.3gp' -o -iname '*.swf' \
    \) 2>/dev/null | sed 's/^/         /' | head -50

    sub "Hacking tool downloads in user homes"
    find /home /root -type f \( \
        -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.zip' -o -iname '*.rar' \
        -o -iname '*.deb' -o -iname '*.rpm' -o -iname '*.iso' \
    \) 2>/dev/null | sed 's/^/         /' | head -50

    sub "Suspicious filenames in user homes"
    find /home /root -type f \( \
        -iname 'wordlist*' -o -iname 'passwords*' -o -iname 'rockyou*' \
        -o -iname 'shadow*' -o -iname 'crack*' -o -iname 'hash*' \
    \) 2>/dev/null | sed 's/^/         /'

    sub "Shell scripts in /bin /usr/bin (suspicious)"
    find /bin /usr/bin -maxdepth 1 -type f -name '*.sh' 2>/dev/null | sed 's/^/         /'

    sub "PHP files (web shell hunting)"
    find / -xdev -type f -name '*.php' 2>/dev/null | head -30 | sed 's/^/         /'

    info "Compare against README; remove anything not work-related."
}

############################################################
# CHECKS - Critical service configs
############################################################

check_apache() {
    hdr "Apache (if installed)"

    local conf=""
    for c in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf; do
        [[ -f "$c" ]] && conf="$c" && break
    done
    [[ -z "$conf" ]] && { info "Apache not configured."; return; }

    info "Config: $conf"
    local sec=""
    for c in /etc/apache2/conf-enabled/security.conf /etc/httpd/conf.d/security.conf; do
        [[ -f "$c" ]] && sec="$c" && break
    done

    local f="$sec"
    [[ -z "$f" ]] && f="$conf"

    if grep -qE '^[[:space:]]*ServerTokens[[:space:]]+Prod' "$f" 2>/dev/null; then
        ok "ServerTokens Prod"
    else
        bad "ServerTokens not set to Prod"
    fi
    if grep -qE '^[[:space:]]*ServerSignature[[:space:]]+Off' "$f" 2>/dev/null; then
        ok "ServerSignature Off"
    else
        bad "ServerSignature not Off"
    fi
    if grep -qE 'Options.*-Indexes' "$f" 2>/dev/null; then
        ok "Indexes disabled"
    else
        warn "Options -Indexes not set"
    fi
}

check_mysql() {
    hdr "MySQL / MariaDB (if installed)"

    local conf=""
    for c in /etc/mysql/my.cnf /etc/mysql/mariadb.conf.d/50-server.cnf /etc/my.cnf; do
        [[ -f "$c" ]] && conf="$c" && break
    done
    [[ -z "$conf" ]] && { info "MySQL not configured."; return; }

    info "Config: $conf"
    if grep -qE '^[[:space:]]*bind-address[[:space:]]*=[[:space:]]*127\.0\.0\.1' "$conf"; then
        ok "bind-address = 127.0.0.1"
    else
        bad "bind-address not 127.0.0.1 (DB exposed)"
    fi
    if grep -qE '^[[:space:]]*skip-networking' "$conf"; then
        ok "skip-networking enabled"
    fi
    info "Run mysql_secure_installation to fix root pw, anon users, test db."
}

check_vsftpd() {
    hdr "vsftpd (if installed)"

    local conf=""
    for c in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        [[ -f "$c" ]] && conf="$c" && break
    done
    [[ -z "$conf" ]] && { info "vsftpd not configured."; return; }

    info "Config: $conf"
    declare -A want=(
        [anonymous_enable]="NO"
        [anon_upload_enable]="NO"
        [anon_mkdir_write_enable]="NO"
        [chroot_local_user]="YES"
        [ssl_enable]="YES"
    )
    local k v current
    for k in "${!want[@]}"; do
        v="${want[$k]}"
        current="$(grep -E "^[[:space:]]*${k}[[:space:]]*=" "$conf" | tail -n1 | cut -d= -f2 | xargs)"
        if [[ "${current^^}" == "${v^^}" ]]; then
            ok "$k=$v"
        else
            bad "$k is '${current:-unset}', want $v"
        fi
    done
}

check_samba() {
    hdr "Samba (if installed)"
    local f=/etc/samba/smb.conf
    if [[ ! -f "$f" ]]; then
        info "Samba not configured."
        return
    fi
    grep -q "restrict anonymous" "$f" && ok "restrict anonymous present" || warn "restrict anonymous not set"
    grep -q "read only" "$f" && ok "read only present" || warn "read only not set"
    grep -qE "^[[:space:]]*server signing" "$f" && ok "server signing configured" || warn "server signing not configured"
    grep -qE "^[[:space:]]*encrypt passwords" "$f" && ok "encrypt passwords configured" || warn "encrypt passwords not set"
}

check_php() {
    hdr "PHP (if installed)"
    local f
    f="$(find /etc -name 'php.ini' 2>/dev/null | head -1)"
    [[ -z "$f" ]] && { info "PHP not configured."; return; }

    info "Config: $f"
    declare -A want=(
        [expose_php]="Off"
        [allow_url_fopen]="Off"
        [allow_url_include]="Off"
        [display_errors]="Off"
    )
    local k v current
    for k in "${!want[@]}"; do
        v="${want[$k]}"
        current="$(grep -E "^[[:space:]]*${k}[[:space:]]*=" "$f" | tail -n1 | cut -d= -f2 | xargs)"
        if [[ "${current^^}" == "${v^^}" ]]; then
            ok "$k = $v"
        else
            bad "$k is '${current:-unset}', want $v"
        fi
    done
}

############################################################
# CHECKS - Security tools installed
############################################################

check_security_tools() {
    hdr "Security tools / scanners installed"

    local tools=(fail2ban ufw iptables auditd "rkhunter" "chkrootkit" lynis clamav "debsums" aide "apparmor" "selinux-utils")
    local t
    for t in "${tools[@]}"; do
        if command -v "$t" >/dev/null 2>&1 || pkg_is_installed "$t"; then
            ok "$t installed"
        else
            info "$t NOT installed"
        fi
    done

    sub "auditd"
    if command -v systemctl >/dev/null && systemctl is-active --quiet auditd 2>/dev/null; then
        ok "auditd is active."
    else
        warn "auditd not active."
    fi

    sub "fail2ban"
    if command -v systemctl >/dev/null && systemctl is-active --quiet fail2ban 2>/dev/null; then
        ok "fail2ban is active."
    else
        info "fail2ban not active."
    fi

    sub "AppArmor / SELinux"
    if command -v aa-status >/dev/null 2>&1; then
        local profiles
        profiles="$(aa-status --enabled 2>/dev/null && echo enabled || echo disabled)"
        info "AppArmor: $profiles"
    fi
    if command -v systemctl >/dev/null && systemctl list-unit-files 2>/dev/null | grep -q '^apparmor\.service'; then
        if systemctl is-enabled --quiet apparmor 2>/dev/null; then
            ok "apparmor.service is enabled."
        else
            bad "apparmor.service is not enabled."
        fi
        if systemctl is-active --quiet apparmor 2>/dev/null; then
            ok "apparmor.service is active."
        else
            bad "apparmor.service is not active."
        fi
    fi
    if command -v getenforce >/dev/null 2>&1; then
        info "SELinux: $(getenforce)"
    fi
}

check_score_specific_services() {
    hdr "Score-specific services and binaries"

    sub "Apache"
    if pkg_is_installed apache2 || pkg_is_installed httpd; then
        bad "Apache package is installed."
    else
        ok "Apache package is not installed."
    fi
    if command -v systemctl >/dev/null && systemctl list-unit-files 2>/dev/null | grep -qE '^(apache2|httpd)\.service'; then
        if systemctl is-enabled --quiet apache2 2>/dev/null || systemctl is-enabled --quiet httpd 2>/dev/null; then
            bad "Apache service is enabled."
        else
            ok "Apache service is not enabled."
        fi
    fi

    sub "PVPGN"
    if pkg_is_installed pvpgn; then
        bad "PVPGN is installed."
    else
        ok "PVPGN is not installed."
    fi

    sub "date binary"
    local date_bin mode
    date_bin="$(command -v date 2>/dev/null || true)"
    if [[ -n "$date_bin" && -e "$date_bin" ]]; then
        mode="$(stat -c '%a' "$date_bin")"
        if [[ "$mode" =~ ^4 ]]; then
            bad "$date_bin has SUID bit set (mode=$mode)"
        else
            ok "$date_bin does not have SUID bit set (mode=$mode)"
        fi
    fi
}

check_firefox_prefs() {
    hdr "Firefox preferences"

    local found=0 f hits
    for f in /root/.mozilla/firefox/*.default*/prefs.js /home/*/.mozilla/firefox/*.default*/prefs.js; do
        [[ -f "$f" ]] || continue
        found=1
        hits="$(grep -E 'dom\.security\.https_only_mode' "$f" 2>/dev/null || true)"
        if echo "$hits" | grep -q 'true'; then
            ok "$f has HTTPS-only mode enabled."
        else
            bad "$f does not enable HTTPS-only mode."
        fi
    done
    (( found )) || info "No Firefox prefs.js files found."
}

check_seafile() {
    hdr "Seafile / Seahub"

    local seahub_cfg="" seafile_cfg="" f
    for f in \
        /opt/seafile/conf/seahub_settings.py \
        /srv/seafile/conf/seahub_settings.py \
        /etc/seafile/seahub_settings.py \
        /home/*/seafile/conf/seahub_settings.py \
        /root/seafile/conf/seahub_settings.py; do
        [[ -f "$f" ]] && seahub_cfg="$f" && break
    done
    for f in \
        /opt/seafile/conf/seafile.conf \
        /srv/seafile/conf/seafile.conf \
        /etc/seafile/seafile.conf \
        /home/*/seafile/conf/seafile.conf \
        /root/seafile/conf/seafile.conf; do
        [[ -f "$f" ]] && seafile_cfg="$f" && break
    done

    if [[ -n "$seahub_cfg" ]]; then
        info "Seahub config: $seahub_cfg"

        sub "Cookie SameSite"
        local cookie_hits
        cookie_hits="$(grep -E '^(SESSION_COOKIE_SAMESITE|CSRF_COOKIE_SAMESITE)[[:space:]]*=' "$seahub_cfg" 2>/dev/null || true)"
        if echo "$cookie_hits" | grep -qiE "['\"](Lax|Strict)['\"]"; then
            ok "Seahub sets SameSite on cookies."
        else
            bad "Seahub SameSite cookie settings not found or set weakly."
        fi
        [[ -n "$cookie_hits" ]] && echo "$cookie_hits" | sed 's/^/         /'

        sub "Session cookie lifetime"
        if grep -qE '^SESSION_EXPIRE_AT_BROWSER_CLOSE[[:space:]]*=[[:space:]]*True' "$seahub_cfg"; then
            ok "SESSION_EXPIRE_AT_BROWSER_CLOSE = True"
        else
            bad "SESSION_EXPIRE_AT_BROWSER_CLOSE is not enabled."
        fi

        sub "Password minimum length"
        local min_len
        min_len="$(grep -E '^USER_PASSWORD_MIN_LENGTH[[:space:]]*=' "$seahub_cfg" | awk -F= '{print $2}' | tr -dc '0-9' | head -c 8)"
        if [[ -n "$min_len" && "$min_len" -ge 10 ]]; then
            ok "USER_PASSWORD_MIN_LENGTH = $min_len"
        else
            bad "USER_PASSWORD_MIN_LENGTH is '${min_len:-unset}', want at least 10"
        fi

        sub "Password strength level"
        local strength
        strength="$(grep -E '^USER_PASSWORD_STRENGTH_LEVEL[[:space:]]*=' "$seahub_cfg" | awk -F= '{print $2}' | xargs)"
        if echo "$strength" | grep -qiE '3|strong'; then
            ok "USER_PASSWORD_STRENGTH_LEVEL = $strength"
        else
            bad "USER_PASSWORD_STRENGTH_LEVEL is '${strength:-unset}', want strong/3"
        fi

        sub "Password complexity classes"
        local complexity
        complexity="$(grep -E '^USER_PASSWORD_REQUIRED_CATEGORIES[[:space:]]*=' "$seahub_cfg" | awk -F= '{print $2}' | xargs)"
        if echo "$complexity" | grep -qE '4'; then
            ok "USER_PASSWORD_REQUIRED_CATEGORIES = $complexity"
        else
            bad "USER_PASSWORD_REQUIRED_CATEGORIES is '${complexity:-unset}', want 4"
        fi
    else
        info "No Seahub settings file found in common locations."
    fi

    if [[ -n "$seafile_cfg" ]]; then
        info "Seafile config: $seafile_cfg"
        sub "Fileserver access logging"
        if grep -qiE 'access_log[[:space:]]*=[[:space:]]*(true|/)' "$seafile_cfg"; then
            ok "Seafile fileserver access logging appears enabled."
        else
            bad "Seafile fileserver access logging setting not found."
        fi
    else
        info "No seafile.conf found in common locations."
    fi

    sub "Seafile init scripts"
    local init_found=0 init mode
    for init in /etc/init.d/*seafile* /etc/init.d/*seahub*; do
        [[ -f "$init" ]] || continue
        init_found=1
        mode="$(stat -c '%a' "$init")"
        if [[ "${mode: -1}" == "2" || "${mode: -1}" == "3" || "${mode: -1}" == "6" || "${mode: -1}" == "7" ]]; then
            bad "$init is world writable (mode=$mode)"
        else
            ok "$init is not world writable (mode=$mode)"
        fi
    done
    (( init_found )) || info "No Seafile init scripts found in /etc/init.d."
}

############################################################
# CHECKS - Browser hints (informational)
############################################################

############################################################
# CHECKS - Persistence mechanisms (advanced)
############################################################

check_pam_backdoors() {
    hdr "PAM backdoor detection"

    sub "pam_permit.so misuse (allows ANY auth to succeed)"
    local f hits
    for f in /etc/pam.d/*; do
        [[ -f "$f" ]] || continue
        hits="$(grep -E '^[^#]*pam_permit\.so' "$f" 2>/dev/null || true)"
        if [[ -n "$hits" ]]; then
            # pam_permit is sometimes legitimate (e.g., common-account "account required pam_permit.so")
            # but is suspicious when used in auth or session as 'sufficient' or replacing pam_deny
            local s
            while IFS= read -r s; do
                if echo "$s" | grep -qE 'auth.*pam_permit|sufficient.*pam_permit'; then
                    bad "$f: $s   <-- pam_permit in auth context (likely backdoor)"
                else
                    info "$f: $s"
                fi
            done <<< "$hits"
        fi
    done

    sub "pam_unix nullok (allows empty passwords)"
    for f in /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [[ -f "$f" ]] || continue
        if grep -qE 'pam_unix\.so.*nullok' "$f" 2>/dev/null; then
            bad "$f has pam_unix nullok (empty passwords allowed)"
        fi
    done

    sub "Custom PAM modules in /lib/security or /lib64/security"
    local d
    for d in /lib/security /lib64/security /usr/lib/security /usr/lib64/security /usr/lib/x86_64-linux-gnu/security; do
        [[ -d "$d" ]] || continue
        local cnt
        cnt="$(find "$d" -type f -newer /etc/hostname 2>/dev/null | wc -l)"
        if (( cnt > 0 )); then
            warn "$d has $cnt file(s) newer than /etc/hostname (review for injected PAM modules)"
            find "$d" -type f -newer /etc/hostname 2>/dev/null | sed 's/^/         /'
        fi
    done
}

check_ld_preload() {
    hdr "Library injection (/etc/ld.so.preload, LD_PRELOAD)"

    if [[ -f /etc/ld.so.preload ]]; then
        local content
        content="$(grep -vE '^\s*(#|$)' /etc/ld.so.preload || true)"
        if [[ -z "$content" ]]; then
            ok "/etc/ld.so.preload exists but is empty"
        else
            bad "/etc/ld.so.preload contains entries:"
            echo "$content" | sed 's/^/         /'
            info "Default should be empty. Inspect each library; this is a classic rootkit hook."
        fi
    else
        ok "/etc/ld.so.preload does not exist"
    fi

    sub "ld.so.conf.d entries"
    if [[ -d /etc/ld.so.conf.d ]]; then
        local f
        for f in /etc/ld.so.conf.d/*.conf; do
            [[ -f "$f" ]] && note "$(basename "$f")"
        done
    fi

    sub "LD_PRELOAD in current environment"
    if [[ -n "${LD_PRELOAD:-}" ]]; then
        bad "LD_PRELOAD is set: $LD_PRELOAD"
    else
        ok "LD_PRELOAD not set in current shell"
    fi

    sub "LD_PRELOAD in /etc/environment, /etc/profile"
    local f
    for f in /etc/environment /etc/profile /etc/bash.bashrc; do
        [[ -f "$f" ]] || continue
        if grep -q "LD_PRELOAD" "$f" 2>/dev/null; then
            bad "$f mentions LD_PRELOAD"
            grep -n "LD_PRELOAD" "$f" | sed 's/^/         /'
        fi
    done
}

check_motd_persistence() {
    hdr "MOTD / login banner persistence"

    sub "/etc/update-motd.d/ scripts"
    if [[ -d /etc/update-motd.d ]]; then
        local f
        for f in /etc/update-motd.d/*; do
            [[ -f "$f" ]] || continue
            local base name size
            base="$(basename "$f")"
            size="$(stat -c '%s' "$f")"
            # Default scripts are typically 00-header, 10-help-text, 50-motd-news, etc.
            if [[ "$base" =~ ^[0-9]+- ]]; then
                if grep -qE 'curl|wget|nc |bash -i|/dev/tcp|base64.*-d' "$f" 2>/dev/null; then
                    bad "$f contains suspicious commands (curl/wget/nc/reverse shell pattern)"
                    grep -nE 'curl|wget|nc |bash -i|/dev/tcp|base64.*-d' "$f" | sed 's/^/         /'
                else
                    info "$base ($size bytes)"
                fi
            else
                warn "non-standard MOTD script name: $base"
            fi
        done
    fi

    sub "/etc/motd, /etc/issue, /etc/issue.net"
    for f in /etc/motd /etc/issue /etc/issue.net; do
        if [[ -f "$f" ]]; then
            local size
            size="$(stat -c '%s' "$f")"
            info "$f ($size bytes)"
        fi
    done
}

check_polkit() {
    hdr "Polkit / PolicyKit rules"

    if [[ -d /etc/polkit-1/rules.d ]]; then
        local f
        for f in /etc/polkit-1/rules.d/*.rules; do
            [[ -f "$f" ]] || continue
            local base
            base="$(basename "$f")"
            # Default rules are 49-polkit-pkla-compat.rules and 50-default.rules
            if [[ "$base" =~ ^(49-polkit|50-default) ]]; then
                ok "$base (default)"
            else
                warn "$base — review (custom rule)"
                if grep -qE 'polkit\.Result\.YES' "$f" 2>/dev/null; then
                    bad "$base contains polkit.Result.YES (potential privesc)"
                    grep -nE 'polkit\.Result\.YES' "$f" | sed 's/^/         /'
                fi
            fi
        done
    else
        info "No /etc/polkit-1/rules.d/"
    fi

    if [[ -d /etc/polkit-1/localauthority ]]; then
        local f
        for f in /etc/polkit-1/localauthority/*/*.pkla; do
            [[ -f "$f" ]] && warn "polkit pkla file: $f"
        done
    fi
}

check_tmpfiles() {
    hdr "/etc/tmpfiles.d/ (sticky bit on /tmp)"

    if [[ -d /etc/tmpfiles.d ]] || [[ -d /usr/lib/tmpfiles.d ]]; then
        local f line
        for f in /etc/tmpfiles.d/*.conf /usr/lib/tmpfiles.d/tmp.conf; do
            [[ -f "$f" ]] || continue
            while IFS= read -r line; do
                if [[ "$line" =~ ^d[[:space:]]+/(tmp|var/tmp) ]]; then
                    local mode
                    mode="$(echo "$line" | awk '{print $3}')"
                    if [[ "$mode" =~ ^1 ]]; then
                        ok "$f: $line   (sticky bit set)"
                    else
                        bad "$f: $line   (no sticky bit; default should be 1777)"
                    fi
                fi
            done < "$f"
        done
    fi

    sub "Live perms on /tmp /var/tmp /dev/shm"
    local d mode
    for d in /tmp /var/tmp /dev/shm; do
        [[ -d "$d" ]] || continue
        mode="$(stat -c '%a' "$d")"
        if [[ "$mode" == "1777" ]]; then
            ok "$d: $mode"
        else
            bad "$d: $mode (want 1777)"
        fi
    done
}

check_systemd_units() {
    hdr "systemd unit file inspection"

    sub "Unit files in /etc/systemd/system/ (custom)"
    if [[ -d /etc/systemd/system ]]; then
        local f base
        for f in /etc/systemd/system/*.service; do
            [[ -f "$f" ]] || continue
            base="$(basename "$f")"
            local user execstart
            user="$(grep -E '^User=' "$f" | head -1 | cut -d= -f2)"
            execstart="$(grep -E '^ExecStart=' "$f" | head -1 | cut -d= -f2-)"
            if [[ -z "$user" || "$user" == "root" ]]; then
                warn "$base runs as root: $execstart"
            else
                info "$base (User=$user): $execstart"
            fi
        done
    fi

    sub "systemd-sockets"
    if command -v systemctl >/dev/null; then
        systemctl list-sockets --no-legend --no-pager 2>/dev/null | sed 's/^/         /'
    fi

    sub "Suspicious unit names (heuristic)"
    if command -v systemctl >/dev/null; then
        local susp
        susp="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null \
            | awk '{print $1}' | grep -iE 'backdoor|reverse|persist|update-system|system-update|hidden|tmp\.service' || true)"
        if [[ -z "$susp" ]]; then
            ok "No obviously suspicious service names."
        else
            echo "$susp" | sed 's/^/         /'
        fi
    fi
}

check_docker() {
    hdr "Docker / container security"

    if ! command -v docker >/dev/null 2>&1 && ! pkg_is_installed docker && ! pkg_is_installed docker.io && ! pkg_is_installed docker-ce; then
        info "Docker not installed."
        return
    fi

    sub "/etc/docker/daemon.json"
    if [[ -f /etc/docker/daemon.json ]]; then
        if grep -q "insecure-registries" /etc/docker/daemon.json; then
            bad "/etc/docker/daemon.json has insecure-registries"
            grep "insecure-registries" /etc/docker/daemon.json | sed 's/^/         /'
        else
            ok "no insecure-registries in daemon.json"
        fi
    fi

    sub "docker-compose files"
    local f
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        info "compose file: $f"
        if grep -qE 'privileged:[[:space:]]*true' "$f"; then
            bad "  privileged: true (container has root on host)"
        fi
        if grep -q '/var/run/docker.sock' "$f"; then
            bad "  mounts /var/run/docker.sock (escape vector)"
        fi
        if grep -qE 'pid:[[:space:]]*"?host"?' "$f"; then
            bad "  pid: host (sees host processes)"
        fi
        if grep -qE 'network_mode:[[:space:]]*"?host"?' "$f"; then
            bad "  network_mode: host"
        fi
        if grep -q 'SYS_ADMIN' "$f"; then
            bad "  SYS_ADMIN capability granted"
        fi
        if grep -qE '^\s*-\s*[A-Z_]+_KEY\b|password\b|secret\b' "$f"; then
            warn "  may contain hardcoded secrets"
        fi
    done < <(find / -xdev -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' 2>/dev/null)

    sub "Running containers"
    if command -v docker >/dev/null; then
        docker ps --format '         {{.ID}}  {{.Image}}  {{.Names}}  {{.Status}}' 2>/dev/null
    fi

    sub "User docker config files (~/.docker/config.json)"
    local cfg
    for cfg in /root/.docker/config.json /home/*/.docker/config.json; do
        [[ -f "$cfg" ]] || continue
        if grep -q '"auths"' "$cfg" 2>/dev/null; then
            warn "$cfg has stored 'auths' (registry credentials)"
        fi
    done
}

check_web_persistence() {
    hdr "Web persistence (web shells, .env, .git in webroots)"

    local roots=(/var/www /srv/www /srv/http /usr/share/nginx/html /var/www/html /var/www/dashboard /srv/files)
    local r f

    sub ".env files in webroots"
    for r in "${roots[@]}"; do
        [[ -d "$r" ]] || continue
        while IFS= read -r f; do
            [[ -f "$f" ]] || continue
            bad ".env in webroot: $f"
        done < <(find "$r" -type f -name '.env*' 2>/dev/null)
    done

    sub ".git directories in webroots"
    for r in "${roots[@]}"; do
        [[ -d "$r" ]] || continue
        while IFS= read -r f; do
            bad ".git in webroot: $f"
        done < <(find "$r" -type d -name '.git' 2>/dev/null)
    done

    sub "Backup files in webroots (.bak, .old, .swp, ~)"
    for r in "${roots[@]}"; do
        [[ -d "$r" ]] || continue
        find "$r" -type f \( -name '*.bak' -o -name '*.old' -o -name '*.swp' -o -name '*~' -o -name '*.orig' \) 2>/dev/null | sed 's/^/         /'
    done

    sub "PHP web shells (look for system/exec/passthru/eval in .php)"
    for r in "${roots[@]}"; do
        [[ -d "$r" ]] || continue
        local hits
        hits="$(grep -rlEs 'system\(|exec\(|passthru\(|shell_exec\(|eval\(.*\$_(GET|POST|REQUEST|COOKIE)' "$r" 2>/dev/null || true)"
        if [[ -n "$hits" ]]; then
            echo "$hits" | while read -r f; do bad "possible web shell: $f"; done
        fi
    done

    sub "Hidden files in webroots"
    for r in "${roots[@]}"; do
        [[ -d "$r" ]] || continue
        find "$r" -name '.*' -type f 2>/dev/null | sed 's/^/         /'
    done
}

check_nginx() {
    hdr "Nginx (if installed)"

    local conf=""
    for c in /etc/nginx/nginx.conf; do
        [[ -f "$c" ]] && conf="$c" && break
    done
    if [[ -z "$conf" ]]; then
        info "Nginx not configured."
        return
    fi

    info "Config: $conf"

    if grep -qE '^[[:space:]]*server_tokens[[:space:]]+off' "$conf"; then
        ok "server_tokens off"
    else
        bad "server_tokens not off"
    fi

    if grep -qE '^[[:space:]]*user[[:space:]]+root' "$conf"; then
        bad "nginx running as root user"
    else
        local nguser
        nguser="$(grep -E '^[[:space:]]*user[[:space:]]+' "$conf" | head -1 | awk '{print $2}' | tr -d ';')"
        info "nginx user: ${nguser:-(default)}"
    fi

    sub "site configs in /etc/nginx/sites-enabled/ and conf.d/"
    local f
    for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [[ -f "$f" ]] || continue
        info "$f"
        if grep -qE '^\s*alias\s+[^;]*;' "$f"; then
            local alines
            alines="$(grep -nE 'location[^/]*/[^/]+[^/];|alias' "$f")"
            warn "  contains alias directive — review for off-by-slash:"
            echo "$alines" | sed 's/^/         /'
        fi
        if grep -qE 'ssl_protocols.*(SSLv|TLSv1\.0|TLSv1\.1)' "$f"; then
            bad "  insecure ssl_protocols"
        fi
        if grep -qE '^\s*autoindex\s+on' "$f"; then
            bad "  autoindex on (directory listing)"
        fi
    done
}

check_pkexec() {
    hdr "pkexec / pwnkit (CVE-2021-4034)"

    if [[ -f /usr/bin/pkexec ]]; then
        local mode
        mode="$(stat -c '%a' /usr/bin/pkexec)"
        info "pkexec exists, mode=$mode"
        # SUID is 4xxx
        if [[ "$mode" =~ ^4 ]]; then
            warn "pkexec is SUID. Verify the package is patched:"
            case "$PKG_MGR" in
                apt) note "dpkg -s policykit-1 | grep Version" ;;
                dnf|yum) note "rpm -q polkit" ;;
            esac
            note "Patched versions: policykit-1 >= 0.105-31ubuntu0.x, polkit >= 0.115-13.0.1.el7_9, etc."
            note "If unpatched, an apt/dnf upgrade fixes it."
        fi
    else
        info "pkexec not present"
    fi
}

check_rclocal_extras() {
    hdr "Boot-time persistence (extras)"

    sub "/etc/init.d/ custom scripts"
    if [[ -d /etc/init.d ]]; then
        local f
        for f in /etc/init.d/*; do
            [[ -f "$f" ]] || continue
            # Skip well-known
            local base
            base="$(basename "$f")"
            case "$base" in
                README|skeleton|hwclock.sh|networking|procps|udev|cron|rsyslog|ssh|alsa-utils|console-setup.sh|kbd|keyboard-setup.sh|kmod|plymouth|plymouth-log|rsync|saned|x11-common|atd|anacron|apparmor|apport|console-setup|cups|cups-browsed|dbus|grub-common|hwclock|irqbalance|keyboard-setup|killprocs|lvm2|lvm2-lvmpolld|networking|ondemand|open-vm-tools|rc|rc.local|rcS|reboot|resolvconf|rmnologin|rsync|samba-ad-dc|saned|sendsigs|single|smbd|sudo|umountfs|umountnfs.sh|umountroot|unattended-upgrades|urandom)
                    : ;;
                *)
                    info "non-standard init script: $base"
                    ;;
            esac
        done
    fi

    sub "/etc/systemd/system/multi-user.target.wants/"
    if [[ -d /etc/systemd/system/multi-user.target.wants ]]; then
        ls /etc/systemd/system/multi-user.target.wants/ 2>/dev/null | sed 's/^/         /'
    fi

    sub "/etc/xdg/autostart/ desktop autostart"
    if [[ -d /etc/xdg/autostart ]]; then
        ls /etc/xdg/autostart/ 2>/dev/null | sed 's/^/         /'
    fi

    sub "User .config/autostart/"
    local d
    for d in /home/*/.config/autostart /root/.config/autostart; do
        [[ -d "$d" ]] || continue
        info "$d:"
        ls "$d" 2>/dev/null | sed 's/^/         /'
    done
}

check_bash_history_secrets() {
    hdr "Bash histories (look for secrets, attacker commands)"
    local f
    for f in /root/.bash_history /home/*/.bash_history; do
        [[ -f "$f" ]] || continue
        local size
        size="$(stat -c '%s' "$f")"
        info "$f ($size bytes)"
        if grep -qE 'curl.*http|wget.*http|/dev/tcp|nc -[el]|bash -i|reverse|base64 -d|chattr \+i|history -c' "$f" 2>/dev/null; then
            warn "  contains suspicious commands:"
            grep -nE 'curl.*http|wget.*http|/dev/tcp|nc -[el]|bash -i|reverse|base64 -d|chattr \+i|history -c' "$f" | head -10 | sed 's/^/         /'
        fi
        if grep -qE 'Authorization: Bearer|password=|api[_-]?key|secret=' "$f" 2>/dev/null; then
            warn "  contains potential secrets (Bearer token, password=, api_key, secret=)"
        fi
    done
}

check_git_repos() {
    hdr "Git repositories on disk"
    local f
    while IFS= read -r f; do
        [[ -d "$f" ]] || continue
        info "git repo: $(dirname "$f")"
        if [[ -d "$(dirname "$f")/../" ]]; then
            local secrets
            secrets="$(grep -rIs 'password\|secret\|api[_-]key\|token' "$(dirname "$f")" 2>/dev/null | head -3 || true)"
            if [[ -n "$secrets" ]]; then
                warn "  may contain secrets in working tree"
            fi
        fi
    done < <(find / -xdev -type d -name '.git' 2>/dev/null | head -20)
}

check_database_users() {
    hdr "Database users (MySQL/MariaDB/Postgres)"

    if command -v mysql >/dev/null && systemctl is-active --quiet mysql 2>/dev/null \
       || command -v mariadb >/dev/null && systemctl is-active --quiet mariadb 2>/dev/null; then
        info "MySQL/MariaDB is running. To list users:"
        note "  sudo mysql -e 'SELECT User, Host FROM mysql.user;'"
        note "  sudo mysql -e 'SELECT user, host, plugin FROM mysql.user;'  # check auth plugins"
        note "  sudo mariadb-secure-installation"
        note "  Drop unauthorized users:  DROP USER 'name'@'host';"
    fi

    if command -v psql >/dev/null && systemctl is-active --quiet postgresql 2>/dev/null; then
        info "PostgreSQL is running. To list users:"
        note "  sudo -u postgres psql -c '\\du'"
    fi
}

check_browser_hints() {
    hdr "Browser security (manual review)"
    cat <<'EOF'
         Firefox (Settings → Privacy & Security):
         - Block dangerous and deceptive content: ON
         - Block dangerous downloads: ON
         - Warn you about unwanted and uncommon software: ON
         - HTTPS-Only Mode: Enable in all windows
         - Tracking Protection: Strict
         - Send websites a Do Not Track signal: ON
         - Clear cookies and site data when Firefox is closed: ON
         - Master password / Primary password: SET
         - Saved Logins: review and remove unauthorized
         - Updates: Automatically install updates
         - Search engines: Remove non-default suspicious entries
         - Default browser: SET if README requires

         Chrome / Chromium:
         - Safe Browsing: Enhanced protection
         - Clear browsing data on exit
         - Saved passwords: review

         Manual: open the browser and verify these in Settings.
EOF
}


############################################################
# Suggestions
############################################################

print_suggestions() {
    hdr "Suggested commands (REVIEW BEFORE RUNNING)"
    detect_distro
    cat <<EOF
  # Detected: distro=$DISTRO_ID family=$DISTRO_FAMILY pkg_mgr=$PKG_MGR
  # Admin group on this distro: $ADMIN_GROUP

  # ─── USERS ───
  awk -F: '\$3>=1000 && \$3<60000 {print \$1}' /etc/passwd
EOF
    case "$DISTRO_FAMILY" in
        debian) echo "  sudo deluser --remove-home <user>" ;;
        *) echo "  sudo userdel -r <user>" ;;
    esac
    cat <<EOF
  sudo gpasswd -d <user> $ADMIN_GROUP            # demote admin
  sudo usermod -aG $ADMIN_GROUP <user>           # promote
  sudo gpasswd -a <user> <group>                 # add to custom group
  sudo passwd <user>                             # set password
  sudo passwd -l <user>                          # lock account
  sudo passwd -e <user>                          # force change next login
  sudo passwd -l root                            # lock root
  sudo chage -M 90 -m 7 -W 14 <user>             # password aging

  # ─── PACKAGES ───
  $PKG_LIST_INSTALLED                            # list installed
  sudo $PKG_REMOVE_CMD <pkg>                     # remove
  sudo $PKG_UPDATE_CMD                           # refresh package list
EOF
    case "$PKG_MGR" in
        apt)    echo "  sudo apt upgrade -y && sudo apt autoremove -y" ;;
        dnf)    echo "  sudo dnf upgrade -y" ;;
        yum)    echo "  sudo yum update -y" ;;
        zypper) echo "  sudo zypper --non-interactive update" ;;
        pacman) echo "  sudo pacman -Syu --noconfirm" ;;
    esac

    cat <<'EOF'

  # ─── FILES ───
  sudo find / -xdev -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.mkv' \
    -o -iname '*.avi' -o -iname '*.flac' -o -iname '*.wav' \) 2>/dev/null
  sudo find /home -type f -perm -111 2>/dev/null    # executables in homes
  sudo find / -perm -4000 2>/dev/null               # SUID binaries
  sudo find / \( -nouser -o -nogroup \) 2>/dev/null # orphans
  sudo find / -mtime -7 2>/dev/null                 # modified last week
  sudo rm -i /path/to/file
  sudo chmod 750 /home/<user>

  # ─── SERVICES ───
  systemctl list-units --type=service --state=active
  sudo systemctl disable --now <service>
  sudo ss -tulnp                                   # listening sockets
  sudo lsof -i -P -n                               # process->network map

  # ─── SSH ───
  sudo sshd -t && sudo systemctl reload sshd

  # ─── FIREWALL (UFW) ───
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow OpenSSH
  sudo ufw enable

  # ─── ROOTKIT / MALWARE SCANS ───
  sudo apt install -y rkhunter chkrootkit lynis clamav debsums
  sudo rkhunter --update && sudo rkhunter --check --rwo
  sudo chkrootkit -q
  sudo lynis audit system -Q
  sudo freshclam && sudo clamscan -ri /
  sudo debsums -as

  # ─── README / TASK HUNTING ───
  sudo find / -iname 'readme*' 2>/dev/null
  sudo find / -newer /etc/hostname -type f 2>/dev/null  # files newer than install

  # ─── BOOT BACKDOORS ───
  cat /etc/rc.local
  sudo grep -r '' /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
  sudo crontab -l ; for u in $(awk -F: '$3>=1000{print $1}' /etc/passwd); do sudo crontab -l -u "$u"; done

  # ─── /etc/sudoers.d AUDIT ───
  sudo ls -la /etc/sudoers.d/
  sudo grep -RIn 'NOPASSWD\|!authenticate' /etc/sudoers /etc/sudoers.d/

  # ─── PROCESS / MEMORY ───
  ps -ef --forest
  sudo lsof -p <pid>
  sudo strings /proc/<pid>/cmdline
EOF
}

############################################################
# Rollback
############################################################

list_backups() {
    hdr "Recorded actions"
    if [[ ! -s "$ACTION_LOG" ]]; then
        info "No actions recorded in $ACTION_LOG."
        return
    fi
    awk -F'\t' '{printf "  %s  %-15s  %s   (backup: %s)\n", $1, $2, $3, $4}' "$ACTION_LOG"
}

do_rollback() {
    local target="${1:-}"
    if [[ ! -s "$ACTION_LOG" ]]; then
        warn "No action log at $ACTION_LOG."
        return
    fi

    local rollback_ts=""
    if [[ "$target" == "all" ]]; then
        rollback_ts=""
    else
        rollback_ts="$(awk -F'\t' '{print $1}' "$ACTION_LOG" | sort -u | tail -n1)"
        info "Rolling back run: $rollback_ts"
    fi

    local ts type tgt backup extra
    while IFS=$'\t' read -r ts type tgt backup extra; do
        if [[ -n "$rollback_ts" && "$ts" != "$rollback_ts" ]]; then
            continue
        fi
        case "$type" in
            BACKUP_FILE)
                if [[ -n "$backup" && -e "$backup" ]]; then
                    cp -a -- "$backup" "$tgt" && fixed "restored $tgt from $backup"
                else
                    warn "missing backup for $tgt ($backup)"
                fi
                ;;
            CREATE_FILE)
                if [[ -e "$tgt" ]]; then
                    rm -f -- "$tgt" && fixed "removed $tgt (created by $SCRIPT_NAME)"
                fi
                ;;
            UFW_ENABLE)
                if command -v ufw >/dev/null; then
                    ufw --force disable >/dev/null && fixed "ufw disabled"
                fi
                ;;
            SERVICE_ENABLE)
                if command -v systemctl >/dev/null; then
                    systemctl disable --now "$tgt" >/dev/null 2>&1 && fixed "$tgt disabled"
                fi
                ;;
            *)
                warn "unknown action type $type"
                ;;
        esac
    done < <(tac "$ACTION_LOG")

    if [[ "$target" == "all" ]]; then
        : > "$ACTION_LOG"
    else
        grep -v -P "^${rollback_ts}\t" "$ACTION_LOG" > "${ACTION_LOG}.tmp" 2>/dev/null && mv "${ACTION_LOG}.tmp" "$ACTION_LOG" || true
    fi
}

############################################################
# Summary
############################################################

print_summary() {
    hdr "Summary"
    echo "  Distro: ${C_BOLD}$DISTRO_ID${C_RESET} (family=$DISTRO_FAMILY, version=$DISTRO_VERSION, pkg_mgr=$PKG_MGR, admin_group=$ADMIN_GROUP)"
    echo "  ${C_GREEN}OK    : $COUNT_OK${C_RESET}"
    echo "  ${C_YELLOW}WARN  : $COUNT_WARN${C_RESET}"
    echo "  ${C_RED}BAD   : $COUNT_BAD${C_RESET}"
    echo "  ${C_BLUE}INFO  : $COUNT_INFO${C_RESET}"
    if [[ "$MODE" == "fix" ]]; then
        echo "  ${C_MAGENTA}FIXED : $COUNT_FIXED${C_RESET}"
        echo
        echo "  Action log: $ACTION_LOG"
        echo "  Roll back this run with:  sudo $SCRIPT_NAME --rollback"
    fi
    echo
    echo "  ${C_DIM}Cross-check users, admins, packages, and files against the README manually.${C_RESET}"
}

############################################################
# Main
############################################################

main() {
    detect_distro

    case "${1:-}" in
        ""|--audit) MODE="audit" ;;
        --fix) MODE="fix" ;;
        --rollback) MODE="rollback"; do_rollback ""; exit 0 ;;
        --rollback-all) MODE="rollback-all"; do_rollback "all"; exit 0 ;;
        --list-backups|--list) list_backups; exit 0 ;;
        --suggest) print_suggestions; exit 0 ;;
        --preserve-logs) preserve_logs; exit 0 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac

    echo "${C_BOLD}${C_CYAN}$SCRIPT_NAME v$CP_AUDIT_VERSION${C_RESET}  mode=${MODE}  user=$(id -un)  host=$(hostname)  ts=$RUN_TS"
    echo "  Detected distro: ${C_BOLD}$DISTRO_ID${C_RESET}  family=$DISTRO_FAMILY  pkg_mgr=$PKG_MGR  admin_group=$ADMIN_GROUP"
    if [[ $EUID -ne 0 ]]; then
        echo "${C_YELLOW}  (not root: many checks will be skipped or incomplete)${C_RESET}"
    fi

    # In fix mode, snapshot logs first
    if [[ "$MODE" == "fix" ]]; then
        preserve_logs
    fi

    find_and_parse_readme
    check_users_and_admins
    check_sudoers
    check_password_policy
    check_pam
    check_pam_backdoors
    check_ld_preload
    check_motd_persistence
    check_polkit
    check_tmpfiles
    check_systemd_units
    check_sshd
    check_firewall
    check_sysctl
    check_critical_perms
    check_suid_sgid
    check_world_writable
    check_no_owner
    check_services
    check_prohibited_packages
    check_pkg_mgr_config
    check_display_manager
    check_scheduled
    check_network_files
    check_boot
    check_rclocal_extras
    check_modules
    check_aliases
    check_authorized_keys
    check_apache
    check_nginx
    check_mysql
    check_database_users
    check_seafile
    check_vsftpd
    check_samba
    check_php
    check_docker
    check_web_persistence
    check_pkexec
    check_security_tools
    check_score_specific_services
    check_bash_history_secrets
    check_git_repos
    check_forensics_questions
    check_prohibited_files
    check_firefox_prefs
    check_browser_hints

    print_summary

    if [[ "$MODE" == "audit" ]]; then
        echo
        echo "  ${C_DIM}Run '$SCRIPT_NAME --suggest' for copy-paste commands.${C_RESET}"
    fi
}

main "$@"
