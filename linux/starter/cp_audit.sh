#!/usr/bin/env bash
#
# cp_audit.sh - CyberPatriot Linux audit / fix / rollback tool
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
#   -h | --help      Show usage.
#
# Notes:
#   * Run as root for full coverage.
#   * Default scans the entire filesystem for prohibited media (slow).
#   * Action log:
#       /var/log/cp_audit/actions.log  (root)
#       ~/.cp_audit/actions.log        (non-root)
#

set -u
shopt -s nullglob

############################################################
# Globals
############################################################

CP_AUDIT_VERSION="1.1"
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

# Distro / package manager detection results (filled in by detect_distro)
DISTRO_ID=""           # ubuntu, debian, fedora, rhel, centos, rocky, almalinux, opensuse, arch, ...
DISTRO_FAMILY=""       # debian | rhel | suse | arch | unknown
DISTRO_VERSION=""
PKG_MGR=""             # apt | dnf | yum | zypper | pacman | unknown
PKG_INSTALL_CMD=""     # full noninteractive install prefix
PKG_REMOVE_CMD=""
PKG_UPDATE_CMD=""
PKG_QUERY_INSTALLED="" # how to ask "is package X installed", expects $pkg substituted via $1
PKG_LIST_INSTALLED=""  # how to list everything installed
SHADOW_GROUP="shadow"  # 'shadow' on Debian, 'root' on RHEL/SUSE/Arch

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

hdr() { echo; echo "${C_BOLD}${C_CYAN}=== $* ===${C_RESET}"; }
ok()      { echo "  ${C_GREEN}[ OK  ]${C_RESET} $*";   COUNT_OK=$((COUNT_OK+1)); }
warn()    { echo "  ${C_YELLOW}[WARN ]${C_RESET} $*"; COUNT_WARN=$((COUNT_WARN+1)); }
bad()     { echo "  ${C_RED}[ BAD ]${C_RESET} $*";    COUNT_BAD=$((COUNT_BAD+1)); }
info()    { echo "  ${C_BLUE}[INFO ]${C_RESET} $*";   COUNT_INFO=$((COUNT_INFO+1)); }
note()    { echo "  ${C_DIM}       $*${C_RESET}"; }
fixed()   { echo "  ${C_MAGENTA}[FIXED]${C_RESET} $*"; COUNT_FIXED=$((COUNT_FIXED+1)); }
skipped() { echo "  ${C_DIM}[SKIP ] $*${C_RESET}";    COUNT_SKIPPED=$((COUNT_SKIPPED+1)); }

usage() {
    cat <<EOF
${C_BOLD}$SCRIPT_NAME${C_RESET} v$CP_AUDIT_VERSION  -  CyberPatriot Linux audit / fix / rollback (distro-agnostic)

Usage:
  $SCRIPT_NAME                  Audit only (read-only). Default.
  $SCRIPT_NAME --fix            Apply safe fixes (prompts before each change).
  $SCRIPT_NAME --rollback       Reverse the most recent --fix run.
  $SCRIPT_NAME --rollback-all   Reverse every recorded fix, newest first.
  $SCRIPT_NAME --list-backups   List recorded actions / backups.
  $SCRIPT_NAME --suggest        Print copy-paste commands for unsafe fixes
                                the script will not perform automatically.
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
        # Source in a subshell so VERSION/NAME/etc don't clobber our globals
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
                DISTRO_FAMILY="debian"
                ;;
            fedora|rhel|centos|rocky|almalinux|ol|amzn|scientific)
                DISTRO_FAMILY="rhel"
                ;;
            opensuse*|sles|sled|suse)
                DISTRO_FAMILY="suse"
                ;;
            arch|manjaro|endeavouros|artix|garuda)
                DISTRO_FAMILY="arch"
                ;;
            *)
                # Fall back to ID_LIKE
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

    # Pick package manager based on what's actually present, in case /etc/os-release lies
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
        *)
            PKG_INSTALL_CMD=""
            PKG_REMOVE_CMD=""
            PKG_UPDATE_CMD=""
            PKG_LIST_INSTALLED=""
            ;;
    esac
}

# Is package $1 installed?
pkg_is_installed() {
    local p="$1"
    case "$PKG_MGR" in
        apt)    dpkg -s "$p" >/dev/null 2>&1 ;;
        dnf|yum|zypper) rpm -q "$p" >/dev/null 2>&1 ;;
        pacman) pacman -Qq "$p" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

# Convert generic package name -> distro-specific name.
# Returns the distro-specific name on stdout, or empty string if N/A on this distro.
pkg_resolve() {
    local generic="$1"
    case "$generic" in
        ssh-server)
            case "$DISTRO_FAMILY" in
                debian) echo "openssh-server" ;;
                rhel|suse) echo "openssh-server" ;;
                arch) echo "openssh" ;;
            esac ;;
        ufw)
            # ufw exists on most distros via package "ufw"
            echo "ufw" ;;
        firewalld)
            echo "firewalld" ;;
        wireshark)
            case "$DISTRO_FAMILY" in
                debian) echo "wireshark wireshark-common" ;;
                *) echo "wireshark" ;;
            esac ;;
        *)
            echo "$generic" ;;
    esac
}

############################################################
# Action log helpers
############################################################
#
# Log format (tab-separated):
#   RUN_TS  ACTION_TYPE  TARGET  BACKUP_PATH  EXTRA
#

log_action() {
    local type="$1" target="$2" backup="${3:-}" extra="${4:-}"
    printf '%s\t%s\t%s\t%s\t%s\n' "$RUN_TS" "$type" "$target" "$backup" "$extra" >> "$ACTION_LOG"
}

backup_file() {
    local f="$1"
    if [[ ! -e "$f" ]]; then
        echo ""
        return 0
    fi
    local b="${f}.cpbak-${RUN_TS}"
    cp -a -- "$f" "$b"
    echo "$b"
}

############################################################
# Confirm prompt
############################################################

confirm() {
    local prompt="$1"
    if [[ "$MODE" != "fix" ]]; then
        return 1
    fi
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

############################################################
# Generic config helpers
############################################################

ensure_line_kv() {
    local file="$1" key="$2" value="$3" sep="${4:- }"
    local b
    b="$(backup_file "$file")"
    if [[ -z "$b" && ! -e "$file" ]]; then
        # Make sure parent dir exists
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
# CHECKS
############################################################

check_users_and_admins() {
    hdr "Users & Administrators"

    info "Human-looking accounts (UID 1000-60000):"
    while IFS=: read -r u _ uid _ gecos home shell; do
        if (( uid >= 1000 && uid < 60000 )); then
            note "$u  uid=$uid  shell=$shell  home=$home  gecos='$gecos'"
        fi
    done < /etc/passwd

    # Sudo group is "wheel" on RHEL/SUSE/Arch by default, "sudo" on Debian.
    local admin_groups=()
    case "$DISTRO_FAMILY" in
        debian) admin_groups=(sudo admin) ;;
        rhel|suse|arch) admin_groups=(wheel sudo) ;;
        *) admin_groups=(sudo wheel admin) ;;
    esac

    local g members
    for g in "${admin_groups[@]}"; do
        if getent group "$g" >/dev/null; then
            members="$(getent group "$g" | awk -F: '{print $4}')"
            info "Members of '$g' group:"
            note "${members:-(none)}"
        fi
    done

    info "Accounts with UID 0 (should only be root):"
    local uid0
    uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd)"
    if [[ "$uid0" == "root" ]]; then
        ok "Only root has UID 0."
    else
        bad "Multiple UID-0 accounts: $uid0"
    fi

    info "Accounts with empty passwords (from /etc/shadow):"
    if [[ -r /etc/shadow ]]; then
        local empty
        empty="$(awk -F: '($2 == "" ) {print $1}' /etc/shadow)"
        if [[ -z "$empty" ]]; then
            ok "No accounts with empty password fields."
        else
            bad "Empty password: $empty"
        fi
    else
        warn "Cannot read /etc/shadow (need root)."
    fi

    info "Compare the above against the README for unauthorized users/admins."
}

check_password_policy() {
    hdr "Password & Login Policy (/etc/login.defs)"

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

check_sshd() {
    hdr "OpenSSH (sshd_config)"

    local f=/etc/ssh/sshd_config
    if [[ ! -r "$f" ]]; then
        warn "$f not readable."
        return
    fi

    declare -A want=(
        [PermitRootLogin]="no"
        [PasswordAuthentication]="no"
        [PubkeyAuthentication]="yes"
        [PermitEmptyPasswords]="no"
        [X11Forwarding]="no"
        [Protocol]="2"
        [ClientAliveInterval]="300"
        [ClientAliveCountMax]="0"
        [LoginGraceTime]="60"
        [MaxAuthTries]="4"
        [IgnoreRhosts]="yes"
        [HostbasedAuthentication]="no"
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
                        warn "sshd -t failed; left config in place but not restarting."
                    fi
                fi
            fi
        fi
    done

    info "(SSH service is NOT restarted automatically. After review:  systemctl reload sshd)"
}

check_firewall() {
    hdr "Firewall"

    local found_firewall=""

    # 1. UFW
    if command -v ufw >/dev/null; then
        found_firewall="ufw"
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            ok "UFW is active."
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

    # 2. firewalld
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

    # 3. nftables
    if command -v nft >/dev/null; then
        found_firewall="${found_firewall:+$found_firewall, }nftables"
        if nft list ruleset 2>/dev/null | grep -q .; then
            ok "nftables has rules loaded."
        else
            warn "nftables present but no ruleset loaded."
        fi
    fi

    # 4. iptables
    if command -v iptables >/dev/null; then
        found_firewall="${found_firewall:+$found_firewall, }iptables"
        local rules
        rules="$(iptables -S 2>/dev/null | grep -v -- '-P ' | wc -l)"
        if (( rules > 0 )); then
            ok "iptables has $rules custom rule(s)."
        else
            info "iptables present but no custom rules (default policy only)."
        fi
    fi

    if [[ -z "$found_firewall" ]]; then
        bad "No firewall tooling found (ufw, firewalld, nftables, iptables)."
        if confirm "Install ufw via $PKG_MGR ?"; then
            if need_root_for_fix && [[ -n "$PKG_INSTALL_CMD" ]]; then
                eval "$PKG_INSTALL_CMD ufw" >/dev/null 2>&1 && fixed "ufw installed (don't forget to enable it)"
            fi
        fi
    else
        info "Firewall tools present: $found_firewall"
    fi
}

check_sysctl() {
    hdr "Kernel / Network sysctl hardening"

    declare -A want=(
        [net.ipv4.ip_forward]="0"
        [net.ipv4.conf.all.log_martians]="1"
        [net.ipv4.conf.default.log_martians]="1"
        [net.ipv4.conf.all.accept_redirects]="0"
        [net.ipv4.conf.all.send_redirects]="0"
        [net.ipv4.conf.all.accept_source_route]="0"
        [net.ipv4.conf.all.rp_filter]="1"
        [net.ipv4.icmp_echo_ignore_broadcasts]="1"
        [net.ipv4.tcp_syncookies]="1"
        [net.ipv4.tcp_sack]="0"
        [net.ipv6.conf.all.accept_redirects]="0"
        [net.ipv6.conf.all.accept_source_route]="0"
        [kernel.randomize_va_space]="2"
        [kernel.kptr_restrict]="2"
        [kernel.dmesg_restrict]="1"
        [kernel.watchdog]="1"
        [kernel.unprivileged_userns_clone]="0"
        [vm.unprivileged_userfaultfd]="0"
    )

    local persist_file="/etc/sysctl.d/99-cp-audit.conf"
    local need_persist=0
    local fixes_buffer=""

    local k v current
    for k in "${!want[@]}"; do
        v="${want[$k]}"
        current="$(sysctl -n "$k" 2>/dev/null || true)"
        if [[ -z "$current" ]]; then
            info "$k not present on this kernel."
            continue
        fi
        if [[ "$current" == "$v" ]]; then
            ok "$k = $v"
        else
            bad "$k = $current, want $v"
            if confirm "Set $k=$v (persisted in $persist_file) ?"; then
                if need_root_for_fix; then
                    fixes_buffer+="${k} = ${v}"$'\n'
                    sysctl -w "$k=$v" >/dev/null 2>&1 && fixed "$k -> $v (live)" || warn "live set failed for $k"
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

check_critical_perms() {
    hdr "Critical file permissions"

    # Shadow group differs by distro: Debian uses 'shadow', RHEL/SUSE/Arch use 'root'.
    declare -A want=(
        [/etc/shadow]="640 root:${SHADOW_GROUP}"
        [/etc/gshadow]="640 root:${SHADOW_GROUP}"
        [/etc/passwd]="644 root:root"
        [/etc/group]="644 root:root"
        [/etc/ssh/sshd_config]="600 root:root"
        [/etc/sudoers]="440 root:root"
    )

    local f mode owner group actual target_mode target_own b
    for f in "${!want[@]}"; do
        if [[ ! -e "$f" ]]; then
            info "$f does not exist."
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
}

check_suid() {
    hdr "SUID binaries (review for unexpected entries)"

    if [[ $EUID -ne 0 ]]; then
        warn "Non-root: results may be incomplete."
    fi
    local suspicious=(nano vi vim less more man find cp mv tar zip unzip ruby python python3 perl awk sed bash sh dash ksh zsh tee dd)
    local f base flag s
    while IFS= read -r f; do
        base="$(basename "$f")"
        flag=""
        for s in "${suspicious[@]}"; do
            if [[ "$base" == "$s" ]]; then
                flag=" ${C_RED}<-- suspicious${C_RESET}"
                break
            fi
        done
        echo "         $f$flag"
    done < <(find / -xdev -type f -perm -4000 2>/dev/null | sort)
}

check_services() {
    hdr "Running services & insecure / unwanted packages"

    if command -v systemctl >/dev/null; then
        info "Active services:"
        systemctl list-units --type=service --state=active --no-legend --no-pager 2>/dev/null \
          | awk '{print "         " $1}'
    fi

    info "Listening sockets:"
    if command -v ss >/dev/null; then
        ss -tulnp 2>/dev/null | awk 'NR>1 {print "         " $0}'
    elif command -v netstat >/dev/null; then
        netstat -tulnp 2>/dev/null | awk 'NR>2 {print "         " $0}'
    fi

    # Cross-distro list of commonly-prohibited packages.
    # Names that differ by distro are listed as alternates separated by '|'.
    # We just check each variant.
    local bad_pkgs=(
        ophcrack john hydra hashcat
        "aircrack-ng|aircrack"
        nmap zenmap
        "netcat-traditional|nc|gnu-netcat|netcat-openbsd"
        ncat
        "wireshark|wireshark-common|tshark"
        tcpdump
        "ettercap-text-only|ettercap"
        nikto sqlmap medusa
        "vsftpd" "proftpd" "pure-ftpd"
        "ftp" "telnet" "telnetd" "telnet-server"
        "rsh-server" "rsh-client" "rsh" "rsh-redone-server"
        nis "yp-tools" "ypbind" "ypserv"
        talk talkd
        samba
        nginx "apache2|httpd" lighttpd
        snmpd "net-snmp"
        "bind9|bind"
        "dovecot-core|dovecot|dovecot-imapd"
        postfix sendmail "exim4|exim"
    )

    info "Checking for commonly-prohibited packages..."
    local pkgspec p
    for pkgspec in "${bad_pkgs[@]}"; do
        IFS='|' read -ra alts <<< "$pkgspec"
        for p in "${alts[@]}"; do
            if pkg_is_installed "$p"; then
                warn "Installed: $p  (check README; may be allowed)"
                break
            fi
        done
    done
}

check_pkg_mgr_config() {
    hdr "Package manager configuration"

    case "$PKG_MGR" in
        apt)
            local f=/etc/apt/apt.conf.d/99-cp-audit
            declare -A want=(
                ['APT::Get::AllowUnauthenticated']='"false";'
                ['APT::Periodic::Update-Package-Lists']='"1";'
                ['APT::Periodic::Unattended-Upgrade']='"1";'
            )
            local k v b
            for k in "${!want[@]}"; do
                v="${want[$k]}"
                if grep -rqs "${k}" /etc/apt/apt.conf.d/ /etc/apt/apt.conf 2>/dev/null; then
                    ok "$k present somewhere in /etc/apt/."
                else
                    bad "$k not set."
                    if confirm "Append $k $v to $f ?"; then
                        if need_root_for_fix; then
                            b="$(backup_file "$f")"
                            printf '%s %s\n' "$k" "$v" >> "$f"
                            if [[ -n "$b" ]]; then
                                log_action "BACKUP_FILE" "$f" "$b" ""
                            else
                                log_action "CREATE_FILE" "$f" "" ""
                            fi
                            fixed "$k -> $v"
                        fi
                    fi
                fi
            done
            ;;
        dnf|yum)
            local f=/etc/dnf/dnf.conf
            [[ "$PKG_MGR" == "yum" ]] && f=/etc/yum.conf
            if [[ -r "$f" ]]; then
                if grep -qE '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*1' "$f"; then
                    ok "$f gpgcheck=1"
                else
                    bad "$f gpgcheck not set to 1"
                    if confirm "Set gpgcheck=1 in $f ?"; then
                        if need_root_for_fix; then
                            ensure_line_kv "$f" "gpgcheck" "1" "="
                            fixed "gpgcheck=1"
                        fi
                    fi
                fi
            fi
            # dnf-automatic for auto updates
            if [[ "$PKG_MGR" == "dnf" ]] && command -v systemctl >/dev/null; then
                if systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
                    ok "dnf-automatic.timer enabled."
                else
                    info "dnf-automatic.timer not enabled (auto-updates off)."
                fi
            fi
            ;;
        zypper)
            local f=/etc/zypp/zypp.conf
            if [[ -r "$f" ]]; then
                if grep -qE '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*1' "$f"; then
                    ok "$f gpgcheck=1"
                else
                    info "$f gpgcheck not explicitly set to 1 (zypper default is on)."
                fi
            fi
            ;;
        pacman)
            local f=/etc/pacman.conf
            if [[ -r "$f" ]]; then
                if grep -qE '^[[:space:]]*SigLevel[[:space:]]*=' "$f"; then
                    local sl
                    sl="$(grep -E '^[[:space:]]*SigLevel[[:space:]]*=' "$f" | head -1 | cut -d= -f2- | xargs)"
                    if [[ "$sl" =~ Required ]]; then
                        ok "pacman SigLevel includes Required ($sl)"
                    else
                        bad "pacman SigLevel does not require signatures: $sl"
                    fi
                fi
            fi
            ;;
        *)
            info "No package manager detected; skipping package config checks."
            ;;
    esac

    # PIP (cross-distro)
    if [[ -f /etc/pip.conf ]] && grep -q "require-hashes" /etc/pip.conf; then
        ok "/etc/pip.conf require-hashes set."
    else
        info "/etc/pip.conf does not require hashes (only relevant if pip is used)."
    fi
}

check_display_manager() {
    hdr "Display manager"

    # LightDM (Mint, some Ubuntu, others)
    local f=/etc/lightdm/lightdm.conf
    if [[ -f "$f" ]]; then
        if grep -q "^greeter-hide-users=true" "$f"; then
            ok "LightDM hides user list."
        else
            bad "LightDM does NOT hide user list."
            if confirm "Set greeter-hide-users=true in $f ?"; then
                if need_root_for_fix; then
                    local b
                    b="$(backup_file "$f")"
                    if grep -q "^\[Seat:\*\]" "$f"; then
                        sed -i '/^\[Seat:\*\]/a greeter-hide-users=true' "$f"
                    else
                        printf '[Seat:*]\ngreeter-hide-users=true\n' >> "$f"
                    fi
                    log_action "BACKUP_FILE" "$f" "$b" ""
                    fixed "lightdm hides users"
                fi
            fi
        fi
    fi

    # GDM (Ubuntu default, Fedora default)
    local gdm=""
    for cand in /etc/gdm3/greeter.dconf-defaults /etc/gdm/custom.conf; do
        [[ -f "$cand" ]] && gdm="$cand" && break
    done
    if [[ -n "$gdm" ]]; then
        if grep -qE 'disable-user-list[[:space:]]*=[[:space:]]*true' "$gdm"; then
            ok "GDM disable-user-list = true"
        else
            bad "GDM does not hide user list ($gdm)"
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
    fi

    # SDDM (KDE / openSUSE / some Arch)
    local sddm=/etc/sddm.conf
    if [[ -f "$sddm" ]] || [[ -d /etc/sddm.conf.d ]]; then
        if grep -rqsE 'EnableHidpi|MaximumUid' "$sddm" /etc/sddm.conf.d/ 2>/dev/null; then
            info "SDDM config present at $sddm or /etc/sddm.conf.d/"
        else
            info "SDDM detected; review /etc/sddm.conf for user list visibility."
        fi
    fi

    if [[ ! -f /etc/lightdm/lightdm.conf && -z "$gdm" && ! -f "$sddm" ]]; then
        info "No display manager config found; skipping."
    fi
}

check_samba() {
    hdr "Samba (only if installed)"

    local f=/etc/samba/smb.conf
    if [[ ! -f "$f" ]]; then
        info "Samba not configured; skipping."
        return
    fi
    grep -q "restrict anonymous" "$f" && ok "restrict anonymous line present." || warn "restrict anonymous not set."
    grep -q "read only" "$f" && ok "read only setting present." || warn "read only not set."
    grep -qE "^[[:space:]]*path[[:space:]]*=" "$f" && ok "path setting present." || info "no share path defined."
}

check_forensics_questions() {
    hdr "Forensics question files (informational)"

    local found=0 d f
    for d in /home/*/Desktop /root/Desktop; do
        [[ -d "$d" ]] || continue
        for f in "$d"/Forensic* "$d"/forensic* "$d"/FQ* "$d"/fq*; do
            [[ -e "$f" ]] || continue
            info "FQ file: $f"
            found=1
        done
    done
    (( found )) || info "No Forensics Question files found on common Desktops."
    info "(These must be answered manually.)"
}

check_prohibited_media() {
    hdr "Prohibited media files (full filesystem scan)"

    info "Scanning entire filesystem (this may take a while)..."
    local exts="mp3|mp4|m4a|m4v|mkv|avi|mov|wmv|flac|ogg|wav|aac|webm|flv|mpg|mpeg"
    local results
    results="$(find / -xdev -type f 2>/dev/null | grep -iE "\.(${exts})$" || true)"
    if [[ -z "$results" ]]; then
        ok "No media files found."
    else
        warn "Media files found:"
        local f
        while IFS= read -r f; do
            note "$f"
        done <<< "$results"
        info "Compare against README; remove if unauthorized."
    fi
}

check_cron() {
    hdr "Scheduled tasks (cron / systemd timers)"

    info "User crontabs:"
    # Debian/Ubuntu
    if [[ -d /var/spool/cron/crontabs ]]; then
        local u
        for u in /var/spool/cron/crontabs/*; do
            [[ -f "$u" ]] && note "$(basename "$u"): $(wc -l <"$u") lines"
        done
    fi
    # RHEL/SUSE/Arch
    if [[ -d /var/spool/cron ]] && [[ ! -d /var/spool/cron/crontabs ]]; then
        local u
        for u in /var/spool/cron/*; do
            [[ -f "$u" ]] && note "$(basename "$u"): $(wc -l <"$u") lines"
        done
    fi
    info "/etc/crontab and /etc/cron.d entries:"
    [[ -f /etc/crontab ]] && note "/etc/crontab exists ($(wc -l </etc/crontab) lines)"
    if [[ -d /etc/cron.d ]]; then
        local f
        for f in /etc/cron.d/*; do
            note "$(basename "$f")"
        done
    fi
    if command -v systemctl >/dev/null; then
        info "Active systemd timers:"
        systemctl list-timers --no-legend --no-pager 2>/dev/null | awk '{print "         " $0}'
    fi
}

check_world_writable() {
    hdr "World-writable files (excluding /proc, /sys, /dev, /run, /tmp)"
    local results
    results="$(find / -xdev -type f -perm -0002 \
        ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' \
        ! -path '/run/*' ! -path '/tmp/*' ! -path '/var/tmp/*' 2>/dev/null || true)"
    if [[ -z "$results" ]]; then
        ok "No world-writable files outside expected dirs."
    else
        local f
        while IFS= read -r f; do
            warn "world-writable: $f"
        done <<< "$results"
    fi
}

check_sudoers() {
    hdr "Sudoers / NOPASSWD"
    if [[ ! -r /etc/sudoers ]]; then
        warn "/etc/sudoers not readable (need root)."
        return
    fi
    local hits
    hits="$(grep -RInE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)"
    if [[ -z "$hits" ]]; then
        ok "No NOPASSWD entries."
    else
        local line
        while IFS= read -r line; do
            bad "NOPASSWD: $line"
        done <<< "$hits"
    fi
}

############################################################
# Suggestions
############################################################

print_suggestions() {
    hdr "Suggested commands (REVIEW BEFORE RUNNING)"

    local INSTALL="$PKG_INSTALL_CMD"
    local REMOVE="$PKG_REMOVE_CMD"
    local UPDATE="$PKG_UPDATE_CMD"
    local LIST="$PKG_LIST_INSTALLED"

    cat <<EOF
  # Detected: distro=$DISTRO_ID family=$DISTRO_FAMILY pkg_mgr=$PKG_MGR

  # --- USERS ---
  # List all human users:
  awk -F: '\$3>=1000 && \$3<60000 {print \$1}' /etc/passwd

  # Delete an unauthorized user (and home dir):
EOF
    case "$DISTRO_FAMILY" in
        debian) echo "  sudo deluser --remove-home <username>" ;;
        rhel|suse) echo "  sudo userdel -r <username>" ;;
        arch) echo "  sudo userdel -r <username>" ;;
        *) echo "  sudo userdel -r <username>   # or deluser on debian" ;;
    esac

    cat <<EOF

  # Demote / promote administrators:
EOF
    case "$DISTRO_FAMILY" in
        debian)
            echo "  sudo gpasswd -d <username> sudo"
            echo "  sudo usermod -aG sudo <username>"
            ;;
        *)
            echo "  sudo gpasswd -d <username> wheel"
            echo "  sudo usermod -aG wheel <username>"
            ;;
    esac

    cat <<EOF

  # Force password change on next login:
  sudo passwd -e <username>
  sudo passwd <username>            # set a new password
  sudo passwd -l <username>         # lock the account

  # --- PACKAGES ---
  # List installed packages:
  $LIST

  # Remove a prohibited package (example: ophcrack):
  sudo $REMOVE ophcrack

  # Update everything:
  sudo $UPDATE
EOF

    case "$PKG_MGR" in
        apt)    echo "  sudo apt upgrade -y && sudo apt autoremove -y" ;;
        dnf)    echo "  sudo dnf upgrade -y" ;;
        yum)    echo "  sudo yum update -y" ;;
        zypper) echo "  sudo zypper --non-interactive update" ;;
        pacman) echo "  sudo pacman -Syu --noconfirm" ;;
    esac

    cat <<'EOF'

  # --- FILES ---
  # Find media files:
  sudo find / -xdev -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.mkv' \
    -o -iname '*.avi' -o -iname '*.flac' -o -iname '*.wav' \) 2>/dev/null

  # Find executables in user homes (often suspicious):
  sudo find /home -type f -perm -111 2>/dev/null

  # Remove a prohibited file (review first!):
  sudo rm -i /path/to/file

  # --- SERVICES ---
  # Stop & disable a service (works on any systemd distro):
  sudo systemctl disable --now <service>

  # --- SSH ---
  # Validate sshd config and reload:
  sudo sshd -t && sudo systemctl reload sshd
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
                    rm -f -- "$tgt" && fixed "removed $tgt (was created by $SCRIPT_NAME)"
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
    echo "  Distro: ${C_BOLD}$DISTRO_ID${C_RESET} (family=$DISTRO_FAMILY, version=$DISTRO_VERSION, pkg_mgr=$PKG_MGR)"
    echo "  ${C_GREEN}OK    : $COUNT_OK${C_RESET}"
    echo "  ${C_YELLOW}WARN  : $COUNT_WARN${C_RESET}"
    echo "  ${C_RED}BAD   : $COUNT_BAD${C_RESET}"
    echo "  ${C_BLUE}INFO  : $COUNT_INFO${C_RESET}"
    if [[ "$MODE" == "fix" ]]; then
        echo "  ${C_MAGENTA}FIXED : $COUNT_FIXED${C_RESET}"
        echo "  ${C_DIM}SKIP  : $COUNT_SKIPPED${C_RESET}"
        echo
        echo "  Action log: $ACTION_LOG"
        echo "  Roll back this run with:  sudo $SCRIPT_NAME --rollback"
    fi
    echo
    echo "  ${C_DIM}Remember: this script does not know your README. Cross-check users,${C_RESET}"
    echo "  ${C_DIM}admins, packages, and files against the authorized list manually.${C_RESET}"
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
        -h|--help) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac

    echo "${C_BOLD}${C_CYAN}$SCRIPT_NAME v$CP_AUDIT_VERSION${C_RESET}  mode=${MODE}  user=$(id -un)  host=$(hostname)  ts=$RUN_TS"
    echo "  Detected distro: ${C_BOLD}$DISTRO_ID${C_RESET}  family=$DISTRO_FAMILY  pkg_mgr=$PKG_MGR"
    if [[ $EUID -ne 0 ]]; then
        echo "${C_YELLOW}  (not root: some checks will be skipped or incomplete)${C_RESET}"
    fi
    if [[ "$DISTRO_FAMILY" == "unknown" ]]; then
        echo "${C_YELLOW}  WARNING: distro family unknown. Most checks will still run.${C_RESET}"
    fi

    check_users_and_admins
    check_password_policy
    check_sshd
    check_firewall
    check_sysctl
    check_critical_perms
    check_sudoers
    check_suid
    check_services
    check_pkg_mgr_config
    check_display_manager
    check_samba
    check_cron
    check_world_writable
    check_forensics_questions
    check_prohibited_media

    print_summary

    if [[ "$MODE" == "audit" ]]; then
        echo
        echo "  ${C_DIM}Run '$SCRIPT_NAME --suggest' for copy-paste commands for the${C_RESET}"
        echo "  ${C_DIM}things this script will not change automatically.${C_RESET}"
    fi
}

main "$@"
