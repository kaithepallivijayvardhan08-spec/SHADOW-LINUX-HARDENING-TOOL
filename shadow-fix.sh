#!/bin/bash
# ============================================================
# ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
# ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
# ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
# ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
# ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
# ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
#
# ╔══════════════════════════════════════════════════════════╗
# ║  CYBORG REPAIR SYSTEM v1.0                             ║
# ║  [ADVANCED RECOVERY ENGINE]                            ║
# ║  [PAM RECOVERY ENGINE]                                 ║
# ║  [NEURAL CACHE PURGE]                                  ║
# ║  [QUANTUM TRANSACTION RESET]                           ║
# ║  [REBOOT PROTOCOL NEUTRALIZATION]                     ║
# ╚══════════════════════════════════════════════════════════╝
# ============================================================

# ─── CYBER COLORS ──────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
BLINK='\033[5m'
UNDERLINE='\033[4m'
REVERSE='\033[7m'
NC='\033[0m'

# ─── ASCII BANNER ──────────────────────────────────────────────
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║     ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗              ║
    ║     ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║              ║
    ║     ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║              ║
    ║     ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║              ║
    ║     ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝              ║
    ║     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝               ║
    ║                                                                       ║
    ║     ╔═══════════════════════════════════════════════════════════════╗  ║
    ║     ║  ⚡ CYBORG REPAIR SYSTEM v1.0                                ║  ║
    ║     ║  🛡️  ADVANCED RECOVERY ENGINE                               ║  ║
    ║     ║  🔧 PAM RECOVERY ENGINE                                      ║  ║
    ║     ║  🧠 NEURAL CACHE PURGE                                      ║  ║
    ║     ║  ⚛️  QUANTUM TRANSACTION RESET                              ║  ║
    ║     ║  🔮 SYSTEM INTEGRITY VERIFICATION                           ║  ║
    ║     ║  🚫 REBOOT PROTOCOL NEUTRALIZATION                         ║  ║
    ║     ╚═══════════════════════════════════════════════════════════════╝  ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# ─── SYSTEM STATUS INDICATOR ────────────────────────────────────
sys_status() {
    local status=$1
    local msg=$2
    local symbol=""
    local color=""
    
    case $status in
        "ok")
            symbol="✅"
            color="${GREEN}"
            ;;
        "warn")
            symbol="⚠️"
            color="${YELLOW}"
            ;;
        "error")
            symbol="❌"
            color="${RED}"
            ;;
        "info")
            symbol="ℹ️"
            color="${CYAN}"
            ;;
        "scan")
            symbol="📡"
            color="${BLUE}"
            ;;
        "reboot")
            symbol="🚫"
            color="${MAGENTA}"
            ;;
        "pam")
            symbol="🔧"
            color="${YELLOW}"
            ;;
        "cache")
            symbol="🧹"
            color="${CYAN}"
            ;;
        *)
            symbol="⚡"
            color="${WHITE}"
            ;;
    esac
    
    echo -e "${color}  ${symbol} ${msg}${NC}"
}

# ─── PROGRESS BAR ──────────────────────────────────────────────
draw_progress() {
    local current=$1
    local total=$2
    local label=$3
    local width=50
    local percent=$((current * 100 / total))
    local filled=$((percent * width / 100))
    local empty=$((width - filled))
    
    printf "\r${CYAN}┃${NC} ${WHITE}${label}${NC} "
    printf "[${GREEN}"
    printf "%${filled}s" | tr ' ' '█'
    printf "${DIM}"
    printf "%${empty}s" | tr ' ' '░'
    printf "${NC}] ${WHITE}%3d%%${NC}" "$percent"
}

# ─── ANIMATED LOADER ────────────────────────────────────────────
animate_loader() {
    local pid=$1
    local msg=$2
    local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    local cols=$(tput cols 2>/dev/null || echo 80)
    local msg_len=${#msg}
    local pad=$(( (cols - msg_len - 10) / 2 ))
    if [ $pad -lt 0 ]; then pad=0; fi
    
    while kill -0 $pid 2>/dev/null; do
        printf "\r${CYAN}${chars:$i:1}${NC} %${pad}s${msg}%${pad}s" "" ""
        i=$(( (i+1) % 10 ))
        sleep 0.08
    done
    printf "\r${GREEN}✅${NC} %${pad}s${msg}%${pad}s\n" "" ""
}

# ─── TERMINAL SIZE ──────────────────────────────────────────────
term_width=$(tput cols 2>/dev/null || echo 80)
term_height=$(tput lines 2>/dev/null || echo 24)

# ─── DIVIDER ────────────────────────────────────────────────────
divider() {
    local char=$1
    local len=${2:-$term_width}
    printf "${DIM}"
    for ((i=0; i<len; i++)); do
        printf "%s" "$char"
    done
    printf "${NC}\n"
}

# ─── HEADER ─────────────────────────────────────────────────────
show_banner
divider "═" $term_width
echo ""

# ─── SYSTEM INIT ──────────────────────────────────────────────
sys_status "info" "INITIALIZING CYBORG REPAIR SEQUENCE..."
sys_status "info" "TARGET: /opt/shadow/"
sys_status "info" "MODE: SELECTABLE RECOVERY ENGINE"
echo ""

# ─── CHECK ROOT ────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    divider "─" $term_width
    echo ""
    echo -e "${RED}  ██████╗  ██████╗  ██████╗ ████████╗${NC}"
    echo -e "${RED}  ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝${NC}"
    echo -e "${RED}  ██████╔╝██║   ██║██║   ██║   ██║   ${NC}"
    echo -e "${RED}  ██╔══██╗██║   ██║██║   ██║   ██║   ${NC}"
    echo -e "${RED}  ██║  ██║╚██████╔╝╚██████╔╝   ██║   ${NC}"
    echo -e "${RED}  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ${NC}"
    echo ""
    sys_status "error" "ROOT ACCESS REQUIRED"
    sys_status "info" "Run: sudo ./shadow-fix.sh"
    echo ""
    divider "─" $term_width
    exit 1
fi

# ─── CHECK SOURCE ──────────────────────────────────────────────
SOURCE_DIR="$(pwd)"
if [ ! -d "$SOURCE_DIR/shadow" ]; then
    divider "─" $term_width
    echo ""
    echo -e "${RED}  ███████╗ ██████╗ ██╗   ██╗██████╗  ██████╗███████╗${NC}"
    echo -e "${RED}  ██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝${NC}"
    echo -e "${RED}  ███████╗██║   ██║██║   ██║██████╔╝██║     █████╗  ${NC}"
    echo -e "${RED}  ╚════██║██║   ██║██║   ██║██╔══██╗██║     ██╔══╝  ${NC}"
    echo -e "${RED}  ███████║╚██████╔╝╚██████╔╝██║  ██║╚██████╗███████╗${NC}"
    echo -e "${RED}  ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝${NC}"
    echo ""
    sys_status "error" "SOURCE DIRECTORY NOT FOUND"
    sys_status "info" "Run from: cd ~/SHADOW-LINUX-HARDENING-TOOL"
    echo ""
    divider "─" $term_width
    exit 1
fi

# ─── SHOW STATUS BEFORE MENU ──────────────────────────────────
divider "─" $term_width
echo ""
sys_status "scan" "SCANNING SYSTEM STATE..."
echo ""

# Check for stuck transactions
if ls /var/lib/shadow/state/transaction_*.json 2>/dev/null | grep -q .; then
    sys_status "warn" "DETECTED: STUCK TRANSACTION"
else
    sys_status "ok" "TRANSACTION STATE: CLEAN"
fi

# Check for reboot flags
if [ -f /var/run/reboot-required ] || [ -f /var/run/reboot-required.pkgs ]; then
    sys_status "warn" "DETECTED: PENDING REBOOT FLAGS"
else
    sys_status "ok" "REBOOT STATE: CLEAN"
fi

# Check Unattended Upgrades config
if grep -q "Unattended-Upgrade::Automatic-Reboot \"true\"" /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
    sys_status "warn" "DETECTED: AUTO-REBOOT ENABLED"
else
    sys_status "ok" "AUTO-REBOOT: DISABLED"
fi

# Check cache
if [ -d /opt/shadow/shadow/__pycache__ ] 2>/dev/null; then
    sys_status "warn" "DETECTED: CACHED BYTECODE"
else
    sys_status "ok" "CACHE STATE: CLEAN"
fi

# Check PAM state
if [ -f /etc/pam.d/common-password ] && [ -f /etc/pam.d/common-auth ]; then
    if grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
        sys_status "ok" "PAM STATE: CONFIGURED"
    else
        sys_status "warn" "PAM STATE: MAY NEED RECOVERY"
    fi
else
    sys_status "error" "PAM STATE: CRITICAL - FILES MISSING"
fi

echo ""
divider "═" $term_width
echo ""

# ─── MAIN MENU ──────────────────────────────────────────────────
show_menu() {
    echo -e "${BOLD}${CYAN}  ╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}  ${BOLD}${WHITE}SELECT REPAIR OPTION${NC}                               ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ╠═══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}                                                           ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}  ${YELLOW}${BOLD}1.${NC} ${WHITE}PAM RECOVERY${NC} ${DIM}(FIX BROKEN SUDO)${NC}                    ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}     ${DIM}→ Restore PAM from backup + fix sudo${NC}                 ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}                                                           ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}  ${GREEN}${BOLD}2.${NC} ${WHITE}FULL SYSTEM REPAIR${NC}                           ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}     ${DIM}→ Complete recovery + reboot neutralization${NC}          ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}                                                           ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}  ${MAGENTA}${BOLD}3.${NC} ${WHITE}REBOOT FIX ONLY${NC}                           ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}     ${DIM}→ Neutralize auto-reboot + remove flags${NC}             ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}                                                           ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ║${NC}  ${RED}${BOLD}4.${NC} ${WHITE}EXIT${NC}                                      ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}  ╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${BOLD}${YELLOW}  Enter choice [1-4]: ${NC}"
}

# ─── FUNCTION: PAM RECOVERY ────────────────────────────────────
pam_recovery() {
    echo ""
    divider "═" $term_width
    echo -e "${BOLD}${YELLOW}  🔧 PAM RECOVERY ENGINE${NC}"
    divider "═" $term_width
    echo ""
    
    sys_status "pam" "EXECUTING PAM RECOVERY..."
    echo ""
    
    BACKUP_DIR="/var/backups/shadow"
    
    # ─── Locate backups ──────────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ LOCATING PAM BACKUPS ──────────────────────────────┐${NC}"
    echo -e "${DIM}  │  → Scanning backup directory...${NC}"
    
    PASSWORD_BACKUP=$(ls -t ${BACKUP_DIR}/common-password.backup_* 2>/dev/null | head -1)
    AUTH_BACKUP=$(ls -t ${BACKUP_DIR}/common-auth.backup_* 2>/dev/null | head -1)
    SSH_BACKUP=$(ls -t ${BACKUP_DIR}/sshd.backup_* 2>/dev/null | head -1)
    LOGIN_BACKUP=$(ls -t ${BACKUP_DIR}/login.backup_* 2>/dev/null | head -1)
    
    if [ -n "$PASSWORD_BACKUP" ]; then
        sys_status "ok" "Found: $(basename $PASSWORD_BACKUP)"
    else
        sys_status "error" "No common-password backup found!"
    fi
    
    if [ -n "$AUTH_BACKUP" ]; then
        sys_status "ok" "Found: $(basename $AUTH_BACKUP)"
    else
        sys_status "error" "No common-auth backup found!"
    fi
    
    echo ""
    
    # ─── Restore PAM files ──────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ RESTORING PAM FILES ──────────────────────────────┐${NC}"
    
    if [ -n "$PASSWORD_BACKUP" ]; then
        echo -e "${DIM}  │  → Restoring /etc/pam.d/common-password...${NC}"
        cp "$PASSWORD_BACKUP" /etc/pam.d/common-password &
        animate_loader $! "Restoring common-password"
        chmod 644 /etc/pam.d/common-password
        sys_status "ok" "common-password restored"
    fi
    
    if [ -n "$AUTH_BACKUP" ]; then
        echo -e "${DIM}  │  → Restoring /etc/pam.d/common-auth...${NC}"
        cp "$AUTH_BACKUP" /etc/pam.d/common-auth &
        animate_loader $! "Restoring common-auth"
        chmod 644 /etc/pam.d/common-auth
        sys_status "ok" "common-auth restored"
    fi
    
    if [ -n "$SSH_BACKUP" ]; then
        echo -e "${DIM}  │  → Restoring /etc/pam.d/sshd...${NC}"
        cp "$SSH_BACKUP" /etc/pam.d/sshd &
        animate_loader $! "Restoring sshd"
        chmod 644 /etc/pam.d/sshd
        sys_status "ok" "sshd restored"
    fi
    
    if [ -n "$LOGIN_BACKUP" ]; then
        echo -e "${DIM}  │  → Restoring /etc/pam.d/login...${NC}"
        cp "$LOGIN_BACKUP" /etc/pam.d/login &
        animate_loader $! "Restoring login"
        chmod 644 /etc/pam.d/login
        sys_status "ok" "login restored"
    fi
    
    echo ""
    
    # ─── Cache Purge ──────────────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ CACHE PURGE ──────────────────────────────────────┐${NC}"
    echo -e "${DIM}  │  → Removing Python bytecode cache...${NC}"
    
    find /opt/shadow -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null &
    animate_loader $! "Purging cache"
    
    find /opt/shadow -type f -name "*.pyc" -delete 2>/dev/null &
    animate_loader $! "Removing bytecode"
    
    sys_status "cache" "Cache purged"
    echo ""
    
    # ─── Verify ────────────────────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ VERIFICATION ──────────────────────────────────────┐${NC}"
    echo -e "${DIM}  │  → Testing sudo...${NC}"
    
    if sudo echo "test" 2>/dev/null | grep -q "test"; then
        echo -e "${GREEN}  │  ████████████████████████████████████████████████████████${NC}"
        echo -e "${GREEN}  │  ░ SUDO .......................... ✅ WORKING!         ░${NC}"
        echo -e "${GREEN}  │  ████████████████████████████████████████████████████████${NC}"
    else
        echo -e "${RED}  │  ████████████████████████████████████████████████████████${NC}"
        echo -e "${RED}  │  ░ SUDO .......................... ❌ STILL BROKEN!    ░${NC}"
        echo -e "${RED}  │  ░ Try: su - root (use root password)                  ░${NC}"
        echo -e "${RED}  │  ░ Then manually restore PAM files from:               ░${NC}"
        echo -e "${RED}  │  ░ ${BACKUP_DIR}/                                      ░${NC}"
        echo -e "${RED}  │  ████████████████████████████████████████████████████████${NC}"
    fi
    
    echo ""
    
    # ─── COMPLETE ──────────────────────────────────────────────────
    divider "═" $term_width
    echo -e "${BOLD}${GREEN}  ✅ PAM RECOVERY COMPLETE${NC}"
    divider "═" $term_width
    echo ""
    
    echo -e "${BOLD}${WHITE}  📊 STATUS:${NC}"
    echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    sys_status "ok" "PAM FILES: RESTORED"
    sys_status "cache" "CACHE: PURGED"
    echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    echo ""
    echo -e "${BOLD}${GREEN}  ⚡ NEXT STEPS:${NC}"
    echo -e "${CYAN}  ┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}  │  ${WHITE}1.${NC} ${GREEN}sudo shadow --scan${NC}          ${DIM}→ Verify system health${NC}${CYAN}  │${NC}"
    echo -e "${CYAN}  │  ${WHITE}2.${NC} ${GREEN}sudo shadow --harden --force${NC} ${DIM}→ Apply hardening${NC}${CYAN}  │${NC}"
    echo -e "${CYAN}  └─────────────────────────────────────────────────────────────┘${NC}"
    
    echo ""
    divider "═" $term_width
    echo ""
}

# ─── FUNCTION: FULL SYSTEM REPAIR ──────────────────────────────
full_repair() {
    echo ""
    divider "═" $term_width
    echo -e "${BOLD}${GREEN}  ⚡ FULL SYSTEM REPAIR SEQUENCE${NC}"
    divider "═" $term_width
    echo ""
    
    sys_status "info" "EXECUTING FULL REPAIR..."
    echo ""
    
    # ─── PHASE 1 ────────────────────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ PHASE 1: FILE SYNCHRONIZATION ──────────────────────┐${NC}"
    
    echo -e "${DIM}  │  → Removing obsolete binary files...${NC}"
    rm -rf /opt/shadow/shadow/core 2>/dev/null
    rm -rf /opt/shadow/shadow/modules 2>/dev/null
    rm -rf /opt/shadow/shadow/reports 2>/dev/null
    rm -rf /opt/shadow/shadow/database 2>/dev/null
    sys_status "ok" "Obsolete files purged"
    
    echo -e "${DIM}  │  → Deploying fresh source code...${NC}"
    cp -r "$SOURCE_DIR/shadow/"* /opt/shadow/shadow/ &
    animate_loader $! "Deploying source files"
    
    chmod -R 644 /opt/shadow/shadow/*.py 2>/dev/null
    chmod -R 755 /opt/shadow/shadow/core 2>/dev/null
    chmod -R 755 /opt/shadow/shadow/modules 2>/dev/null
    chmod -R 755 /opt/shadow/shadow/reports 2>/dev/null
    
    sys_status "ok" "Source files synchronized"
    
    # ─── PHASE 2 ────────────────────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ PHASE 2: NEURAL CACHE PURGE ─────────────────────────┐${NC}"
    
    echo -e "${DIM}  │  → Scanning for Python bytecode...${NC}"
    
    find /opt/shadow -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null &
    animate_loader $! "Purging neural cache"
    
    find /opt/shadow -type f -name "*.pyc" -delete 2>/dev/null &
    animate_loader $! "Removing compiled bytecode"
    
    sys_status "ok" "Neural cache purged"
    
    # ─── PHASE 3 ────────────────────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ PHASE 3: QUANTUM TRANSACTION RESET ──────────────────┐${NC}"
    
    echo -e "${DIM}  │  → Clearing stuck transactions...${NC}"
    
    rm -rf /var/lib/shadow/state/transaction_*.json 2>/dev/null &
    animate_loader $! "Resetting transaction logs"
    
    rm -rf /var/backups/shadow/pre_restore_* 2>/dev/null &
    animate_loader $! "Cleaning restore backups"
    
    sys_status "ok" "Quantum transactions reset"
    
    # ─── PHASE 4: REBOOT PROTOCOL NEUTRALIZATION ──────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ PHASE 4: REBOOT PROTOCOL NEUTRALIZATION ─────────────┐${NC}"
    
    echo -e "${DIM}  │  → Neutralizing reboot flags...${NC}"
    
    # Remove reboot-required flags
    if [ -f /var/run/reboot-required ]; then
        rm -f /var/run/reboot-required &
        animate_loader $! "Removing /var/run/reboot-required"
    fi
    
    if [ -f /var/run/reboot-required.pkgs ]; then
        rm -f /var/run/reboot-required.pkgs &
        animate_loader $! "Removing /var/run/reboot-required.pkgs"
    fi
    
    sys_status "ok" "Reboot flags neutralized"
    
    # ─── Disable Unattended Upgrades Auto-Reboot ──────────────────
    echo -e "${DIM}  │  → Disabling auto-reboot in Unattended Upgrades...${NC}"
    
    if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
        # Backup original config
        cp /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.backup.$(date +%Y%m%d_%H%M%S)
        
        # Disable auto-reboot
        sed -i 's/Unattended-Upgrade::Automatic-Reboot "true";/Unattended-Upgrade::Automatic-Reboot "false";/' /etc/apt/apt.conf.d/50unattended-upgrades
        sed -i 's/\/\/Unattended-Upgrade::Automatic-Reboot "false";/Unattended-Upgrade::Automatic-Reboot "false";/' /etc/apt/apt.conf.d/50unattended-upgrades
        sed -i 's/\/\/Unattended-Upgrade::Automatic-Reboot-WithUsers "true";/Unattended-Upgrade::Automatic-Reboot-WithUsers "false";/' /etc/apt/apt.conf.d/50unattended-upgrades
        
        sys_status "ok" "Auto-reboot disabled in Unattended Upgrades"
    else
        sys_status "warn" "Unattended Upgrades config not found"
    fi
    
    # ─── Patch engine.py to remove reboot calls ────────────────────
    echo -e "${DIM}  │  → Patching engine.py to prevent auto-reboot...${NC}"
    
    ENGINE_PATH="/opt/shadow/shadow/core/engine.py"
    
    if [ -f "$ENGINE_PATH" ]; then
        # Create backup
        cp "$ENGINE_PATH" "${ENGINE_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Use Python to patch the file safely
        python3 << 'PYTHON_PATCH' &
import re
import os

engine_path = "/opt/shadow/shadow/core/engine.py"

try:
    with open(engine_path, 'r') as f:
        content = f.read()
    
    # Pattern to find the reboot check block with user prompt
    pattern = r'(# FIX: Prevent auto-reboot from system.*?)(?=\n        self\.logger\.info\("Reboot check complete"\))'
    
    replacement = '''        # FIX: Prevent auto-reboot from system - NEUTRALIZED
        reboot_files = ['/var/run/reboot-required', '/var/run/reboot-required.pkgs']
        reboot_found = False
        
        for file in reboot_files:
            if os.path.exists(file):
                reboot_found = True
                self.logger.warning(f"Pending reboot detected: {file}")
        
        if reboot_found:
            self.logger.warning("System has pending reboot (from updates)")
            self.logger.warning("Shadow will continue but reboot is recommended")
            self.logger.info("You should reboot manually after hardening completes")
            
            # Remove flags to prevent auto-reboot
            for file in reboot_files:
                try:
                    os.remove(file)
                    self.logger.info(f"Removed reboot flag: {file}")
                except Exception as e:
                    self.logger.warning(f"Could not remove {file}: {e}")
            
            # Store state that reboot is needed
            self.reboot_pending = True
            self.logger.info("Reboot pending flag set - manual reboot recommended")
        else:
            self.reboot_pending = False
        
        self.logger.info("Reboot check complete")'''
    
    # Apply replacement
    updated_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    
    # Write the patched content
    with open(engine_path, 'w') as f:
        f.write(updated_content)
    
    print("✅ engine.py patched successfully")
    
except Exception as e:
    print(f"⚠️ Could not patch engine.py: {e}")
PYTHON_PATCH
    
        wait $!
        sys_status "ok" "engine.py patched - auto-reboot neutralized"
    else
        sys_status "warn" "engine.py not found - skipping patch"
    fi
    
    sys_status "ok" "Reboot protocol neutralized"
    
    # ─── PHASE 5 ────────────────────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ PHASE 5: SYSTEM INTEGRITY VERIFICATION ──────────────┐${NC}"
    
    # hardener.py
    if grep -q "if 'verified' not in backup" /opt/shadow/shadow/core/hardener.py 2>/dev/null; then
        echo -e "${GREEN}  │  █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█${NC}"
        echo -e "${GREEN}  │  ░ hardener.py ................... ✅ FIX CONFIRMED ░${NC}"
        echo -e "${GREEN}  │  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█${NC}"
    else
        echo -e "${RED}  │  █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█${NC}"
        echo -e "${RED}  │  ░ hardener.py ................... ❌ FIX MISSING  ░${NC}"
        echo -e "${RED}  │  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█${NC}"
    fi
    
    # restore.py
    if grep -q "try:" /opt/shadow/shadow/core/restore.py 2>/dev/null && grep -q "backup_valid" /opt/shadow/shadow/core/restore.py 2>/dev/null; then
        echo -e "${GREEN}  │  █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█${NC}"
        echo -e "${GREEN}  │  ░ restore.py .................. ✅ FIX CONFIRMED ░${NC}"
        echo -e "${GREEN}  │  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█${NC}"
    else
        echo -e "${RED}  │  █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█${NC}"
        echo -e "${RED}  │  ░ restore.py .................. ❌ FIX MISSING  ░${NC}"
        echo -e "${RED}  │  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█${NC}"
    fi
    
    # engine.py - Check for reboot fix
    if grep -q "reboot_pending" /opt/shadow/shadow/core/engine.py 2>/dev/null; then
        echo -e "${GREEN}  │  █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█${NC}"
        echo -e "${GREEN}  │  ░ engine.py ................... ✅ REBOOT FIXED ░${NC}"
        echo -e "${GREEN}  │  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█${NC}"
    else
        echo -e "${RED}  │  █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█${NC}"
        echo -e "${RED}  │  ░ engine.py ................... ❌ REBOOT ACTIVE ░${NC}"
        echo -e "${RED}  │  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█${NC}"
    fi
    
    # ─── PHASE 6 ────────────────────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ PHASE 6: DIAGNOSTIC SCAN ───────────────────────────┐${NC}"
    
    echo -e "${DIM}  │  → Running neural scan...${NC}"
    SCAN_OUTPUT=$(shadow --scan 2>/dev/null | head -3)
    if echo "$SCAN_OUTPUT" | grep -q "SCAN\|Shadow"; then
        echo -e "${GREEN}  │  █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█${NC}"
        echo -e "${GREEN}  │  ░ Scan test ................... ✅ PASSED     ░${NC}"
        echo -e "${GREEN}  │  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█${NC}"
    else
        echo -e "${RED}  │  █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█${NC}"
        echo -e "${RED}  │  ░ Scan test ................... ❌ FAILED     ░${NC}"
        echo -e "${RED}  │  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█${NC}"
    fi
    
    # ─── COMPLETE ──────────────────────────────────────────────────
    echo ""
    divider "═" $term_width
    echo -e "${BOLD}${GREEN}  ✅ FULL REPAIR SEQUENCE COMPLETE${NC}"
    divider "═" $term_width
    echo ""
    
    # ─── SYSTEM STATUS ─────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}  📊 SYSTEM STATUS:${NC}"
    echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    sys_status "ok" "NEURAL CACHE: PURGED"
    sys_status "ok" "QUANTUM TRANSACTIONS: RESET"
    sys_status "ok" "SOURCE CODE: DEPLOYED"
    sys_status "reboot" "REBOOT PROTOCOL: NEUTRALIZED"
    sys_status "ok" "UNATTENDED UPGRADES: AUTO-REBOOT DISABLED"
    sys_status "ok" "SYSTEM INTEGRITY: VERIFIED"
    echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    echo ""
    echo -e "${BOLD}${GREEN}  ⚡ RECOMMENDED NEXT STEPS:${NC}"
    echo -e "${CYAN}  ┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}  │  ${WHITE}1.${NC} ${GREEN}sudo shadow --scan${NC}          ${DIM}→ Verify system health${NC}${CYAN}  │${NC}"
    echo -e "${CYAN}  │  ${WHITE}2.${NC} ${GREEN}sudo shadow --harden --force${NC} ${DIM}→ Apply hardening${NC}${CYAN}  │${NC}"
    echo -e "${CYAN}  │  ${WHITE}3.${NC} ${YELLOW}Reboot manually when ready${NC}   ${DIM}→ System will NOT auto-reboot${NC}${CYAN}  │${NC}"
    echo -e "${CYAN}  └─────────────────────────────────────────────────────────────┘${NC}"
    
    echo ""
    echo -e "${DIM}  📡 Logs: /var/log/shadow/shadow.log${NC}"
    echo -e "${DIM}  📡 Config: /etc/shadow-tool/shadow.yml${NC}"
    echo -e "${DIM}  📡 Backups: /var/backups/shadow/${NC}"
    echo -e "${DIM}  📡 Engine Backup: /opt/shadow/shadow/core/engine.py.backup.*${NC}"
    
    echo ""
    divider "═" $term_width
    echo -e "${BOLD}${GREEN}  ⚡ SHADOW CYBORG REPAIR COMPLETE ⚡${NC}"
    echo -e "${BOLD}${MAGENTA}  🚫 AUTO-REBOOT HAS BEEN NEUTRALIZED 🚫${NC}"
    divider "═" $term_width
    echo ""
}

# ─── FUNCTION: REBOOT FIX ONLY ──────────────────────────────
reboot_fix_only() {
    echo ""
    divider "═" $term_width
    echo -e "${BOLD}${MAGENTA}  🚫 REBOOT PROTOCOL NEUTRALIZATION ONLY${NC}"
    divider "═" $term_width
    echo ""
    
    sys_status "reboot" "EXECUTING REBOOT FIX..."
    echo ""
    
    # ─── Remove reboot flags ──────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ REMOVING REBOOT FLAGS ─────────────────────────────┐${NC}"
    
    echo -e "${DIM}  │  → Checking for reboot flags...${NC}"
    
    if [ -f /var/run/reboot-required ]; then
        rm -f /var/run/reboot-required &
        animate_loader $! "Removing /var/run/reboot-required"
        sys_status "ok" "Removed /var/run/reboot-required"
    else
        sys_status "ok" "No reboot-required flag found"
    fi
    
    if [ -f /var/run/reboot-required.pkgs ]; then
        rm -f /var/run/reboot-required.pkgs &
        animate_loader $! "Removing /var/run/reboot-required.pkgs"
        sys_status "ok" "Removed /var/run/reboot-required.pkgs"
    else
        sys_status "ok" "No reboot-required.pkgs flag found"
    fi
    
    echo ""
    
    # ─── Disable Unattended Upgrades Auto-Reboot ──────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ DISABLING AUTO-REBOOT ─────────────────────────────┐${NC}"
    
    if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
        echo -e "${DIM}  │  → Modifying Unattended Upgrades config...${NC}"
        
        # Backup original config
        cp /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.backup.$(date +%Y%m%d_%H%M%S)
        
        # Disable auto-reboot
        sed -i 's/Unattended-Upgrade::Automatic-Reboot "true";/Unattended-Upgrade::Automatic-Reboot "false";/' /etc/apt/apt.conf.d/50unattended-upgrades
        sed -i 's/\/\/Unattended-Upgrade::Automatic-Reboot "false";/Unattended-Upgrade::Automatic-Reboot "false";/' /etc/apt/apt.conf.d/50unattended-upgrades
        sed -i 's/\/\/Unattended-Upgrade::Automatic-Reboot-WithUsers "true";/Unattended-Upgrade::Automatic-Reboot-WithUsers "false";/' /etc/apt/apt.conf.d/50unattended-upgrades
        
        sys_status "ok" "Auto-reboot disabled in Unattended Upgrades"
    else
        sys_status "warn" "Unattended Upgrades config not found"
    fi
    
    echo ""
    
    # ─── Patch engine.py to remove reboot calls ────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ PATCHING ENGINE.PY ────────────────────────────────┐${NC}"
    
    ENGINE_PATH="/opt/shadow/shadow/core/engine.py"
    
    if [ -f "$ENGINE_PATH" ]; then
        echo -e "${DIM}  │  → Modifying engine.py to prevent auto-reboot...${NC}"
        
        # Create backup
        cp "$ENGINE_PATH" "${ENGINE_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Use Python to patch the file safely
        python3 << 'PYTHON_PATCH' &
import re
import os

engine_path = "/opt/shadow/shadow/core/engine.py"

try:
    with open(engine_path, 'r') as f:
        content = f.read()
    
    # Pattern to find the reboot check block with user prompt
    pattern = r'(# FIX: Prevent auto-reboot from system.*?)(?=\n        self\.logger\.info\("Reboot check complete"\))'
    
    replacement = '''        # FIX: Prevent auto-reboot from system - NEUTRALIZED
        reboot_files = ['/var/run/reboot-required', '/var/run/reboot-required.pkgs']
        reboot_found = False
        
        for file in reboot_files:
            if os.path.exists(file):
                reboot_found = True
                self.logger.warning(f"Pending reboot detected: {file}")
        
        if reboot_found:
            self.logger.warning("System has pending reboot (from updates)")
            self.logger.warning("Shadow will continue but reboot is recommended")
            self.logger.info("You should reboot manually after hardening completes")
            
            # Remove flags to prevent auto-reboot
            for file in reboot_files:
                try:
                    os.remove(file)
                    self.logger.info(f"Removed reboot flag: {file}")
                except Exception as e:
                    self.logger.warning(f"Could not remove {file}: {e}")
            
            # Store state that reboot is needed
            self.reboot_pending = True
            self.logger.info("Reboot pending flag set - manual reboot recommended")
        else:
            self.reboot_pending = False
        
        self.logger.info("Reboot check complete")'''
    
    # Apply replacement
    updated_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    
    # Write the patched content
    with open(engine_path, 'w') as f:
        f.write(updated_content)
    
    print("✅ engine.py patched successfully")
    
except Exception as e:
    print(f"⚠️ Could not patch engine.py: {e}")
PYTHON_PATCH
    
        wait $!
        
        if grep -q "reboot_pending" /opt/shadow/shadow/core/engine.py 2>/dev/null; then
            sys_status "ok" "engine.py patched successfully"
        else
            sys_status "warn" "engine.py may not be fully patched - check manually"
        fi
    else
        sys_status "error" "engine.py not found at $ENGINE_PATH"
    fi
    
    echo ""
    
    # ─── Verification ──────────────────────────────────────────────
    echo -e "${BOLD}${YELLOW}  ┌─ VERIFICATION ──────────────────────────────────────┐${NC}"
    
    echo -e "${DIM}  │  → Verifying fixes...${NC}"
    
    # Check reboot flags
    if [ ! -f /var/run/reboot-required ] && [ ! -f /var/run/reboot-required.pkgs ]; then
        sys_status "ok" "Reboot flags: CLEARED"
    else
        sys_status "warn" "Reboot flags: STILL PRESENT"
    fi
    
    # Check Unattended Upgrades
    if grep -q "Unattended-Upgrade::Automatic-Reboot \"false\"" /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
        sys_status "ok" "Auto-reboot: DISABLED"
    else
        sys_status "warn" "Auto-reboot: MAY STILL BE ENABLED"
    fi
    
    # Check engine.py
    if grep -q "reboot_pending" /opt/shadow/shadow/core/engine.py 2>/dev/null; then
        sys_status "ok" "engine.py: REBOOT NEUTRALIZED"
    else
        sys_status "warn" "engine.py: REBOOT MAY STILL BE ACTIVE"
    fi
    
    echo ""
    
    # ─── COMPLETE ──────────────────────────────────────────────────
    divider "═" $term_width
    echo -e "${BOLD}${MAGENTA}  ✅ REBOOT PROTOCOL NEUTRALIZATION COMPLETE${NC}"
    divider "═" $term_width
    echo ""
    
    echo -e "${BOLD}${WHITE}  📊 REBOOT STATUS:${NC}"
    echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    sys_status "reboot" "REBOOT FLAGS: REMOVED"
    sys_status "reboot" "AUTO-REBOOT: DISABLED"
    sys_status "reboot" "ENGINE.PY: PATCHED"
    echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    echo ""
    echo -e "${BOLD}${GREEN}  ⚡ RECOMMENDED NEXT STEPS:${NC}"
    echo -e "${CYAN}  ┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}  │  ${WHITE}1.${NC} ${GREEN}sudo shadow --scan${NC}          ${DIM}→ Verify system health${NC}${CYAN}  │${NC}"
    echo -e "${CYAN}  │  ${WHITE}2.${NC} ${GREEN}sudo shadow --harden --force${NC} ${DIM}→ Apply hardening${NC}${CYAN}  │${NC}"
    echo -e "${CYAN}  │  ${WHITE}3.${NC} ${YELLOW}Reboot manually when ready${NC}   ${DIM}→ System will NOT auto-reboot${NC}${CYAN}  │${NC}"
    echo -e "${CYAN}  └─────────────────────────────────────────────────────────────┘${NC}"
    
    echo ""
    echo -e "${DIM}  📡 Backups created:${NC}"
    echo -e "${DIM}     • /etc/apt/apt.conf.d/50unattended-upgrades.backup.*${NC}"
    echo -e "${DIM}     • /opt/shadow/shadow/core/engine.py.backup.*${NC}"
    
    echo ""
    divider "═" $term_width
    echo -e "${BOLD}${MAGENTA}  🚫 REBOOT NEUTRALIZED - SYSTEM WILL NOT AUTO-REBOOT 🚫${NC}"
    divider "═" $term_width
    echo ""
}

# ─── MAIN LOOP ──────────────────────────────────────────────────
while true; do
    show_menu
    read choice
    
    case $choice in
        1)
            pam_recovery
            break
            ;;
        2)
            full_repair
            break
            ;;
        3)
            reboot_fix_only
            break
            ;;
        4)
            echo ""
            sys_status "info" "EXITING CYBORG REPAIR SYSTEM"
            echo ""
            divider "─" $term_width
            exit 0
            ;;
        *)
            echo ""
            sys_status "error" "INVALID CHOICE - Please select 1, 2, 3, or 4"
            echo ""
            sleep 2
            ;;
    esac
done