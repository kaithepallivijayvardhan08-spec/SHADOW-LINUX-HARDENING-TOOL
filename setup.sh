#!/bin/bash
# ============================================================
# SHADOW LINUX HARDENING TOOL - INSTALLATION SCRIPT
# ============================================================
# This script installs Shadow on your Linux system.
# Run as root: sudo ./setup.sh
# Options:
#   --help        Show this help message
#   --dry-run     Preview installation without making changes
#   --uninstall   Remove Shadow from the system
#   --upgrade     Upgrade existing installation
# ============================================================

set -e  # Exit on error

# ============================================================
# ✅ FIX 4: AUTO-CORRECT SINGLE DASHES (e.g., -force -> --force)
# ============================================================
ARGS=()
for arg in "$@"; do
    case "$arg" in
        -force|-interactive|-scan|-harden|-restore|-report|-boot|-dry-run|-debug|-safe-mode)
            ARGS+=("--${arg#-}")
            ;;
        *)
            ARGS+=("$arg")
            ;;
    esac
done
set -- "${ARGS[@]}"

# ============================================================
# COLORS AND HELP
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_help() {
    cat << EOF
Usage: ./setup.sh [OPTIONS]

Options:
    --help          Show this help message
    --dry-run       Preview installation without making changes
    --uninstall     Remove Shadow from the system
    --upgrade       Upgrade existing installation

Examples:
    sudo ./setup.sh                 # Install Shadow
    sudo ./setup.sh --dry-run       # Preview installation
    sudo ./setup.sh --uninstall     # Remove Shadow
    sudo ./setup.sh --upgrade       # Upgrade Shadow

For more information, see README.md
EOF
    exit 0
}

# ============================================================
# PARSE COMMAND LINE ARGUMENTS
# ============================================================
DRY_RUN=false
UNINSTALL=false
UPGRADE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            show_help
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        --upgrade)
            UPGRADE=true
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================================
# CHECK ROOT
# ============================================================
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Please run as root (sudo ./setup.sh)${NC}"
    exit 1
fi

# ============================================================
# UNINSTALL FUNCTION
# ============================================================
do_uninstall() {
    echo -e "${YELLOW}Uninstalling Shadow...${NC}"
    
    # Remove executable
    rm -f /usr/local/bin/shadow
    
    # Remove systemd service
    systemctl stop shadow 2>/dev/null || true
    systemctl disable shadow 2>/dev/null || true
    rm -f /etc/systemd/system/shadow.service
    
    # Remove application files
    rm -rf /opt/shadow
    
    # Remove config
    rm -f /etc/shadow-tool/shadow.yml
    rmdir /etc/shadow-tool 2>/dev/null || true
    
    # Ask about removing logs and backups
    echo -e "${YELLOW}Remove logs and backups? (y/N)${NC}"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        rm -rf /var/log/shadow
        rm -rf /var/backups/shadow
    fi
    
    # Reload systemd
    systemctl daemon-reload 2>/dev/null || true
    
    echo -e "${GREEN}✅ Shadow uninstalled successfully${NC}"
    exit 0
}

# ============================================================
# DRY RUN MODE
# ============================================================
if [ "$DRY_RUN" = true ]; then
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}🛡️  SHADOW - DRY RUN MODE${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Would perform the following actions:${NC}"
    echo "  1. Detect OS and Python version"
    echo "  2. Install Python if needed"
    echo "  3. Create directories under /opt/shadow/"
    echo "  4. Copy application files"
    echo "  5. Install configuration to /etc/shadow-tool/"
    echo "  6. Install Python dependencies (including PDF support)"
    echo "  7. Create executable /usr/local/bin/shadow"
    echo "  8. Install systemd service"
    echo "  9. Create log and backup directories"
    echo "  10. Set permissions"
    echo ""
    echo -e "${GREEN}✅ Dry run complete. No changes were made.${NC}"
    exit 0
fi

# ============================================================
# UNINSTALL MODE
# ============================================================
if [ "$UNINSTALL" = true ]; then
    do_uninstall
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}🛡️  SHADOW LINUX HARDENING TOOL${NC}"
echo -e "${BLUE}   Installation Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# ============================================================
# LOG INSTALLATION
# ============================================================
INSTALL_LOG="/var/log/shadow/install.log"
mkdir -p /var/log/shadow 2>/dev/null || true
exec > >(tee -a "$INSTALL_LOG") 2>&1

echo "Installation started: $(date)"

# ============================================================
# DETECT OS
# ============================================================
echo -e "${YELLOW}Detecting operating system...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
    echo -e "${GREEN}Detected: $OS $VERSION${NC}"
else
    echo -e "${RED}Could not detect OS. Continuing anyway...${NC}"
    OS="unknown"
fi

# ============================================================
# PYTHON VERSION CHECK - AUTO FIX
# ============================================================
echo -e "${YELLOW}Checking Python version...${NC}"

# List of Python commands to try in order (newest first)
PYTHON_CANDIDATES=("python3.13" "python3.12" "python3.11" "python3.10" "python3")

PYTHON_CMD=""
PYTHON_VERSION=""

for candidate in "${PYTHON_CANDIDATES[@]}"; do
    if command -v $candidate &> /dev/null; then
        VERSION=$($candidate -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
        MAJOR=$(echo $VERSION | cut -d. -f1)
        MINOR=$(echo $VERSION | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 8 ]; then
            PYTHON_CMD=$candidate
            PYTHON_VERSION=$VERSION
            echo -e "${GREEN}Python $PYTHON_VERSION detected (using $PYTHON_CMD)${NC}"
            break
        fi
    fi
done

# If no suitable Python found, try to install one
if [ -z "$PYTHON_CMD" ]; then
    echo -e "${YELLOW}Python 3.8+ not found. Attempting to install...${NC}"
    
    # Detect OS and install Python
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ] || [ "$OS" = "kali" ]; then
        if [ "$OS" = "ubuntu" ] && [ "$VERSION" = "20.04" ] || [ "$VERSION" = "18.04" ]; then
            echo -e "${YELLOW}Adding deadsnakes PPA for Python 3.10...${NC}"
            add-apt-repository ppa:deadsnakes/ppa -y
            apt-get update -qq
        fi
        apt-get update -qq
        apt-get install -y python3.10 python3.10-venv python3.10-dev
        PYTHON_CMD="python3.10"
        PYTHON_VERSION="3.10"
        echo -e "${GREEN}Python 3.10 installed successfully${NC}"
        
    elif [ "$OS" = "rhel" ] || [ "$OS" = "fedora" ] || [ "$OS" = "centos" ]; then
        if [ "$OS" = "centos" ] || [ "$OS" = "rhel" ]; then
            yum install -y epel-release
            yum install -y python3.10
        else
            dnf install -y python3.10
        fi
        PYTHON_CMD="python3.10"
        PYTHON_VERSION="3.10"
        echo -e "${GREEN}Python 3.10 installed successfully${NC}"
        
    else
        echo -e "${RED}Could not install Python automatically.${NC}"
        echo -e "${YELLOW}Please install Python 3.8+ manually and run setup again.${NC}"
        exit 1
    fi
fi

# Export Python command
export PYTHON_CMD
export PYTHON_VERSION

# Check pip for the selected Python
echo -e "${YELLOW}Checking pip for $PYTHON_CMD...${NC}"
if ! $PYTHON_CMD -m pip --version &> /dev/null; then
    echo -e "${YELLOW}pip not found. Installing...${NC}"
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ] || [ "$OS" = "kali" ]; then
        apt-get install -y python3-pip
    elif [ "$OS" = "rhel" ] || [ "$OS" = "fedora" ] || [ "$OS" = "centos" ]; then
        yum install -y python3-pip
    else
        curl -sS https://bootstrap.pypa.io/get-pip.py | $PYTHON_CMD
    fi
fi
echo -e "${GREEN}pip found for $PYTHON_CMD${NC}"

# ============================================================
# CREATE DIRECTORIES
# ============================================================
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p /opt/shadow/shadow/core
mkdir -p /opt/shadow/shadow/modules/authentication
mkdir -p /opt/shadow/shadow/modules/remote_access
mkdir -p /opt/shadow/shadow/modules/network
mkdir -p /opt/shadow/shadow/modules/file_security
mkdir -p /opt/shadow/shadow/modules/services
mkdir -p /opt/shadow/shadow/modules/storage
mkdir -p /opt/shadow/shadow/modules/monitoring
mkdir -p /opt/shadow/shadow/modules/updates
mkdir -p /opt/shadow/shadow/modules/kernel
mkdir -p /opt/shadow/shadow/modules/processes
mkdir -p /opt/shadow/shadow/modules/audit
mkdir -p /opt/shadow/shadow/modules/access_control
mkdir -p /opt/shadow/shadow/modules/scheduled_tasks
mkdir -p /opt/shadow/shadow/modules/integrity
mkdir -p /opt/shadow/shadow/reports
mkdir -p /opt/shadow/shadow/database
mkdir -p /opt/shadow/shadow/config
mkdir -p /opt/shadow/tests/kali_tests
mkdir -p /opt/shadow/tests/ubuntu_tests

mkdir -p /etc/shadow-tool
mkdir -p /var/log/shadow
mkdir -p /var/log/shadow/reports
mkdir -p /var/backups/shadow
mkdir -p /var/backups/shadow/original_configs
mkdir -p /etc/systemd/system

echo -e "${GREEN}Directories created${NC}"

# ============================================================
# COPY APPLICATION FILES
# ============================================================
echo -e "${YELLOW}Copying application files...${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Backup existing installation if upgrading
if [ "$UPGRADE" = true ] && [ -d "/opt/shadow" ]; then
    echo -e "${YELLOW}Creating backup of existing installation...${NC}"
    BACKUP_DIR="/opt/shadow_backup_$(date +%Y%m%d_%H%M%S)"
    cp -r /opt/shadow "$BACKUP_DIR"
    echo -e "${GREEN}Backup created: $BACKUP_DIR${NC}"
fi

# Copy core files
if [ -d "$SCRIPT_DIR/shadow" ]; then
    cp -r "$SCRIPT_DIR/shadow/"* /opt/shadow/shadow/ 2>/dev/null || echo "No shadow files to copy"
else
    echo -e "${RED}Error: shadow/ directory not found in $SCRIPT_DIR${NC}"
    exit 1
fi

# Copy test files
if [ -d "$SCRIPT_DIR/tests" ]; then
    cp -r "$SCRIPT_DIR/tests/"* /opt/shadow/tests/ 2>/dev/null || echo "No test files to copy"
fi

# Create __init__.py files if missing
touch /opt/shadow/shadow/__init__.py
touch /opt/shadow/shadow/core/__init__.py
touch /opt/shadow/shadow/modules/__init__.py
touch /opt/shadow/shadow/modules/authentication/__init__.py
touch /opt/shadow/shadow/modules/remote_access/__init__.py
touch /opt/shadow/shadow/modules/network/__init__.py
touch /opt/shadow/shadow/modules/file_security/__init__.py
touch /opt/shadow/shadow/modules/services/__init__.py
touch /opt/shadow/shadow/modules/storage/__init__.py
touch /opt/shadow/shadow/modules/monitoring/__init__.py
touch /opt/shadow/shadow/modules/updates/__init__.py
touch /opt/shadow/shadow/modules/kernel/__init__.py
touch /opt/shadow/shadow/modules/processes/__init__.py
touch /opt/shadow/shadow/modules/audit/__init__.py
touch /opt/shadow/shadow/modules/access_control/__init__.py
touch /opt/shadow/shadow/modules/scheduled_tasks/__init__.py
touch /opt/shadow/shadow/modules/integrity/__init__.py
touch /opt/shadow/shadow/reports/__init__.py
touch /opt/shadow/shadow/database/__init__.py
touch /opt/shadow/tests/__init__.py
touch /opt/shadow/tests/kali_tests/__init__.py
touch /opt/shadow/tests/ubuntu_tests/__init__.py

echo -e "${GREEN}Application files copied${NC}"

# ============================================================
# COPY CONFIGURATION - ONE LOCATION ONLY
# ============================================================
echo -e "${YELLOW}Copying configuration to ONE location...${NC}"

# Backup existing config if upgrading
if [ "$UPGRADE" = true ] && [ -f "/etc/shadow-tool/shadow.yml" ]; then
    echo -e "${YELLOW}Backing up existing config...${NC}"
    cp /etc/shadow-tool/shadow.yml /etc/shadow-tool/shadow.yml.bak
    echo -e "${GREEN}Config backed up: /etc/shadow-tool/shadow.yml.bak${NC}"
fi

# Copy config to ONE location only
if [ -f "$SCRIPT_DIR/config/shadow.yml" ]; then
    cp "$SCRIPT_DIR/config/shadow.yml" /etc/shadow-tool/shadow.yml
elif [ -f "$SCRIPT_DIR/shadow/config/shadow.yml" ]; then
    cp "$SCRIPT_DIR/shadow/config/shadow.yml" /etc/shadow-tool/shadow.yml
else
    # Create default config with ALL modules (auto_fix: true)
    cat > /etc/shadow-tool/shadow.yml << 'EOF'
# Shadow Linux Hardening Tool - Configuration
general:
  auto_fix: true
  force: false
  dry_run: false
modules:
  authentication: {enabled: true, password_policy: true, login_protection: true, sudo_check: true, users: true}
  remote_access: {enabled: true, ssh: true, telnet: true, rdp_vnc: true}
  network: {enabled: true, firewall: true, ports: true, dns: true, connections: true}
  file_security: {enabled: true, permissions: true, ownership: true, sensitive_files: true}
  services: {enabled: true, apache: true, nginx: true, mysql: true, docker: true, nfs: true}
  storage: {enabled: true, disk_check: true, lvm: true, encryption: true}
  monitoring: {enabled: true, logs: true, suspicious_process: true, malware_scan: true}
  updates: {enabled: true, package_updates: true, package_integrity: true}
  kernel: {enabled: true, kernel_check: true, sysctl_security: true, kernel_modules: true}
  processes: {enabled: true, process_audit: true, startup_process: true, resource_check: true}
  audit: {enabled: true, auditd_check: true, audit_rules: true, system_events: true}
  access_control: {enabled: true, selinux: true, apparmor: true, capabilities: true}
  scheduled_tasks: {enabled: true, cron_check: true, systemd_timer: true, startup_jobs: true}
  integrity: {enabled: true, file_integrity: true, hash_monitor: true, change_detection: true}
password:
  min_length: 8
  max_age: 90
  min_age: 1
  warn_age: 7
  history: 5
  complexity: true
  require_upper: true
  require_lower: true
  require_digit: true
  require_special: true
  max_attempts: 3
  lockout_time: 600
ssh:
  permit_root_login: false
  max_auth_tries: 3
  protocol: 2
  max_sessions: 10
firewall:
  default_policy: deny
  enable_logging: true
  apply_basic_rules: true
risk_weights: {FAIL: 10, WARN: 5, ERROR: 8, PASS: 0}
risk_thresholds: {LOW: 25, MEDIUM: 50, HIGH: 75, CRITICAL: 100}
reporting: {terminal: true, json: true, html: true, pdf: true, save: true}
backup: {enabled: true, location: /var/backups/shadow/}
scan: {module_timeout: 30}
logging: {level: INFO, file: /var/log/shadow/shadow.log}
EOF
fi

# Set permissions for config
chmod 600 /etc/shadow-tool/shadow.yml

# REMOVE old config files from other locations
rm -f /opt/shadow/shadow/config/shadow.yml 2>/dev/null || true
rm -f "$SCRIPT_DIR/shadow/config/shadow.yml" 2>/dev/null || true

echo -e "${GREEN}Configuration installed at /etc/shadow-tool/shadow.yml${NC}"
echo -e "${GREEN}Old config files removed${NC}"

# ============================================================
# ✅ FIX 2: INSTALL SYSTEM DEPENDENCIES FOR PDF (WEASYPRINT)
# ============================================================
if [ "$OS" = "kali" ] || [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    echo -e "${YELLOW}Installing system dependencies for PDF generation...${NC}"
    apt-get update -qq
    # These C-libraries are REQUIRED for WeasyPrint to draw PDFs without crashing
    apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info 2>/dev/null || true
fi

# ============================================================
# INSTALL PYTHON DEPENDENCIES
# ============================================================
echo -e "${YELLOW}Installing Python dependencies...${NC}"

# Try apt-based installation first (Kali fix)
if [ "$OS" = "kali" ] || [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    echo -e "${YELLOW}Attempting apt-based installation for compatibility...${NC}"
    apt-get install -y python3-yaml python3-jinja2 python3-requests python3-weasyprint 2>/dev/null || true
fi

# Then try pip with fallback
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    # Try normal pip install
    if ! $PYTHON_CMD -m pip install -r "$SCRIPT_DIR/requirements.txt" --quiet 2>/dev/null; then
        echo -e "${YELLOW}Retrying pip with --break-system-packages (Kali compatibility)...${NC}"
        $PYTHON_CMD -m pip install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages --quiet 2>/dev/null || true
    fi
else
    # Install ALL core packages including PDF dependencies
    for pkg in pyyaml jinja2 requests weasyprint reportlab pdfkit; do
        $PYTHON_CMD -m pip install $pkg --quiet 2>/dev/null || \
        $PYTHON_CMD -m pip install $pkg --break-system-packages --quiet 2>/dev/null || true
    done
fi

echo -e "${GREEN}Python dependencies installed${NC}"

# ============================================================
# CREATE EXECUTABLE
# ============================================================
echo -e "${YELLOW}Creating executable...${NC}"

cat > /usr/local/bin/shadow << EOF
#!/bin/bash
exec $PYTHON_CMD /opt/shadow/shadow/main.py "\$@"
EOF

chmod +x /usr/local/bin/shadow
echo -e "${GREEN}Executable created: /usr/local/bin/shadow${NC}"

# ============================================================
# INSTALL SYSTEMD SERVICE
# ============================================================
echo -e "${YELLOW}Installing systemd service...${NC}"
if [ -f "$SCRIPT_DIR/systemd/shadow.service" ]; then
    cp "$SCRIPT_DIR/systemd/shadow.service" /etc/systemd/system/shadow.service
else
    cat > /etc/systemd/system/shadow.service << 'EOF'
[Unit]
Description=Shadow Linux Hardening Tool
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/shadow --boot
PrivateTmp=true
ProtectSystem=strict
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
fi

chmod 644 /etc/systemd/system/shadow.service
systemctl daemon-reload 2>/dev/null || true
echo -e "${GREEN}Systemd service installed${NC}"

# ============================================================
# CREATE LOG FILES
# ============================================================
echo -e "${YELLOW}Creating log files...${NC}"
touch /var/log/shadow/shadow.log
touch /var/log/shadow/errors.log
touch /var/log/shadow/changes.log
touch /var/log/shadow/install.log
# ✅ FIX 3: Changed from 640 to 644 to prevent Permission Denied crashes
chmod 644 /var/log/shadow/*.log
echo -e "${GREEN}Log files created${NC}"

# ============================================================
# CREATE BACKUP DIRECTORY
# ============================================================
echo -e "${YELLOW}Creating backup directory...${NC}"
mkdir -p /var/backups/shadow/original_configs
chmod 700 /var/backups/shadow
echo -e "${GREEN}Backup directory created${NC}"

# ============================================================
# SET PERMISSIONS
# ============================================================
echo -e "${YELLOW}Setting permissions...${NC}"
chown -R root:root /opt/shadow 2>/dev/null || true
chown -R root:root /etc/shadow-tool 2>/dev/null || true
chown -R root:root /var/log/shadow 2>/dev/null || true
chown -R root:root /var/backups/shadow 2>/dev/null || true
echo -e "${GREEN}Permissions set${NC}"

# ============================================================
# CREATE DATABASE WITH COMPLETE RULES
# ============================================================
echo -e "${YELLOW}Creating database directory...${NC}"
mkdir -p /opt/shadow/database

# Copy rules.json if it exists
if [ -f "$SCRIPT_DIR/shadow/database/rules.json" ]; then
    cp "$SCRIPT_DIR/shadow/database/rules.json" /opt/shadow/database/rules.json
elif [ -f "$SCRIPT_DIR/database/rules.json" ]; then
    cp "$SCRIPT_DIR/database/rules.json" /opt/shadow/database/rules.json
else
    # Create default complete rules
    cat > /opt/shadow/database/rules.json << 'EOF'
{
  "version": "1.0.0",
  "last_updated": "2025-01-15",
  "description": "Security rules for Linux hardening - Complete coverage for all modules",
  "rules": {
    "ssh": {
      "SSH-001": {"name": "PermitRootLogin", "expected": "no", "severity": "high", "category": "authentication", "compliance": ["CIS-5.2.8"], "description": "Root login should be disabled", "fix": "Set PermitRootLogin no in /etc/ssh/sshd_config"},
      "SSH-002": {"name": "MaxAuthTries", "expected": 3, "severity": "high", "category": "authentication", "compliance": ["CIS-5.2.10"], "description": "Max authentication attempts limited", "fix": "Set MaxAuthTries 3 in /etc/ssh/sshd_config"},
      "SSH-003": {"name": "MaxSessions", "expected": 10, "severity": "medium", "category": "authentication", "compliance": ["CIS-5.2.9"], "description": "Max SSH sessions limited", "fix": "Set MaxSessions 10 in /etc/ssh/sshd_config"},
      "SSH-004": {"name": "Protocol", "expected": 2, "severity": "critical", "category": "authentication", "compliance": ["CIS-5.2.1"], "description": "SSH protocol 1 is insecure", "fix": "Set Protocol 2 in /etc/ssh/sshd_config"}
    },
    "password": {
      "PASS-001": {"name": "min_length", "expected": 8, "severity": "high", "category": "authentication", "compliance": ["CIS-5.3.1"], "description": "Minimum password length 8", "fix": "Set PASS_MIN_LEN 8 in /etc/login.defs"},
      "PASS-002": {"name": "history", "expected": 5, "severity": "medium", "category": "authentication", "compliance": ["CIS-5.3.4"], "description": "Password history enforced", "fix": "Configure pam_pwhistory remember=5"},
      "PASS-003": {"name": "max_attempts", "expected": 3, "severity": "critical", "category": "authentication", "compliance": ["CIS-5.3.3"], "description": "Account locks after 3 attempts", "fix": "Configure pam_faillock deny=3"}
    },
    "kernel": {
      "KERN-001": {"name": "tcp_syncookies", "expected": 1, "severity": "critical", "category": "kernel", "compliance": ["CIS-3.5.6"], "description": "TCP SYN cookies enabled", "fix": "net.ipv4.tcp_syncookies = 1"},
      "KERN-002": {"name": "ip_forward", "expected": 0, "severity": "medium", "category": "kernel", "compliance": ["CIS-3.5.1"], "description": "IP forwarding disabled", "fix": "net.ipv4.ip_forward = 0"}
    },
    "access_control": {
      "SEL-001": {"name": "selinux_status", "expected": "enforcing", "severity": "critical", "category": "access_control", "compliance": ["CIS-1.6.1"], "description": "SELinux in enforcing mode", "fix": "Set SELINUX=enforcing in /etc/selinux/config"}
    },
    "file_security": {
      "FILE-001": {"name": "shadow_perms", "expected": "600", "severity": "critical", "category": "file_security", "compliance": ["CIS-6.1.2"], "description": "/etc/shadow secure permissions", "fix": "chmod 600 /etc/shadow"},
      "FILE-002": {"name": "sudoers_perms", "expected": "440", "severity": "critical", "category": "file_security", "compliance": ["CIS-6.1.4"], "description": "/etc/sudoers secure permissions", "fix": "chmod 440 /etc/sudoers"}
    }
  }
}
EOF
fi

# ✅ FIX 1: DO NOT CREATE A FAKE baseline.json!
# Creating a hardcoded Ubuntu baseline on a Kali system causes the tool 
# to flag 61,000 changes on the first scan. The Python code will 
# automatically build a correct baseline on the first run.
rm -f /opt/shadow/database/baseline.json 2>/dev/null || true
rm -f "$SCRIPT_DIR/shadow/database/baseline.json" 2>/dev/null || true
rm -f "$SCRIPT_DIR/database/baseline.json" 2>/dev/null || true

chmod 600 /opt/shadow/database/*.json 2>/dev/null || true
echo -e "${GREEN}Database created with complete rules${NC}"

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✅ SHADOW INSTALLATION COMPLETE!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}Python used:${NC} $PYTHON_CMD ($PYTHON_VERSION)"
if [ "$UPGRADE" = true ]; then
    echo -e "${YELLOW}Upgrade completed${NC}"
fi
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo ""
echo "  # Run manual scan"
echo "  sudo shadow --scan"
echo ""
echo "  # Interactive mode"
echo "  sudo shadow --interactive"
echo ""
echo "  # Apply hardening fixes"
echo "  sudo shadow --harden"
echo ""
echo "  # Force apply fixes (bypass auto_fix)"
echo "  sudo shadow --harden --force"
echo ""
echo -e "${YELLOW}Logs:${NC} /var/log/shadow/"
echo -e "${YELLOW}Backups:${NC} /var/backups/shadow/"
echo -e "${YELLOW}Config:${NC} /etc/shadow-tool/shadow.yml"
echo ""
if [ "$UPGRADE" = true ]; then
    echo -e "${YELLOW}Backup of previous installation:${NC} $BACKUP_DIR"
    echo ""
fi
echo -e "${GREEN}Thank you for installing Shadow! 🛡️${NC}"
echo -e "${BLUE}========================================${NC}"