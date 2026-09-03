<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/License-Custom-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/OS-Kali%20%7C%20Ubuntu%20%7C%20RHEL-red?style=for-the-badge&logo=linux" />
  <img src="https://img.shields.io/badge/Compliance-CIS%20%7C%20NIST%20%7C%20ISO-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Production%20Ready-success?style=for-the-badge" />
</p>

<h1 align="center">🛡️ SHADOW: Enterprise Linux Hardening Framework</h1>

<p align="center">
  <b>A dynamically adaptive, OS-aware, and transaction-safe security framework for Linux.</b><br>
  <i>Designed for security professionals, sysadmins, and DevSecOps engineers.</i>
</p>

<p align="center">
  <b>Submitted by:</b> KAITHEPALLI VIJAY VARDHAN | <b>Category:</b> Security / DevSecOps
</p>

---

## 🌟 Overview

**SHADOW** is a comprehensive, terminal-based Linux system hardening tool that automates security assessment, vulnerability detection, risk analysis, and secure remediation. Built with **5,000+ lines of production-ready Python** across **89 source files**, it performs 40+ security checks in under two minutes.

Unlike traditional bash scripts or manual audits, SHADOW operates as an intelligent framework. It features **Dynamic OS-Awareness** to filter false positives, an **Honest Risk Engine** that tracks remediation progress across reboots, and **Atomic Transactions** that guarantee your system is never left in a broken state.

### ✨ Core Innovations (What makes SHADOW unique?)

- 🧠 **Dynamic OS-Awareness:** SHADOW reads `/etc/os-release` and probes virtualization layers. It dynamically suppresses "expected" warnings (e.g., hiding SELinux alerts on Kali Linux, or Disk Encryption alerts in VMs) so your risk score is mathematically accurate for *your specific environment*.
- 🧮 **Honest Risk Engine & State Persistence:** Solves the "Amnesia Bug". SHADOW persists its memory to disk (`fix_status.json`). It calculates `Total Baseline Risk - Auto-Fixed Issues = Potential Future Risk`, giving admins a true picture of their attack surface reduction over time.
- 🛡️ **Atomic Transaction Safety:** Before modifying critical files (`/etc/sudoers`, `/etc/ssh/sshd_config`), SHADOW creates backups. It runs Pre-Validation, applies the fix, and runs Post-Validation. If SSH or Sudo breaks, it triggers an **Instant Auto-Rollback**.
- 🎨 **Sci-Fi Terminal UI:** A beautiful, silent, animated terminal HUD. No messy log vomiting or stuck progress bars—just clean, color-coded panels and visual risk bars `[▓▓░░░░░░░░]`.
- 📄 **Actionable Remediation:** Automatically generates `/var/log/shadow/manual_fixes.txt` with exact, copy-pasteable commands for issues requiring human intervention (like Kernel CPU vulnerability patches).
- 🔒 **Automated Brute-Force Protection:** Configures `PAM faillock` (deny=3, unlock_time=600) to automatically lock accounts after 3 failed login attempts.

---

## 🖥️ Visual Terminal Experience

When you run `sudo shadow --scan`, you get a clean, professional interface:

```text
        ╭──────────────────────────────────────────────────╮
        │       ◈  LINUX SYSTEM HARDENING TOOL  ◈        │
        │          Security Assessment Interface          │
        ╰──────────────────────────────────────────────────╯

  ◤ ASSESSMENT RESULTS ◢
  ═══════════════════════════════════════════════════════
   ✔ PASSED    :   15
   ✘ FAILED    :    3
   ⚠ WARNING   :    6
   ℹ ERROR     :    0
   ─────────────────────────
   Total Checks :   32    <-- (Dynamically filtered for your OS)
   Pass Rate    : 46.8%

  ◤ RISK ASSESSMENT ◢
  ═══════════════════════════════════════════════════════
   🛡  Risk Score : 24/100  [▓▓░░░░░░░░]  LOW
   Assessment   : System is secure. Minor issues found.

  ◤ HONEST RISK SUMMARY ◢
  ═══════════════════════════════════════════════════════
   Total Baseline Risk : 39/100 (MEDIUM)
   ✔ Fixed Automatically: 8 issues → 24/100 (LOW)
   ⚠ Manual Required   : 1 issue  → 12/100 (LOW)
   Improvement       : 27 points (69.2%)

   ⚠️  1 issues require manual intervention:
      ▸ kernel.kernel_check: 4 critical kernel issues found
      See: /var/log/shadow/manual_fixes.txt
```

---

## ⚙️ Algorithms & Methodologies

SHADOW utilizes industry-standard algorithms and Linux native tools to ensure comprehensive system hardening:

| Algorithm / Method | Purpose | Implementation / Tool |
| :--- | :--- | :--- |
| **PAM faillock** | 3-attempt login lockout | Prevents brute-force attacks (`pam_faillock.so`) |
| **SHA256 Hashing** | File integrity verification | Detects unauthorized binary/config changes |
| **Pattern Matching** | Malware & process detection | Identifies suspicious cron jobs and SUID bits |
| **Weighted Risk Scoring** | Security assessment | Prioritizes vulnerabilities (0-100 scale) |
| **Atomic Transactions** | Safe modification | Ensures 100% system recoverability via backups |
| **Sysctl Tuning** | Kernel hardening | Secures network parameters (IP forwarding, SYN cookies) |

---

## 📂 The 14 Security Categories (40+ Modules)

SHADOW's modular architecture allows for infinite scalability. It currently audits 14 critical domains:

| Category | Modules | What It Secures |
| :--- | :--- | :--- |
| **Authentication** | 4 | Passwords, PAM login lockout, sudoers, empty/inactive users |
| **Remote Access** | 3 | OpenSSH hardening, Telnet removal, RDP/VNC security |
| **Network** | 4 | UFW/iptables firewall, open ports, DNS spoofing, connections |
| **File Security** | 3 | Permissions (chmod), ownership (chown), sensitive file exposure |
| **Services** | 5 | Apache, Nginx, MySQL, Docker daemon, NFS exports |
| **Storage** | 3 | Disk usage thresholds, LVM snapshots, LUKS encryption |
| **Monitoring** | 3 | Rsyslog/Auditd logging, suspicious root processes, malware |
| **Updates** | 2 | APT package updates, dpkg integrity verification |
| **Kernel** | 3 | CPU vulnerabilities (Spectre/Meltdown), sysctl, kernel modules |
| **Processes** | 3 | Process auditing, hidden startup processes, resource hogs |
| **Audit** | 3 | Auditd rules, system event tracking, log retention |
| **Access Control** | 3 | SELinux/AppArmor status, dangerous Linux capabilities (`getcap`) |
| **Scheduled Tasks** | 3 | Malicious cron jobs, systemd timers, startup jobs |
| **Integrity** | 3 | AIDE/Tripwire file integrity, hash monitoring, change detection |

---

## 🚀 Quick Start & Commands

### Installation
```bash
# 1. Clone the repository
git clone https://github.com/kaithepallivijayvardhan08-spec/SHADOW-LINUX-HARDENING-TOOL.git
cd SHADOW-LINUX-HARDENING-TOOL

# 2. Run the installer (Sets up /opt/shadow, systemd, and dependencies)
sudo ./setup.sh

# 3. Enable automatic boot-time scanning (Type=oneshot)
sudo systemctl enable shadow
```

### CLI Usage
| Command | Description |
| :--- | :--- |
| `sudo shadow --scan` | Run a read-only security scan and generate reports |
| `sudo shadow --harden` | Interactively apply hardening fixes with confirmations |
| `sudo shadow --harden --force` | Force apply fixes without prompts (for automation) |
| `sudo shadow --harden --dry-run` | Preview what changes *would* be made without applying them |
| `sudo shadow --harden --safe-mode --force`| Apply safe fixes instantly, skipping dangerous ops (e.g., firewall) |
| `sudo shadow --interactive` | Open the TUI menu to harden specific categories |
| `sudo shadow --restore` | **Rollback** the system to the state before the last hardening |
| `sudo shadow --report` | Generate JSON, HTML, and PDF reports from the last scan |

---

## 🛠️ Developer Workflow & Quick Code Sync

If you modified the Python source code, added a new module, or pulled updates from GitHub, you **do not** need to run the full installer again. 

### ⚡ The One-Liner Sync Command
Simply copy and paste this single command into your terminal. It will instantly purge the Python cache, deploy your new code to `/opt/shadow/`, and restart the background service:

```bash
sudo find /opt/shadow -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null && sudo cp -r ~/SHADOW-LINUX-HARDENING-TOOL/shadow/* /opt/shadow/shadow/ && sudo systemctl restart shadow 2>/dev/null && echo -e "\n✅ \033[32mSHADOW Code Synced Successfully! Run 'sudo shadow --scan' to test.\033[0m\n"
```

### 🚀 Bonus: Make it a Permanent Shortcut
Run this command **once** in your terminal to add a permanent alias to your `.bashrc`:

```bash
echo 'alias shadow-sync="sudo find /opt/shadow -type d -name \"__pycache__\" -exec rm -rf {} + 2>/dev/null && sudo cp -r ~/SHADOW-LINUX-HARDENING-TOOL/shadow/* /opt/shadow/shadow/ && sudo systemctl restart shadow 2>/dev/null && echo -e \"\n✅ \033[32mSHADOW Synced!\033[0m\n\""' >> ~/.bashrc && source ~/.bashrc
```
Now, anytime you change your code in VS Code, just type `shadow-sync` and hit Enter!

---

## 🚑 Emergency Recovery Engine (`shadow-fix.sh`)

Even the most secure systems can encounter edge cases—like a broken `sudo` configuration, a stuck background transaction, or an OS forcing an automatic reboot. To handle catastrophic failures, SHADOW includes a built-in **Cyborg Repair System**.

Navigate to your repository folder and run:
```bash
cd ~/SHADOW-LINUX-HARDENING-TOOL
sudo ./shadow-fix.sh
```

| Option | Protocol Name | What It Fixes |
|:---|:---|:---|
| **1** | **PAM Recovery Engine** | Restores `/etc/pam.d/` files from automated backups if `sudo` breaks or login lockouts fail. |
| **2** | **Full System Repair** | Re-deploys fresh source code, purges the Python neural cache, resets stuck transactions, and runs a diagnostic scan. |
| **3** | **Reboot Neutralization** | Removes stuck `/var/run/reboot-required` flags and patches `Unattended Upgrades` to prevent auto-reboots. |

---

## 🏢 Enterprise Compliance & Safety

Shadow is designed to help systems achieve compliance with major security frameworks:
✅ **CIS Benchmarks** (Center for Internet Security)
✅ **NIST** (National Institute of Standards and Technology)
✅ **PCI-DSS** (Payment Card Industry Data Security Standard)
✅ **ISO 27001**, **GDPR** & **HIPAA** readiness

### 🛡️ Uncompromising Safety Features
* **Pre & Post Validation:** Tests `sshd -t` and `visudo -c` before and after modifications.
* **Automatic Backups:** Every modified file is timestamped and saved to `/var/backups/shadow/`.
* **One-Command Rollback:** `sudo shadow --restore` instantly reverts the system.
* **Dry-Run Mode:** Full simulation of fixes without touching the disk.

---

## 💻 Supported Environments

| Operating System | Versions | Status |
| :--- | :--- | :--- |
| **Kali Linux** | 2023+ | 🟢 Fully Tested (OS-Awareness Active) |
| **Ubuntu** | 20.04, 22.04, 24.04 LTS | 🟢 Fully Tested |
| **Debian** | 11, 12 | 🟢 Fully Tested |
| **RHEL / CentOS** | 8, 9 | 🟡 Supported |
| **Fedora** | 38, 39+ | 🟡 Supported |

---

## 🤝 A Note to Fellow Students & Contributors

If you are a student, a beginner in cybersecurity, or someone eagerly waiting to learn how enterprise Linux systems actually work under the hood—**welcome!** 

I built SHADOW during my internship because I wanted to bridge the gap between theoretical networking classes and real-world DevSecOps. I know how intimidating `/etc/pam.d`, `systemd` services, and Python architecture can be at first. 

If you want to add a new security module, fix a bug, or just study the code to learn how automated hardening works, please feel free to fork this repository. Don't be afraid to break things in your Virtual Machine—that's exactly how we learn! 

**How to contribute:**
1. Fork the repository.
2. Create a new module in `shadow/modules/`.
3. Test it using `sudo shadow --harden --dry-run`.
4. Submit a Pull Request. Let's build and secure together! 🚀

---

## 📊 Project Statistics & Architecture

| Metric | Details |
| :--- | :--- |
| **Total Source Files** | 89 |
| **Lines of Code** | 5,000+ (Production-ready Python & Bash) |
| **Security Checks** | 40+ across 14 categories |
| **Average Scan Time** | < 2 Minutes |
| **Architecture** | Modular, Object-Oriented, Transaction-Safe |

---

## 🔬 Independent Validation — Benchmarking Against Lynis

SHADOW's results are **not just self-reported**. Every hardening run was cross-checked with **Lynis 3.1.6** (CISOfy), the industry-standard Linux auditor, on the same Kali Linux machine (kernel `6.18.12+kali`). Anyone can reproduce this validation:

```bash
sudo shadow --scan            # baseline assessment
sudo shadow --harden --force  # automated remediation
sudo lynis audit system       # independent third-party audit
```

**Lynis post-hardening audit summary (real output):**

```text
Hardening index : 63
Tests performed : 273
Warnings        : 0  ("Great, no warnings")
Suggestions     : 54
```

### ✅ Hardened by SHADOW → independently confirmed by Lynis

| Area | SHADOW's Action | Lynis Verdict |
|:---|:---|:---|
| Host firewall | Enabled UFW, default-deny | `Checking host based firewall [ ACTIVE ]` |
| SSH root login | `PermitRootLogin no` | `OpenSSH option: PermitRootLogin [ OK ]` |
| Sudoers safety | Enforced `0440` permissions | `Permissions for: /etc/sudoers [ OK ]` |
| Password policy | Aging + complexity in `login.defs` | `User password aging (min/max) [ CONFIGURED ]` |
| Sticky bits | `/tmp` & `/var/tmp` verified | `[ OK ]` / `[ OK ]` |
| System logging | rsyslog enabled & running | `RSyslog status [ FOUND ]`, log daemon `[ OK ]` |
| Core dumps | setuid core dumps disabled | `[ DISABLED ]` |
| Kernel network stack | `ip_forward=0`, SYN cookies on | `forwarding [ OK ]`, `tcp_syncookies [ OK ]` |

### 🔧 Lynis *suggested* — SHADOW actually *fixed*

| Lynis Suggestion (ID) | SHADOW's Automated Remediation |
|:---|:---|
| Install fail2ban `[DEB-0880]` | PAM `faillock` (deny=3, unlock=600s) auto-configured |
| Enable auditd `[ACCT-9628]` | auditd auto-installed, enabled & verified running |
| Install a file-integrity tool `[FINT-4350]` | Built-in FIM: hash monitoring + change detection |
| Harden SSH `[SSH-7408]` | SSH hardening applied automatically (tries, forwarding, ciphers) |
| Tune sysctl values `[KRNL-6000]` | Kernel sysctl hardening module |
| Install malware scanner `[HRDN-7230]` | Malware/process scanning module |

### ⚖️ Honest Differences (Read This)

- **Lynis has deeper audit coverage (273 tests).** SHADOW does not try to out-audit Lynis — it solves the gap Lynis intentionally leaves open: **remediation**. Lynis advises; SHADOW detects, backs up, fixes, verifies, and rolls back safely.
- On the same machine where Lynis reported *"Great, no warnings"*, SHADOW's risk engine flagged **6 critical failures (79/100)** — missing lockout protection, weak sudo posture, absent audit logging — and reduced them to **0/100** in one verified pass. Audit-only tools see suggestions; a remediation engine sees risk.
- Some Lynis `[ OK ]` values are also Kali defaults. SHADOW's job is to **verify and maintain** them, and to correct them where they are weak.

---

## ❤️ A Personal Note From the Author

I am a student, and I will be honest: **this tool is not perfect, and I never claimed it is.** What I can claim is that every line of it was written to solve problems I personally hit while learning Linux security — breaking my own VMs, locking myself out of SSH, and realizing that *detecting* a problem and *safely fixing* it are two completely different engineering challenges.

I built SHADOW because I fell in love with how Linux actually works under the hood — PAM stacks, systemd units, kernel sysctls, atomic file transactions. I respect tools like Lynis deeply; they are my teachers, not my competitors. My hope is that one day a module I write could be good enough to be part of an ecosystem like that.

If you are a security professional reading this: **please break my tool.** Open an issue, critique the architecture, tell me what I got wrong. Every piece of harsh feedback is a lesson I cannot get from a textbook.

## 👤 About the Author & My Cybersecurity Journey

**KAITHEPALLI VIJAY VARDHAN**  
*B.Tech (4-1) | Lingaya's Institute of Management and Technology*  
*Project Context: Short-Term Internship in Cyber Defense and Security Analysis*

### 🚀 Why Cybersecurity?
My fascination with cybersecurity didn't start with hacking; it started with **architecture and automation**. As I progressed through my engineering journey at Lingaya's Institute of Management and Technology, I realized a fundamental truth about modern IT infrastructure: *Linux powers the world's servers, cloud platforms, and enterprise networks, yet human error in configuration remains the single largest vulnerability.*

During my short-term internship, I wanted to move beyond theoretical security concepts and manual bash scripting. I wanted to understand how enterprise-grade **DevSecOps** pipelines actually work. This led to the creation of **SHADOW**. 

Building SHADOW was not just about writing 5,000+ lines of Python code; it was about solving real-world sysadmin problems. I became deeply passionate about:
* **Atomic Transactions in Security:** Learning how to modify critical system files (`/etc/sudoers`, `/etc/ssh/sshd_config`) safely without locking out administrators.
* **OS-Aware Automation:** Understanding the deep architectural differences between Kali, Ubuntu, and RHEL, and writing dynamic logic that adapts to the environment.
* **Risk Mathematics:** Designing algorithms that don't just "flag" errors, but calculate an honest, mathematically sound risk score that tracks remediation progress over time.

### 🎯 Future Vision
This internship project solidified my career path. I am deeply interested in **Cloud Security, DevSecOps Automation, and Penetration Testing**. My goal is to bridge the gap between development and security, ensuring that systems are "secure by default" rather than "secured as an afterthought." 

> *"Security is not a product, but a process. It is about building systems that are resilient, recoverable, and intelligent."*

**Let's Connect:**
* 🐙 **GitHub:** [kaithepallivijayvardhan08-spec](https://github.com/kaithepallivijayvardhan08-spec)
* 📧 **Email:** kaithepallivijayvardhan08@gmail.com
* 📱 **Phone:** +91 93462 61527

---

## 📝 License

This project is protected under a **Custom Source-Available License with Attribution Requirements**. 
You are free to use, study, and modify this software for educational and internal business purposes. However, the Original Author's name must remain visible, and commercial redistribution requires adherence to the royalty terms outlined in the license.

Please see the [LICENSE](LICENSE) file for full legal details and the Security Disclaimer.

---

<p align="center">
  <b>Built with 🐧 and 🐍 for Linux security professionals.</b><br>
  <i>© 2026 KAITHEPALLI VIJAY VARDHAN | Shadow Framework</i><br>
  <i>Project submitted in partial fulfillment of the Short-Term Internship requirements at Lingayas Institute of Management and Technology.</i>
</p>


