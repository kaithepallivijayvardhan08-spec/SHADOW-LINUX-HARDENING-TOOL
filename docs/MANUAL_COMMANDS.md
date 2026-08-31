# 🛡️ SHADOW Manual Commands Sheet

Some security issues cannot be safely fixed automatically because they require system reboots, complete OS reinstallations, or interactive user choices. 

Use this guide to manually fix the remaining issues based on your Linux distribution.

---

## 🐧 1. For Kali Linux / Ubuntu / Debian (APT)

### 🔄 Kernel & System Updates (Requires Reboot)
Shadow cannot automatically reboot your machine. Run these commands to update your kernel and apply critical security patches.
```bash
sudo apt update
sudo apt upgrade -y
sudo apt dist-upgrade -y
sudo apt autoremove -y
sudo reboot
```

### 🛡️ Enable Automatic Security Updates
Keep your system patched automatically in the background.
```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
# Select "Yes" when prompted
```

### 🔍 Install File Integrity Monitoring (AIDE)
Shadow checks for AIDE but doesn't install it automatically to avoid heavy background CPU usage on low-end VMs.
```bash
sudo apt install aide aide-common -y
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### 🛑 Enforce AppArmor
Ensure AppArmor is running in enforce mode, not just complain mode.
```bash
sudo apt install apparmor apparmor-profiles apparmor-utils -y
sudo systemctl enable apparmor
sudo systemctl start apparmor
sudo aa-enforce /etc/apparmor.d/*
```

---

## 🎩 2. For RHEL / CentOS / Fedora / AlmaLinux (DNF/YUM)

### 🔄 Kernel & System Updates (Requires Reboot)
```bash
sudo dnf update -y
sudo dnf upgrade -y
sudo reboot
```

### 🛡️ Enable Automatic Security Updates
```bash
sudo dnf install dnf-automatic -y
sudo sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
sudo systemctl enable --now dnf-automatic.timer
```

### 🔍 Install File Integrity Monitoring (AIDE)
```bash
sudo dnf install aide -y
sudo aide --init
sudo cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

### 🛑 Enforce SELinux
Ensure SELinux is set to Enforcing, not Permissive or Disabled.
```bash
sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
sudo setenforce 1
```

---

## 🐉 3. For Arch Linux / Manjaro (Pacman)

### 🔄 System Updates
```bash
sudo pacman -Syu
sudo reboot
```

---

## 🔒 4. Advanced Security (All Distributions)

### 💽 Full Disk Encryption (LUKS)
**Warning:** This requires a complete OS reinstallation. You cannot easily encrypt an existing root partition.
When installing Linux, choose **"Erase disk and use LVM with LUKS encryption"** or **"Guided - use entire disk and set up encrypted LVM"**.

### 🧬 BIOS / UEFI Password
Shadow cannot access your motherboard firmware. 
1. Reboot your computer and enter the BIOS/UEFI setup (usually `F2`, `F12`, or `Del`).
2. Navigate to the **Security** tab.
3. Set an **Administrator / Supervisor Password**.
4. Enable **Secure Boot**.

### 🗑️ Disable Unused Filesystems
Prevent attackers from mounting obscure filesystems. Add these lines to `/etc/modprobe.d/blacklist-shadow.conf`:
```bash
sudo bash -c 'echo "install cramfs /bin/true" >> /etc/modprobe.d/blacklist-shadow.conf'
sudo bash -c 'echo "install freevxfs /bin/true" >> /etc/modprobe.d/blacklist-shadow.conf'
sudo bash -c 'echo "install jffs2 /bin/true" >> /etc/modprobe.d/blacklist-shadow.conf'
sudo bash -c 'echo "install hfs /bin/true" >> /etc/modprobe.d/blacklist-shadow.conf'
sudo bash -c 'echo "install hfsplus /bin/true" >> /etc/modprobe.d/blacklist-shadow.conf'
sudo bash -c 'echo "install squashfs /bin/true" >> /etc/modprobe.d/blacklist-shadow.conf'
sudo bash -c 'echo "install udf /bin/true" >> /etc/modprobe.d/blacklist-shadow.conf'
```

---

## 📝 How to use this with Shadow?
After you manually apply these fixes and reboot your system, simply run:
```bash
sudo shadow --scan
```
Shadow will detect that the kernel is updated, AppArmor/SELinux is enforcing, and your Honest Risk Score will drop to **LOW (0-25)**!
```