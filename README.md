# NetRescue Ultimate 🛡️

![Platform](https://img.shields.io/badge/platform-Linux-linux)
![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen)

> **A professional, interactive system administration tool for diagnosing and repairing Linux networking issues.**

```text
   _  __     __  ___                           
  / |/ /__  / /_/ _ \___z___ ______ _____      
 /    / -_)/ __/ , _/ -_|_-</ __/ // / -_)     
/_/|_/\__/ \__/_/|_|\__/___/\__/\_,_/\__/ v2.6
  Linux Network Recovery & Diagnostic Tool
```

NetRescue is a Python-based CLI utility designed to save sysadmins and Linux users from network connectivity disasters. It offers a beautiful, menu-driven interface to diagnose issues, backup configurations, and perform repairs ranging from simple DNS fixes to complete network stack resets.

## 🚀 Features

* **🎨 Beautiful UI:** Colorful, interactive terminal interface with progress bars and spinners.
* **🔍 Advanced Diagnostics:** Scan interfaces (WiFi/Ethernet), IP configs, routing tables, DNS (including systemd-resolved), firewall status, and internet connectivity.
* **🛡️ Safety First:**

  * **Auto-Backups:** Automatically backs up config files and routing tables before applying repairs.
  * **Dry-Run Mode:** Test operations without making actual changes.
  * **Smart Warnings:** Suppresses false alarms if internet is working fine.
* **🔧 Repair Modes:**

  * **Standard:** Fixes DNS, restarts services, releases/renews DHCP.
  * **Deep:** Reloads kernel modules, flushes firewalls, resolves service conflicts.
  * **Reset:** A "nuclear option" to wipe and reset the network stack (with safeguards).
* **🎓 Guided Wizard:** Step-by-step troubleshooting assistant for beginners.
* **💾 Robust Backups:** Preserves full directory structure of configuration files for easy manual restoration.

## 📋 Requirements

* **OS:** Linux (Debian/Ubuntu, Arch, RHEL/CentOS/Fedora supported automatically)
* **Python:** Version 3.6+
* **Privileges:** Must run as root (`sudo`) to modify network interfaces and services
* **Dependencies:** Standard Python libraries only; no `pip install` required

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/ashardian/Net-rescue.git

# Navigate to the directory
cd Net-rescue

# Make the script executable (optional)
chmod +x netrescue.py
```

## 💻 Usage

NetRescue can be used in **Interactive Mode** (menu-driven) or **CLI Mode** (direct flags).

### 1. Interactive Menu (Recommended)

Launch the full TUI with menus:

```bash
sudo python3 netrescue.py
```

### 2. Guided Wizard

Best for beginners:

```bash
sudo python3 netrescue.py --wizard
```

### 3. Quick Diagnostics

Scan and print a report without making changes:

```bash
sudo python3 netrescue.py --diagnose
```

Optional: Save report to JSON:

```bash
sudo python3 netrescue.py --diagnose --output report.json
```

### 4. Advanced CLI Commands

```bash
# Standard Repair (Safe)
sudo python3 netrescue.py --repair

# Deep Repair (Reloads modules)
sudo python3 netrescue.py --deep-repair

# Dry Run (Simulate repair without changes)
sudo python3 netrescue.py --repair --dry-run
```

## 📂 Backup & Restore

NetRescue creates backups in `/var/backups/netrescue/`. Each backup folder contains:

* `configs/` : Mirror of `/etc/` network files
* `iptables.rules` : Firewall rule dump
* `metadata.json` : Timestamp and system info
* `restore.sh` : Auto-generated script to apply this backup

**Restore a backup:**

```bash
# Via NetRescue UI
Select "Backup Management"

# Or manually
sudo bash /var/backups/netrescue/backup_<TIMESTAMP>/restore.sh
```

## ⚠️ Disclaimer

This tool performs administrative actions such as restarting network services, flushing IP addresses, and modifying DNS configurations.

**Warning:** Always ensure physical or console access (VNC/IPMI) when performing a Deep Repair or Network Reset, as SSH connectivity may be temporarily lost.

The tool is provided "as is" without warranty.

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/NewFix`
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

<p align="center">Made with ❤️ by <a href="https://github.com/ashardian">ashardian</a></p>
