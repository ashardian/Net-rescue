#!/usr/bin/env python3
"""
NetRescue Ultimate - Linux Network Recovery & Diagnostic Tool
=============================================================

A professional, user-friendly system administration tool for diagnosing 
and repairing Linux networking issues with an impressive UI.

UPDATES IN THIS VERSION:
- Fixed false alarms in Service Status (Inactive services are now neutral)
- Suppressed "Multiple Managers" warning if Internet is working
- Full feature set preserved

REQUIREMENTS:
- Python 3.6+
- Root/sudo privileges
- Linux operating system

USAGE:
    sudo python3 netrescue.py              # Interactive mode
    sudo python3 netrescue.py --diagnose   # Direct command
    sudo python3 netrescue.py --wizard     # Guided wizard

WARNING: Use only on systems you own or are authorized to modify.
"""

import os
import sys
import subprocess
import argparse
import json
import shutil
import datetime
import socket
import time
import threading
import urllib.request
import platform
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
import logging


# ============================================================================
# ANSI COLOR CODES & STYLING
# ============================================================================

class Colors:
    """ANSI color codes for terminal output"""
    # Basic colors
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    
    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'
    BG_BLUE = '\033[104m'
    BG_MAGENTA = '\033[105m'
    BG_CYAN = '\033[106m'
    BG_WHITE = '\033[107m'


class Symbols:
    """Unicode symbols for pretty output"""
    CHECK = '✓'
    CROSS = '✗'
    NEUTRAL = '○'  # Used for inactive but non-critical services
    ARROW = '→'
    BULLET = '•'
    STAR = '★'
    WARN = '⚠'
    INFO = 'ℹ'
    GEAR = '⚙'
    ROCKET = '🚀'
    SHIELD = '🛡'
    WRENCH = '🔧'
    SEARCH = '🔍'
    BACKUP = '💾'
    NETWORK = '🌐'
    WIFI = '📶'
    SUCCESS = '✅'
    FAILURE = '❌'
    WARNING = '⚠️'
    HOURGLASS = '⏳'
    
    # Box drawing
    BOX_H = '─'
    BOX_V = '│'
    BOX_TL = '╭'
    BOX_TR = '╮'
    BOX_BL = '╰'
    BOX_BR = '╯'
    BOX_VR = '├'
    BOX_VL = '┤'


# ============================================================================
# UI COMPONENTS
# ============================================================================

class UI:
    """Beautiful terminal UI components"""
    
    @staticmethod
    def clear_screen():
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    @staticmethod
    def print_banner():
        """Print short and simple impressive banner"""
        banner = f"""
{Colors.CYAN}   _  __     __  ___                           
  / |/ /__  / /_/ _ \___z___ ______ _____      
 /    / -_)/ __/ , _/ -_|_-</ __/ // / -_)     
/_/|_/\__/ \__/_/|_|\__/___/\__/\_,_/\__/{Colors.RESET} {Colors.YELLOW}v2.6{Colors.RESET}
{Colors.DIM}  Linux Network Recovery & Diagnostic Tool{Colors.RESET}
"""
        print(banner)
    
    @staticmethod
    def print_box(title: str, content: List[str], color: str = Colors.CYAN, width: int = 70):
        """Print content in a box"""
        print(f"\n{color}{Symbols.BOX_TL}{Symbols.BOX_H * (width - 2)}{Symbols.BOX_TR}{Colors.RESET}")
        
        # Title
        if title:
            padding = (width - len(title) - 4) // 2
            print(f"{color}{Symbols.BOX_V}{Colors.RESET} {' ' * padding}{Colors.BOLD}{Colors.WHITE}{title}{Colors.RESET}{' ' * padding} {color}{Symbols.BOX_V}{Colors.RESET}")
            print(f"{color}{Symbols.BOX_VR}{Symbols.BOX_H * (width - 2)}{Symbols.BOX_VL}{Colors.RESET}")
        
        # Content
        for line in content:
            # Remove ANSI codes for length calculation
            clean_line = line
            for code in [Colors.RESET, Colors.BOLD, Colors.RED, Colors.GREEN, Colors.YELLOW, Colors.CYAN, Colors.WHITE, Colors.DIM, Colors.BLUE, Colors.MAGENTA]:
                clean_line = clean_line.replace(code, '')
            
            # Truncate if too long to prevent breaking layout
            if len(clean_line) > width - 4:
                 line = line[:width-7] + "..."
                 clean_line = clean_line[:width-7] + "..."

            padding = width - len(clean_line) - 4
            print(f"{color}{Symbols.BOX_V}{Colors.RESET} {line}{' ' * padding} {color}{Symbols.BOX_V}{Colors.RESET}")
        
        print(f"{color}{Symbols.BOX_BL}{Symbols.BOX_H * (width - 2)}{Symbols.BOX_BR}{Colors.RESET}")
    
    @staticmethod
    def print_menu(title: str, options: List[Tuple[str, str]], color: str = Colors.CYAN):
        """Print interactive menu"""
        print(f"\n{color}{Symbols.BOX_TL}{Symbols.BOX_H * 68}{Symbols.BOX_TR}{Colors.RESET}")
        
        # Title
        padding = (68 - len(title)) // 2
        print(f"{color}{Symbols.BOX_V}{Colors.RESET} {' ' * padding}{Colors.BOLD}{Colors.WHITE}{title}{Colors.RESET}{' ' * (68 - len(title) - padding)} {color}{Symbols.BOX_V}{Colors.RESET}")
        print(f"{color}{Symbols.BOX_VR}{Symbols.BOX_H * 68}{Symbols.BOX_VL}{Colors.RESET}")
        
        # Options
        for key, description in options:
            display = f"  {Colors.YELLOW}{Colors.BOLD}[{key}]{Colors.RESET} {Colors.WHITE}{description}{Colors.RESET}"
            clean = description
            padding = 68 - len(f"  [{key}] {clean}") - 2
            print(f"{color}{Symbols.BOX_V}{Colors.RESET}{display}{' ' * padding} {color}{Symbols.BOX_V}{Colors.RESET}")
        
        print(f"{color}{Symbols.BOX_BL}{Symbols.BOX_H * 68}{Symbols.BOX_BR}{Colors.RESET}")
    
    @staticmethod
    def print_status(message: str, status: str = "info"):
        """Print status message with icon"""
        icons = {
            "info": f"{Colors.CYAN}{Symbols.INFO}{Colors.RESET}",
            "success": f"{Colors.GREEN}{Symbols.CHECK}{Colors.RESET}",
            "error": f"{Colors.RED}{Symbols.CROSS}{Colors.RESET}",
            "warning": f"{Colors.YELLOW}{Symbols.WARN}{Colors.RESET}",
            "working": f"{Colors.CYAN}{Symbols.GEAR}{Colors.RESET}",
        }
        icon = icons.get(status, icons["info"])
        print(f"{icon}  {message}")
    
    @staticmethod
    def print_progress_bar(progress: float, width: int = 50, label: str = ""):
        """Print progress bar"""
        filled = int(width * progress)
        bar = '█' * filled + '░' * (width - filled)
        percentage = int(progress * 100)
        
        color = Colors.GREEN if progress == 1.0 else Colors.CYAN
        print(f"\r{label} {color}[{bar}]{Colors.RESET} {percentage}%", end='', flush=True)
        
        if progress >= 1.0:
            print()  # New line when complete
    
    @staticmethod
    def prompt_input(message: str, default: str = "") -> str:
        """Prompt for user input with styling"""
        prompt = f"{Colors.CYAN}{Symbols.ARROW}{Colors.RESET} {Colors.WHITE}{message}{Colors.RESET}"
        if default:
            prompt += f" {Colors.DIM}[{default}]{Colors.RESET}"
        prompt += f": "
        
        response = input(prompt).strip()
        return response if response else default
    
    @staticmethod
    def confirm(message: str, default: bool = False) -> bool:
        """Ask for confirmation"""
        default_str = "Y/n" if default else "y/N"
        response = UI.prompt_input(f"{message} ({default_str})", "y" if default else "n").lower()
        
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        return default


class Spinner:
    """Animated spinner for long operations"""
    
    def __init__(self, message: str = "Working..."):
        self.message = message
        self.running = False
        self.thread = None
        self.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.current_frame = 0
    
    def _spin(self):
        """Spinner animation loop"""
        while self.running:
            frame = self.frames[self.current_frame % len(self.frames)]
            print(f"\r{Colors.CYAN}{frame}{Colors.RESET} {self.message}", end='', flush=True)
            self.current_frame += 1
            time.sleep(0.1)
    
    def start(self):
        """Start spinner animation"""
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self, final_message: str = None, success: bool = True):
        """Stop spinner animation"""
        self.running = False
        if self.thread:
            self.thread.join()
        
        # Clear line
        print('\r' + ' ' * (len(self.message) + 10), end='')
        
        # Print final message
        if final_message:
            icon = f"{Colors.GREEN}{Symbols.CHECK}" if success else f"{Colors.RED}{Symbols.CROSS}"
            print(f"\r{icon}{Colors.RESET} {final_message}")
        else:
            print('\r', end='')


# ============================================================================
# CONFIGURATION
# ============================================================================

BACKUP_DIR = Path("/var/backups/netrescue")
LOG_DIR = Path("/var/log/netrescue")
CONFIG_FILES = [
    "/etc/network/interfaces",
    "/etc/netplan/*.yaml",
    "/etc/NetworkManager/NetworkManager.conf",
    "/etc/systemd/network/*.network",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/dhcp/dhclient.conf",
    "/etc/wpa_supplicant/wpa_supplicant.conf"
]


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class NetworkDiagnostics:
    """Container for network diagnostic results"""
    interfaces: Dict[str, Dict]
    ip_addresses: List[Dict]
    routes: List[Dict]
    dns_config: Dict
    firewall_status: Dict
    kernel_params: Dict
    services: Dict
    internet_status: Dict
    issues: List[str]
    warnings: List[str]
    timestamp: str


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def setup_logging(log_file: Optional[str] = None) -> logging.Logger:
    """Configure logging with file and console handlers"""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    if log_file is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = LOG_DIR / f"netrescue_{timestamp}.log"
    
    logger = logging.getLogger("netrescue")
    logger.setLevel(logging.DEBUG)
    
    # File handler - detailed
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    # Console handler - minimal (we use UI.print_status instead)
    ch = logging.StreamHandler()
    ch.setLevel(logging.ERROR)
    ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    return logger


def run_command(cmd: List[str], check: bool = False, capture: bool = True) -> Tuple[int, str, str]:
    """Execute a system command safely"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            check=check,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def check_root() -> bool:
    """Verify script is running with root privileges"""
    return os.geteuid() == 0


def detect_distro() -> str:
    """Detect Linux distribution family accurately"""
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                content = f.read()
                if "debian" in content or "ubuntu" in content: return "debian"
                if "arch" in content: return "arch"
                if "rhel" in content or "centos" in content or "fedora" in content: return "redhat"
    except Exception:
        pass
    
    # Fallback
    if Path("/etc/debian_version").exists(): return "debian"
    if Path("/etc/arch-release").exists(): return "arch"
    if Path("/etc/redhat-release").exists(): return "redhat"
    return "unknown"


# ============================================================================
# BACKUP AND RESTORE
# ============================================================================

class BackupManager:
    """Manages system state backups and restoration"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.backup_root = BACKUP_DIR
        self.current_backup: Optional[Path] = None
    
    def create_backup(self) -> Path:
        """Create a complete backup of current network configuration"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = self.backup_root / f"backup_{timestamp}"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        spinner = Spinner(f"Creating backup: {backup_dir.name}")
        spinner.start()
        
        try:
            # Backup configuration files with directory structure preservation
            config_backup = backup_dir / "configs"
            for pattern in CONFIG_FILES:
                parent_dir = Path(pattern).parent
                search_pattern = Path(pattern).name
                
                if parent_dir.exists():
                    for file_path in parent_dir.glob(search_pattern):
                        if file_path.is_file() and not file_path.is_symlink():
                            # Create mirror path inside backup
                            rel_path = str(file_path).lstrip('/')
                            dest = config_backup / rel_path
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            try:
                                shutil.copy2(file_path, dest)
                            except PermissionError:
                                pass
            
            # Backup routing table
            _, routes, _ = run_command(["ip", "route", "show"])
            (backup_dir / "routes.txt").write_text(routes)
            
            # Backup firewall rules
            _, iptables, _ = run_command(["iptables-save"])
            (backup_dir / "iptables.rules").write_text(iptables)
            
            _, nft, _ = run_command(["nft", "list", "ruleset"])
            (backup_dir / "nftables.rules").write_text(nft)
            
            # Backup network interfaces state
            _, interfaces, _ = run_command(["ip", "addr", "show"])
            (backup_dir / "interfaces.txt").write_text(interfaces)
            
            # Backup sysctl network parameters
            _, sysctl, _ = run_command(["sysctl", "-a"])
            sysctl_net = "\n".join([line for line in sysctl.split("\n") if "net." in line])
            (backup_dir / "sysctl_net.txt").write_text(sysctl_net)
            
            # Create restore script
            restore_script = backup_dir / "restore.sh"
            restore_script.write_text(self._generate_restore_script(backup_dir))
            restore_script.chmod(0o755)
            
            # Save metadata
            metadata = {
                "timestamp": timestamp,
                "hostname": socket.gethostname(),
                "distro": detect_distro(),
            }
            (backup_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
            
            self.current_backup = backup_dir
            spinner.stop(f"Backup created: {Colors.GREEN}{backup_dir}{Colors.RESET}", success=True)
            return backup_dir
            
        except Exception as e:
            spinner.stop(f"Backup failed: {e}", success=False)
            raise
    
    def _generate_restore_script(self, backup_dir: Path) -> str:
        """Generate a shell script for restoring from backup"""
        return f"""#!/bin/bash
# Auto-generated restore script
# Created: {datetime.datetime.now()}
# Backup location: {backup_dir}

set -e

echo "Restoring network configuration from {backup_dir}"

# Restore Config Files
if [ -d "{backup_dir}/configs" ]; then
    echo "Copying config files..."
    cp -rfv {backup_dir}/configs/* /
fi

# Restore iptables if present
if [ -f "{backup_dir}/iptables.rules" ]; then
    echo "Restoring iptables rules..."
    iptables-restore < {backup_dir}/iptables.rules
fi

echo "Restarting services..."
systemctl restart NetworkManager 2>/dev/null || true
systemctl restart systemd-networkd 2>/dev/null || true
service networking restart 2>/dev/null || true

echo "Restore complete. Please review and restart networking services."
"""
    
    def list_backups(self) -> List[Path]:
        """List all available backups"""
        if not self.backup_root.exists():
            return []
        return sorted(self.backup_root.glob("backup_*"), reverse=True)


# ============================================================================
# DIAGNOSTICS
# ============================================================================

class NetworkDiagnostic:
    """Comprehensive network diagnostics with progress tracking"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.issues = []
        self.warnings = []
    
    def run_full_diagnostic(self, show_progress: bool = True) -> NetworkDiagnostics:
        """Execute complete network diagnostic suite"""
        # Reset issues
        self.issues = []
        self.warnings = []

        checks = [
            ("Scanning network interfaces", self._check_interfaces),
            ("Checking IP addresses", self._check_ip_addresses),
            ("Analyzing routing table", self._check_routing),
            ("Verifying DNS configuration", self._check_dns),
            ("Inspecting firewall status", self._check_firewall),
            ("Reading kernel parameters", self._check_kernel_params),
            ("Testing Internet Connectivity", self._check_connectivity),
            ("Checking network services", self._check_services),
        ]
        
        results = {}
        total = len(checks)
        
        if show_progress:
            print(f"\n{Colors.CYAN}{Symbols.SEARCH}  Running Comprehensive Network Diagnostics{Colors.RESET}")
            print(f"{Colors.DIM}{Symbols.BOX_H * 70}{Colors.RESET}\n")
        
        for i, (description, check_func) in enumerate(checks, 1):
            if show_progress:
                spinner = Spinner(description)
                spinner.start()
                time.sleep(0.3)  # Brief delay for visual effect
            
            result = check_func()
            results[check_func.__name__.replace('_check_', '')] = result
            
            if show_progress:
                spinner.stop(f"{description} {Colors.GREEN}{Symbols.CHECK}{Colors.RESET}", success=True)
        
        diagnostics = NetworkDiagnostics(
            interfaces=results.get('interfaces', {}),
            ip_addresses=results.get('ip_addresses', []),
            routes=results.get('routing', []),
            dns_config=results.get('dns', {}),
            firewall_status=results.get('firewall', {}),
            kernel_params=results.get('kernel_params', {}),
            services=results.get('services', {}),
            internet_status=results.get('connectivity', {}),
            issues=self.issues,
            warnings=self.warnings,
            timestamp=datetime.datetime.now().isoformat()
        )
        
        self._analyze_diagnostics(diagnostics)
        return diagnostics
    
    def _check_interfaces(self) -> Dict[str, Dict]:
        """Check network interfaces status"""
        interfaces = {}
        
        returncode, output, _ = run_command(["ip", "-d", "link", "show"])
        if returncode != 0:
            self.issues.append("Failed to query network interfaces")
            return interfaces
        
        for line in output.split("\n"):
            if not line.strip():
                continue
            
            if not line.startswith(" "):
                parts = line.split(":")
                if len(parts) >= 2:
                    iface_name = parts[1].strip()
                    state = "UP" if "UP" in line else "DOWN"
                    is_wifi = "wlan" in iface_name or "wl" in iface_name
                    
                    interfaces[iface_name] = {
                        "name": iface_name,
                        "state": state,
                        "type": "wifi" if is_wifi else "ethernet",
                        "flags": line,
                    }
        
        active_interfaces = [k for k, v in interfaces.items() if v["state"] == "UP"]
        if not active_interfaces:
            self.issues.append("No active network interfaces found")
        
        return interfaces
    
    def _check_ip_addresses(self) -> List[Dict]:
        """Check IP address assignments"""
        addresses = []
        
        returncode, output, _ = run_command(["ip", "addr", "show"])
        if returncode != 0:
            self.issues.append("Failed to query IP addresses")
            return addresses
        
        current_iface = None
        for line in output.split("\n"):
            if not line.strip():
                continue
            
            if not line.startswith(" ") and ":" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    current_iface = parts[1].strip().split("@")[0]
            
            elif line.strip().startswith("inet"):
                parts = line.strip().split()
                if len(parts) >= 2 and current_iface:
                    addresses.append({
                        "interface": current_iface,
                        "address": parts[1],
                        "family": "ipv4" if line.strip().startswith("inet ") else "ipv6"
                    })
        
        has_loopback = any(
            a["interface"] == "lo" and a["address"].startswith("127.0.0.1") 
            for a in addresses
        )
        if not has_loopback:
            self.issues.append("Loopback interface not configured")
        
        return addresses
    
    def _check_routing(self) -> List[Dict]:
        """Check routing table"""
        routes = []
        
        returncode, output, _ = run_command(["ip", "route", "show"])
        if returncode != 0:
            self.issues.append("Failed to query routing table")
            return routes
        
        for line in output.split("\n"):
            if line.strip():
                routes.append({"route": line.strip()})
        
        has_default = any("default" in r["route"] for r in routes)
        if not has_default:
            self.warnings.append("No default route configured")
        
        return routes
    
    def _check_dns(self) -> Dict:
        """Check DNS configuration including systemd-resolved"""
        dns_config = {
            "mode": "standard",
            "nameservers": [],
            "search_domains": []
        }
        
        # Check systemd-resolved
        ret, _, _ = run_command(["systemctl", "is-active", "systemd-resolved"])
        if ret == 0:
            dns_config["mode"] = "systemd-resolved"
            ret, output, _ = run_command(["resolvectl", "status"])
            if ret == 0:
                for line in output.split('\n'):
                    if "DNS Servers:" in line:
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            dns_config["nameservers"].append(parts[1].strip())
        
        # Check /etc/resolv.conf
        resolv_conf = Path("/etc/resolv.conf")
        if resolv_conf.exists():
            content = resolv_conf.read_text()
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("nameserver"):
                    ns = line.split()[1] if len(line.split()) > 1 else None
                    if ns and ns not in dns_config["nameservers"]:
                        dns_config["nameservers"].append(ns)
        else:
            self.warnings.append("/etc/resolv.conf not found")
        
        if not dns_config["nameservers"]:
            self.issues.append("No DNS nameservers configured")
        
        return dns_config
    
    def _check_firewall(self) -> Dict:
        """Check firewall status"""
        firewall = {
            "iptables_active": False,
            "nftables_active": False,
            "ufw_status": None,
            "firewalld_status": None
        }
        
        returncode, output, _ = run_command(["iptables", "-L", "-n"])
        if returncode == 0 and output.strip():
            firewall["iptables_active"] = True
        
        returncode, output, _ = run_command(["nft", "list", "ruleset"])
        if returncode == 0 and output.strip():
            firewall["nftables_active"] = True
        
        returncode, output, _ = run_command(["ufw", "status"])
        if returncode == 0:
            firewall["ufw_status"] = output.strip()
        
        returncode, output, _ = run_command(["firewall-cmd", "--state"])
        if returncode == 0:
            firewall["firewalld_status"] = output.strip()
        
        return firewall
    
    def _check_kernel_params(self) -> Dict:
        """Check kernel networking parameters"""
        params = {}
        
        critical_params = [
            "net.ipv4.ip_forward",
            "net.ipv4.conf.all.rp_filter",
            "net.ipv6.conf.all.disable_ipv6",
        ]
        
        for param in critical_params:
            returncode, output, _ = run_command(["sysctl", param])
            if returncode == 0:
                value = output.strip().split("=")[1].strip() if "=" in output else None
                params[param] = value
        
        return params

    def _check_connectivity(self) -> Dict:
        """Check WAN and Internet connectivity"""
        status = {"wan_ping": False, "dns_resolv": False, "public_ip": None}
        
        # 1. Ping 8.8.8.8
        ret, _, _ = run_command(["ping", "-c", "1", "-W", "2", "8.8.8.8"])
        status["wan_ping"] = (ret == 0)
        
        if not status["wan_ping"]:
            self.issues.append("Cannot ping external IP (8.8.8.8)")
        
        # 2. Resolve Domain
        try:
            socket.gethostbyname("google.com")
            status["dns_resolv"] = True
        except:
            self.warnings.append("DNS resolution failed for google.com")
        
        # 3. Get Public IP
        if status["wan_ping"]:
            try:
                with urllib.request.urlopen("https://api.ipify.org", timeout=2) as response:
                    status["public_ip"] = response.read().decode('utf-8')
            except:
                status["public_ip"] = "Unknown"
        
        return status
    
    def _check_services(self) -> Dict:
        """Check network-related service status"""
        services = {}
        
        service_list = [
            "NetworkManager",
            "systemd-networkd",
            "systemd-resolved",
            "networking",
            "wpa_supplicant"
        ]
        
        for service in service_list:
            returncode, output, _ = run_command(["systemctl", "is-active", service])
            services[service] = output.strip()
        
        return services
    
    def _analyze_diagnostics(self, diagnostics: NetworkDiagnostics):
        """Analyze diagnostic results for common problems"""
        active_network_managers = [
            s for s, status in diagnostics.services.items()
            if status == "active" and s in ["NetworkManager", "systemd-networkd"]
        ]
        
        # INTELLIGENT WARNING:
        # Only warn about multiple managers if Internet is NOT working.
        # If internet works, assume the configuration is intentional/valid.
        if len(active_network_managers) > 1:
            if not diagnostics.internet_status.get('wan_ping', False):
                self.warnings.append(
                    f"Multiple network managers active: {', '.join(active_network_managers)}"
                )
    
    def print_report(self, diagnostics: NetworkDiagnostics):
        """Print beautiful diagnostic report"""
        print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.WHITE}  📊 NETWORK DIAGNOSTIC REPORT{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}\n")
        
        # System info
        info_lines = [
            f"{Colors.CYAN}Timestamp:{Colors.RESET} {diagnostics.timestamp}",
            f"{Colors.CYAN}Hostname:{Colors.RESET} {socket.gethostname()}",
            f"{Colors.CYAN}Distribution:{Colors.RESET} {detect_distro().title()}",
        ]
        UI.print_box("System Information", info_lines, Colors.CYAN, 70)
        
        # Interfaces
        iface_lines = []
        for name, info in diagnostics.interfaces.items():
            status_color = Colors.GREEN if info['state'] == 'UP' else Colors.RED
            status_icon = Symbols.CHECK if info['state'] == 'UP' else Symbols.CROSS
            type_icon = Symbols.WIFI if info.get('type') == 'wifi' else Symbols.NETWORK
            iface_lines.append(f"{status_color}{status_icon}{Colors.RESET} {type_icon} {Colors.WHITE}{name}{Colors.RESET}: {status_color}{info['state']}{Colors.RESET}")
        UI.print_box("Network Interfaces", iface_lines, Colors.BLUE, 70)
        
        # IP Addresses
        addr_lines = []
        for addr in diagnostics.ip_addresses[:10]:
            family_icon = "🌐" if addr['family'] == 'ipv4' else "🌍"
            addr_lines.append(f"{family_icon} {Colors.CYAN}{addr['interface']}{Colors.RESET}: {Colors.WHITE}{addr['address']}{Colors.RESET}")
        if len(diagnostics.ip_addresses) > 10:
            addr_lines.append(f"{Colors.DIM}... and {len(diagnostics.ip_addresses) - 10} more{Colors.RESET}")
        UI.print_box("IP Addresses", addr_lines, Colors.MAGENTA, 70)
        
        # Connectivity
        conn = diagnostics.internet_status
        conn_lines = [
            f"WAN Ping (8.8.8.8): {Colors.GREEN if conn['wan_ping'] else Colors.RED}{'OK' if conn['wan_ping'] else 'FAIL'}{Colors.RESET}",
            f"DNS Resolution:     {Colors.GREEN if conn['dns_resolv'] else Colors.RED}{'OK' if conn['dns_resolv'] else 'FAIL'}{Colors.RESET}",
            f"Public IP:          {Colors.YELLOW}{conn['public_ip'] or 'N/A'}{Colors.RESET}"
        ]
        UI.print_box("Internet Connectivity", conn_lines, Colors.GREEN, 70)
        
        # DNS
        dns_lines = []
        for ns in diagnostics.dns_config["nameservers"]:
            dns_lines.append(f"{Colors.GREEN}{Symbols.CHECK}{Colors.RESET} Nameserver: {Colors.WHITE}{ns}{Colors.RESET}")
        if not dns_lines:
            dns_lines.append(f"{Colors.RED}{Symbols.CROSS}{Colors.RESET} {Colors.RED}No nameservers configured{Colors.RESET}")
        UI.print_box("DNS Configuration", dns_lines, Colors.GREEN, 70)
        
        # Services (SMART DISPLAY)
        service_lines = []
        for service, status in diagnostics.services.items():
            if status == "active":
                status_color = Colors.GREEN
                status_icon = Symbols.CHECK
            else:
                # Use dim/neutral for inactive services instead of RED CROSS
                # This prevents false alarm anxiety
                status_color = Colors.DIM
                status_icon = Symbols.NEUTRAL
            
            service_lines.append(f"{status_color}{status_icon}{Colors.RESET} {Colors.WHITE}{service}{Colors.RESET}: {status_color}{status}{Colors.RESET}")
        UI.print_box("Network Services", service_lines, Colors.CYAN, 70)
        
        # Issues & Warnings
        if diagnostics.issues or diagnostics.warnings:
            issue_lines = []
            for issue in diagnostics.issues:
                issue_lines.append(f"{Colors.RED}{Symbols.FAILURE}{Colors.RESET} {Colors.RED}{issue}{Colors.RESET}")
            for warning in diagnostics.warnings:
                issue_lines.append(f"{Colors.YELLOW}{Symbols.WARNING}{Colors.RESET} {Colors.YELLOW}{warning}{Colors.RESET}")
            UI.print_box("Issues & Warnings", issue_lines, Colors.RED, 70)
        else:
            success_lines = [f"{Colors.GREEN}{Symbols.SUCCESS} No critical issues detected!{Colors.RESET}"]
            UI.print_box("Status", success_lines, Colors.GREEN, 70)
        
        print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}\n")


# ============================================================================
# REPAIR ENGINE
# ============================================================================

class NetworkRepair:
    """Network repair and restoration engine with progress tracking"""
    
    def __init__(self, logger: logging.Logger, dry_run: bool = False):
        self.logger = logger
        self.dry_run = dry_run
        self.distro = detect_distro()
    
    def repair_standard(self, diagnostics: NetworkDiagnostics) -> bool:
        """Perform standard repair operations based on diagnostics"""
        print(f"\n{Colors.YELLOW}{Symbols.WRENCH}  Starting Standard Repair{Colors.RESET}")
        print(f"{Colors.DIM}{Symbols.BOX_H * 70}{Colors.RESET}\n")
        
        repairs = []
        
        # Check what needs repair
        active_managers = [
            s for s, status in diagnostics.services.items()
            if status == "active" and s in ["NetworkManager", "systemd-networkd"]
        ]
        
        # Only attempt to fix manager conflict if internet is actually broken
        if len(active_managers) > 1 and not diagnostics.internet_status['wan_ping']:
            repairs.append(("Fixing network manager conflicts", self._fix_network_manager_conflict))
        
        if not diagnostics.dns_config["nameservers"] or not diagnostics.internet_status['dns_resolv']:
            repairs.append(("Repairing DNS configuration", self._repair_dns))
        
        down_interfaces = [
            name for name, info in diagnostics.interfaces.items()
            if info["state"] == "DOWN" and name != "lo"
        ]
        if down_interfaces or not diagnostics.ip_addresses:
            repairs.append(("Restarting network services", self._restart_network_services))
            repairs.append(("Renewing DHCP leases", self._renew_dhcp))
        
        if not repairs:
            UI.print_status("No repairs needed - system looks good!", "success")
            return True
        
        # Perform repairs
        success = True
        for description, repair_func in repairs:
            if self.dry_run:
                UI.print_status(f"[DRY-RUN] Would execute: {description}", "warning")
                continue

            spinner = Spinner(description)
            spinner.start()
            time.sleep(0.5)
            
            try:
                result = repair_func()
                success &= result
                spinner.stop(f"{description} {'✓' if result else '✗'}", success=result)
            except Exception as e:
                spinner.stop(f"{description} Failed: {e}", success=False)
                success = False
        
        return success
    
    def repair_deep(self, diagnostics: NetworkDiagnostics) -> bool:
        """Perform deep repair including module reloading"""
        print(f"\n{Colors.RED}{Symbols.WRENCH}  Starting Deep Repair{Colors.RESET}")
        print(f"{Colors.DIM}{Symbols.BOX_H * 70}{Colors.RESET}\n")
        
        success = self.repair_standard(diagnostics)
        
        if self.dry_run:
            UI.print_status("[DRY-RUN] Would reset network services and reload modules", "warning")
            return True

        # Additional deep repairs
        spinner = Spinner("Resetting network services to defaults")
        spinner.start()
        time.sleep(0.5)
        success &= self._reset_network_services()
        spinner.stop("Network services reset", success=True)
        
        # Reload modules
        spinner = Spinner("Reloading kernel modules")
        spinner.start()
        self._reload_modules()
        spinner.stop("Kernel modules reloaded", success=True)
        
        return success
    
    def reset_network(self, force: bool = False) -> bool:
        """Complete network reset - DESTRUCTIVE OPERATION"""
        if not force:
            print(f"\n{Colors.RED}{'!' * 70}{Colors.RESET}")
            UI.print_box(
                "⚠️  DESTRUCTIVE OPERATION WARNING ⚠️",
                [
                    f"{Colors.RED}This will completely reset network configuration.{Colors.RESET}",
                    f"{Colors.YELLOW}You may lose connectivity immediately.{Colors.RESET}",
                    f"{Colors.YELLOW}A backup will be created automatically.{Colors.RESET}",
                    f"{Colors.RED}Continue only if you have physical/console access.{Colors.RESET}",
                ],
                Colors.RED,
                70
            )
            
            confirm = UI.prompt_input(f"{Colors.RED}Type 'RESET' to confirm{Colors.RESET}", "")
            
            if confirm != "RESET":
                UI.print_status("Reset cancelled by user", "info")
                return False
        
        print(f"\n{Colors.RED}{Symbols.ROCKET}  Performing Complete Network Reset{Colors.RESET}")
        print(f"{Colors.DIM}{Symbols.BOX_H * 70}{Colors.RESET}\n")
        
        if self.dry_run:
            UI.print_status("[DRY RUN] Would perform network reset", "warning")
            return True
        
        steps = [
            ("Stopping network services", self._stop_network_services),
            ("Flushing IP addresses", self._flush_ip_addresses),
            ("Clearing routing table", self._flush_routes),
            ("Resetting firewall rules", self._reset_firewall),
            ("Applying minimal configuration", self._apply_minimal_config),
            ("Starting network services", self._start_network_services),
        ]
        
        for i, (description, step_func) in enumerate(steps, 1):
            UI.print_progress_bar(i / len(steps), label=description)
            time.sleep(0.3)
            
            try:
                step_func()
            except Exception as e:
                UI.print_status(f"Step failed: {e}", "error")
                return False
        
        UI.print_progress_bar(1.0, label="Network reset complete")
        print()
        UI.print_status("Network has been reset successfully!", "success")
        return True
    
    # Helper methods
    def _fix_network_manager_conflict(self) -> bool:
        run_command(["systemctl", "stop", "systemd-networkd"])
        run_command(["systemctl", "disable", "systemd-networkd"])
        run_command(["systemctl", "enable", "NetworkManager"])
        run_command(["systemctl", "restart", "NetworkManager"])
        return True
    
    def _repair_dns(self) -> bool:
        # Smart DNS repair
        ret, _, _ = run_command(["systemctl", "is-active", "systemd-resolved"])
        if ret == 0:
            # Try to set via resolvectl for the first active link
            ret, links, _ = run_command(["ip", "-o", "link", "show", "up"])
            if ret == 0:
                for line in links.split('\n'):
                    if ": lo" not in line and ": " in line:
                        iface = line.split(":")[1].strip()
                        run_command(["resolvectl", "dns", iface, "8.8.8.8", "1.1.1.1"])
                        break
        else:
            # Traditional repair
            resolv_conf = Path("/etc/resolv.conf")
            if resolv_conf.exists():
                shutil.copy2(resolv_conf, resolv_conf.with_suffix(".conf.bak"))
            dns_content = "# Generated by netrescue\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n"
            resolv_conf.write_text(dns_content)
        return True
    
    def _restart_network_services(self) -> bool:
        services = ["NetworkManager", "systemd-networkd", "networking"]
        for service in services:
            returncode, _, _ = run_command(["systemctl", "restart", service])
            if returncode == 0:
                return True
        return False

    def _renew_dhcp(self) -> bool:
        run_command(["dhclient", "-r"])
        run_command(["dhclient", "-v"])
        return True
    
    def _reset_network_services(self) -> bool:
        run_command(["systemctl", "stop", "NetworkManager"])
        run_command(["systemctl", "stop", "systemd-networkd"])
        run_command(["systemctl", "disable", "systemd-networkd"])
        
        if self.distro == "debian":
            run_command(["systemctl", "enable", "NetworkManager"])
            run_command(["systemctl", "start", "NetworkManager"])
        return True

    def _reload_modules(self):
        drivers = ["e1000e", "r8169", "iwlwifi", "ath9k"]
        for drv in drivers:
            ret, _, _ = run_command(["lsmod"])
            if ret == 0 and drv in _:
                run_command(["modprobe", "-r", drv])
                time.sleep(1)
                run_command(["modprobe", drv])
    
    def _stop_network_services(self):
        services = ["NetworkManager", "systemd-networkd", "networking"]
        for service in services:
            run_command(["systemctl", "stop", service])
    
    def _start_network_services(self):
        run_command(["systemctl", "stop", "systemd-networkd"])
        run_command(["systemctl", "disable", "systemd-networkd"])
        if self.distro == "debian":
            run_command(["systemctl", "enable", "NetworkManager"])
            run_command(["systemctl", "start", "NetworkManager"])
    
    def _flush_ip_addresses(self):
        returncode, output, _ = run_command(["ip", "link", "show"])
        for line in output.split("\n"):
            if ":" in line and not line.strip().startswith(" "):
                iface = line.split(":")[1].strip().split("@")[0]
                if iface != "lo":
                    run_command(["ip", "addr", "flush", "dev", iface])
    
    def _flush_routes(self):
        run_command(["ip", "route", "flush", "table", "main"])
    
    def _reset_firewall(self):
        run_command(["iptables", "-F"])
        run_command(["iptables", "-X"])
        run_command(["iptables", "-P", "INPUT", "ACCEPT"])
        run_command(["iptables", "-P", "FORWARD", "ACCEPT"])
        run_command(["iptables", "-P", "OUTPUT", "ACCEPT"])
        run_command(["nft", "flush", "ruleset"])
    
    def _apply_minimal_config(self):
        run_command(["ip", "link", "set", "lo", "up"])
        run_command(["ip", "addr", "add", "127.0.0.1/8", "dev", "lo"])


# ============================================================================
# INTERACTIVE MENU SYSTEM
# ============================================================================

class InteractiveMenu:
    """Interactive menu-driven interface"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.backup_mgr = BackupManager(logger)
        self.diagnostic = NetworkDiagnostic(logger)
        self.repair = NetworkRepair(logger, dry_run=False)
        self.running = True
    
    def show_main_menu(self):
        """Display main menu"""
        while self.running:
            UI.clear_screen()
            UI.print_banner()
            
            # System status quick check
            distro = detect_distro()
            hostname = socket.gethostname()
            print(f"  {Colors.DIM}System: {hostname} | Distribution: {distro.title()}{Colors.RESET}\n")
            
            UI.print_menu(
                "Main Menu",
                [
                    ("1", "🔍 Run Network Diagnostics"),
                    ("2", "🔧 Standard Repair"),
                    ("3", "⚡ Deep Repair"),
                    ("4", "🚀 Complete Network Reset"),
                    ("5", "💾 Backup Management"),
                    ("6", "🎓 Guided Wizard"),
                    ("7", "📚 Help & Documentation"),
                    ("0", "Exit"),
                ],
                Colors.CYAN
            )
            
            choice = UI.prompt_input("Select an option", "1")
            
            if choice == "1":
                self.run_diagnostics()
            elif choice == "2":
                self.run_standard_repair()
            elif choice == "3":
                self.run_deep_repair()
            elif choice == "4":
                self.run_network_reset()
            elif choice == "5":
                self.backup_menu()
            elif choice == "6":
                self.guided_wizard()
            elif choice == "7":
                self.show_help()
            elif choice == "0":
                self.exit_program()
            else:
                UI.print_status("Invalid option", "error")
                time.sleep(1)
    
    def run_diagnostics(self):
        """Run diagnostic scan"""
        UI.clear_screen()
        UI.print_banner()
        
        diagnostics = self.diagnostic.run_full_diagnostic(show_progress=True)
        self.diagnostic.print_report(diagnostics)
        
        # Save option
        if UI.confirm("Save diagnostic report to file?", default=False):
            filename = UI.prompt_input("Filename", "/tmp/network_diagnostic.json")
            Path(filename).write_text(json.dumps(asdict(diagnostics), indent=2))
            UI.print_status(f"Report saved to {filename}", "success")
        
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
    
    def run_standard_repair(self):
        """Run standard repair"""
        UI.clear_screen()
        UI.print_banner()
        
        if not UI.confirm("Create backup before repair?", default=True):
            if not UI.confirm("Are you sure? Backup is strongly recommended!", default=False):
                return
        else:
            self.backup_mgr.create_backup()
        
        diagnostics = self.diagnostic.run_full_diagnostic(show_progress=False)
        success = self.repair.repair_standard(diagnostics)
        
        if success:
            UI.print_status("\n✅ Repair completed successfully!", "success")
        else:
            UI.print_status("\n❌ Some repairs failed. Check logs for details.", "error")
        
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
    
    def run_deep_repair(self):
        """Run deep repair"""
        UI.clear_screen()
        UI.print_banner()
        
        UI.print_box(
            "Deep Repair Information",
            [
                "Deep repair will:",
                "• Perform all standard repairs",
                "• Reset network service configurations",
                "• Resolve service conflicts",
                "• Reload kernel modules",
                "",
                f"{Colors.YELLOW}Recommended for persistent issues{Colors.RESET}",
            ],
            Colors.YELLOW,
            70
        )
        
        if not UI.confirm("\nProceed with deep repair?", default=False):
            return
        
        self.backup_mgr.create_backup()
        diagnostics = self.diagnostic.run_full_diagnostic(show_progress=False)
        success = self.repair.repair_deep(diagnostics)
        
        if success:
            UI.print_status("\n✅ Deep repair completed successfully!", "success")
        else:
            UI.print_status("\n❌ Some repairs failed. Check logs for details.", "error")
        
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
    
    def run_network_reset(self):
        """Run complete network reset"""
        UI.clear_screen()
        UI.print_banner()
        
        UI.print_box(
            "⚠️  COMPLETE NETWORK RESET ⚠️",
            [
                f"{Colors.RED}This is a DESTRUCTIVE operation!{Colors.RESET}",
                "",
                "This will:",
                "• Stop all network services",
                "• Clear all IP addresses (except loopback)",
                "• Flush routing table",
                "• Reset firewall to default",
                "• Restore minimal working configuration",
                "",
                f"{Colors.YELLOW}You may lose connectivity immediately!{Colors.RESET}",
                f"{Colors.YELLOW}Use only if you have physical/console access.{Colors.RESET}",
            ],
            Colors.RED,
            70
        )
        
        if not UI.confirm("\nDo you understand the risks?", default=False):
            return
        
        self.backup_mgr.create_backup()
        success = self.repair.reset_network(force=False)
        
        if success:
            UI.print_status("\n✅ Network reset completed!", "success")
            UI.print_status("Please verify connectivity before closing this session.", "warning")
        else:
            UI.print_status("\n❌ Reset failed. System may be in an inconsistent state.", "error")
            UI.print_status("Consider restoring from backup.", "warning")
        
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
    
    def backup_menu(self):
        """Backup management submenu"""
        while True:
            UI.clear_screen()
            UI.print_banner()
            
            UI.print_menu(
                "Backup Management",
                [
                    ("1", "List All Backups"),
                    ("2", "Create New Backup"),
                    ("3", "Restore from Backup"),
                    ("0", "Back to Main Menu"),
                ],
                Colors.GREEN
            )
            
            choice = UI.prompt_input("Select an option", "0")
            
            if choice == "1":
                self.list_backups()
            elif choice == "2":
                self.create_backup()
            elif choice == "3":
                self.restore_backup()
            elif choice == "0":
                break
    
    def list_backups(self):
        """List available backups"""
        UI.clear_screen()
        backups = self.backup_mgr.list_backups()
        
        if not backups:
            UI.print_status("No backups found", "warning")
        else:
            backup_lines = []
            for i, backup in enumerate(backups, 1):
                metadata_file = backup / "metadata.json"
                if metadata_file.exists():
                    metadata = json.loads(metadata_file.read_text())
                    backup_lines.append(f"{Colors.CYAN}[{i}]{Colors.RESET} {Colors.WHITE}{backup.name}{Colors.RESET}")
                    backup_lines.append(f"    Timestamp: {metadata['timestamp']}")
                    backup_lines.append(f"    Hostname: {metadata['hostname']}")
                    backup_lines.append("")
            
            UI.print_box("Available Backups", backup_lines, Colors.GREEN, 70)
        
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
    
    def create_backup(self):
        """Create a new backup"""
        UI.clear_screen()
        backup = self.backup_mgr.create_backup()
        UI.print_status(f"Backup created: {backup}", "success")
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
    
    def restore_backup(self):
        """Restore from backup"""
        backups = self.backup_mgr.list_backups()
        
        if not backups:
            UI.print_status("No backups available", "warning")
            time.sleep(2)
            return
        
        print("\nAvailable backups:")
        for i, backup in enumerate(backups, 1):
            print(f"  {Colors.CYAN}[{i}]{Colors.RESET} {backup.name}")
        
        choice = UI.prompt_input("\nSelect backup number (0 to cancel)", "0")
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(backups):
                if UI.confirm(f"Restore from {backups[idx].name}?", default=False):
                    UI.print_status("Restore functionality requires manual intervention", "warning")
                    UI.print_status(f"Run: sudo bash {backups[idx]}/restore.sh", "info")
        except ValueError:
            pass
        
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
    
    def guided_wizard(self):
        """Guided troubleshooting wizard"""
        UI.clear_screen()
        UI.print_banner()
        
        print(f"\n{Colors.CYAN}{Symbols.STAR}  Network Troubleshooting Wizard{Colors.RESET}")
        print(f"{Colors.DIM}{Symbols.BOX_H * 70}{Colors.RESET}\n")
        
        # Question 1
        UI.print_status("Let's diagnose your network issue step by step...", "info")
        print()
        
        q1 = UI.prompt_input("Can you ping 8.8.8.8? (y/n)", "n").lower()
        
        if q1 == 'n':
            UI.print_status("No internet connectivity detected", "warning")
            q2 = UI.prompt_input("Can you ping your router/gateway? (y/n)", "n").lower()
            
            if q2 == 'n':
                UI.print_status("Local network issue detected", "error")
                print(f"\n{Colors.YELLOW}Recommendation:{Colors.RESET} Standard Repair")
                if UI.confirm("Run standard repair now?", default=True):
                    self.run_standard_repair()
            else:
                UI.print_status("DNS or routing issue detected", "warning")
                print(f"\n{Colors.YELLOW}Recommendation:{Colors.RESET} Check DNS and routing")
                if UI.confirm("Run diagnostics?", default=True):
                    self.run_diagnostics()
        else:
            q3 = UI.prompt_input("Can you resolve domain names (e.g., google.com)? (y/n)", "y").lower()
            
            if q3 == 'n':
                UI.print_status("DNS issue detected", "warning")
                print(f"\n{Colors.YELLOW}Recommendation:{Colors.RESET} Repair DNS configuration")
                if UI.confirm("Fix DNS now?", default=True):
                    self.repair._repair_dns()
                    UI.print_status("DNS repaired!", "success")
            else:
                UI.print_status("Network appears to be working!", "success")
                print(f"\n{Colors.GREEN}Your network seems healthy.{Colors.RESET}")
        
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
    
    def show_help(self):
        """Show help documentation"""
        UI.clear_screen()
        UI.print_banner()
        
        help_lines = [
            f"{Colors.BOLD}Network Diagnostics{Colors.RESET}",
            "Scans your entire network configuration and identifies issues.",
            "Safe to run anytime - makes no changes to your system.",
            "",
            f"{Colors.BOLD}Standard Repair{Colors.RESET}",
            "Fixes common issues like DNS problems, service conflicts,",
            "and restarting crashed network services.",
            "",
            f"{Colors.BOLD}Deep Repair{Colors.RESET}",
            "More aggressive repairs including service resets and",
            "configuration cleanups. Use when standard repair doesn't work.",
            "",
            f"{Colors.BOLD}Complete Network Reset{Colors.RESET}",
            f"{Colors.RED}DESTRUCTIVE!{Colors.RESET} Completely resets networking to minimal state.",
            "Use only as last resort with physical console access.",
            "",
            f"{Colors.BOLD}Backup Management{Colors.RESET}",
            "All destructive operations create automatic backups.",
            "You can list, create, or restore backups manually.",
            "",
            f"{Colors.BOLD}Guided Wizard{Colors.RESET}",
            "Step-by-step troubleshooting for beginners.",
            "Asks questions to identify and fix your specific issue.",
        ]
        
        UI.print_box("Help & Documentation", help_lines, Colors.BLUE, 70)
        
        print(f"\n{Colors.CYAN}Pro Tips:{Colors.RESET}")
        print(f"  • Always create backups before making changes")
        print(f"  • Use --dry-run flag in CLI mode to test operations")
        print(f"  • Logs are saved to {LOG_DIR}")
        print(f"  • Backups are stored in {BACKUP_DIR}")
        
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
    
    def exit_program(self):
        """Exit the program"""
        UI.clear_screen()
        print(f"\n{Colors.GREEN}Thank you for using NetRescue!{Colors.RESET}")
        print(f"{Colors.DIM}Stay connected! 🌐{Colors.RESET}\n")
        self.running = False


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class NetRescue:
    """Main application controller"""
    
    def __init__(self, args):
        self.args = args
        self.logger = setup_logging(args.log)
        self.backup_mgr = BackupManager(self.logger)
        self.diagnostic = NetworkDiagnostic(self.logger)
        self.repair = NetworkRepair(self.logger, args.dry_run)
    
    def run(self) -> int:
        """Main execution flow"""
        try:
            # Root check
            if not check_root():
                print(f"\n{Colors.RED}{Symbols.CROSS} This tool requires root privileges{Colors.RESET}")
                print(f"{Colors.YELLOW}Please run with: sudo python3 netrescue.py{Colors.RESET}\n")
                return 1
            
            # Interactive mode (default)
            if not any([
                self.args.diagnose, self.args.repair, self.args.deep_repair,
                self.args.reset_network, self.args.list_backups, self.args.wizard
            ]):
                menu = InteractiveMenu(self.logger)
                menu.show_main_menu()
                return 0
            
            # CLI mode
            UI.print_banner()
            
            distro = detect_distro()
            if distro == "unknown":
                UI.print_status("Unknown distribution - some features may not work", "warning")
            else:
                UI.print_status(f"Detected distribution: {distro.title()}", "info")
            
            print()
            
            # Execute requested operation
            if self.args.diagnose:
                return self._run_diagnostic()
            elif self.args.repair:
                return self._run_repair()
            elif self.args.deep_repair:
                return self._run_deep_repair()
            elif self.args.reset_network:
                return self._run_reset()
            elif self.args.list_backups:
                return self._list_backups()
            elif self.args.wizard:
                menu = InteractiveMenu(self.logger)
                menu.guided_wizard()
                return 0
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}Operation cancelled by user{Colors.RESET}\n")
            return 130
        
        except Exception as e:
            print(f"\n{Colors.RED}{Symbols.CROSS} Unexpected error: {e}{Colors.RESET}\n")
            self.logger.exception(f"Unexpected error: {e}")
            return 1
    
    def _run_diagnostic(self) -> int:
        """Run diagnostic mode"""
        diagnostics = self.diagnostic.run_full_diagnostic(show_progress=True)
        self.diagnostic.print_report(diagnostics)
        
        if self.args.output:
            output_file = Path(self.args.output)
            output_file.write_text(json.dumps(asdict(diagnostics), indent=2))
            UI.print_status(f"Diagnostics saved to {output_file}", "success")
        
        return 0
    
    def _run_repair(self) -> int:
        """Run standard repair mode"""
        if not self.args.dry_run:
            backup = self.backup_mgr.create_backup()
            print()
        
        diagnostics = self.diagnostic.run_full_diagnostic(show_progress=False)
        success = self.repair.repair_standard(diagnostics)
        
        if success:
            print(f"\n{Colors.GREEN}{Symbols.SUCCESS} Repair completed successfully!{Colors.RESET}\n")
            return 0
        else:
            print(f"\n{Colors.RED}{Symbols.FAILURE} Repair encountered errors{Colors.RESET}\n")
            return 1
    
    def _run_deep_repair(self) -> int:
        """Run deep repair mode"""
        if not self.args.dry_run:
            backup = self.backup_mgr.create_backup()
            print()
        
        diagnostics = self.diagnostic.run_full_diagnostic(show_progress=False)
        success = self.repair.repair_deep(diagnostics)
        
        if success:
            print(f"\n{Colors.GREEN}{Symbols.SUCCESS} Deep repair completed successfully!{Colors.RESET}\n")
            return 0
        else:
            print(f"\n{Colors.RED}{Symbols.FAILURE} Deep repair encountered errors{Colors.RESET}\n")
            return 1
    
    def _run_reset(self) -> int:
        """Run network reset mode"""
        if not self.args.dry_run:
            backup = self.backup_mgr.create_backup()
            print()
        
        success = self.repair.reset_network(force=self.args.force)
        
        if success:
            print(f"\n{Colors.GREEN}{Symbols.SUCCESS} Network reset completed{Colors.RESET}\n")
            return 0
        else:
            print(f"\n{Colors.RED}{Symbols.FAILURE} Network reset failed{Colors.RESET}\n")
            return 1
    
    def _list_backups(self) -> int:
        """List available backups"""
        backups = self.backup_mgr.list_backups()
        
        if not backups:
            UI.print_status("No backups found", "warning")
            return 0
        
        backup_lines = []
        for i, backup in enumerate(backups, 1):
            metadata_file = backup / "metadata.json"
            if metadata_file.exists():
                metadata = json.loads(metadata_file.read_text())
                backup_lines.append(f"{Colors.CYAN}[{i}]{Colors.RESET} {Colors.WHITE}{backup.name}{Colors.RESET}")
                backup_lines.append(f"    Timestamp: {metadata['timestamp']}")
                backup_lines.append(f"    Hostname: {metadata['hostname']}")
                backup_lines.append("")
        
        UI.print_box("Available Backups", backup_lines, Colors.GREEN, 70)
        return 0


def main():
    """Entry point"""
    parser = argparse.ArgumentParser(
        description="NetRescue - Interactive Linux Network Recovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo netrescue.py                    # Interactive menu (recommended)
  sudo netrescue.py --wizard           # Guided troubleshooting
  sudo netrescue.py --diagnose         # Quick diagnostic scan
  sudo netrescue.py --repair           # Standard repair
  sudo netrescue.py --deep-repair      # Deep repair
  sudo netrescue.py --reset-network    # Complete reset
  sudo netrescue.py --list-backups     # List backups

Safety Features:
  • Automatic backups before modifications
  • Dry-run mode for testing
  • Explicit confirmation for destructive operations
  • Comprehensive logging
        """
    )
    
    # Operation modes
    parser.add_argument("--diagnose", action="store_true",
                       help="Run diagnostic scan only")
    parser.add_argument("--repair", action="store_true",
                       help="Perform standard repair operations")
    parser.add_argument("--deep-repair", action="store_true",
                       help="Perform deep repair (includes module reload)")
    parser.add_argument("--reset-network", action="store_true",
                       help="Complete network reset (DESTRUCTIVE)")
    parser.add_argument("--wizard", action="store_true",
                       help="Launch guided troubleshooting wizard")
    
    # Backup/restore
    parser.add_argument("--list-backups", action="store_true",
                       help="List available backups")
    
    # Options
    parser.add_argument("--dry-run", action="store_true",
                       help="Simulate operations without making changes")
    parser.add_argument("--force", action="store_true",
                       help="Skip confirmation prompts")
    parser.add_argument("--log", metavar="FILE",
                       help="Custom log file path")
    parser.add_argument("--output", metavar="FILE",
                       help="Save diagnostic output to file")
    
    args = parser.parse_args()
    
    # Validate arguments
    operation_count = sum([
        args.diagnose,
        args.repair,
        args.deep_repair,
        args.reset_network,
        args.list_backups,
        args.wizard,
    ])
    
    if operation_count > 1:
        print(f"{Colors.RED}ERROR: Please specify only one operation{Colors.RESET}")
        return 1
    
    # Run application
    app = NetRescue(args)
    return app.run()


if __name__ == "__main__":
    sys.exit(main())
