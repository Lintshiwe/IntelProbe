#!/usr/bin/env python3
"""
IntelProbe Enhanced Network Scanner
Military-grade network reconnaissance with exploitation intelligence

Author: Lintshiwe Slade (@lintshiwe)
Enhanced from netspionage framework with AI-powered capabilities
"""

import socket
import threading
import subprocess
import time
import ipaddress
import platform
import json
import logging
from typing import List, Dict, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict

@dataclass
class ExploitSuggestion:
    """Exploitation suggestion for discovered services"""
    service: str
    port: int
    vulnerability: str
    exploit_tools: List[str]
    description: str
    severity: str
    references: List[str]

@dataclass
class NetworkDevice:
    """Enhanced network device information"""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None
    open_ports: List[int] = None
    services: Dict[int, str] = None
    vulnerabilities: List[str] = None
    exploits: List[ExploitSuggestion] = None
    response_time: float = 0.0
    last_seen: str = None
    risk_score: int = 0
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.exploits is None:
            self.exploits = []

class EnhancedNetworkScanner:
    """
    Enhanced network scanner with exploitation intelligence
    """
    
    def __init__(self):
        self.logger = self._setup_logger()
        self.exploit_database = self._load_exploit_database()
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017
        ]
        self.critical_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 9090: "HTTP-Admin", 27017: "MongoDB"
        }
    
    def _setup_logger(self):
        """Setup logging for network scanning"""
        logger = logging.getLogger("enhanced_scanner")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _load_exploit_database(self) -> Dict[str, List[ExploitSuggestion]]:
        """Load exploitation suggestions database"""
        return {
            "SSH": [
                ExploitSuggestion(
                    service="SSH",
                    port=22,
                    vulnerability="Weak credentials / Default passwords",
                    exploit_tools=["hydra", "medusa", "ncrack", "patator"],
                    description="Brute force SSH credentials using common passwords",
                    severity="HIGH",
                    references=["CVE-2021-28041", "https://attack.mitre.org/techniques/T1110/"]
                ),
                ExploitSuggestion(
                    service="SSH",
                    port=22,
                    vulnerability="SSH key exploitation",
                    exploit_tools=["ssh-audit", "ssh-keyscan", "paramiko"],
                    description="Exploit weak SSH key configurations or stolen keys",
                    severity="CRITICAL",
                    references=["https://attack.mitre.org/techniques/T1552/004/"]
                )
            ],
            "HTTP": [
                ExploitSuggestion(
                    service="HTTP",
                    port=80,
                    vulnerability="Web application vulnerabilities",
                    exploit_tools=["nikto", "dirb", "gobuster", "sqlmap", "burp"],
                    description="Scan for OWASP Top 10 vulnerabilities, SQL injection, XSS",
                    severity="HIGH",
                    references=["https://owasp.org/www-project-top-ten/"]
                ),
                ExploitSuggestion(
                    service="HTTP",
                    port=80,
                    vulnerability="Directory traversal / LFI",
                    exploit_tools=["dotdotpwn", "fimap", "kadimus"],
                    description="Exploit local file inclusion and directory traversal",
                    severity="MEDIUM",
                    references=["CWE-22", "CWE-98"]
                )
            ],
            "HTTPS": [
                ExploitSuggestion(
                    service="HTTPS",
                    port=443,
                    vulnerability="SSL/TLS vulnerabilities",
                    exploit_tools=["sslscan", "testssl.sh", "sslyze"],
                    description="Test for SSL/TLS misconfigurations and vulnerabilities",
                    severity="HIGH",
                    references=["CVE-2014-0224", "CVE-2014-3566"]
                )
            ],
            "FTP": [
                ExploitSuggestion(
                    service="FTP",
                    port=21,
                    vulnerability="Anonymous FTP access",
                    exploit_tools=["ftp", "curl", "wget"],
                    description="Check for anonymous FTP access and sensitive files",
                    severity="MEDIUM",
                    references=["CWE-200"]
                ),
                ExploitSuggestion(
                    service="FTP",
                    port=21,
                    vulnerability="FTP bounce attack",
                    exploit_tools=["nmap", "ftpbounce"],
                    description="Exploit FTP bounce to scan internal networks",
                    severity="MEDIUM",
                    references=["RFC 2577"]
                )
            ],
            "SMB": [
                ExploitSuggestion(
                    service="SMB",
                    port=445,
                    vulnerability="EternalBlue (MS17-010)",
                    exploit_tools=["metasploit", "exploit-db", "AutoBlue-MS17-010"],
                    description="Exploit SMB vulnerability for remote code execution",
                    severity="CRITICAL",
                    references=["CVE-2017-0144", "MS17-010"]
                ),
                ExploitSuggestion(
                    service="SMB",
                    port=445,
                    vulnerability="SMB null session",
                    exploit_tools=["enum4linux", "smbclient", "rpcclient"],
                    description="Enumerate shares and users via null session",
                    severity="MEDIUM",
                    references=["CWE-287"]
                )
            ],
            "RDP": [
                ExploitSuggestion(
                    service="RDP",
                    port=3389,
                    vulnerability="BlueKeep (CVE-2019-0708)",
                    exploit_tools=["metasploit", "bluekeep-scanner", "rdp-sec-check"],
                    description="Remote code execution via RDP vulnerability",
                    severity="CRITICAL",
                    references=["CVE-2019-0708"]
                ),
                ExploitSuggestion(
                    service="RDP",
                    port=3389,
                    vulnerability="RDP brute force",
                    exploit_tools=["hydra", "crowbar", "rdesktop"],
                    description="Brute force RDP credentials",
                    severity="HIGH",
                    references=["https://attack.mitre.org/techniques/T1110/"]
                )
            ],
            "Telnet": [
                ExploitSuggestion(
                    service="Telnet",
                    port=23,
                    vulnerability="Unencrypted authentication",
                    exploit_tools=["telnet", "medusa", "hydra"],
                    description="Intercept credentials or brute force login",
                    severity="HIGH",
                    references=["CWE-319"]
                )
            ],
            "VNC": [
                ExploitSuggestion(
                    service="VNC",
                    port=5900,
                    vulnerability="Weak VNC authentication",
                    exploit_tools=["vnccrack", "medusa", "patator"],
                    description="Brute force VNC password or exploit weak authentication",
                    severity="HIGH",
                    references=["CWE-287"]
                )
            ]
        }
    
    def discover_network_interfaces(self) -> List[Dict[str, str]]:
        """Discover available network interfaces and their subnets"""
        interfaces = []
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                output = result.stdout
                
                current_interface = None
                for line in output.split('\n'):
                    line = line.strip()
                    if "adapter" in line and ":" in line:
                        current_interface = line.split("adapter")[1].split(":")[0].strip()
                    elif "IPv4 Address" in line and current_interface:
                        ip = line.split(":")[1].strip()
                        if ip and not ip.startswith("169.254"):  # Skip APIPA
                            interfaces.append({
                                "interface": current_interface,
                                "ip": ip,
                                "network": self._calculate_network(ip)
                            })
            else:
                # Linux/macOS
                result = subprocess.run(["ip", "route"], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if "src" in line and "/" in line:
                        parts = line.split()
                        network = parts[0]
                        src_ip = parts[parts.index("src") + 1]
                        interfaces.append({
                            "interface": "auto-detected",
                            "ip": src_ip,
                            "network": network
                        })
        except Exception as e:
            self.logger.error(f"Failed to discover interfaces: {e}")
        
        return interfaces
    
    def _calculate_network(self, ip: str, mask: str = "255.255.255.0") -> str:
        """Calculate network address from IP and mask"""
        try:
            # Assume /24 for simplicity
            octets = ip.split('.')
            return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        except:
            return f"{ip}/32"
    
    def scan_host(self, target_ip: str, ports: List[int] = None) -> Optional[NetworkDevice]:
        """Enhanced host scanning with exploitation intelligence"""
        if ports is None:
            ports = self.common_ports
        
        self.logger.info(f"Scanning host: {target_ip}")
        
        # Check if host is alive
        if not self._ping_host(target_ip):
            return None
        
        device = NetworkDevice(ip=target_ip)
        device.last_seen = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Hostname resolution
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
            device.hostname = hostname
        except:
            pass
        
        # Port scanning
        open_ports = []
        services = {}
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {
                executor.submit(self._scan_port, target_ip, port): port
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        service = self.critical_services.get(port, "unknown")
                        services[port] = service
                        self.logger.info(f"Open port: {target_ip}:{port} ({service})")
                except Exception as e:
                    self.logger.debug(f"Port scan error {target_ip}:{port}: {e}")
        
        device.open_ports = sorted(open_ports)
        device.services = services
        
        # OS Detection
        device.os_type = self._detect_os(target_ip, open_ports)
        
        # Generate exploitation suggestions
        device.exploits = self._generate_exploits(services)
        
        # Calculate risk score
        device.risk_score = self._calculate_risk_score(device)
        
        return device
    
    def scan_network_range(self, network: str, max_hosts: int = 254) -> List[NetworkDevice]:
        """Scan entire network range with enhanced capabilities"""
        self.logger.info(f"Starting enhanced network scan: {network}")
        
        # Parse network
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            self.logger.error(f"Invalid network format: {network}")
            return []
        
        # Collect target IPs
        targets = []
        for ip in net.hosts():
            targets.append(str(ip))
            if len(targets) >= max_hosts:
                break
        
        # Also scan network and broadcast addresses (common for routers)
        targets.insert(0, str(net.network_address))
        try:
            router_ip = str(ipaddress.ip_address(int(net.broadcast_address) - 1))
            if router_ip not in targets:
                targets.append(router_ip)
        except:
            pass
        
        self.logger.info(f"Scanning {len(targets)} potential hosts")
        
        # Parallel host scanning
        devices = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {
                executor.submit(self.scan_host, target): target
                for target in targets
            }
            
            for future in as_completed(future_to_ip):
                target = future_to_ip[future]
                try:
                    device = future.result()
                    if device and device.open_ports:
                        devices.append(device)
                        self.logger.info(f"Active device found: {device.ip} ({len(device.open_ports)} ports)")
                except Exception as e:
                    self.logger.debug(f"Host scan error for {target}: {e}")
        
        return sorted(devices, key=lambda d: ipaddress.ip_address(d.ip))
    
    def _ping_host(self, target_ip: str) -> bool:
        """Enhanced host discovery using multiple methods"""
        # Method 1: ICMP ping
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "1000", target_ip],
                    capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    return True
            else:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", target_ip],
                    capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    return True
        except:
            pass
        
        # Method 2: TCP connect to common ports
        for port in [80, 443, 22, 21, 23]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                pass
        
        return False
    
    def _scan_port(self, target_ip: str, port: int) -> bool:
        """Scan individual port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _detect_os(self, target_ip: str, open_ports: List[int]) -> str:
        """Enhanced OS detection based on open ports and behavior"""
        os_indicators = []
        
        # Windows indicators
        if 135 in open_ports or 139 in open_ports or 445 in open_ports:
            os_indicators.append("Windows")
        if 3389 in open_ports:
            os_indicators.append("Windows (RDP)")
        
        # Linux indicators
        if 22 in open_ports:
            os_indicators.append("Linux/Unix")
        
        # Network devices
        if 23 in open_ports and 80 in open_ports:
            os_indicators.append("Network Device")
        
        # Web servers
        if 80 in open_ports or 443 in open_ports:
            os_indicators.append("Web Server")
        
        return ", ".join(os_indicators) if os_indicators else "Unknown"
    
    def _generate_exploits(self, services: Dict[int, str]) -> List[ExploitSuggestion]:
        """Generate exploitation suggestions based on discovered services"""
        exploits = []
        
        for port, service in services.items():
            service_upper = service.upper()
            if service_upper in self.exploit_database:
                exploits.extend(self.exploit_database[service_upper])
            
            # Add custom exploits based on specific ports
            if port == 445:  # SMB
                exploits.extend(self.exploit_database.get("SMB", []))
            elif port in [80, 8080]:  # HTTP
                exploits.extend(self.exploit_database.get("HTTP", []))
            elif port in [443, 8443]:  # HTTPS
                exploits.extend(self.exploit_database.get("HTTPS", []))
        
        return exploits
    
    def _calculate_risk_score(self, device: NetworkDevice) -> int:
        """Calculate risk score based on discovered vulnerabilities"""
        score = 0
        
        # Base score for being accessible
        score += 10
        
        # Port-based scoring
        high_risk_ports = [21, 23, 135, 139, 445, 3389, 5900]
        for port in device.open_ports:
            if port in high_risk_ports:
                score += 25
            else:
                score += 5
        
        # Service-based scoring
        for exploit in device.exploits:
            if exploit.severity == "CRITICAL":
                score += 40
            elif exploit.severity == "HIGH":
                score += 25
            elif exploit.severity == "MEDIUM":
                score += 15
        
        return min(score, 100)  # Cap at 100
    
    def generate_detailed_report(self, devices: List[NetworkDevice]) -> Dict[str, Any]:
        """Generate comprehensive network security report"""
        total_devices = len(devices)
        total_ports = sum(len(d.open_ports) for d in devices)
        total_exploits = sum(len(d.exploits) for d in devices)
        
        high_risk_devices = [d for d in devices if d.risk_score >= 70]
        medium_risk_devices = [d for d in devices if 40 <= d.risk_score < 70]
        low_risk_devices = [d for d in devices if d.risk_score < 40]
        
        report = {
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_devices": total_devices,
                "total_open_ports": total_ports,
                "total_potential_exploits": total_exploits,
                "high_risk_devices": len(high_risk_devices),
                "medium_risk_devices": len(medium_risk_devices),
                "low_risk_devices": len(low_risk_devices)
            },
            "devices": [asdict(device) for device in devices],
            "top_vulnerabilities": self._get_top_vulnerabilities(devices),
            "recommended_actions": self._get_recommendations(devices)
        }
        
        return report
    
    def _get_top_vulnerabilities(self, devices: List[NetworkDevice]) -> List[Dict[str, Any]]:
        """Get most common vulnerabilities across the network"""
        vuln_count = {}
        
        for device in devices:
            for exploit in device.exploits:
                vuln = exploit.vulnerability
                if vuln not in vuln_count:
                    vuln_count[vuln] = {
                        "count": 0,
                        "severity": exploit.severity,
                        "affected_devices": []
                    }
                vuln_count[vuln]["count"] += 1
                vuln_count[vuln]["affected_devices"].append(device.ip)
        
        # Sort by count and severity
        sorted_vulns = sorted(
            vuln_count.items(),
            key=lambda x: (x[1]["count"], {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(x[1]["severity"], 0)),
            reverse=True
        )
        
        return [
            {
                "vulnerability": vuln,
                "count": data["count"],
                "severity": data["severity"],
                "affected_devices": data["affected_devices"]
            }
            for vuln, data in sorted_vulns[:10]
        ]
    
    def _get_recommendations(self, devices: List[NetworkDevice]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check for critical services
        smb_devices = [d for d in devices if 445 in d.open_ports]
        if smb_devices:
            recommendations.append(f"🚨 {len(smb_devices)} devices with SMB exposed - Update to latest patches (MS17-010)")
        
        rdp_devices = [d for d in devices if 3389 in d.open_ports]
        if rdp_devices:
            recommendations.append(f"⚠️  {len(rdp_devices)} devices with RDP exposed - Enable NLA and strong passwords")
        
        telnet_devices = [d for d in devices if 23 in d.open_ports]
        if telnet_devices:
            recommendations.append(f"🔴 {len(telnet_devices)} devices with Telnet - Replace with SSH immediately")
        
        ftp_devices = [d for d in devices if 21 in d.open_ports]
        if ftp_devices:
            recommendations.append(f"⚠️  {len(ftp_devices)} devices with FTP - Use SFTP/FTPS instead")
        
        web_devices = [d for d in devices if 80 in d.open_ports and 443 not in d.open_ports]
        if web_devices:
            recommendations.append(f"🔒 {len(web_devices)} devices with HTTP only - Implement HTTPS")
        
        return recommendations
