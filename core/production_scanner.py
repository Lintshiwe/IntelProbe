#!/usr/bin/env python3
"""
IntelProbe Production Scanner
Military-grade network reconnaissance and security assessment
Created by: Lintshiwe Slade
"""

import socket
import threading
import subprocess
import time
import ipaddress
import struct
import select
import sys
import os
import platform
from typing import List, Dict, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json
import logging

@dataclass
class ScanTarget:
    """Network scan target"""
    ip: str
    hostname: Optional[str] = None
    ports: List[int] = None
    os: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    services: Dict[int, str] = None
    vulnerabilities: List[str] = None
    response_time: float = 0.0
    
    def __post_init__(self):
        if self.ports is None:
            self.ports = []
        if self.services is None:
            self.services = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []

class ProductionScanner:
    """
    Military-grade network scanner with stealth capabilities
    """
    
    def __init__(self, config=None):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.alive_hosts = []
        self.scan_results = {}
        
        # Stealth options
        self.stealth_mode = True
        self.randomize_ports = True
        self.spoof_source = False
        
        # Performance settings
        self.max_threads = 100
        self.socket_timeout = 3
        self.scan_delay = 0.1
        
        # Common service ports for military/corporate environments
        self.critical_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            443, 993, 995, 1723, 3389, 5900, 8080, 8443, 9100
        ]
        
        # Extended port ranges for comprehensive scanning
        self.common_ports = list(range(1, 1024)) + [
            1433, 1521, 2049, 2082, 2083, 2086, 2087, 3306, 3389,
            5432, 5900, 6379, 8080, 8443, 8888, 9100, 10000, 27017
        ]

    def ping_host(self, target: str) -> Tuple[bool, float]:
        """
        Advanced host discovery using multiple methods
        """
        start_time = time.time()
        
        # Method 1: TCP SYN to common ports (stealth)
        if self._tcp_ping(target):
            return True, time.time() - start_time
        
        # Method 2: ICMP ping (if allowed)
        if self._icmp_ping(target):
            return True, time.time() - start_time
        
        # Method 3: UDP ping to DNS
        if self._udp_ping(target):
            return True, time.time() - start_time
        
        # Method 4: ARP ping for local network
        if self._arp_ping(target):
            return True, time.time() - start_time
        
        return False, time.time() - start_time

    def _tcp_ping(self, target: str, ports: List[int] = None) -> bool:
        """TCP SYN ping to detect hosts"""
        if ports is None:
            ports = [80, 443, 22, 21, 23]
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    return True
            except:
                continue
        return False

    def _icmp_ping(self, target: str) -> bool:
        """ICMP ping with platform-specific implementation"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "1000", target],
                    capture_output=True,
                    timeout=3
                )
            else:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", target],
                    capture_output=True,
                    timeout=3
                )
            return result.returncode == 0
        except:
            return False

    def _udp_ping(self, target: str) -> bool:
        """UDP ping to DNS port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00', (target, 53))
            sock.close()
            return True
        except:
            return False

    def _arp_ping(self, target: str) -> bool:
        """ARP ping for local network detection"""
        try:
            # Check if target is in local network
            import subprocess
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["arp", "-a", target],
                    capture_output=True,
                    timeout=3
                )
                return target in result.stdout.decode()
            else:
                result = subprocess.run(
                    ["arping", "-c", "1", "-W", "1", target],
                    capture_output=True,
                    timeout=3
                )
                return result.returncode == 0
        except:
            return False

    def scan_port(self, target: str, port: int) -> Dict[str, Any]:
        """
        Advanced port scanning with service detection
        """
        result = {
            'port': port,
            'state': 'closed',
            'service': 'unknown',
            'version': '',
            'banner': '',
            'response_time': 0.0
        }
        
        start_time = time.time()
        
        try:
            # TCP Connect scan
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.socket_timeout)
            
            connect_result = sock.connect_ex((target, port))
            response_time = time.time() - start_time
            
            if connect_result == 0:
                result['state'] = 'open'
                result['response_time'] = response_time
                
                # Service detection
                service_info = self._detect_service(sock, port)
                result.update(service_info)
                
            sock.close()
            
        except Exception as e:
            self.logger.debug(f"Port scan error {target}:{port} - {e}")
            
        return result

    def _detect_service(self, sock: socket.socket, port: int) -> Dict[str, str]:
        """
        Service detection and banner grabbing
        """
        service_info = {
            'service': 'unknown',
            'version': '',
            'banner': ''
        }
        
        # Common service mappings
        service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            3389: 'rdp', 5900: 'vnc', 8080: 'http-proxy'
        }
        
        service_info['service'] = service_map.get(port, 'unknown')
        
        # Banner grabbing
        try:
            # Send service-specific probes
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            elif port == 443:
                service_info['service'] = 'https'
            elif port == 22:
                pass  # SSH will send banner automatically
            elif port == 21:
                pass  # FTP will send banner automatically
            else:
                sock.send(b"\r\n")
            
            # Receive banner
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['banner'] = banner[:200]  # Limit banner length
            
            # Extract version information
            if banner:
                service_info['version'] = self._extract_version(banner)
                
        except:
            pass
            
        return service_info

    def _extract_version(self, banner: str) -> str:
        """Extract version information from banner"""
        import re
        
        # Common version patterns
        patterns = [
            r'Server: ([^\r\n]+)',
            r'SSH-[\d.]+ ([^\r\n]+)',
            r'220[- ]([^\r\n]+)',
            r'HTTP/[\d.]+ \d+ [^\r\n]*\r\nServer: ([^\r\n]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)[:50]  # Limit version length
        
        return ''

    def detect_os(self, target: str, open_ports: List[int]) -> str:
        """
        Operating system detection using multiple techniques
        """
        os_hints = []
        
        # TTL-based detection
        ttl = self._get_ttl(target)
        if ttl:
            if ttl <= 64:
                os_hints.append("Linux/Unix")
            elif ttl <= 128:
                os_hints.append("Windows")
            elif ttl <= 255:
                os_hints.append("Network Device")
        
        # Port-based detection
        if 3389 in open_ports:
            os_hints.append("Windows (RDP)")
        if 22 in open_ports and 80 in open_ports:
            os_hints.append("Linux Server")
        if 135 in open_ports or 139 in open_ports:
            os_hints.append("Windows (SMB)")
        if 161 in open_ports:
            os_hints.append("Network Device (SNMP)")
        
        # Combine hints
        if os_hints:
            return ", ".join(set(os_hints))
        return "Unknown"

    def _get_ttl(self, target: str) -> Optional[int]:
        """Get TTL value for OS detection"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["ping", "-n", "1", target],
                    capture_output=True,
                    timeout=5
                )
                output = result.stdout.decode()
                import re
                match = re.search(r'TTL=(\d+)', output)
                if match:
                    return int(match.group(1))
            else:
                result = subprocess.run(
                    ["ping", "-c", "1", target],
                    capture_output=True,
                    timeout=5
                )
                output = result.stdout.decode()
                import re
                match = re.search(r'ttl=(\d+)', output)
                if match:
                    return int(match.group(1))
        except:
            pass
        return None

    def get_mac_address(self, target: str) -> Optional[str]:
        """Get MAC address for local network targets"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["arp", "-a", target],
                    capture_output=True,
                    timeout=3
                )
                output = result.stdout.decode()
                import re
                match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', output)
                if match:
                    return match.group(0)
            else:
                result = subprocess.run(
                    ["arp", "-n", target],
                    capture_output=True,
                    timeout=3
                )
                output = result.stdout.decode()
                lines = output.split('\n')
                for line in lines:
                    if target in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', part):
                                return part
        except:
            pass
        return None

    def scan_network(self, network: str, port_range: str = "common") -> List[ScanTarget]:
        """
        Comprehensive network scanning
        """
        self.logger.info(f"Starting network scan: {network}")
        
        # Parse network range
        try:
            net = ipaddress.ip_network(network, strict=False)
            targets = [str(ip) for ip in net.hosts()]
            
            # Limit scan size for performance
            if len(targets) > 254:
                targets = targets[:254]
                self.logger.warning(f"Limited scan to first 254 hosts")
                
        except ValueError:
            # Single IP
            targets = [network]
        
        # Host discovery phase
        self.logger.info("Phase 1: Host Discovery")
        alive_hosts = []
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {
                executor.submit(self.ping_host, target): target 
                for target in targets
            }
            
            for future in as_completed(future_to_ip):
                target = future_to_ip[future]
                try:
                    is_alive, response_time = future.result()
                    if is_alive:
                        alive_hosts.append((target, response_time))
                        self.logger.info(f"Host alive: {target} ({response_time:.3f}s)")
                except Exception as e:
                    self.logger.debug(f"Host discovery error for {target}: {e}")
        
        self.logger.info(f"Found {len(alive_hosts)} alive hosts")
        
        # Port scanning phase
        self.logger.info("Phase 2: Port Scanning")
        scan_results = []
        
        # Determine port list
        if port_range == "critical":
            ports = self.critical_ports
        elif port_range == "common":
            ports = self.common_ports[:100]  # Limit for performance
        elif port_range == "full":
            ports = list(range(1, 65536))
        else:
            # Parse custom range
            ports = self._parse_port_range(port_range)
        
        for target_ip, response_time in alive_hosts:
            scan_target = ScanTarget(ip=target_ip, response_time=response_time)
            
            # Resolve hostname
            try:
                hostname = socket.gethostbyaddr(target_ip)[0]
                scan_target.hostname = hostname
            except:
                pass
            
            # Port scan
            open_ports = []
            services = {}
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, target_ip, port): port 
                    for port in ports
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        if result['state'] == 'open':
                            open_ports.append(port)
                            services[port] = result['service']
                            
                            self.logger.info(
                                f"Open port: {target_ip}:{port} "
                                f"({result['service']}) - {result['banner'][:30]}"
                            )
                    except Exception as e:
                        self.logger.debug(f"Port scan error {target_ip}:{port}: {e}")
            
            scan_target.ports = sorted(open_ports)
            scan_target.services = services
            
            # OS Detection
            if open_ports:
                scan_target.os = self.detect_os(target_ip, open_ports)
            
            # MAC Address (for local network)
            scan_target.mac = self.get_mac_address(target_ip)
            
            scan_results.append(scan_target)
            
            # Stealth delay
            if self.stealth_mode:
                time.sleep(self.scan_delay)
        
        self.logger.info(f"Scan completed. Found {len([t for t in scan_results if t.ports])} hosts with open ports")
        return scan_results

    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string into list of ports"""
        ports = []
        
        for part in port_range.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-', 1))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))

    def vulnerability_scan(self, targets: List[ScanTarget]) -> List[ScanTarget]:
        """
        Basic vulnerability assessment
        """
        self.logger.info("Phase 3: Vulnerability Assessment")
        
        for target in targets:
            vulns = []
            
            # Check for common vulnerabilities
            for port in target.ports:
                service = target.services.get(port, 'unknown')
                
                # Common vulnerable services
                if port == 21 and 'vsftpd 2.3.4' in str(target.services.get(port, '')):
                    vulns.append("FTP Backdoor (CVE-2011-2523)")
                
                if port == 22 and service == 'ssh':
                    vulns.append("SSH Service - Check for weak authentication")
                
                if port == 23:
                    vulns.append("Telnet - Unencrypted protocol")
                
                if port == 80 or port == 8080:
                    vulns.append("HTTP Service - Check for web vulnerabilities")
                
                if port == 139 or port == 445:
                    vulns.append("SMB Service - Check for SMB vulnerabilities")
                
                if port == 3389:
                    vulns.append("RDP Service - Check for BlueKeep (CVE-2019-0708)")
                
                if port == 5900:
                    vulns.append("VNC Service - Check for authentication bypass")
            
            target.vulnerabilities = vulns
        
        return targets

    def generate_report(self, scan_results: List[ScanTarget], output_format: str = "json") -> str:
        """
        Generate comprehensive scan report
        """
        report = {
            "scan_metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scanner": "IntelProbe Production Scanner v1.0",
                "operator": "Lintshiwe Slade",
                "total_hosts_scanned": len(scan_results),
                "hosts_with_open_ports": len([t for t in scan_results if t.ports])
            },
            "executive_summary": {
                "total_open_ports": sum(len(t.ports) for t in scan_results),
                "critical_services": [],
                "vulnerabilities_found": sum(len(t.vulnerabilities) for t in scan_results),
                "risk_level": "LOW"
            },
            "detailed_results": []
        }
        
        # Analyze results for executive summary
        critical_services = set()
        high_risk_ports = [21, 23, 135, 139, 445, 3389, 5900]
        
        for target in scan_results:
            target_data = {
                "ip_address": target.ip,
                "hostname": target.hostname,
                "response_time": target.response_time,
                "operating_system": target.os,
                "mac_address": target.mac,
                "open_ports": target.ports,
                "services": target.services,
                "vulnerabilities": target.vulnerabilities
            }
            report["detailed_results"].append(target_data)
            
            # Check for critical services
            for port in target.ports:
                if port in high_risk_ports:
                    critical_services.add(f"{target.services.get(port, 'unknown')} ({port})")
        
        report["executive_summary"]["critical_services"] = list(critical_services)
        
        # Determine risk level
        total_vulns = report["executive_summary"]["vulnerabilities_found"]
        if total_vulns > 10:
            report["executive_summary"]["risk_level"] = "HIGH"
        elif total_vulns > 5:
            report["executive_summary"]["risk_level"] = "MEDIUM"
        
        if output_format == "json":
            return json.dumps(report, indent=2)
        else:
            # Generate text report
            text_report = f"""
INTELPROBE NETWORK SECURITY ASSESSMENT REPORT
Generated: {report['scan_metadata']['timestamp']}
Operator: {report['scan_metadata']['operator']}

EXECUTIVE SUMMARY
=================
Total Hosts Scanned: {report['scan_metadata']['total_hosts_scanned']}
Hosts with Open Ports: {report['scan_metadata']['hosts_with_open_ports']}
Total Open Ports: {report['executive_summary']['total_open_ports']}
Vulnerabilities Found: {report['executive_summary']['vulnerabilities_found']}
Risk Level: {report['executive_summary']['risk_level']}

CRITICAL SERVICES DETECTED:
{chr(10).join(f"- {service}" for service in report['executive_summary']['critical_services'])}

DETAILED RESULTS
================
"""
            
            for target_data in report["detailed_results"]:
                if target_data["open_ports"]:
                    text_report += f"""
Host: {target_data['ip_address']}
Hostname: {target_data['hostname'] or 'Unknown'}
OS: {target_data['operating_system'] or 'Unknown'}
Open Ports: {', '.join(map(str, target_data['open_ports']))}
Vulnerabilities: {len(target_data['vulnerabilities'])}
"""
                    for vuln in target_data['vulnerabilities']:
                        text_report += f"  - {vuln}\n"
            
            return text_report

# Test the production scanner
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    scanner = ProductionScanner()
    
    # Example scan
    targets = scanner.scan_network("127.0.0.1", "critical")
    targets_with_vulns = scanner.vulnerability_scan(targets)
    
    report = scanner.generate_report(targets_with_vulns, "text")
    print(report)
