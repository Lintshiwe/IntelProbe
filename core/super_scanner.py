#!/usr/bin/env python3
"""
IntelProbe SuperScanner - Ultra High-Performance Network Scanner
Maximum speed, intelligence, and accuracy with async operations

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License
Copyright (c) 2025 Lintshiwe Slade
"""

import asyncio
import socket
import struct
import time
import subprocess
import platform
import ipaddress
import concurrent.futures
import threading
import hashlib
import json
import os
import re
import logging
from typing import List, Dict, Optional, Tuple, Any, Set, Callable
from dataclasses import dataclass, field, asdict
from functools import lru_cache
from datetime import datetime
from enum import Enum
from pathlib import Path

# Performance constants
MAX_CONCURRENT_HOSTS = 256
MAX_CONCURRENT_PORTS = 500
SOCKET_TIMEOUT = 1.5
CACHE_EXPIRY = 3600  # 1 hour

class ScanSpeed(Enum):
    """Scan speed presets"""
    INSANE = "insane"      # Maximum speed, less stealth
    FAST = "fast"          # High speed, reasonable stealth
    NORMAL = "normal"      # Balanced
    STEALTH = "stealth"    # Slow, maximum stealth
    PARANOID = "paranoid"  # Ultra slow, forensic mode

class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    NONE = 0

@dataclass
class ServiceInfo:
    """Detailed service information"""
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    cpe: str = ""
    vulnerabilities: List[str] = field(default_factory=list)
    exploit_suggestions: List[str] = field(default_factory=list)
    response_time: float = 0.0
    fingerprint: str = ""

@dataclass
class HostResult:
    """Comprehensive host scan result"""
    ip: str
    hostname: str = ""
    mac_address: str = ""
    vendor: str = ""
    os_type: str = ""
    os_version: str = ""
    os_confidence: float = 0.0
    device_type: str = ""
    services: Dict[int, ServiceInfo] = field(default_factory=dict)
    open_ports: List[int] = field(default_factory=list)
    filtered_ports: List[int] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)
    ttl: int = 0
    response_time: float = 0.0
    last_seen: str = ""
    threat_level: ThreatLevel = ThreatLevel.NONE
    risk_score: int = 0
    vulnerabilities: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    raw_data: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Handle services - may be ServiceInfo dataclass or dict
        services_dict = {}
        for k, v in self.services.items():
            if hasattr(v, '__dataclass_fields__'):
                services_dict[k] = asdict(v)
            elif isinstance(v, dict):
                services_dict[k] = v
            else:
                services_dict[k] = str(v)
        data['services'] = services_dict
        # Handle threat_level - may be enum or string
        if hasattr(self.threat_level, 'name'):
            data['threat_level'] = self.threat_level.name
        else:
            data['threat_level'] = str(self.threat_level)
        return data

class ScanCache:
    """High-performance scan result cache"""
    
    def __init__(self, cache_dir: str = "cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.memory_cache: Dict[str, Tuple[float, Any]] = {}
        self.lock = threading.Lock()
    
    def _get_key(self, target: str, scan_type: str) -> str:
        """Generate cache key"""
        return hashlib.md5(f"{target}:{scan_type}".encode()).hexdigest()
    
    def get(self, target: str, scan_type: str, max_age: int = CACHE_EXPIRY) -> Optional[Any]:
        """Get cached result if not expired"""
        key = self._get_key(target, scan_type)
        
        with self.lock:
            if key in self.memory_cache:
                timestamp, data = self.memory_cache[key]
                if time.time() - timestamp < max_age:
                    return data
        
        # Try file cache
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                stat = cache_file.stat()
                if time.time() - stat.st_mtime < max_age:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
            except:
                pass
        
        return None
    
    def set(self, target: str, scan_type: str, data: Any) -> None:
        """Cache scan result"""
        key = self._get_key(target, scan_type)
        
        with self.lock:
            self.memory_cache[key] = (time.time(), data)
        
        # Also write to file
        try:
            cache_file = self.cache_dir / f"{key}.json"
            with open(cache_file, 'w') as f:
                json.dump(data, f)
        except:
            pass
    
    def clear(self) -> None:
        """Clear all caches"""
        with self.lock:
            self.memory_cache.clear()
        
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
            except:
                pass

class ServiceDatabase:
    """Comprehensive service and vulnerability database"""
    
    # Extended service mappings
    SERVICES = {
        20: ("ftp-data", "FTP Data"),
        21: ("ftp", "FTP Control"),
        22: ("ssh", "SSH"),
        23: ("telnet", "Telnet"),
        25: ("smtp", "SMTP"),
        53: ("dns", "DNS"),
        67: ("dhcp", "DHCP Server"),
        68: ("dhcp-client", "DHCP Client"),
        69: ("tftp", "TFTP"),
        80: ("http", "HTTP"),
        88: ("kerberos", "Kerberos"),
        110: ("pop3", "POP3"),
        111: ("rpc", "Sun RPC"),
        119: ("nntp", "NNTP"),
        123: ("ntp", "NTP"),
        135: ("msrpc", "Microsoft RPC"),
        137: ("netbios-ns", "NetBIOS Name"),
        138: ("netbios-dgm", "NetBIOS Datagram"),
        139: ("netbios-ssn", "NetBIOS Session"),
        143: ("imap", "IMAP"),
        161: ("snmp", "SNMP"),
        162: ("snmptrap", "SNMP Trap"),
        389: ("ldap", "LDAP"),
        443: ("https", "HTTPS"),
        445: ("smb", "SMB"),
        464: ("kpasswd", "Kerberos Password"),
        465: ("smtps", "SMTPS"),
        500: ("isakmp", "ISAKMP/IKE"),
        514: ("syslog", "Syslog"),
        515: ("printer", "LPD Printer"),
        520: ("rip", "RIP"),
        587: ("submission", "Mail Submission"),
        593: ("http-rpc", "HTTP RPC"),
        631: ("ipp", "IPP/CUPS"),
        636: ("ldaps", "LDAPS"),
        993: ("imaps", "IMAPS"),
        995: ("pop3s", "POP3S"),
        1080: ("socks", "SOCKS Proxy"),
        1433: ("mssql", "Microsoft SQL Server"),
        1434: ("mssql-udp", "MSSQL Browser"),
        1521: ("oracle", "Oracle DB"),
        1723: ("pptp", "PPTP VPN"),
        1883: ("mqtt", "MQTT"),
        2049: ("nfs", "NFS"),
        2082: ("cpanel", "cPanel"),
        2083: ("cpanel-ssl", "cPanel SSL"),
        2181: ("zookeeper", "ZooKeeper"),
        2375: ("docker", "Docker API"),
        2376: ("docker-ssl", "Docker SSL"),
        3000: ("ntop", "ntopng/Grafana"),
        3128: ("squid", "Squid Proxy"),
        3268: ("globalcatalog", "AD Global Catalog"),
        3269: ("globalcatalog-ssl", "AD GC SSL"),
        3306: ("mysql", "MySQL"),
        3389: ("rdp", "RDP"),
        3690: ("svn", "SVN"),
        4369: ("epmd", "Erlang Port Mapper"),
        4443: ("pharos", "Pharos"),
        5000: ("upnp", "UPnP/Flask"),
        5432: ("postgresql", "PostgreSQL"),
        5672: ("amqp", "RabbitMQ"),
        5900: ("vnc", "VNC"),
        5984: ("couchdb", "CouchDB"),
        5985: ("winrm", "WinRM HTTP"),
        5986: ("winrm-ssl", "WinRM HTTPS"),
        6379: ("redis", "Redis"),
        6443: ("kubernetes", "Kubernetes API"),
        6660: ("irc", "IRC"),
        6667: ("irc", "IRC"),
        7001: ("weblogic", "WebLogic"),
        7002: ("weblogic-ssl", "WebLogic SSL"),
        8000: ("http-alt", "HTTP Alt"),
        8008: ("http-alt", "HTTP Alt"),
        8080: ("http-proxy", "HTTP Proxy"),
        8081: ("blackice", "BlackIce"),
        8443: ("https-alt", "HTTPS Alt"),
        8888: ("sun-answerbook", "HTTP Alt"),
        9000: ("cslistener", "PHP-FPM"),
        9001: ("tor-orport", "Tor ORPort"),
        9042: ("cassandra", "Cassandra"),
        9090: ("zeus-admin", "Prometheus"),
        9100: ("jetdirect", "JetDirect Print"),
        9200: ("elasticsearch", "Elasticsearch"),
        9300: ("elasticsearch", "ES Transport"),
        9418: ("git", "Git"),
        10000: ("webmin", "Webmin"),
        11211: ("memcached", "Memcached"),
        15672: ("rabbitmq", "RabbitMQ Web"),
        27017: ("mongodb", "MongoDB"),
        27018: ("mongodb", "MongoDB Shard"),
        27019: ("mongodb", "MongoDB Config"),
        50000: ("db2", "DB2"),
    }
    
    # Critical vulnerabilities by service
    VULNS = {
        "smb": [
            {"name": "EternalBlue (MS17-010)", "cve": "CVE-2017-0144", "severity": "CRITICAL"},
            {"name": "SMBGhost", "cve": "CVE-2020-0796", "severity": "CRITICAL"},
            {"name": "SMB Null Session", "cve": None, "severity": "MEDIUM"},
        ],
        "rdp": [
            {"name": "BlueKeep", "cve": "CVE-2019-0708", "severity": "CRITICAL"},
            {"name": "DejaBlue", "cve": "CVE-2019-1181", "severity": "CRITICAL"},
        ],
        "ssh": [
            {"name": "Weak Credentials", "cve": None, "severity": "HIGH"},
            {"name": "SSH Key Exposure", "cve": None, "severity": "HIGH"},
        ],
        "telnet": [
            {"name": "Cleartext Protocol", "cve": None, "severity": "HIGH"},
            {"name": "Default Credentials", "cve": None, "severity": "HIGH"},
        ],
        "ftp": [
            {"name": "Anonymous Access", "cve": None, "severity": "MEDIUM"},
            {"name": "Cleartext Protocol", "cve": None, "severity": "MEDIUM"},
        ],
        "vnc": [
            {"name": "Weak Authentication", "cve": None, "severity": "HIGH"},
            {"name": "No Encryption", "cve": None, "severity": "MEDIUM"},
        ],
        "redis": [
            {"name": "No Authentication", "cve": None, "severity": "CRITICAL"},
            {"name": "Remote Code Execution", "cve": None, "severity": "CRITICAL"},
        ],
        "mongodb": [
            {"name": "No Authentication", "cve": None, "severity": "CRITICAL"},
            {"name": "Data Exposure", "cve": None, "severity": "HIGH"},
        ],
        "elasticsearch": [
            {"name": "No Authentication", "cve": None, "severity": "HIGH"},
            {"name": "Data Exposure", "cve": None, "severity": "HIGH"},
        ],
        "docker": [
            {"name": "Unauthenticated API", "cve": None, "severity": "CRITICAL"},
            {"name": "Container Escape", "cve": None, "severity": "CRITICAL"},
        ],
    }
    
    @classmethod
    def get_service(cls, port: int) -> Tuple[str, str]:
        """Get service name and description for port"""
        return cls.SERVICES.get(port, ("unknown", "Unknown Service"))
    
    @classmethod
    def get_vulnerabilities(cls, service: str) -> List[Dict]:
        """Get known vulnerabilities for service"""
        return cls.VULNS.get(service.lower(), [])

class SuperScanner:
    """
    Ultra high-performance network scanner with:
    - Async/parallel scanning for maximum speed
    - Smart caching to avoid redundant scans
    - Intelligent service detection and fingerprinting
    - Built-in vulnerability assessment
    - Real-time progress reporting
    - Multiple scan modes (stealth to insane)
    """
    
    def __init__(self, config=None):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.cache = ScanCache()
        self.db = ServiceDatabase()
        
        # Scan settings
        self.speed = ScanSpeed.FAST
        self.timeout = SOCKET_TIMEOUT
        self.max_hosts = MAX_CONCURRENT_HOSTS
        self.max_ports = MAX_CONCURRENT_PORTS
        
        # Progress callback
        self.progress_callback: Optional[Callable] = None
        
        # Statistics
        self.stats = {
            'hosts_scanned': 0,
            'ports_scanned': 0,
            'services_found': 0,
            'vulns_found': 0,
            'scan_start': 0,
            'scan_end': 0,
        }
        
        # Port presets
        self.port_presets = {
            'top20': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
            'top100': list(range(1, 101)) + [110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443],
            'common': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9090, 9200, 10000, 27017],
            'web': [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443],
            'database': [1433, 1521, 3306, 5432, 6379, 9042, 11211, 27017],
            'full': list(range(1, 1025)),
            'all': list(range(1, 65536)),
        }
    
    def set_speed(self, speed: ScanSpeed) -> None:
        """Configure scan speed preset"""
        self.speed = speed
        
        if speed == ScanSpeed.INSANE:
            self.timeout = 0.5
            self.max_hosts = 500
            self.max_ports = 1000
        elif speed == ScanSpeed.FAST:
            self.timeout = 1.0
            self.max_hosts = 256
            self.max_ports = 500
        elif speed == ScanSpeed.NORMAL:
            self.timeout = 2.0
            self.max_hosts = 100
            self.max_ports = 200
        elif speed == ScanSpeed.STEALTH:
            self.timeout = 3.0
            self.max_hosts = 20
            self.max_ports = 50
        elif speed == ScanSpeed.PARANOID:
            self.timeout = 5.0
            self.max_hosts = 5
            self.max_ports = 10
    
    def _report_progress(self, message: str, percent: float = 0) -> None:
        """Report progress to callback if set"""
        if self.progress_callback:
            self.progress_callback(message, percent)
    
    async def _async_tcp_connect(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Async TCP port scan with service detection"""
        service_info = ServiceInfo(port=port)
        
        try:
            start = time.time()
            
            # Async socket connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            service_info.response_time = time.time() - start
            service_info.state = "open"
            
            # Get service info
            svc_name, svc_desc = self.db.get_service(port)
            service_info.service = svc_name
            
            # Try banner grabbing
            try:
                # Send probe based on service
                if port in [80, 8080, 8000, 8008]:
                    writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                elif port in [21, 22, 25, 110, 143]:
                    pass  # These send banner automatically
                else:
                    writer.write(b"\r\n")
                
                await writer.drain()
                
                # Read response
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                service_info.banner = banner.decode('utf-8', errors='ignore')[:200].strip()
                
                # Extract version from banner
                service_info.version = self._extract_version(service_info.banner, svc_name)
                
            except:
                pass
            
            # Add vulnerability info
            vulns = self.db.get_vulnerabilities(svc_name)
            service_info.vulnerabilities = [v['name'] for v in vulns]
            
            writer.close()
            await writer.wait_closed()
            
            return service_info
            
        except asyncio.TimeoutError:
            service_info.state = "filtered"
        except ConnectionRefusedError:
            service_info.state = "closed"
        except Exception:
            service_info.state = "error"
        
        return service_info if service_info.state == "open" else None
    
    def _sync_tcp_connect(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Synchronous TCP port scan for non-async contexts"""
        service_info = ServiceInfo(port=port)
        
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((host, port))
            service_info.response_time = time.time() - start
            
            if result == 0:
                service_info.state = "open"
                
                # Get service info
                svc_name, svc_desc = self.db.get_service(port)
                service_info.service = svc_name
                
                # Try banner grabbing
                try:
                    if port in [80, 8080, 8000]:
                        sock.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    elif port not in [21, 22, 25, 110]:
                        sock.send(b"\r\n")
                    
                    sock.settimeout(1.0)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')[:200]
                    service_info.banner = banner.strip()
                    service_info.version = self._extract_version(banner, svc_name)
                except:
                    pass
                
                # Add vulnerability info
                vulns = self.db.get_vulnerabilities(svc_name)
                service_info.vulnerabilities = [v['name'] for v in vulns]
                
                sock.close()
                return service_info
                
        except Exception:
            pass
        
        return None
    
    def _extract_version(self, banner: str, service: str) -> str:
        """Extract version information from banner"""
        patterns = [
            r'Server:\s*([^\r\n]+)',
            r'SSH-[\d.]+-([^\r\n]+)',
            r'220[- ]([^\r\n]+)',
            r'Apache/([^\s]+)',
            r'nginx/([^\s]+)',
            r'Microsoft-IIS/([^\s]+)',
            r'OpenSSH[_\s]([^\s]+)',
            r'MySQL\s+([^\s]+)',
            r'PostgreSQL\s+([^\s]+)',
            r'Redis\s+server\s+v=([^\s]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)[:50]
        
        return ""
    
    def _ping_host(self, host: str) -> Tuple[bool, float, int]:
        """Check if host is alive using multiple methods"""
        start = time.time()
        
        # Method 1: TCP SYN to common ports
        for port in [80, 443, 22, 445, 3389]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return True, time.time() - start, 0
            except:
                continue
        
        # Method 2: ICMP ping
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", host]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                # Extract TTL
                ttl_match = re.search(r'ttl[=:](\d+)', result.stdout.lower())
                ttl = int(ttl_match.group(1)) if ttl_match else 0
                return True, time.time() - start, ttl
        except:
            pass
        
        return False, time.time() - start, 0
    
    def _detect_os(self, ttl: int, open_ports: List[int]) -> Tuple[str, str, float]:
        """Detect operating system from TTL and open ports"""
        os_type = "Unknown"
        os_version = ""
        confidence = 0.0
        
        # TTL-based detection
        if ttl > 0:
            if ttl <= 64:
                os_type = "Linux/Unix"
                confidence = 0.6
            elif ttl <= 128:
                os_type = "Windows"
                confidence = 0.6
            elif ttl <= 255:
                os_type = "Network Device"
                confidence = 0.5
        
        # Port-based refinement
        windows_ports = {135, 139, 445, 3389, 5985, 5986}
        linux_ports = {22}
        network_ports = {161, 162, 23}
        
        if windows_ports & set(open_ports):
            if 3389 in open_ports:
                os_type = "Windows"
                os_version = "RDP Enabled"
                confidence = 0.8
            elif 445 in open_ports:
                os_type = "Windows"
                os_version = "SMB Enabled"
                confidence = 0.75
        
        if 22 in open_ports and os_type != "Windows":
            os_type = "Linux/Unix"
            os_version = "SSH Enabled"
            confidence = 0.7
        
        if network_ports & set(open_ports):
            if 161 in open_ports:
                os_type = "Network Device"
                os_version = "SNMP Enabled"
                confidence = 0.7
        
        return os_type, os_version, confidence
    
    def _get_mac_address(self, host: str) -> Tuple[str, str]:
        """Get MAC address and vendor for host"""
        mac = ""
        vendor = ""
        
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["arp", "-a", host], capture_output=True, text=True, timeout=3)
                match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', result.stdout)
            else:
                result = subprocess.run(["arp", "-n", host], capture_output=True, text=True, timeout=3)
                match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', result.stdout)
            
            if match:
                mac = match.group(0).upper()
                # Get vendor from OUI (first 3 bytes)
                vendor = self._lookup_vendor(mac)
        except:
            pass
        
        return mac, vendor
    
    @lru_cache(maxsize=1000)
    def _lookup_vendor(self, mac: str) -> str:
        """Lookup vendor from MAC address OUI"""
        # Common vendor OUIs
        oui_db = {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU/KVM",
            "00:15:5D": "Microsoft Hyper-V",
            "DC:A6:32": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi",
            "00:1A:79": "Dell",
            "00:1E:67": "Dell",
            "00:23:AE": "Dell",
            "00:25:B5": "Dell",
            "00:14:22": "Dell",
            "00:00:0C": "Cisco",
            "00:01:63": "Cisco",
            "00:01:64": "Cisco",
            "00:1B:2F": "Netgear",
            "00:1F:33": "Netgear",
            "A0:21:B7": "Netgear",
            "00:17:9A": "D-Link",
            "00:1C:F0": "D-Link",
            "00:22:B0": "D-Link",
            "00:1A:A0": "HP",
            "00:1E:0B": "HP",
            "00:21:5A": "HP",
            "3C:D9:2B": "HP",
            "00:1B:21": "Intel",
            "00:1E:65": "Intel",
            "00:24:D7": "Intel",
            "00:25:22": "Apple",
            "00:26:B0": "Apple",
            "00:26:BB": "Apple",
            "AC:87:A3": "Apple",
        }
        
        oui = mac[:8].upper()
        return oui_db.get(oui, "")
    
    def _calculate_risk_score(self, result: HostResult) -> Tuple[int, ThreatLevel]:
        """Calculate risk score and threat level"""
        score = 0
        
        # Critical services
        critical_ports = {23, 69, 135, 139, 445, 1433, 3389, 5900}
        for port in result.open_ports:
            if port in critical_ports:
                score += 20
            elif port in [21, 22, 25, 110]:
                score += 10
            else:
                score += 5
        
        # Vulnerabilities
        for svc in result.services.values():
            score += len(svc.vulnerabilities) * 15
        
        # OS-based risk
        if "Windows" in result.os_type and 445 in result.open_ports:
            score += 15
        
        # Determine threat level
        if score >= 80:
            level = ThreatLevel.CRITICAL
        elif score >= 60:
            level = ThreatLevel.HIGH
        elif score >= 40:
            level = ThreatLevel.MEDIUM
        elif score >= 20:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.INFO
        
        return min(score, 100), level
    
    async def scan_host_async(self, host: str, ports: List[int] = None) -> Optional[HostResult]:
        """Async scan a single host with full enumeration"""
        if ports is None:
            ports = self.port_presets['common']
        
        # Check cache first
        cached = self.cache.get(host, 'host_scan')
        if cached:
            return HostResult(**cached)
        
        # Check if host is alive
        is_alive, response_time, ttl = self._ping_host(host)
        if not is_alive:
            return None
        
        result = HostResult(
            ip=host,
            ttl=ttl,
            response_time=response_time,
            last_seen=datetime.now().isoformat(),
        )
        
        # Hostname resolution
        try:
            result.hostname = socket.gethostbyaddr(host)[0]
        except:
            pass
        
        # MAC address lookup
        result.mac_address, result.vendor = self._get_mac_address(host)
        
        # Async port scanning
        tasks = [self._async_tcp_connect(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for port_result in results:
            if isinstance(port_result, ServiceInfo) and port_result:
                result.services[port_result.port] = port_result
                result.open_ports.append(port_result.port)
        
        result.open_ports.sort()
        
        # OS detection
        result.os_type, result.os_version, result.os_confidence = self._detect_os(ttl, result.open_ports)
        
        # Calculate risk
        result.risk_score, result.threat_level = self._calculate_risk_score(result)
        
        # Cache result
        self.cache.set(host, 'host_scan', result.to_dict())
        
        self.stats['hosts_scanned'] += 1
        self.stats['services_found'] += len(result.open_ports)
        
        return result
    
    def scan_host(self, host: str, ports: List[int] = None) -> Optional[HostResult]:
        """Synchronous host scan wrapper"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.scan_host_async(host, ports))
    
    async def scan_network_async(self, network: str, ports: List[int] = None) -> List[HostResult]:
        """Async scan entire network range"""
        if ports is None:
            ports = self.port_presets['common']
        
        self.stats['scan_start'] = time.time()
        results = []
        
        # Parse network
        try:
            net = ipaddress.ip_network(network, strict=False)
            targets = [str(ip) for ip in net.hosts()]
        except ValueError:
            targets = [network]  # Single host
        
        self._report_progress(f"Scanning {len(targets)} hosts...", 0)
        
        # Batch processing for better performance
        batch_size = self.max_hosts
        total_batches = (len(targets) + batch_size - 1) // batch_size
        
        for batch_num, i in enumerate(range(0, len(targets), batch_size)):
            batch = targets[i:i + batch_size]
            
            # First do quick host discovery
            alive_hosts = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
                futures = {executor.submit(self._ping_host, host): host for host in batch}
                for future in concurrent.futures.as_completed(futures):
                    host = futures[future]
                    try:
                        is_alive, _, _ = future.result()
                        if is_alive:
                            alive_hosts.append(host)
                    except:
                        pass
            
            # Then do detailed scanning on alive hosts
            if alive_hosts:
                tasks = [self.scan_host_async(host, ports) for host in alive_hosts]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for r in batch_results:
                    if isinstance(r, HostResult) and r:
                        results.append(r)
            
            progress = (batch_num + 1) / total_batches * 100
            self._report_progress(f"Batch {batch_num + 1}/{total_batches} complete", progress)
        
        self.stats['scan_end'] = time.time()
        
        return sorted(results, key=lambda x: ipaddress.ip_address(x.ip))
    
    def scan_network(self, network: str, ports: List[int] = None) -> List[HostResult]:
        """Synchronous network scan wrapper"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.scan_network_async(network, ports))
    
    def quick_scan(self, target: str) -> List[HostResult]:
        """Quick scan with minimal ports"""
        return self.scan_network(target, self.port_presets['top20'])
    
    def full_scan(self, target: str) -> List[HostResult]:
        """Full port scan (1-1024)"""
        return self.scan_network(target, self.port_presets['full'])
    
    def get_stats(self) -> Dict:
        """Get scan statistics"""
        duration = self.stats['scan_end'] - self.stats['scan_start']
        return {
            **self.stats,
            'duration': duration,
            'hosts_per_second': self.stats['hosts_scanned'] / duration if duration > 0 else 0,
        }


# Convenience functions
def quick_scan(target: str) -> List[HostResult]:
    """Quick scan a target"""
    scanner = SuperScanner()
    return scanner.quick_scan(target)

def full_scan(target: str) -> List[HostResult]:
    """Full scan a target"""
    scanner = SuperScanner()
    return scanner.full_scan(target)


if __name__ == "__main__":
    # Demo
    print("🚀 SuperScanner Demo")
    print("=" * 50)
    
    scanner = SuperScanner()
    scanner.set_speed(ScanSpeed.FAST)
    
    # Scan localhost
    print("\n📡 Scanning localhost...")
    result = scanner.scan_host("127.0.0.1", scanner.port_presets['common'])
    
    if result:
        print(f"\n✅ Host: {result.ip}")
        print(f"   OS: {result.os_type} {result.os_version}")
        print(f"   Open Ports: {result.open_ports}")
        print(f"   Risk Score: {result.risk_score} ({result.threat_level.name})")
        
        for port, svc in result.services.items():
            print(f"   - Port {port}: {svc.service} {svc.version}")
            if svc.vulnerabilities:
                print(f"     ⚠️  Vulns: {', '.join(svc.vulnerabilities)}")
    else:
        print("❌ No response from localhost")
    
    print("\n✨ SuperScanner ready for action!")
