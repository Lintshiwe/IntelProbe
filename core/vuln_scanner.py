#!/usr/bin/env python3
"""
IntelProbe Vulnerability Scanner & CVE Database
Deep vulnerability analysis with CVE identification and exploit tool mapping

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License

WARNING: This tool is for authorized security testing only.
Unauthorized access to computer systems is illegal.
"""

import json
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Logging setup
logger = logging.getLogger(__name__)


@dataclass
class CVEInfo:
    """CVE vulnerability information"""
    cve_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    description: str
    affected_versions: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_tools: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    mitigation: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'cve_id': self.cve_id,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'description': self.description,
            'affected_versions': self.affected_versions,
            'exploit_available': self.exploit_available,
            'exploit_tools': self.exploit_tools,
            'references': self.references,
            'mitigation': self.mitigation
        }


@dataclass
class VulnerabilityResult:
    """Complete vulnerability assessment result"""
    host: str
    port: int
    service: str
    version: str = ""
    banner: str = ""
    vulnerabilities: List[CVEInfo] = field(default_factory=list)
    risk_level: str = "INFO"
    recommendations: List[str] = field(default_factory=list)
    scan_time: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'host': self.host,
            'port': self.port,
            'service': self.service,
            'version': self.version,
            'banner': self.banner,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'risk_level': self.risk_level,
            'recommendations': self.recommendations,
            'scan_time': self.scan_time
        }


class CVEDatabase:
    """
    Comprehensive CVE database with exploit tool mappings
    Contains known vulnerabilities for common services
    """
    
    # ==========================================
    # CRITICAL CVE DATABASE
    # ==========================================
    
    CVE_DATABASE = {
        # ========== SMB/CIFS (Port 445, 139) ==========
        "smb": [
            CVEInfo(
                cve_id="CVE-2017-0144",
                severity="CRITICAL",
                cvss_score=9.8,
                description="EternalBlue - SMBv1 Remote Code Execution. Exploited by WannaCry ransomware.",
                affected_versions=["Windows XP", "Windows 7", "Windows Server 2008", "Windows Server 2008 R2"],
                exploit_available=True,
                exploit_tools=["Metasploit (ms17_010_eternalblue)", "EternalBlue-Exploit", "AutoBlue-MS17-010"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
                mitigation="Apply MS17-010 patch, disable SMBv1, block port 445"
            ),
            CVEInfo(
                cve_id="CVE-2020-0796",
                severity="CRITICAL",
                cvss_score=10.0,
                description="SMBGhost - SMBv3 Compression Remote Code Execution",
                affected_versions=["Windows 10 1903", "Windows 10 1909", "Windows Server 1903", "Windows Server 1909"],
                exploit_available=True,
                exploit_tools=["Metasploit (smbghost_cve_2020_0796)", "SMBGhost-Scanner", "CoronaBlue"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2020-0796"],
                mitigation="Apply KB4551762 patch, disable SMBv3 compression"
            ),
            CVEInfo(
                cve_id="CVE-2020-1472",
                severity="CRITICAL",
                cvss_score=10.0,
                description="Zerologon - Netlogon Elevation of Privilege",
                affected_versions=["Windows Server 2008-2019", "All Domain Controllers"],
                exploit_available=True,
                exploit_tools=["Metasploit (zerologon)", "Mimikatz", "SharpZeroLogon", "zerologon_tester.py"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2020-1472"],
                mitigation="Apply August 2020 security update, enable DC enforcement mode"
            ),
            CVEInfo(
                cve_id="CVE-2017-0145",
                severity="CRITICAL",
                cvss_score=9.8,
                description="EternalRomance - SMBv1 Remote Code Execution",
                affected_versions=["Windows XP-2008"],
                exploit_available=True,
                exploit_tools=["Metasploit (ms17_010_psexec)", "EternalRomance"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0145"],
                mitigation="Apply MS17-010 patch, disable SMBv1"
            ),
        ],
        
        # ========== RDP (Port 3389) ==========
        "rdp": [
            CVEInfo(
                cve_id="CVE-2019-0708",
                severity="CRITICAL",
                cvss_score=9.8,
                description="BlueKeep - RDP Remote Code Execution (Pre-authentication)",
                affected_versions=["Windows XP", "Windows 7", "Windows Server 2003", "Windows Server 2008"],
                exploit_available=True,
                exploit_tools=["Metasploit (bluekeep_scanner)", "BlueKeep-Exploit", "rdpscan"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
                mitigation="Apply patch, enable NLA, disable RDP if not needed"
            ),
            CVEInfo(
                cve_id="CVE-2019-1181",
                severity="CRITICAL",
                cvss_score=9.8,
                description="DejaBlue - RDP Remote Code Execution",
                affected_versions=["Windows 7-10", "Windows Server 2008-2019"],
                exploit_available=True,
                exploit_tools=["Metasploit", "DejaBlue-Scanner"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-1181"],
                mitigation="Apply August 2019 patches"
            ),
            CVEInfo(
                cve_id="CVE-2019-1182",
                severity="CRITICAL",
                cvss_score=9.8,
                description="DejaBlue variant - RDP Remote Code Execution",
                affected_versions=["Windows 7-10", "Windows Server 2008-2019"],
                exploit_available=True,
                exploit_tools=["Metasploit"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-1182"],
                mitigation="Apply August 2019 patches"
            ),
        ],
        
        # ========== SSH (Port 22) ==========
        "ssh": [
            CVEInfo(
                cve_id="CVE-2024-6387",
                severity="CRITICAL",
                cvss_score=8.1,
                description="RegreSSHion - OpenSSH Remote Code Execution (Race condition in signal handler)",
                affected_versions=["OpenSSH 8.5p1-9.7p1"],
                exploit_available=True,
                exploit_tools=["regresshion-exploit", "Custom PoC"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
                mitigation="Update to OpenSSH 9.8p1 or later"
            ),
            CVEInfo(
                cve_id="CVE-2018-15473",
                severity="MEDIUM",
                cvss_score=5.3,
                description="OpenSSH User Enumeration",
                affected_versions=["OpenSSH < 7.7"],
                exploit_available=True,
                exploit_tools=["Metasploit (ssh_enumusers)", "ssh-user-enum", "osueta"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
                mitigation="Update OpenSSH to 7.7+"
            ),
            CVEInfo(
                cve_id="CVE-2016-20012",
                severity="MEDIUM",
                cvss_score=5.3,
                description="OpenSSH User Existence Oracle",
                affected_versions=["OpenSSH < 8.8"],
                exploit_available=True,
                exploit_tools=["ssh-audit", "Custom scripts"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2016-20012"],
                mitigation="Update to OpenSSH 8.8+"
            ),
        ],
        
        # ========== FTP (Port 21) ==========
        "ftp": [
            CVEInfo(
                cve_id="CVE-2015-3306",
                severity="CRITICAL",
                cvss_score=10.0,
                description="ProFTPD mod_copy Remote Command Execution",
                affected_versions=["ProFTPD 1.3.5"],
                exploit_available=True,
                exploit_tools=["Metasploit (proftpd_modcopy_exec)", "proftpd-exploit"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"],
                mitigation="Disable mod_copy module, update ProFTPD"
            ),
            CVEInfo(
                cve_id="CVE-2010-4221",
                severity="CRITICAL",
                cvss_score=10.0,
                description="vsftpd 2.3.4 Backdoor Command Execution",
                affected_versions=["vsftpd 2.3.4"],
                exploit_available=True,
                exploit_tools=["Metasploit (vsftpd_234_backdoor)", "vsftpd-backdoor"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2010-4221"],
                mitigation="Update vsftpd to latest version"
            ),
            CVEInfo(
                cve_id="CVE-2011-2523",
                severity="HIGH",
                cvss_score=7.5,
                description="vsftpd Denial of Service",
                affected_versions=["vsftpd < 2.3.5"],
                exploit_available=True,
                exploit_tools=["Metasploit"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
                mitigation="Update vsftpd"
            ),
            CVEInfo(
                cve_id="ANON-FTP",
                severity="MEDIUM",
                cvss_score=5.0,
                description="Anonymous FTP Access Enabled - Information Disclosure Risk",
                affected_versions=["All FTP servers with anonymous enabled"],
                exploit_available=True,
                exploit_tools=["ftp", "Metasploit (ftp_anonymous)", "Nmap ftp-anon script"],
                references=["https://owasp.org/www-community/attacks/FTP_Bounce_Attack"],
                mitigation="Disable anonymous FTP access"
            ),
        ],
        
        # ========== Telnet (Port 23) ==========
        "telnet": [
            CVEInfo(
                cve_id="TELNET-CLEARTEXT",
                severity="HIGH",
                cvss_score=7.5,
                description="Telnet transmits data in cleartext - credentials can be intercepted",
                affected_versions=["All Telnet implementations"],
                exploit_available=True,
                exploit_tools=["Wireshark", "tcpdump", "Ettercap", "Bettercap"],
                references=["https://cwe.mitre.org/data/definitions/319.html"],
                mitigation="Replace Telnet with SSH"
            ),
            CVEInfo(
                cve_id="CVE-2020-10188",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Telnetd Remote Code Execution (netkit-telnet)",
                affected_versions=["netkit-telnet through 0.17"],
                exploit_available=True,
                exploit_tools=["Custom PoC", "Metasploit"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2020-10188"],
                mitigation="Update or disable Telnet"
            ),
        ],
        
        # ========== HTTP/HTTPS (Port 80, 443) ==========
        "http": [
            CVEInfo(
                cve_id="CVE-2021-44228",
                severity="CRITICAL",
                cvss_score=10.0,
                description="Log4Shell - Apache Log4j Remote Code Execution",
                affected_versions=["Log4j 2.0-2.14.1"],
                exploit_available=True,
                exploit_tools=["log4j-scan", "Metasploit", "JNDI-Injection-Exploit", "marshalsec"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                mitigation="Update Log4j to 2.17.0+, set log4j2.formatMsgNoLookups=true"
            ),
            CVEInfo(
                cve_id="CVE-2021-41773",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Apache HTTP Server Path Traversal & RCE",
                affected_versions=["Apache 2.4.49"],
                exploit_available=True,
                exploit_tools=["Metasploit (apache_normalize_path_rce)", "curl"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                mitigation="Update to Apache 2.4.51+"
            ),
            CVEInfo(
                cve_id="CVE-2021-42013",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Apache HTTP Server Path Traversal (bypass of CVE-2021-41773)",
                affected_versions=["Apache 2.4.49-2.4.50"],
                exploit_available=True,
                exploit_tools=["Metasploit", "curl", "Nuclei template"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
                mitigation="Update to Apache 2.4.51+"
            ),
            CVEInfo(
                cve_id="CVE-2017-5638",
                severity="CRITICAL",
                cvss_score=10.0,
                description="Apache Struts2 Remote Code Execution (Equifax breach)",
                affected_versions=["Struts 2.3.x-2.3.32", "Struts 2.5.x-2.5.10"],
                exploit_available=True,
                exploit_tools=["Metasploit (struts2_content_type_ognl)", "struts-pwn"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
                mitigation="Update Struts to latest version"
            ),
            CVEInfo(
                cve_id="CVE-2023-44487",
                severity="HIGH",
                cvss_score=7.5,
                description="HTTP/2 Rapid Reset DDoS Attack",
                affected_versions=["Most HTTP/2 implementations"],
                exploit_available=True,
                exploit_tools=["rapidreset", "Custom scripts"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
                mitigation="Apply vendor patches, rate limit RST_STREAM"
            ),
        ],
        
        # ========== MySQL (Port 3306) ==========
        "mysql": [
            CVEInfo(
                cve_id="CVE-2012-2122",
                severity="HIGH",
                cvss_score=7.5,
                description="MySQL Authentication Bypass",
                affected_versions=["MySQL 5.1.x-5.5.x", "MariaDB 5.1.x-5.3.x"],
                exploit_available=True,
                exploit_tools=["Metasploit (mysql_authbypass_hashdump)", "mysql-auth-bypass"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2012-2122"],
                mitigation="Update MySQL/MariaDB"
            ),
            CVEInfo(
                cve_id="CVE-2016-6662",
                severity="CRITICAL",
                cvss_score=9.8,
                description="MySQL Remote Root Code Execution",
                affected_versions=["MySQL <= 5.7.15", "MariaDB <= 10.1.17"],
                exploit_available=True,
                exploit_tools=["Metasploit", "mysql-exploit-remote-root"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2016-6662"],
                mitigation="Update to patched versions"
            ),
        ],
        
        # ========== PostgreSQL (Port 5432) ==========
        "postgresql": [
            CVEInfo(
                cve_id="CVE-2019-9193",
                severity="HIGH",
                cvss_score=9.0,
                description="PostgreSQL COPY FROM PROGRAM Command Execution",
                affected_versions=["PostgreSQL 9.3-11.2"],
                exploit_available=True,
                exploit_tools=["Metasploit (postgres_copy_from_program_cmd_exec)"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-9193"],
                mitigation="Restrict superuser access, update PostgreSQL"
            ),
        ],
        
        # ========== Redis (Port 6379) ==========
        "redis": [
            CVEInfo(
                cve_id="CVE-2022-0543",
                severity="CRITICAL",
                cvss_score=10.0,
                description="Redis Lua Sandbox Escape - Remote Code Execution",
                affected_versions=["Redis on Debian/Ubuntu with Lua 5.1"],
                exploit_available=True,
                exploit_tools=["Metasploit (redis_debian_sandbox_escape)", "redis-rce"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-0543"],
                mitigation="Update Redis package"
            ),
            CVEInfo(
                cve_id="REDIS-NOAUTH",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Redis No Authentication - Remote Code Execution via SSH key injection",
                affected_versions=["All Redis without authentication"],
                exploit_available=True,
                exploit_tools=["redis-cli", "Metasploit (redis_file_upload)", "redis-rogue-server"],
                references=["https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis"],
                mitigation="Enable requirepass, bind to localhost, use ACLs"
            ),
        ],
        
        # ========== MongoDB (Port 27017) ==========
        "mongodb": [
            CVEInfo(
                cve_id="MONGODB-NOAUTH",
                severity="CRITICAL",
                cvss_score=9.8,
                description="MongoDB No Authentication - Database exposed to internet",
                affected_versions=["MongoDB without authentication"],
                exploit_available=True,
                exploit_tools=["mongo shell", "Metasploit", "NoSQLBooster"],
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                mitigation="Enable authentication, bind to localhost, use TLS"
            ),
            CVEInfo(
                cve_id="CVE-2019-2386",
                severity="HIGH",
                cvss_score=7.1,
                description="MongoDB Session Hijacking",
                affected_versions=["MongoDB < 3.6.13, < 4.0.9"],
                exploit_available=True,
                exploit_tools=["Custom scripts"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-2386"],
                mitigation="Update MongoDB"
            ),
        ],
        
        # ========== Elasticsearch (Port 9200) ==========
        "elasticsearch": [
            CVEInfo(
                cve_id="CVE-2015-1427",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Elasticsearch Groovy Sandbox Bypass - Remote Code Execution",
                affected_versions=["Elasticsearch 1.3.x-1.4.2"],
                exploit_available=True,
                exploit_tools=["Metasploit (elasticsearch_script_mvel_rce)", "elastic-exploit"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2015-1427"],
                mitigation="Update Elasticsearch, disable dynamic scripting"
            ),
            CVEInfo(
                cve_id="ES-NOAUTH",
                severity="HIGH",
                cvss_score=8.6,
                description="Elasticsearch No Authentication - Data exposure",
                affected_versions=["Elasticsearch without X-Pack security"],
                exploit_available=True,
                exploit_tools=["curl", "elasticsearch-head", "Kibana"],
                references=["https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api.html"],
                mitigation="Enable X-Pack security, use authentication"
            ),
        ],
        
        # ========== Docker (Port 2375, 2376) ==========
        "docker": [
            CVEInfo(
                cve_id="DOCKER-NOAUTH",
                severity="CRITICAL",
                cvss_score=10.0,
                description="Docker API Exposed - Full host compromise possible",
                affected_versions=["Docker with TCP socket exposed"],
                exploit_available=True,
                exploit_tools=["docker cli", "Metasploit", "docker-escape", "deepce"],
                references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security"],
                mitigation="Never expose Docker socket to network, use TLS with client certs"
            ),
            CVEInfo(
                cve_id="CVE-2019-5736",
                severity="CRITICAL",
                cvss_score=8.6,
                description="runC Container Escape - Host compromise via container",
                affected_versions=["Docker < 18.09.2", "runC < 1.0-rc6"],
                exploit_available=True,
                exploit_tools=["Metasploit", "CVE-2019-5736-PoC"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-5736"],
                mitigation="Update Docker/runC"
            ),
        ],
        
        # ========== VNC (Port 5900) ==========
        "vnc": [
            CVEInfo(
                cve_id="CVE-2006-2369",
                severity="HIGH",
                cvss_score=7.5,
                description="RealVNC Authentication Bypass",
                affected_versions=["RealVNC 4.1.1"],
                exploit_available=True,
                exploit_tools=["Metasploit (realvnc_41_bypass)", "vncviewer"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2006-2369"],
                mitigation="Update RealVNC"
            ),
            CVEInfo(
                cve_id="VNC-WEAK",
                severity="MEDIUM",
                cvss_score=5.9,
                description="VNC uses weak encryption and is susceptible to brute force",
                affected_versions=["All VNC implementations"],
                exploit_available=True,
                exploit_tools=["Hydra", "Ncrack", "Medusa", "vncpwdump"],
                references=["https://book.hacktricks.xyz/network-services-pentesting/5900-5901-vnc"],
                mitigation="Use VNC over SSH tunnel, strong passwords"
            ),
        ],
        
        # ========== SMTP (Port 25, 587) ==========
        "smtp": [
            CVEInfo(
                cve_id="CVE-2019-15846",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Exim Remote Code Execution via SNI",
                affected_versions=["Exim 4.80-4.92.1"],
                exploit_available=True,
                exploit_tools=["Metasploit", "exim-rce-cve-2019-15846"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-15846"],
                mitigation="Update Exim to 4.92.2+"
            ),
            CVEInfo(
                cve_id="CVE-2019-10149",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Exim Remote Command Execution (Return of the WIZard)",
                affected_versions=["Exim 4.87-4.91"],
                exploit_available=True,
                exploit_tools=["Metasploit (exim_exim4_string_format)", "exim-rce"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-10149"],
                mitigation="Update Exim"
            ),
            CVEInfo(
                cve_id="SMTP-RELAY",
                severity="MEDIUM",
                cvss_score=5.3,
                description="Open SMTP Relay - Can be used for spam",
                affected_versions=["Misconfigured SMTP servers"],
                exploit_available=True,
                exploit_tools=["swaks", "smtp-user-enum", "Nmap smtp-open-relay"],
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                mitigation="Configure SMTP authentication, restrict relay"
            ),
        ],
        
        # ========== DNS (Port 53) ==========
        "dns": [
            CVEInfo(
                cve_id="CVE-2020-1350",
                severity="CRITICAL",
                cvss_score=10.0,
                description="SigRed - Windows DNS Server Remote Code Execution",
                affected_versions=["Windows Server 2003-2019"],
                exploit_available=True,
                exploit_tools=["Metasploit", "SigRed-scanner", "PoC scripts"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2020-1350"],
                mitigation="Apply July 2020 patch, limit DNS response size"
            ),
            CVEInfo(
                cve_id="CVE-2021-25216",
                severity="CRITICAL",
                cvss_score=9.8,
                description="BIND9 Buffer Overflow Remote Code Execution",
                affected_versions=["BIND 9.5.0-9.11.29", "9.12.0-9.16.13"],
                exploit_available=True,
                exploit_tools=["Metasploit", "Custom PoC"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-25216"],
                mitigation="Update BIND9"
            ),
        ],
        
        # ========== SNMP (Port 161) ==========
        "snmp": [
            CVEInfo(
                cve_id="SNMP-DEFAULT",
                severity="HIGH",
                cvss_score=7.5,
                description="SNMP Default/Weak Community String",
                affected_versions=["All SNMP devices"],
                exploit_available=True,
                exploit_tools=["snmpwalk", "onesixtyone", "snmp-check", "Metasploit"],
                references=["https://book.hacktricks.xyz/network-services-pentesting/161-162-10161-10162-udp-snmp"],
                mitigation="Change default community strings, use SNMPv3"
            ),
        ],
        
        # ========== LDAP (Port 389, 636) ==========
        "ldap": [
            CVEInfo(
                cve_id="CVE-2021-44228",
                severity="CRITICAL",
                cvss_score=10.0,
                description="Log4Shell via JNDI/LDAP injection",
                affected_versions=["Applications using Log4j 2.0-2.14.1"],
                exploit_available=True,
                exploit_tools=["JNDI-Injection-Exploit", "marshalsec", "log4j-scan"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                mitigation="Update Log4j, disable JNDI lookups"
            ),
            CVEInfo(
                cve_id="LDAP-NULL-BIND",
                severity="MEDIUM",
                cvss_score=5.3,
                description="LDAP Anonymous/Null Bind Allowed",
                affected_versions=["Misconfigured LDAP servers"],
                exploit_available=True,
                exploit_tools=["ldapsearch", "ad-ldap-enum", "windapsearch"],
                references=["https://book.hacktricks.xyz/network-services-pentesting/389-636-ldap"],
                mitigation="Disable anonymous binds"
            ),
        ],
        
        # ========== NFS (Port 2049) ==========
        "nfs": [
            CVEInfo(
                cve_id="NFS-EXPORT",
                severity="HIGH",
                cvss_score=7.5,
                description="NFS Shares Exported to Everyone",
                affected_versions=["Misconfigured NFS servers"],
                exploit_available=True,
                exploit_tools=["showmount", "nfs-ls", "Metasploit (nfs)"],
                references=["https://book.hacktricks.xyz/network-services-pentesting/2049-pentesting-nfs"],
                mitigation="Restrict NFS exports to specific hosts"
            ),
        ],
        
        # ========== Memcached (Port 11211) ==========
        "memcached": [
            CVEInfo(
                cve_id="CVE-2018-1000115",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Memcached DDoS Amplification & Data Exfiltration",
                affected_versions=["Memcached exposed to internet"],
                exploit_available=True,
                exploit_tools=["memcrashed", "memcached-cli", "Metasploit"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-1000115"],
                mitigation="Bind to localhost, enable SASL authentication"
            ),
        ],
        
        # ========== Kubernetes (Port 6443, 10250) ==========
        "kubernetes": [
            CVEInfo(
                cve_id="CVE-2018-1002105",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Kubernetes API Server Privilege Escalation",
                affected_versions=["Kubernetes < 1.10.11, 1.11.5, 1.12.3"],
                exploit_available=True,
                exploit_tools=["kubectl", "kube-hunter", "peirates"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-1002105"],
                mitigation="Update Kubernetes"
            ),
            CVEInfo(
                cve_id="KUBELET-ANON",
                severity="CRITICAL",
                cvss_score=9.8,
                description="Kubelet API Anonymous Access Enabled",
                affected_versions=["Misconfigured Kubernetes"],
                exploit_available=True,
                exploit_tools=["kubeletctl", "kube-hunter", "curl"],
                references=["https://book.hacktricks.xyz/pentesting/pentesting-kubernetes"],
                mitigation="Disable anonymous authentication on kubelet"
            ),
        ],
    }
    
    # ==========================================
    # EXPLOIT TOOL DATABASE
    # ==========================================
    
    EXPLOIT_TOOLS = {
        "metasploit": {
            "name": "Metasploit Framework",
            "type": "Framework",
            "description": "World's most used penetration testing framework",
            "url": "https://www.metasploit.com/",
            "install": "apt install metasploit-framework",
            "usage": "msfconsole -x 'use exploit/multi/handler; set LHOST <IP>; run'"
        },
        "nmap": {
            "name": "Nmap",
            "type": "Scanner",
            "description": "Network scanner with NSE scripting engine",
            "url": "https://nmap.org/",
            "install": "apt install nmap",
            "usage": "nmap -sV --script vuln -p 21,22,23,80,443 <target>"
        },
        "hydra": {
            "name": "THC Hydra",
            "type": "Bruteforce",
            "description": "Fast password brute forcer",
            "url": "https://github.com/vanhauser-thc/thc-hydra",
            "install": "apt install hydra",
            "usage": "hydra -l admin -P /usr/share/wordlists/rockyou.txt <target> ssh"
        },
        "sqlmap": {
            "name": "SQLMap",
            "type": "Injection",
            "description": "Automatic SQL injection tool",
            "url": "https://sqlmap.org/",
            "install": "apt install sqlmap",
            "usage": "sqlmap -u 'http://<target>/page?id=1' --dbs --batch"
        },
        "burpsuite": {
            "name": "Burp Suite",
            "type": "Proxy",
            "description": "Web application security testing",
            "url": "https://portswigger.net/burp",
            "install": "Download from website",
            "usage": "java -jar burpsuite.jar (proxy on 127.0.0.1:8080)"
        },
        "nikto": {
            "name": "Nikto",
            "type": "WebScan",
            "description": "Web server scanner",
            "url": "https://cirt.net/Nikto2",
            "install": "apt install nikto",
            "usage": "nikto -h http://<target> -o report.html -Format htm"
        },
        "gobuster": {
            "name": "Gobuster",
            "type": "Fuzzer",
            "description": "Directory/file brute forcer",
            "url": "https://github.com/OJ/gobuster",
            "install": "apt install gobuster",
            "usage": "gobuster dir -u http://<target> -w /usr/share/dirb/wordlists/common.txt"
        },
        "john": {
            "name": "John the Ripper",
            "type": "Cracker",
            "description": "Password cracker",
            "url": "https://www.openwall.com/john/",
            "install": "apt install john",
            "usage": "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=Raw-MD5"
        },
        "hashcat": {
            "name": "Hashcat",
            "type": "Cracker",
            "description": "Advanced GPU password cracker",
            "url": "https://hashcat.net/hashcat/",
            "install": "apt install hashcat",
            "usage": "hashcat -m 0 -a 0 hash.txt rockyou.txt --force"
        },
        "wireshark": {
            "name": "Wireshark",
            "type": "Sniffer",
            "description": "Network protocol analyzer",
            "url": "https://www.wireshark.org/",
            "install": "apt install wireshark",
            "usage": "wireshark -i eth0 -k -f 'host <target>'"
        },
        "mimikatz": {
            "name": "Mimikatz",
            "type": "PostExploit",
            "description": "Windows credential extraction",
            "url": "https://github.com/gentilkiwi/mimikatz",
            "install": "Download from GitHub",
            "usage": "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'"
        },
        "impacket": {
            "name": "Impacket",
            "type": "PostExploit",
            "description": "Network protocol library for Python",
            "url": "https://github.com/SecureAuthCorp/impacket",
            "install": "pip install impacket",
            "usage": "impacket-psexec domain/user:pass@<target>"
        },
        "crackmapexec": {
            "name": "CrackMapExec",
            "type": "PostExploit",
            "description": "Swiss army knife for pentesting AD",
            "url": "https://github.com/Porchetta-Industries/CrackMapExec",
            "install": "apt install crackmapexec",
            "usage": "crackmapexec smb <target> -u admin -p pass --shares"
        },
        "bloodhound": {
            "name": "BloodHound",
            "type": "Recon",
            "description": "Active Directory attack path analysis",
            "url": "https://github.com/BloodHoundAD/BloodHound",
            "install": "apt install bloodhound",
            "usage": "bloodhound-python -u user -p pass -d domain.local -c All"
        },
        "responder": {
            "name": "Responder",
            "type": "MITM",
            "description": "LLMNR/NBT-NS/MDNS Poisoner",
            "url": "https://github.com/lgandx/Responder",
            "install": "apt install responder",
            "usage": "responder -I eth0 -wrf"
        },
        "ettercap": {
            "name": "Ettercap",
            "type": "MITM",
            "description": "Network sniffing and MITM attacks",
            "url": "https://www.ettercap-project.org/",
            "install": "apt install ettercap-graphical",
            "usage": "ettercap -T -M arp:remote /<gateway>// /<target>//"
        },
        "bettercap": {
            "name": "Bettercap",
            "type": "MITM",
            "description": "Swiss army knife for network attacks",
            "url": "https://www.bettercap.org/",
            "install": "apt install bettercap",
            "usage": "bettercap -iface eth0 -eval 'net.probe on; net.sniff on'"
        },
        "tcpdump": {
            "name": "tcpdump",
            "type": "Sniffer",
            "description": "Command-line packet analyzer",
            "url": "https://www.tcpdump.org/",
            "install": "apt install tcpdump",
            "usage": "tcpdump -i eth0 host <target> -w capture.pcap"
        },
        "searchsploit": {
            "name": "SearchSploit",
            "type": "Database",
            "description": "Exploit-DB command line search",
            "url": "https://www.exploit-db.com/searchsploit",
            "install": "apt install exploitdb",
            "usage": "searchsploit openssh 7.2"
        },
        "enum4linux": {
            "name": "Enum4Linux",
            "type": "Recon",
            "description": "Windows/Samba enumeration tool",
            "url": "https://github.com/cddmp/enum4linux-ng",
            "install": "apt install enum4linux",
            "usage": "enum4linux -a <target>"
        },
        "smbclient": {
            "name": "SMBClient",
            "type": "Recon",
            "description": "SMB/CIFS file sharing client",
            "url": "https://www.samba.org/",
            "install": "apt install smbclient",
            "usage": "smbclient -L //<target> -N"
        },
    }
    
    @classmethod
    def get_cves_for_service(cls, service: str) -> List[CVEInfo]:
        """Get all CVEs for a service"""
        service = service.lower().replace("-", "").replace("_", "")
        
        # Map common service names
        service_map = {
            "microsoft-ds": "smb",
            "netbios-ssn": "smb",
            "ms-wbt-server": "rdp",
            "openssh": "ssh",
            "mysql": "mysql",
            "mariadb": "mysql",
            "postgres": "postgresql",
            "www": "http",
            "https": "http",
            "httpalt": "http",
            "httpproxy": "http",
            "imap": "smtp",
            "pop3": "smtp",
            "domain": "dns",
            "bindshell": "telnet",
        }
        
        mapped_service = service_map.get(service, service)
        return cls.CVE_DATABASE.get(mapped_service, [])
    
    @classmethod
    def get_tool_info(cls, tool_name: str) -> Dict:
        """Get information about an exploit tool"""
        tool_key = tool_name.lower().replace(" ", "").replace("-", "")
        for key, info in cls.EXPLOIT_TOOLS.items():
            if key in tool_key or tool_key in key:
                return info
        return {}


class VulnerabilityScanner:
    """
    Deep vulnerability scanner with CVE identification
    """
    
    # Port to service mapping
    PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "smtp", 111: "rpc", 135: "msrpc", 139: "smb",
        143: "smtp", 161: "snmp", 389: "ldap", 443: "http", 445: "smb",
        465: "smtp", 587: "smtp", 636: "ldap", 993: "smtp", 995: "smtp",
        1433: "mysql", 1521: "oracle", 2049: "nfs", 2375: "docker",
        2376: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 5985: "winrm", 5986: "winrm", 6379: "redis",
        6443: "kubernetes", 8080: "http", 8443: "http", 9200: "elasticsearch",
        10250: "kubernetes", 11211: "memcached", 27017: "mongodb"
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.results: List[VulnerabilityResult] = []
        self.cve_db = CVEDatabase()
    
    def deep_scan(self, host: str, ports: List[int] = None, timeout: float = 5.0) -> List[VulnerabilityResult]:
        """
        Perform deep vulnerability scan on host
        
        Args:
            host: Target IP or hostname
            ports: List of ports to scan (defaults to common vulnerable ports)
            timeout: Connection timeout
            
        Returns:
            List of vulnerability results
        """
        self.logger.info(f"Starting deep vulnerability scan on {host}")
        
        # Default to common vulnerable ports if none specified
        if ports is None or len(ports) == 0:
            ports = list(self.PORT_SERVICE_MAP.keys())
        
        results = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._scan_port, host, port, timeout): port
                for port in ports
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.logger.debug(f"Scan error: {e}")
        
        self.results = results
        return results
    
    def _scan_port(self, host: str, port: int, timeout: float) -> Optional[VulnerabilityResult]:
        """Scan a single port for vulnerabilities"""
        try:
            # Check if port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            
            if result != 0:
                sock.close()
                return None
            
            # Port is open - get banner
            banner = self._grab_banner(sock, port)
            sock.close()
            
            # Identify service
            service = self.PORT_SERVICE_MAP.get(port, "unknown")
            version = self._extract_version(banner)
            
            # Get CVEs for this service
            cves = CVEDatabase.get_cves_for_service(service)
            
            # Calculate risk level
            risk_level = self._calculate_risk(cves)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(service, cves)
            
            return VulnerabilityResult(
                host=host,
                port=port,
                service=service,
                version=version,
                banner=banner[:200] if banner else "",
                vulnerabilities=cves,
                risk_level=risk_level,
                recommendations=recommendations,
                scan_time=datetime.now().isoformat()
            )
            
        except Exception as e:
            self.logger.debug(f"Error scanning {host}:{port} - {e}")
            return None
    
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Grab service banner"""
        try:
            # Send probe based on service
            if port in [80, 8080, 8443, 443]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner on connect
            elif port == 22:
                pass  # SSH sends banner on connect
            elif port == 25:
                pass  # SMTP sends banner on connect
            else:
                sock.send(b"\r\n")
            
            sock.settimeout(3)
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return banner.strip()
        except:
            return ""
    
    def _extract_version(self, banner: str) -> str:
        """Extract version information from banner"""
        if not banner:
            return ""
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+[a-z]?\d*)',  # 1.2.3 or 1.2.3p1
            r'version[:\s]+([^\s\r\n]+)',
            r'v(\d+\.\d+)',
            r'OpenSSH[_\s]+(\d+\.\d+)',
            r'Apache[/\s]+(\d+\.\d+\.\d+)',
            r'nginx[/\s]+(\d+\.\d+\.\d+)',
            r'MySQL[/\s]+(\d+\.\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def _calculate_risk(self, cves: List[CVEInfo]) -> str:
        """Calculate overall risk level"""
        if not cves:
            return "INFO"
        
        max_cvss = max(cve.cvss_score for cve in cves)
        
        if max_cvss >= 9.0:
            return "CRITICAL"
        elif max_cvss >= 7.0:
            return "HIGH"
        elif max_cvss >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, service: str, cves: List[CVEInfo]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Service-specific recommendations
        service_recs = {
            "telnet": "Replace Telnet with SSH immediately",
            "ftp": "Use SFTP or FTPS instead of FTP",
            "http": "Implement HTTPS with valid certificates",
            "smb": "Disable SMBv1, apply latest patches",
            "rdp": "Enable NLA, use VPN for remote access",
            "vnc": "Tunnel VNC over SSH, use strong passwords",
            "redis": "Enable authentication, bind to localhost",
            "mongodb": "Enable authentication, restrict network access",
            "docker": "Never expose Docker socket to network",
        }
        
        if service in service_recs:
            recommendations.append(service_recs[service])
        
        # CVE-specific recommendations
        for cve in cves[:3]:  # Top 3
            if cve.mitigation:
                recommendations.append(f"{cve.cve_id}: {cve.mitigation}")
        
        return recommendations
    
    def get_exploit_suggestions(self, results: List[VulnerabilityResult] = None) -> Dict:
        """Get exploit tool suggestions for discovered vulnerabilities"""
        if results is None:
            results = self.results
        
        suggestions = {
            "critical_findings": [],
            "recommended_tools": [],
            "attack_vectors": []
        }
        
        all_tools = set()
        
        for result in results:
            for cve in result.vulnerabilities:
                if cve.severity in ["CRITICAL", "HIGH"]:
                    suggestions["critical_findings"].append({
                        "host": result.host,
                        "port": result.port,
                        "cve": cve.cve_id,
                        "severity": cve.severity,
                        "cvss": cve.cvss_score,
                        "description": cve.description[:100],
                        "exploit_tools": cve.exploit_tools
                    })
                    all_tools.update(cve.exploit_tools)
                    
                    if cve.exploit_available:
                        suggestions["attack_vectors"].append({
                            "target": f"{result.host}:{result.port}",
                            "vulnerability": cve.cve_id,
                            "tools": cve.exploit_tools[:3]
                        })
        
        # Get detailed tool info
        for tool in list(all_tools)[:10]:
            tool_info = CVEDatabase.get_tool_info(tool)
            if tool_info:
                suggestions["recommended_tools"].append(tool_info)
        
        return suggestions
    
    def generate_report(self, results: List[VulnerabilityResult] = None) -> Dict:
        """Generate comprehensive vulnerability report"""
        if results is None:
            results = self.results
        
        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        all_cves = []
        
        for result in results:
            severity_counts[result.risk_level] = severity_counts.get(result.risk_level, 0) + 1
            all_cves.extend(result.vulnerabilities)
        
        # Unique CVEs
        unique_cves = list({cve.cve_id: cve for cve in all_cves}.values())
        
        return {
            "summary": {
                "total_ports_scanned": len(results),
                "vulnerability_counts": severity_counts,
                "unique_cves_found": len(unique_cves),
                "exploitable_vulnerabilities": sum(1 for c in unique_cves if c.exploit_available)
            },
            "critical_vulnerabilities": [
                cve.to_dict() for cve in unique_cves if cve.severity == "CRITICAL"
            ],
            "high_vulnerabilities": [
                cve.to_dict() for cve in unique_cves if cve.severity == "HIGH"
            ],
            "exploit_suggestions": self.get_exploit_suggestions(results),
            "detailed_results": [r.to_dict() for r in results],
            "scan_time": datetime.now().isoformat()
        }


def deep_vuln_scan(host: str, ports: List[int] = None) -> Dict:
    """
    Convenience function for deep vulnerability scanning
    
    Args:
        host: Target IP or hostname
        ports: List of ports (default: common ports)
    
    Returns:
        Vulnerability report dictionary
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161,
                 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521,
                 2049, 2375, 3306, 3389, 5432, 5900, 5985, 6379, 6443,
                 8080, 8443, 9200, 10250, 11211, 27017]
    
    scanner = VulnerabilityScanner()
    results = scanner.deep_scan(host, ports)
    return scanner.generate_report(results)


if __name__ == "__main__":
    # Demo usage
    print("IntelProbe Vulnerability Scanner")
    print("=" * 50)
    
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"\nScanning {target}...")
        report = deep_vuln_scan(target)
        print(json.dumps(report, indent=2))
    else:
        print("\nUsage: python vuln_scanner.py <target>")
        print("\nExample:")
        print("  python vuln_scanner.py 192.168.1.1")
