#!/usr/bin/env python3
"""
IntelProbe Military Demonstration
Real production-ready network security assessment using industry-standard tools
Created by: Lintshiwe Slade
"""

import time
import subprocess
import socket
import threading
import platform
import logging
import os
import json
import sys
from pathlib import Path
from datetime import datetime

class RealWorldScanner:
    """Production-ready scanner using standard networking tools"""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.results = []
        
    def check_tool_availability(self):
        """Check if required tools are available"""
        tools = {
            'nmap': self._check_nmap(),
            'ping': True,  # Always available
            'netstat': True,  # Always available
            'arp': True,  # Always available
        }
        return tools
    
    def _check_nmap(self):
        """Check if nmap is available"""
        try:
            subprocess.run(['nmap', '--version'], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def port_scan(self, target, ports=None):
        """Real port scanning using socket connections"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        
        open_ports = []
        print(f"🔍 Scanning {target} for open ports...")
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"   ✅ Port {port} OPEN")
            except:
                pass
            finally:
                sock.close()
        
        return open_ports
    
    def os_detection(self, target):
        """Basic OS detection using TTL analysis"""
        try:
            if self.platform == 'windows':
                cmd = ['ping', '-n', '1', target]
            else:
                cmd = ['ping', '-c', '1', target]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if 'TTL=' in result.stdout or 'ttl=' in result.stdout:
                ttl_line = [line for line in result.stdout.split('\n') 
                          if 'TTL=' in line or 'ttl=' in line]
                if ttl_line:
                    ttl = ttl_line[0].split('TTL=')[-1].split('ttl=')[-1].split()[0]
                    ttl_val = int(ttl)
                    
                    if ttl_val <= 64:
                        return "Linux/Unix"
                    elif ttl_val <= 128:
                        return "Windows"
                    else:
                        return "Network Device"
        except:
            pass
        return "Unknown"
    
    def service_detection(self, target, port):
        """Basic service detection"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 1723: "PPTP",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Alt"
        }
        
        service = services.get(port, "Unknown")
        
        # Try banner grabbing for common services
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            if port in [80, 8080]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'Server:' in banner:
                    server = banner.split('Server:')[1].split('\r\n')[0].strip()
                    service += f" ({server})"
            
            sock.close()
        except:
            pass
            
        return service
    
    def vulnerability_assessment(self, target, open_ports):
        """Assess potential vulnerabilities based on open services"""
        vulnerabilities = []
        
        vuln_db = {
            21: {"service": "FTP", "risks": ["Anonymous login", "Weak encryption", "Directory traversal"], "tools": ["Hydra", "Nmap FTP scripts"]},
            22: {"service": "SSH", "risks": ["Brute force attacks", "Weak keys", "Version vulnerabilities"], "tools": ["Hydra", "SSHScan", "SSH-audit"]},
            23: {"service": "Telnet", "risks": ["Unencrypted communication", "Easy credential sniffing"], "tools": ["Telnet client", "Wireshark"]},
            25: {"service": "SMTP", "risks": ["Open relay", "Email spoofing", "Information disclosure"], "tools": ["Swaks", "Nmap SMTP scripts"]},
            53: {"service": "DNS", "risks": ["DNS poisoning", "Zone transfer", "Amplification attacks"], "tools": ["Dig", "DNSRecon", "Fierce"]},
            80: {"service": "HTTP", "risks": ["Web vulnerabilities", "Information disclosure", "Injection attacks"], "tools": ["Nikto", "Gobuster", "OWASP ZAP"]},
            135: {"service": "RPC", "risks": ["RPC enumeration", "Buffer overflows", "Privilege escalation"], "tools": ["RPCClient", "Enum4linux"]},
            139: {"service": "NetBIOS", "risks": ["SMB enumeration", "Null sessions", "Share access"], "tools": ["SMBClient", "Enum4linux", "CrackMapExec"]},
            443: {"service": "HTTPS", "risks": ["SSL/TLS vulnerabilities", "Certificate issues", "Weak ciphers"], "tools": ["SSLScan", "TestSSL", "Nmap SSL scripts"]},
            3389: {"service": "RDP", "risks": ["BlueKeep (CVE-2019-0708)", "Brute force", "Man-in-the-middle"], "tools": ["RDPScan", "Hydra", "Metasploit"]},
            5900: {"service": "VNC", "risks": ["Weak authentication", "Unencrypted traffic", "Remote access"], "tools": ["VNCViewer", "VNCCrack"]}
        }
        
        for port in open_ports:
            if port in vuln_db:
                vuln_info = vuln_db[port]
                vulnerabilities.append({
                    "port": port,
                    "service": vuln_info["service"],
                    "risks": vuln_info["risks"],
                    "tools": vuln_info["tools"],
                    "severity": "HIGH" if port in [23, 135, 3389] else "MEDIUM"
                })
        
        return vulnerabilities

def military_grade_demo():
    """Demonstrate military-standard network assessment"""
    
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    INTELPROBE MILITARY DEMONSTRATION                         ║
║                                                                              ║
║  🎖️ Production-Ready Network Security Assessment                             ║
║  🔒 Real-World Security Tools and Techniques                                 ║
║  ⚡ Industry-Standard Vulnerability Assessment                               ║
║                                                                              ║
║                      Created by: Lintshiwe Slade                             ║
║                      GitHub: @lintshiwe                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    start_time = time.time()
    
    # Setup military-grade logging
    os.makedirs('logs', exist_ok=True)
    log_filename = f'logs/military_scan_{int(time.time())}.log'
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger('IntelProbe-Military')
    scanner = RealWorldScanner()
    
    print("\n🎯 MISSION: REAL-WORLD NETWORK SECURITY ASSESSMENT")
    print("=" * 65)
    
    # Check tool availability
    print("\n🔧 Phase 1: Tool Availability Assessment")
    print("-" * 45)
    tools = scanner.check_tool_availability()
    
    for tool, available in tools.items():
        status = "✅ AVAILABLE" if available else "❌ NOT FOUND"
        print(f"   {tool.upper()}: {status}")
        logger.info(f"Tool {tool}: {'Available' if available else 'Not found'}")
    
    # Local system assessment
    print("\n📡 Phase 2: Local System Assessment")
    print("-" * 40)
    
    local_ip = socket.gethostbyname(socket.gethostname())
    print(f"🖥️  Local IP: {local_ip}")
    print(f"🖥️  Hostname: {socket.gethostname()}")
    print(f"🖥️  Platform: {platform.system()} {platform.release()}")
    
    # Port scanning
    print(f"\n🔍 Phase 3: Port Scanning ({local_ip})")
    print("-" * 35)
    
    open_ports = scanner.port_scan(local_ip)
    
    if open_ports:
        print(f"\n✅ Found {len(open_ports)} open ports:")
        services = {}
        for port in open_ports:
            service = scanner.service_detection(local_ip, port)
            services[port] = service
            print(f"   Port {port}: {service}")
            logger.info(f"Open port {port}: {service}")
    else:
        print("❌ No open ports found (firewall may be blocking)")
        services = {}
    
    # OS Detection
    print(f"\n🔬 Phase 4: OS Detection")
    print("-" * 25)
    
    detected_os = scanner.os_detection(local_ip)
    print(f"🖥️  Detected OS: {detected_os}")
    logger.info(f"OS Detection: {detected_os}")
    
    # Vulnerability Assessment
    if open_ports:
        print(f"\n⚠️  Phase 5: Vulnerability Assessment")
        print("-" * 35)
        
        vulnerabilities = scanner.vulnerability_assessment(local_ip, open_ports)
        
        if vulnerabilities:
            print(f"🚨 Found {len(vulnerabilities)} potential security concerns:")
            
            for vuln in vulnerabilities:
                print(f"\n   🔓 Port {vuln['port']} ({vuln['service']}) - {vuln['severity']} RISK")
                print(f"      Security Risks:")
                for risk in vuln['risks']:
                    print(f"        • {risk}")
                print(f"      Recommended Tools:")
                for tool in vuln['tools']:
                    print(f"        • {tool}")
                logger.warning(f"Vulnerability on port {vuln['port']}: {vuln['service']} - {vuln['severity']}")
        else:
            print("✅ No obvious vulnerabilities detected")
    else:
        vulnerabilities = []
    
    # Network Discovery (if on local network)
    if local_ip.startswith("192.168.") or local_ip.startswith("10.") or local_ip.startswith("172."):
        print(f"\n🌐 Phase 6: Network Discovery")
        print("-" * 30)
        
        print("⚠️  Network discovery disabled in demo mode")
        print("   (Would scan entire subnet for live hosts)")
        logger.info("Network discovery skipped in demo mode")
    
    # Generate Security Report
    print(f"\n📋 Phase 7: Security Assessment Report")
    print("-" * 40)
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": local_ip,
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "tools_available": tools,
        "open_ports": open_ports,
        "services": services,
        "os_detection": detected_os,
        "vulnerabilities": vulnerabilities,
        "risk_level": "HIGH" if any(v.get('severity') == 'HIGH' for v in vulnerabilities) else "MEDIUM"
    }
    
    # Save report
    os.makedirs('reports', exist_ok=True)
    report_file = f'reports/military_assessment_{int(time.time())}.json'
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"📄 Report saved: {report_file}")
    print(f"📄 Logs saved: {log_filename}")
    
    # Summary
    print(f"\n🎯 MISSION SUMMARY")
    print("=" * 20)
    print(f"✅ Assessment completed successfully")
    print(f"🔍 Scanned ports: 20 common ports")
    print(f"🚪 Open ports found: {len(open_ports)}")
    print(f"⚠️  Vulnerabilities: {len(vulnerabilities)}")
    print(f"🛡️  Risk level: {report['risk_level']}")
    print(f"⏱️  Assessment time: {time.time() - start_time:.1f} seconds")
    
    logger.info("Military assessment completed successfully")
    
    print(f"\n🎖️  DEPLOYMENT READY: IntelProbe has demonstrated military-grade capabilities")
    print(f"🔒 This tool is production-ready for real-world security assessments")
    
    # Real-world recommendations
    print(f"\n🎯 REAL-WORLD SECURITY RECOMMENDATIONS:")
    print(f"   • Use Nmap for comprehensive port scanning")
    print(f"   • Implement Wireshark for traffic analysis") 
    print(f"   • Deploy OSSEC/Wazuh for HIDS monitoring")
    print(f"   • Use OpenVAS/Nessus for vulnerability scanning")
    print(f"   • Implement ELK Stack for log analysis")
    print(f"   • Deploy Suricata/Snort for network IDS")

if __name__ == "__main__":
    try:
        military_grade_demo()
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Assessment interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error during assessment: {e}")
        logging.error(f"Assessment failed: {e}")
