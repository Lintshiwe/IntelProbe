#!/usr/bin/env python3
"""
IntelProbe Real-World Network Scanner
Military-grade network reconnaissance with exploitation intelligence

Author: Lintshiwe Slade (@lintshiwe)
Enhanced from netspionage framework with AI-powered capabilities
"""

import time
import json
import os
import sys
import subprocess
import socket
import ipaddress
from typing import List, Dict

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_banner():
    """Display the military-grade banner"""
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                 🎖️ INTELPROBE REAL-WORLD NETWORK SCANNER 🎖️                  ║")
    print("║                                                                              ║")
    print("║  🔍 Military-Grade Network Reconnaissance & Exploitation Intelligence        ║")
    print("║  🎯 Enhanced from netspionage framework with AI capabilities                 ║")
    print("║  ⚡ Real-Time Threat Detection and Analysis                                  ║")
    print("║                                                                              ║")
    print("║                      Created by: Lintshiwe Slade                             ║")
    print("║                         GitHub: @lintshiwe                                   ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")

def discover_network_interfaces():
    """Discover available network interfaces and their subnets"""
    interfaces = []
    
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=10)
            output = result.stdout
            
            current_interface = None
            current_ip = None
            
            for line in output.split('\n'):
                line = line.strip()
                if "adapter" in line and ":" in line:
                    current_interface = line.split("adapter")[1].split(":")[0].strip()
                elif "IPv4 Address" in line and current_interface:
                    try:
                        ip = line.split(":")[1].strip()
                        if ip and not ip.startswith("169.254") and not ip.startswith("127."):
                            # Calculate network (assume /24)
                            octets = ip.split('.')
                            network = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                            interfaces.append({
                                "interface": current_interface,
                                "ip": ip,
                                "network": network
                            })
                    except:
                        pass
        else:
            # Linux/macOS
            result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split('\n'):
                if "src" in line and "/" in line and "default" not in line:
                    try:
                        parts = line.split()
                        network = parts[0]
                        if "src" in parts:
                            src_ip = parts[parts.index("src") + 1]
                            interfaces.append({
                                "interface": "auto-detected",
                                "ip": src_ip,
                                "network": network
                            })
                    except:
                        pass
                        
    except Exception as e:
        print(f"❌ Error discovering interfaces: {e}")
    
    return interfaces

def scan_host_simple(target_ip: str, ports: List[int]) -> Dict:
    """Simple host scanning"""
    result = {
        "ip": target_ip,
        "hostname": None,
        "open_ports": [],
        "services": {},
        "os_guess": "Unknown"
    }
    
    # Check if host is alive
    alive = False
    try:
        # Try ICMP ping first
        if os.name == 'nt':
            ping_result = subprocess.run(
                ["ping", "-n", "1", "-w", "1000", target_ip],
                capture_output=True, text=True, timeout=3
            )
            alive = ping_result.returncode == 0
        else:
            ping_result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", target_ip],
                capture_output=True, text=True, timeout=3
            )
            alive = ping_result.returncode == 0
    except:
        pass
    
    # If ping fails, try TCP connect to common ports
    if not alive:
        for port in [80, 443, 22, 21, 23]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((target_ip, port)) == 0:
                    alive = True
                    result["open_ports"].append(port)
                sock.close()
            except:
                pass
    
    if not alive:
        return None
    
    # Hostname resolution
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
        result["hostname"] = hostname
    except:
        pass
    
    # Port scanning
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
    }
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex((target_ip, port)) == 0:
                result["open_ports"].append(port)
                result["services"][port] = services.get(port, "unknown")
            sock.close()
        except:
            pass
    
    # Simple OS detection
    if 135 in result["open_ports"] or 445 in result["open_ports"]:
        result["os_guess"] = "Windows"
    elif 22 in result["open_ports"]:
        result["os_guess"] = "Linux/Unix"
    elif 80 in result["open_ports"] and 23 in result["open_ports"]:
        result["os_guess"] = "Network Device"
    
    return result

def scan_network_range(network: str, max_hosts: int = 50) -> List[Dict]:
    """Scan network range for active devices"""
    print(f"🔍 Scanning network: {network}")
    
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        print(f"❌ Invalid network format: {network}")
        return []
    
    # Collect target IPs (limit for performance)
    targets = []
    for ip in net.hosts():
        targets.append(str(ip))
        if len(targets) >= max_hosts:
            break
    
    # Also check common gateway addresses
    try:
        gateway_candidates = [
            str(net.network_address),  # Network address
            str(ipaddress.ip_address(int(net.network_address) + 1)),  # .1
            str(ipaddress.ip_address(int(net.broadcast_address) - 1))  # Last host
        ]
        for gw in gateway_candidates:
            if gw not in targets:
                targets.insert(0, gw)
    except:
        pass
    
    print(f"📡 Scanning {len(targets)} potential hosts...")
    
    # Common ports to scan
    common_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389, 5900, 8080]
    
    active_devices = []
    scanned = 0
    
    for target in targets:
        scanned += 1
        if scanned % 10 == 0:
            print(f"   Progress: {scanned}/{len(targets)} hosts...")
        
        device = scan_host_simple(target, common_ports)
        if device and device["open_ports"]:
            active_devices.append(device)
            print(f"✅ Active device: {device['ip']} ({len(device['open_ports'])} ports)")
    
    return active_devices

def generate_exploitation_suggestions(device: Dict) -> List[Dict]:
    """Generate exploitation suggestions for discovered services"""
    exploits = []
    
    for port, service in device["services"].items():
        if port == 21:  # FTP
            exploits.append({
                "service": "FTP",
                "vulnerability": "Anonymous access / Weak credentials",
                "tools": ["ftp", "hydra", "medusa"],
                "severity": "MEDIUM",
                "description": "Check for anonymous FTP access and brute force credentials"
            })
        elif port == 22:  # SSH
            exploits.append({
                "service": "SSH",
                "vulnerability": "Weak credentials / Default passwords",
                "tools": ["hydra", "medusa", "ncrack"],
                "severity": "HIGH",
                "description": "Brute force SSH credentials"
            })
        elif port == 23:  # Telnet
            exploits.append({
                "service": "Telnet",
                "vulnerability": "Unencrypted authentication",
                "tools": ["telnet", "medusa", "hydra"],
                "severity": "HIGH",
                "description": "Unencrypted protocol - credentials can be intercepted"
            })
        elif port in [80, 8080]:  # HTTP
            exploits.append({
                "service": "HTTP",
                "vulnerability": "Web application vulnerabilities",
                "tools": ["nikto", "dirb", "gobuster", "sqlmap"],
                "severity": "HIGH",
                "description": "Scan for OWASP Top 10 vulnerabilities"
            })
        elif port == 445:  # SMB
            exploits.append({
                "service": "SMB",
                "vulnerability": "EternalBlue (MS17-010)",
                "tools": ["metasploit", "AutoBlue-MS17-010"],
                "severity": "CRITICAL",
                "description": "SMB vulnerability allowing remote code execution"
            })
            exploits.append({
                "service": "SMB",
                "vulnerability": "SMB null session",
                "tools": ["enum4linux", "smbclient", "rpcclient"],
                "severity": "MEDIUM",
                "description": "Enumerate shares and users"
            })
        elif port == 3389:  # RDP
            exploits.append({
                "service": "RDP",
                "vulnerability": "BlueKeep (CVE-2019-0708)",
                "tools": ["metasploit", "bluekeep-scanner"],
                "severity": "CRITICAL",
                "description": "Remote code execution via RDP vulnerability"
            })
            exploits.append({
                "service": "RDP",
                "vulnerability": "RDP brute force",
                "tools": ["hydra", "crowbar", "rdesktop"],
                "severity": "HIGH",
                "description": "Brute force RDP credentials"
            })
        elif port == 5900:  # VNC
            exploits.append({
                "service": "VNC",
                "vulnerability": "Weak VNC authentication",
                "tools": ["vnccrack", "medusa"],
                "severity": "HIGH",
                "description": "VNC often has weak or no authentication"
            })
    
    return exploits

def display_results(devices: List[Dict]):
    """Display comprehensive scan results"""
    if not devices:
        print("❌ No active devices discovered")
        return
    
    print(f"\n🎯 NETWORK RECONNAISSANCE COMPLETE")
    print(f"═══════════════════════════════════════════════════════")
    print(f"📊 Total active devices discovered: {len(devices)}")
    print(f"🔌 Total open ports found: {sum(len(d['open_ports']) for d in devices)}")
    
    # Device summary
    print(f"\n🖥️  DISCOVERED DEVICES:")
    print("─────────────────────────────────────────────────────────")
    
    for i, device in enumerate(devices, 1):
        print(f"{i}. 📡 {device['ip']} ({device['hostname'] or 'Unknown hostname'})")
        print(f"   🖥️  OS: {device['os_guess']}")
        print(f"   🔌 Open Ports: {', '.join(map(str, device['open_ports']))}")
        
        if device['services']:
            print(f"   🛠️  Services:")
            for port, service in device['services'].items():
                print(f"       - Port {port}: {service}")
        
        # Generate and display exploitation suggestions
        exploits = generate_exploitation_suggestions(device)
        if exploits:
            print(f"   ⚔️  Exploitation Opportunities:")
            for exploit in exploits[:3]:  # Show top 3
                severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(exploit["severity"], "⚪")
                print(f"       {severity_icon} {exploit['vulnerability']} ({exploit['severity']})")
                print(f"          Tools: {', '.join(exploit['tools'][:3])}")
        
        print()
    
    # High-risk summary
    high_risk_services = []
    for device in devices:
        for port in device['open_ports']:
            if port in [21, 23, 445, 3389, 5900]:  # High-risk ports
                service = device['services'].get(port, 'unknown')
                high_risk_services.append(f"{device['ip']}:{port} ({service})")
    
    if high_risk_services:
        print("🚨 HIGH-RISK SERVICES DETECTED:")
        print("─────────────────────────────────────────────────────────")
        for service in high_risk_services[:10]:
            print(f"   ⚠️  {service}")
        print()
    
    # Recommendations
    print("🛡️  SECURITY RECOMMENDATIONS:")
    print("─────────────────────────────────────────────────────────")
    
    smb_count = sum(1 for d in devices if 445 in d['open_ports'])
    if smb_count > 0:
        print(f"   🚨 {smb_count} devices with SMB - Update to latest patches (MS17-010)")
    
    rdp_count = sum(1 for d in devices if 3389 in d['open_ports'])
    if rdp_count > 0:
        print(f"   ⚠️  {rdp_count} devices with RDP - Enable NLA and strong passwords")
    
    telnet_count = sum(1 for d in devices if 23 in d['open_ports'])
    if telnet_count > 0:
        print(f"   🔴 {telnet_count} devices with Telnet - Replace with SSH immediately")
    
    http_only = sum(1 for d in devices if 80 in d['open_ports'] and 443 not in d['open_ports'])
    if http_only > 0:
        print(f"   🔒 {http_only} devices with HTTP only - Implement HTTPS")

def save_report(devices: List[Dict], interfaces: List[Dict]):
    """Save comprehensive scan report"""
    report = {
        "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scanner": "IntelProbe Real-World Network Scanner",
        "author": "Lintshiwe Slade (@lintshiwe)",
        "summary": {
            "total_devices": len(devices),
            "total_open_ports": sum(len(d['open_ports']) for d in devices),
            "networks_scanned": len(interfaces),
            "high_risk_devices": len([d for d in devices if any(p in [445, 3389, 23] for p in d['open_ports'])])
        },
        "network_interfaces": interfaces,
        "discovered_devices": devices
    }
    
    # Save report
    os.makedirs("reports", exist_ok=True)
    report_file = f"reports/realworld_scan_{int(time.time())}.json"
    
    try:
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"📄 Comprehensive report saved: {report_file}")
    except Exception as e:
        print(f"❌ Failed to save report: {e}")

def main():
    """Main scanning function"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    print("\n🎖️ REAL-WORLD NETWORK RECONNAISSANCE MISSION")
    print("═══════════════════════════════════════════════════════════════")
    print("This scanner will perform actual network reconnaissance on your local networks")
    print("All scanning is performed on networks you have authorized access to")
    print()
    
    try:
        # Phase 1: Network Discovery
        print("🌐 PHASE 1: NETWORK INTERFACE DISCOVERY")
        print("─────────────────────────────────────────────────────────")
        
        interfaces = discover_network_interfaces()
        
        if not interfaces:
            print("❌ No network interfaces discovered")
            return
        
        print("✅ Discovered Network Interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"   {i}. {iface['interface']}: {iface['ip']} ({iface['network']})")
        
        # Phase 2: Network Scanning
        print(f"\n🔍 PHASE 2: COMPREHENSIVE NETWORK SCANNING")
        print("─────────────────────────────────────────────────────────")
        
        all_devices = []
        
        for iface in interfaces:
            print(f"\n📡 Scanning {iface['network']}...")
            devices = scan_network_range(iface['network'], max_hosts=30)
            if devices:
                all_devices.extend(devices)
                print(f"✅ Found {len(devices)} active devices")
            else:
                print("   No active devices found")
        
        # Phase 3: Results Analysis
        print(f"\n📊 PHASE 3: INTELLIGENCE ANALYSIS")
        print("─────────────────────────────────────────────────────────")
        
        display_results(all_devices)
        
        # Save report
        save_report(all_devices, interfaces)
        
        print("\n🎯 RECONNAISSANCE MISSION COMPLETE")
        print("═══════════════════════════════════════════════════════════════")
        print("IntelProbe has successfully demonstrated real-world network scanning capabilities")
        print("Author: Lintshiwe Slade | GitHub: @lintshiwe")
        
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during scanning: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
