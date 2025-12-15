"""Attack Detection Module for IntelProbe.

Enhanced detection capabilities based on netspionage with AI integration.
Provides real-time network monitoring, attack signature matching,
and anomaly detection.

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License
"""

import threading
import time
import logging
from collections import Counter, defaultdict
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
import ipaddress
import socket
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

# Optional dependencies with graceful fallback
try:
    import scapy.all as scapy
    from scapy.all import ARP, Ether, IP, TCP, UDP, ICMP, sniff, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    scapy = None

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

@dataclass
class DetectionAlert:
    """Data class for detection alerts.
    
    Attributes:
        alert_type: Type of detected attack/anomaly.
        severity: Alert severity level (low, medium, high, critical).
        source_ip: Source IP address of the attack.
        target_ip: Target IP address of the attack.
        description: Human-readable description of the alert.
        timestamp: When the alert was generated.
        confidence: Confidence score (0.0-1.0).
        evidence: Supporting evidence data.
    """
    alert_type: str
    severity: str
    source_ip: str = ""
    target_ip: str = ""
    description: str = ""
    timestamp: str = ""
    confidence: float = 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """Initialize default values after dataclass creation."""
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

@dataclass
class AttackSignature:
    """Attack pattern signature for detection.
    
    Attributes:
        name: Human-readable name of the attack.
        pattern_type: Type classification of the attack pattern.
        indicators: List of indicators that identify this attack.
        threshold: Number of events before triggering alert.
        time_window: Time window in seconds for event counting.
        severity: Severity level (low, medium, high, critical).
    """
    name: str
    pattern_type: str
    indicators: List[str]
    threshold: int
    time_window: int
    severity: str

class AttackDetector:
    """Enhanced attack detection with AI-powered analysis.
    
    Provides real-time network monitoring and attack detection
    using signature matching, anomaly detection, and AI analysis.
    
    Attributes:
        config: Configuration manager instance.
        is_monitoring: Whether monitoring is currently active.
        alerts: List of generated detection alerts.
    """
    
    def __init__(self, config) -> None:
        """Initialize attack detector.
        
        Args:
            config: Configuration manager instance.
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._scapy_available = SCAPY_AVAILABLE
        self.detection_config = config.get_detection_config() if hasattr(config, 'get_detection_config') else {}
        
        # Detection state
        self.is_monitoring = False
        self.alerts = []
        self.packet_counts = defaultdict(int)
        self.connection_tracker = defaultdict(list)
        self.arp_table = {}
        self.baseline_traffic = defaultdict(int)
        
        # Attack signatures
        self.signatures = self._load_attack_signatures()
        
        # Monitoring threads
        self.monitor_threads = []
        self.stop_event = threading.Event()
        
        # Statistics
        self.stats = {
            'packets_analyzed': 0,
            'alerts_generated': 0,
            'false_positives': 0,
            'start_time': None
        }
    
    def _load_attack_signatures(self) -> List[AttackSignature]:
        """Load predefined attack signatures"""
        signatures = [
            # ARP Spoofing patterns
            AttackSignature(
                name="ARP Spoofing",
                pattern_type="arp_duplicate",
                indicators=["duplicate_mac", "rapid_arp_replies"],
                threshold=5,
                time_window=60,
                severity="high"
            ),
            
            # Port scanning patterns
            AttackSignature(
                name="Port Scan",
                pattern_type="port_scan",
                indicators=["rapid_port_access", "sequential_ports"],
                threshold=20,
                time_window=30,
                severity="medium"
            ),
            
            # DDoS patterns
            AttackSignature(
                name="SYN Flood",
                pattern_type="syn_flood",
                indicators=["excessive_syn", "no_ack_response"],
                threshold=100,
                time_window=10,
                severity="critical"
            ),
            
            # Network reconnaissance
            AttackSignature(
                name="Network Reconnaissance",
                pattern_type="recon",
                indicators=["icmp_sweep", "dns_enumeration"],
                threshold=50,
                time_window=120,
                severity="medium"
            )
        ]
        
        return signatures
    
    def start_monitoring(self, interface: str = None, duration: int = 0) -> bool:
        """
        Start network monitoring for attack detection
        
        Args:
            interface: Network interface to monitor
            duration: Monitoring duration in seconds (0 = indefinite)
            
        Returns:
            True if monitoring started successfully
        """
        if self.is_monitoring:
            self.logger.warning("Monitoring already in progress")
            return False
        
        try:
            if not interface:
                interface = self._get_default_interface()
            
            if not interface:
                self.logger.error("No suitable network interface found")
                return False
            
            self.logger.info(f"Starting attack detection on interface: {interface}")
            
            # Reset state
            self.is_monitoring = True
            self.stop_event.clear()
            self.stats['start_time'] = time.time()
            
            # Start packet capture thread
            capture_thread = threading.Thread(
                target=self._packet_capture_loop,
                args=(interface, duration),
                daemon=True
            )
            capture_thread.start()
            self.monitor_threads.append(capture_thread)
            
            # Start analysis threads
            analysis_thread = threading.Thread(
                target=self._analysis_loop,
                daemon=True
            )
            analysis_thread.start()
            self.monitor_threads.append(analysis_thread)
            
            self.logger.info("Attack detection monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            self.is_monitoring = False
            return False
    
    def stop_monitoring(self) -> None:
        """Stop network monitoring"""
        if not self.is_monitoring:
            return
        
        self.logger.info("🛑 Stopping attack detection monitoring")
        
        self.is_monitoring = False
        self.stop_event.set()
        
        # Wait for threads to finish
        for thread in self.monitor_threads:
            thread.join(timeout=5)
        
        self.monitor_threads.clear()
        
        # Generate monitoring report
        self._generate_monitoring_report()
        
        self.logger.info("Attack detection monitoring stopped")
    
    def _get_default_interface(self) -> Optional[str]:
        """Get default network interface"""
        try:
            import netifaces
            
            # Get default gateway interface
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                return gws['default'][netifaces.AF_INET][1]
            
            # Fallback to first available interface
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface != 'lo' and not iface.startswith('docker'):
                    return iface
                    
        except ImportError:
            self.logger.warning("netifaces not available, using manual detection")
            
        return None
    
    def _packet_capture_loop(self, interface: str, duration: int) -> None:
        """Main packet capture loop"""
        try:
            def packet_handler(packet):
                if self.stop_event.is_set():
                    return False  # Stop sniffing
                
                self._process_packet(packet)
                return True
            
            # Start packet capture
            if duration > 0:
                scapy.sniff(
                    iface=interface,
                    prn=packet_handler,
                    timeout=duration,
                    store=False,
                    stop_filter=lambda p: self.stop_event.is_set()
                )
            else:
                scapy.sniff(
                    iface=interface,
                    prn=packet_handler,
                    store=False,
                    stop_filter=lambda p: self.stop_event.is_set()
                )
                
        except Exception as e:
            self.logger.error(f"Packet capture failed: {e}")
            self.is_monitoring = False
    
    def _process_packet(self, packet) -> None:
        """Process individual packets for attack patterns"""
        try:
            self.stats['packets_analyzed'] += 1
            
            # ARP packet analysis
            if packet.haslayer(ARP):
                self._analyze_arp_packet(packet)
            
            # IP packet analysis
            if packet.haslayer(IP):
                self._analyze_ip_packet(packet)
            
            # TCP packet analysis
            if packet.haslayer(TCP):
                self._analyze_tcp_packet(packet)
            
            # Update traffic baseline
            self._update_traffic_baseline(packet)
            
        except Exception as e:
            self.logger.debug(f"Packet processing error: {e}")
    
    def _analyze_arp_packet(self, packet) -> None:
        """Analyze ARP packets for spoofing attacks"""
        try:
            if packet[ARP].op == 2:  # ARP reply
                src_ip = packet[ARP].psrc
                src_mac = packet[ARP].hwsrc
                
                # Check for ARP spoofing
                if src_ip in self.arp_table:
                    if self.arp_table[src_ip] != src_mac:
                        # Potential ARP spoofing detected
                        alert = DetectionAlert(
                            alert_type="ARP Spoofing",
                            severity="high",
                            source_ip=src_ip,
                            description=f"MAC address change detected for {src_ip}: {self.arp_table[src_ip]} -> {src_mac}",
                            evidence={
                                'old_mac': self.arp_table[src_ip],
                                'new_mac': src_mac,
                                'packet_type': 'ARP Reply'
                            }
                        )
                        self._generate_alert(alert)
                
                # Update ARP table
                self.arp_table[src_ip] = src_mac
                
        except Exception as e:
            self.logger.debug(f"ARP analysis error: {e}")
    
    def _analyze_ip_packet(self, packet) -> None:
        """Analyze IP packets for various attacks"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Track connections
            connection_key = f"{src_ip}->{dst_ip}"
            self.connection_tracker[connection_key].append(time.time())
            
            # Clean old connections (keep last 5 minutes)
            cutoff_time = time.time() - 300
            self.connection_tracker[connection_key] = [
                t for t in self.connection_tracker[connection_key] if t > cutoff_time
            ]
            
            # Check for reconnaissance patterns
            if len(self.connection_tracker[connection_key]) > 20:  # Many connections in 5 minutes
                alert = DetectionAlert(
                    alert_type="Network Reconnaissance",
                    severity="medium",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    description=f"Potential reconnaissance: {len(self.connection_tracker[connection_key])} connections from {src_ip} to {dst_ip}",
                    evidence={
                        'connection_count': len(self.connection_tracker[connection_key]),
                        'time_window': '5 minutes'
                    }
                )
                self._generate_alert(alert)
            
        except Exception as e:
            self.logger.debug(f"IP analysis error: {e}")
    
    def _analyze_tcp_packet(self, packet) -> None:
        """Analyze TCP packets for attack patterns"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            # SYN flood detection
            if flags & 0x02:  # SYN flag set
                syn_key = f"syn_{src_ip}"
                self.packet_counts[syn_key] += 1
                
                # Check SYN flood threshold
                if self.packet_counts[syn_key] > 50:  # Threshold for SYN flood
                    alert = DetectionAlert(
                        alert_type="SYN Flood Attack",
                        severity="critical",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                        description=f"SYN flood detected from {src_ip}: {self.packet_counts[syn_key]} SYN packets",
                        evidence={
                            'syn_count': self.packet_counts[syn_key],
                            'target_port': dst_port
                        }
                    )
                    self._generate_alert(alert)
                    
                    # Reset counter to avoid spam
                    self.packet_counts[syn_key] = 0
            
            # Port scanning detection
            scan_key = f"portscan_{src_ip}"
            if dst_port not in [80, 443, 22, 21, 25]:  # Exclude common ports
                self.packet_counts[scan_key] += 1
                
                if self.packet_counts[scan_key] > 30:  # Port scan threshold
                    alert = DetectionAlert(
                        alert_type="Port Scanning",
                        severity="medium",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                        description=f"Port scanning detected from {src_ip}: {self.packet_counts[scan_key]} port attempts",
                        evidence={
                            'scan_attempts': self.packet_counts[scan_key],
                            'latest_port': dst_port
                        }
                    )
                    self._generate_alert(alert)
                    self.packet_counts[scan_key] = 0
            
        except Exception as e:
            self.logger.debug(f"TCP analysis error: {e}")
    
    def _update_traffic_baseline(self, packet) -> None:
        """Update baseline traffic patterns for anomaly detection"""
        try:
            # Simple traffic counting for baseline
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                self.baseline_traffic[src_ip] += 1
                
        except Exception as e:
            self.logger.debug(f"Baseline update error: {e}")
    
    def _analysis_loop(self) -> None:
        """Background analysis loop for pattern detection"""
        while not self.stop_event.is_set():
            try:
                # Periodic cleanup of old data
                self._cleanup_old_data()
                
                # Analyze traffic patterns
                self._analyze_traffic_patterns()
                
                # Sleep for analysis interval
                time.sleep(30)  # Analyze every 30 seconds
                
            except Exception as e:
                self.logger.debug(f"Analysis loop error: {e}")
    
    def _cleanup_old_data(self) -> None:
        """Clean up old tracking data"""
        try:
            current_time = time.time()
            cutoff_time = current_time - 600  # Keep last 10 minutes
            
            # Clean connection tracker
            for key in list(self.connection_tracker.keys()):
                self.connection_tracker[key] = [
                    t for t in self.connection_tracker[key] if t > cutoff_time
                ]
                if not self.connection_tracker[key]:
                    del self.connection_tracker[key]
            
            # Clean packet counts (reset every 5 minutes)
            if int(current_time) % 300 == 0:
                self.packet_counts.clear()
                
        except Exception as e:
            self.logger.debug(f"Cleanup error: {e}")
    
    def _analyze_traffic_patterns(self) -> None:
        """Analyze overall traffic patterns for anomalies"""
        try:
            # Detect traffic anomalies
            for ip, count in self.baseline_traffic.items():
                if count > 1000:  # High traffic threshold
                    alert = DetectionAlert(
                        alert_type="Traffic Anomaly",
                        severity="medium",
                        source_ip=ip,
                        description=f"Unusual traffic volume from {ip}: {count} packets",
                        evidence={
                            'packet_count': count,
                            'analysis_window': '30 seconds'
                        }
                    )
                    self._generate_alert(alert)
            
            # Reset baseline for next window
            self.baseline_traffic.clear()
            
        except Exception as e:
            self.logger.debug(f"Pattern analysis error: {e}")
    
    def _generate_alert(self, alert: DetectionAlert) -> None:
        """Generate and process security alert"""
        try:
            # Add to alerts list
            self.alerts.append(alert)
            self.stats['alerts_generated'] += 1
            
            # Log the alert
            severity_levels = {
                'low': 'LOW',
                'medium': 'MEDIUM', 
                'high': 'HIGH',
                'critical': 'CRITICAL'
            }
            
            level = severity_levels.get(alert.severity, 'UNKNOWN')
            
            self.logger.warning(
                f"SECURITY ALERT [{level}] - "
                f"{alert.alert_type}: {alert.description}"
            )
            
            # Trigger alert handlers if configured
            self._handle_alert(alert)
            
        except Exception as e:
            self.logger.error(f"Alert generation failed: {e}")
    
    def _handle_alert(self, alert: DetectionAlert) -> None:
        """Handle generated alerts (notifications, blocking, etc.)"""
        try:
            # Save alert to file
            alert_data = {
                'timestamp': alert.timestamp,
                'type': alert.alert_type,
                'severity': alert.severity,
                'source_ip': alert.source_ip,
                'target_ip': alert.target_ip,
                'description': alert.description,
                'confidence': alert.confidence,
                'evidence': alert.evidence
            }
            
            # Create alerts directory if it doesn't exist
            from pathlib import Path
            alerts_dir = Path("alerts")
            alerts_dir.mkdir(exist_ok=True)
            
            # Save alert to JSON file
            alert_file = alerts_dir / f"alert_{int(time.time())}.json"
            with open(alert_file, 'w') as f:
                json.dump(alert_data, f, indent=2)
            
        except Exception as e:
            self.logger.debug(f"Alert handling error: {e}")
    
    def get_detection_summary(self) -> Dict[str, Any]:
        """Get detection statistics and summary"""
        runtime = time.time() - (self.stats['start_time'] or time.time())
        
        # Count alerts by severity
        severity_counts = defaultdict(int)
        for alert in self.alerts:
            severity_counts[alert.severity] += 1
        
        # Count alerts by type
        type_counts = defaultdict(int)
        for alert in self.alerts:
            type_counts[alert.alert_type] += 1
        
        return {
            'monitoring_status': 'active' if self.is_monitoring else 'stopped',
            'runtime_seconds': runtime,
            'packets_analyzed': self.stats['packets_analyzed'],
            'total_alerts': len(self.alerts),
            'alerts_by_severity': dict(severity_counts),
            'alerts_by_type': dict(type_counts),
            'detection_rate': len(self.alerts) / max(1, runtime / 60),  # alerts per minute
            'recent_alerts': [
                {
                    'type': alert.alert_type,
                    'severity': alert.severity,
                    'timestamp': alert.timestamp,
                    'description': alert.description
                }
                for alert in self.alerts[-5:]  # Last 5 alerts
            ]
        }
    
    def _generate_monitoring_report(self) -> None:
        """Generate final monitoring report"""
        try:
            summary = self.get_detection_summary()
            
            report = {
                'report_type': 'Attack Detection Report',
                'generated_at': time.strftime("%Y-%m-%d %H:%M:%S"),
                'monitoring_period': summary['runtime_seconds'],
                'summary': summary,
                'all_alerts': [
                    {
                        'timestamp': alert.timestamp,
                        'type': alert.alert_type,
                        'severity': alert.severity,
                        'source_ip': alert.source_ip,
                        'target_ip': alert.target_ip,
                        'description': alert.description,
                        'confidence': alert.confidence,
                        'evidence': alert.evidence
                    }
                    for alert in self.alerts
                ]
            }
            
            # Save report
            from pathlib import Path
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            
            report_file = reports_dir / f"detection_report_{int(time.time())}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.info(f"Detection report saved: {report_file}")
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
    
    def detect_arp_spoofing(self, network: str, interface: str = None, duration: int = 60) -> List[DetectionAlert]:
        """
        Dedicated ARP spoofing detection
        
        Args:
            network: Network to monitor (e.g., 192.168.1.0/24)
            interface: Network interface
            duration: Monitoring duration in seconds
            
        Returns:
            List of ARP spoofing alerts
        """
        self.logger.info(f"Starting dedicated ARP spoofing detection on {network}")
        
        arp_alerts = []
        arp_table = {}
        
        def process_arp(packet):
            if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc
                
                if ip in arp_table and arp_table[ip] != mac:
                    alert = DetectionAlert(
                        alert_type="ARP Spoofing",
                        severity="high",
                        source_ip=ip,
                        description=f"ARP spoofing detected: {ip} changed from {arp_table[ip]} to {mac}",
                        evidence={
                            'original_mac': arp_table[ip],
                            'spoofed_mac': mac
                        }
                    )
                    arp_alerts.append(alert)
                    self.logger.warning(f"ARP Spoofing Alert: {alert.description}")
                
                arp_table[ip] = mac
        
        try:
            # Perform initial ARP scan to build baseline
            self._build_arp_baseline(network, arp_table)
            
            # Monitor for changes
            scapy.sniff(
                filter="arp",
                prn=process_arp,
                timeout=duration,
                iface=interface,
                store=False
            )
            
            self.logger.info(f"ARP spoofing detection completed. Found {len(arp_alerts)} alerts")
            return arp_alerts
            
        except Exception as e:
            self.logger.error(f"ARP spoofing detection failed: {e}")
            return []
    
    def _build_arp_baseline(self, network: str, arp_table: Dict[str, str]) -> None:
        """Build baseline ARP table for the network"""
        try:
            # Create ARP request for the network
            network_obj = ipaddress.ip_network(network, strict=False)
            
            # Limit to first 50 hosts for performance
            hosts = list(network_obj.hosts())[:50]
            
            for host in hosts:
                try:
                    # Create ARP request
                    arp_request = ARP(pdst=str(host))
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = broadcast / arp_request
                    
                    # Send and receive
                    answered = scapy.srp(packet, timeout=1, verbose=False)[0]
                    
                    for element in answered:
                        ip = element[1].psrc
                        mac = element[1].hwsrc
                        arp_table[ip] = mac
                        
                except Exception as e:
                    self.logger.debug(f"ARP baseline error for {host}: {e}")
            
            self.logger.info(f"📋 Built ARP baseline with {len(arp_table)} entries")
            
        except Exception as e:
            self.logger.error(f"Failed to build ARP baseline: {e}")
    
    def export_alerts(self, filename: str, format: str = "json") -> bool:
        """
        Export alerts to file
        
        Args:
            filename: Output filename
            format: Export format (json, csv)
            
        Returns:
            True if export successful
        """
        try:
            if format.lower() == "json":
                alerts_data = [
                    {
                        'timestamp': alert.timestamp,
                        'type': alert.alert_type,
                        'severity': alert.severity,
                        'source_ip': alert.source_ip,
                        'target_ip': alert.target_ip,
                        'description': alert.description,
                        'confidence': alert.confidence,
                        'evidence': alert.evidence
                    }
                    for alert in self.alerts
                ]
                
                with open(filename, 'w') as f:
                    json.dump(alerts_data, f, indent=2)
                    
            elif format.lower() == "csv":
                import pandas as pd
                
                df = pd.DataFrame([
                    {
                        'Timestamp': alert.timestamp,
                        'Type': alert.alert_type,
                        'Severity': alert.severity,
                        'Source_IP': alert.source_ip,
                        'Target_IP': alert.target_ip,
                        'Description': alert.description,
                        'Confidence': alert.confidence
                    }
                    for alert in self.alerts
                ])
                
                df.to_csv(filename, index=False)
            
            self.logger.info(f"Alerts exported to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Alert export failed: {e}")
            return False
