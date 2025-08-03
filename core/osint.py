"""
OSINT (Open Source Intelligence) Module for IntelProbe
Enhanced intelligence gathering capabilities based on netspionage
"""

import requests
import json
import time
import socket
import dns.resolver
import ipaddress
from typing import Dict, List, Any, Optional, Tuple
import logging
from dataclasses import dataclass
from pathlib import Path
import re
import concurrent.futures
import threading
from urllib.parse import urljoin
import hashlib

@dataclass
class MacVendorInfo:
    """MAC address vendor information"""
    mac_address: str
    vendor: str
    company: str
    address: str = ""
    country: str = ""
    block_type: str = ""
    last_updated: str = ""
    
    def __post_init__(self):
        if not self.last_updated:
            self.last_updated = time.strftime("%Y-%m-%d %H:%M:%S")

@dataclass
class IPIntelligence:
    """IP address intelligence data"""
    ip_address: str
    hostname: str = ""
    country: str = ""
    city: str = ""
    organization: str = ""
    isp: str = ""
    asn: str = ""
    threat_level: str = "unknown"
    is_malicious: bool = False
    vpn_detected: bool = False
    proxy_detected: bool = False
    last_seen: str = ""
    
    def __post_init__(self):
        if not self.last_seen:
            self.last_seen = time.strftime("%Y-%m-%d %H:%M:%S")

@dataclass
class DomainIntelligence:
    """Domain intelligence information"""
    domain: str
    ip_addresses: List[str] = None
    nameservers: List[str] = None
    mx_records: List[str] = None
    txt_records: List[str] = None
    creation_date: str = ""
    expiration_date: str = ""
    registrar: str = ""
    reputation_score: float = 0.0
    is_suspicious: bool = False
    
    def __post_init__(self):
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.nameservers is None:
            self.nameservers = []
        if self.mx_records is None:
            self.mx_records = []
        if self.txt_records is None:
            self.txt_records = []

class OSINTGatherer:
    """OSINT intelligence gathering module"""
    
    def __init__(self, config):
        """Initialize OSINT gatherer"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'IntelProbe/2.0 OSINT Module'
        })
        
        # API endpoints
        self.endpoints = {
            'macvendors': 'https://macvendors.co/api/',
            'ipapi': 'http://ip-api.com/json/',
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/check',
            'virustotal': 'https://www.virustotal.com/vtapi/v2/',
            'shodan': 'https://api.shodan.io/',
            'ipgeolocation': 'https://api.ipgeolocation.io/ipgeo'
        }
        
        # Load API keys from config
        self.api_keys = {
            'abuseipdb': config.get('OSINT', 'AbuseIPDB_API_Key', ''),
            'virustotal': config.get('OSINT', 'VirusTotal_API_Key', ''),
            'shodan': config.get('OSINT', 'Shodan_API_Key', ''),
            'ipgeolocation': config.get('OSINT', 'IPGeolocation_API_Key', '')
        }
        
        # Cache for results
        self.cache = {}
        self.cache_timeout = config.get('Performance', 'CacheTimeout', 3600)
    
    def lookup_mac_address(self, mac_address: str) -> MacVendorInfo:
        """
        Lookup MAC address vendor information
        
        Args:
            mac_address: MAC address to lookup
            
        Returns:
            MacVendorInfo object with vendor details
        """
        self.logger.info(f"🔍 Looking up MAC address: {mac_address}")
        
        # Normalize MAC address format
        mac_clean = self._normalize_mac(mac_address)
        
        # Check cache first
        cache_key = f"mac_{mac_clean}"
        if cache_key in self.cache:
            cache_time, data = self.cache[cache_key]
            if time.time() - cache_time < self.cache_timeout:
                self.logger.debug("📋 Using cached MAC lookup result")
                return data
        
        try:
            # Try multiple MAC vendor APIs
            vendor_info = self._lookup_mac_macvendors(mac_clean)
            
            if not vendor_info.vendor:
                vendor_info = self._lookup_mac_ieee(mac_clean)
            
            # Cache the result
            self.cache[cache_key] = (time.time(), vendor_info)
            
            self.logger.info(f"✅ MAC lookup completed: {vendor_info.vendor}")
            return vendor_info
            
        except Exception as e:
            self.logger.error(f"❌ MAC lookup failed: {e}")
            return MacVendorInfo(
                mac_address=mac_address,
                vendor="Unknown",
                company="Lookup failed"
            )
    
    def _normalize_mac(self, mac_address: str) -> str:
        """Normalize MAC address format"""
        # Remove common separators and convert to uppercase
        mac_clean = re.sub(r'[:-]', '', mac_address.upper())
        
        # Add colons in standard format
        if len(mac_clean) == 12:
            return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
        
        return mac_address
    
    def _lookup_mac_macvendors(self, mac_address: str) -> MacVendorInfo:
        """Lookup MAC using macvendors.co API"""
        try:
            url = f"{self.endpoints['macvendors']}{mac_address}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('result') and not data['result'].get('error'):
                    result = data['result']
                    return MacVendorInfo(
                        mac_address=mac_address,
                        vendor=result.get('company', 'Unknown'),
                        company=result.get('company', 'Unknown'),
                        address=result.get('address', ''),
                        country=result.get('country', ''),
                        block_type=result.get('block_type', '')
                    )
            
        except Exception as e:
            self.logger.debug(f"macvendors.co lookup failed: {e}")
        
        return MacVendorInfo(mac_address=mac_address, vendor="", company="")
    
    def _lookup_mac_ieee(self, mac_address: str) -> MacVendorInfo:
        """Fallback MAC lookup using local IEEE database"""
        # This would use a local IEEE OUI database
        # For now, return empty result
        return MacVendorInfo(mac_address=mac_address, vendor="Unknown", company="IEEE lookup not implemented")
    
    def lookup_ip_address(self, ip_address: str) -> IPIntelligence:
        """
        Comprehensive IP address intelligence lookup
        
        Args:
            ip_address: IP address to analyze
            
        Returns:
            IPIntelligence object with comprehensive data
        """
        self.logger.info(f"🌐 Analyzing IP address: {ip_address}")
        
        # Validate IP address
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip_address}")
            return IPIntelligence(ip_address=ip_address)
        
        # Check cache
        cache_key = f"ip_{ip_address}"
        if cache_key in self.cache:
            cache_time, data = self.cache[cache_key]
            if time.time() - cache_time < self.cache_timeout:
                self.logger.debug("📋 Using cached IP lookup result")
                return data
        
        # Gather intelligence from multiple sources
        intel = IPIntelligence(ip_address=ip_address)
        
        try:
            # Basic geolocation
            geo_data = self._get_ip_geolocation(ip_address)
            if geo_data:
                intel.country = geo_data.get('country', '')
                intel.city = geo_data.get('city', '')
                intel.organization = geo_data.get('org', '')
                intel.isp = geo_data.get('isp', '')
                intel.asn = geo_data.get('as', '')
            
            # Hostname resolution
            try:
                intel.hostname = socket.gethostbyaddr(ip_address)[0]
            except:
                intel.hostname = "No reverse DNS"
            
            # Threat intelligence
            threat_data = self._check_ip_reputation(ip_address)
            if threat_data:
                intel.threat_level = threat_data.get('threat_level', 'unknown')
                intel.is_malicious = threat_data.get('is_malicious', False)
            
            # VPN/Proxy detection
            proxy_data = self._detect_vpn_proxy(ip_address)
            if proxy_data:
                intel.vpn_detected = proxy_data.get('is_vpn', False)
                intel.proxy_detected = proxy_data.get('is_proxy', False)
            
            # Cache the result
            self.cache[cache_key] = (time.time(), intel)
            
            self.logger.info(f"✅ IP analysis completed for {ip_address}")
            return intel
            
        except Exception as e:
            self.logger.error(f"❌ IP analysis failed: {e}")
            return intel
    
    def _get_ip_geolocation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get IP geolocation data"""
        try:
            # Try ip-api.com (free tier)
            url = f"{self.endpoints['ipapi']}{ip_address}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return data
            
            # Fallback to ipgeolocation.io if API key available
            if self.api_keys['ipgeolocation']:
                url = f"{self.endpoints['ipgeolocation']}?apiKey={self.api_keys['ipgeolocation']}&ip={ip_address}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    return response.json()
            
        except Exception as e:
            self.logger.debug(f"IP geolocation failed: {e}")
        
        return None
    
    def _check_ip_reputation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation using threat intelligence feeds"""
        try:
            # Check AbuseIPDB if API key available
            if self.api_keys['abuseipdb']:
                headers = {
                    'Key': self.api_keys['abuseipdb'],
                    'Accept': 'application/json'
                }
                
                params = {
                    'ipAddress': ip_address,
                    'maxAgeInDays': 90,
                    'verbose': ''
                }
                
                response = self.session.get(
                    self.endpoints['abuseipdb'],
                    headers=headers,
                    params=params,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    abuse_confidence = data.get('data', {}).get('abuseConfidencePercentage', 0)
                    
                    threat_level = 'low'
                    if abuse_confidence > 75:
                        threat_level = 'high'
                    elif abuse_confidence > 25:
                        threat_level = 'medium'
                    
                    return {
                        'threat_level': threat_level,
                        'is_malicious': abuse_confidence > 50,
                        'abuse_confidence': abuse_confidence
                    }
            
            # Additional reputation checks could be added here
            
        except Exception as e:
            self.logger.debug(f"IP reputation check failed: {e}")
        
        return None
    
    def _detect_vpn_proxy(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Detect if IP is VPN or proxy"""
        try:
            # Basic detection based on hostname patterns
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip_address)[0].lower()
            except:
                pass
            
            vpn_indicators = ['vpn', 'proxy', 'tor', 'tunnel', 'relay']
            is_vpn = any(indicator in hostname for indicator in vpn_indicators)
            
            # More sophisticated detection could be added with commercial APIs
            
            return {
                'is_vpn': is_vpn,
                'is_proxy': 'proxy' in hostname,
                'detection_method': 'hostname_analysis'
            }
            
        except Exception as e:
            self.logger.debug(f"VPN/Proxy detection failed: {e}")
        
        return None
    
    def analyze_domain(self, domain: str) -> DomainIntelligence:
        """
        Comprehensive domain analysis
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            DomainIntelligence object with domain data
        """
        self.logger.info(f"🌍 Analyzing domain: {domain}")
        
        # Check cache
        cache_key = f"domain_{domain}"
        if cache_key in self.cache:
            cache_time, data = self.cache[cache_key]
            if time.time() - cache_time < self.cache_timeout:
                self.logger.debug("📋 Using cached domain analysis")
                return data
        
        intel = DomainIntelligence(domain=domain)
        
        try:
            # DNS resolution
            dns_data = self._resolve_domain_dns(domain)
            if dns_data:
                intel.ip_addresses = dns_data.get('ip_addresses', [])
                intel.nameservers = dns_data.get('nameservers', [])
                intel.mx_records = dns_data.get('mx_records', [])
                intel.txt_records = dns_data.get('txt_records', [])
            
            # Domain reputation analysis
            reputation_data = self._check_domain_reputation(domain)
            if reputation_data:
                intel.reputation_score = reputation_data.get('score', 0.0)
                intel.is_suspicious = reputation_data.get('is_suspicious', False)
            
            # WHOIS data (basic implementation)
            whois_data = self._get_whois_data(domain)
            if whois_data:
                intel.registrar = whois_data.get('registrar', '')
                intel.creation_date = whois_data.get('creation_date', '')
                intel.expiration_date = whois_data.get('expiration_date', '')
            
            # Cache the result
            self.cache[cache_key] = (time.time(), intel)
            
            self.logger.info(f"✅ Domain analysis completed for {domain}")
            return intel
            
        except Exception as e:
            self.logger.error(f"❌ Domain analysis failed: {e}")
            return intel
    
    def _resolve_domain_dns(self, domain: str) -> Optional[Dict[str, List[str]]]:
        """Resolve domain DNS records"""
        try:
            dns_data = {
                'ip_addresses': [],
                'nameservers': [],
                'mx_records': [],
                'txt_records': []
            }
            
            # A records (IPv4)
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_data['ip_addresses'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                dns_data['nameservers'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_data['mx_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_data['txt_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            return dns_data
            
        except Exception as e:
            self.logger.debug(f"DNS resolution failed for {domain}: {e}")
        
        return None
    
    def _check_domain_reputation(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain reputation"""
        try:
            # Basic reputation check
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.ru']
            is_suspicious = any(domain.endswith(tld) for tld in suspicious_tlds)
            
            # Length-based suspicion (very short or very long domains)
            domain_parts = domain.split('.')
            main_domain = domain_parts[0] if domain_parts else domain
            
            if len(main_domain) < 3 or len(main_domain) > 30:
                is_suspicious = True
            
            # Calculate basic reputation score
            score = 50.0  # Neutral starting score
            
            if is_suspicious:
                score -= 30
            
            if domain.endswith('.edu') or domain.endswith('.gov'):
                score += 20
            
            return {
                'score': max(0, min(100, score)),
                'is_suspicious': is_suspicious
            }
            
        except Exception as e:
            self.logger.debug(f"Domain reputation check failed: {e}")
        
        return None
    
    def _get_whois_data(self, domain: str) -> Optional[Dict[str, str]]:
        """Get basic WHOIS data (placeholder implementation)"""
        # This would integrate with a WHOIS API or library
        # For now, return placeholder data
        return {
            'registrar': 'WHOIS lookup not implemented',
            'creation_date': '',
            'expiration_date': ''
        }
    
    def bulk_lookup_ips(self, ip_addresses: List[str], max_workers: int = 10) -> Dict[str, IPIntelligence]:
        """
        Perform bulk IP address lookups
        
        Args:
            ip_addresses: List of IP addresses to lookup
            max_workers: Maximum concurrent workers
            
        Returns:
            Dictionary mapping IP addresses to intelligence data
        """
        self.logger.info(f"🔄 Starting bulk IP lookup for {len(ip_addresses)} addresses")
        
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(self.lookup_ip_address, ip): ip 
                for ip in ip_addresses
            }
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    intel = future.result()
                    results[ip] = intel
                except Exception as e:
                    self.logger.error(f"Bulk lookup failed for {ip}: {e}")
                    results[ip] = IPIntelligence(ip_address=ip)
        
        self.logger.info(f"✅ Bulk IP lookup completed")
        return results
    
    def generate_osint_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive OSINT report
        
        Args:
            data: OSINT data to include in report
            
        Returns:
            Formatted OSINT report
        """
        self.logger.info("📊 Generating OSINT intelligence report")
        
        report = {
            'report_metadata': {
                'generated_at': time.strftime("%Y-%m-%d %H:%M:%S"),
                'report_type': 'OSINT Intelligence',
                'version': '2.0'
            },
            'executive_summary': {
                'total_assets_analyzed': 0,
                'threats_identified': 0,
                'high_risk_assets': 0
            },
            'findings': {
                'ip_intelligence': [],
                'domain_intelligence': [],
                'mac_intelligence': [],
                'threats': [],
                'recommendations': []
            },
            'technical_details': data
        }
        
        # Analyze findings for executive summary
        try:
            ip_data = data.get('ip_lookups', {})
            threats = 0
            high_risk = 0
            
            for ip, intel in ip_data.items():
                if hasattr(intel, 'is_malicious') and intel.is_malicious:
                    threats += 1
                if hasattr(intel, 'threat_level') and intel.threat_level == 'high':
                    high_risk += 1
            
            report['executive_summary'].update({
                'total_assets_analyzed': len(ip_data),
                'threats_identified': threats,
                'high_risk_assets': high_risk
            })
            
        except Exception as e:
            self.logger.debug(f"Report analysis failed: {e}")
        
        return report
    
    def clear_cache(self) -> None:
        """Clear OSINT cache"""
        self.cache.clear()
        self.logger.info("🗑️ OSINT cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'cache_size': len(self.cache),
            'cache_timeout': self.cache_timeout,
            'cached_items': list(self.cache.keys())
        }
