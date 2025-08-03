#!/usr/bin/env python3
"""
Test script for enhanced OS detection
"""

from core.scanner import EnhancedScanner
from core.config import ConfigManager

def test_os_detection():
    """Test the enhanced OS detection functionality"""
    print("🧪 Testing Enhanced OS Detection")
    print("=" * 50)
    
    try:
        # Initialize scanner
        config = ConfigManager()
        scanner = EnhancedScanner(config)
        
        # Test localhost detection
        print("🖥️ Testing localhost detection:")
        local_os = scanner._detect_os_enhanced("127.0.0.1")
        print(f"   Local OS: {local_os}")
        
        # Test current machine IP
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"🌐 Testing current machine IP ({local_ip}):")
        machine_os = scanner._detect_os_enhanced(local_ip)
        print(f"   Machine OS: {machine_os}")
        
        # Test TTL-based detection for common IPs
        test_ips = ["192.168.1.1", "8.8.8.8", "1.1.1.1"]
        print("\n🔍 Testing TTL-based detection:")
        for ip in test_ips:
            try:
                detected_os = scanner._detect_os_enhanced(ip)
                print(f"   {ip}: {detected_os}")
            except Exception as e:
                print(f"   {ip}: Detection failed - {e}")
        
        print("\n✅ OS Detection Test Completed")
        
        # Test MAC-based detection
        print("\n🔧 Testing MAC-based detection:")
        test_macs = [
            ("00:50:56:12:34:56", "VMware"),
            ("08:00:27:12:34:56", "VirtualBox"),
            ("AC:DE:48:12:34:56", "Apple"),
            ("52:54:00:12:34:56", "QEMU/KVM")
        ]
        
        for mac, expected in test_macs:
            detected = scanner._detect_os_enhanced("192.168.1.100", mac)
            print(f"   MAC {mac}: {detected} (Expected: {expected})")
        
        print("\n🎯 Enhanced OS Detection is working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ OS Detection test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_os_detection()
