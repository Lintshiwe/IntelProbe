#!/usr/bin/env python3
"""
IntelProbe Test Suite
Basic tests to validate IntelProbe functionality
"""

import sys
import os
import time
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test if all core modules can be imported"""
    print("🧪 Testing imports...")
    
    try:
        from core.config import ConfigManager
        from core.scanner import EnhancedScanner
        from core.ai_engine import AIEngine
        from core.osint import OSINTGatherer
        from core.detection import AttackDetector
        from core.interface import IntelProbeInterface
        from core import utils
        print("✅ All core modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_config():
    """Test configuration management"""
    print("🧪 Testing configuration...")
    
    try:
        from core.config import ConfigManager
        
        config = ConfigManager()
        
        # Test loading config
        network_config = config.get_network_config()
        ai_config = config.get_ai_config()
        output_config = config.get_output_config()
        
        # Validate required keys
        required_network = ['interface', 'timeout', 'threads']
        required_ai = ['provider', 'api_key_file']
        required_output = ['format', 'save_to_file']
        
        for key in required_network:
            if key not in network_config:
                print(f"❌ Missing network config key: {key}")
                return False
        
        for key in required_ai:
            if key not in ai_config:
                print(f"❌ Missing AI config key: {key}")
                return False
        
        for key in required_output:
            if key not in output_config:
                print(f"❌ Missing output config key: {key}")
                return False
        
        print("✅ Configuration management working")
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_scanner():
    """Test basic scanner functionality"""
    print("🧪 Testing scanner...")
    
    try:
        from core.config import ConfigManager
        from core.scanner import EnhancedScanner
        
        config = ConfigManager()
        scanner = EnhancedScanner(config)
        
        # Test IP validation
        if not scanner._is_valid_ip("192.168.1.1"):
            print("❌ IP validation failed")
            return False
        
        if scanner._is_valid_ip("invalid.ip"):
            print("❌ IP validation should have failed")
            return False
        
        # Test OS detection
        ttl_os = scanner._detect_os_ttl(64)
        if not ttl_os:
            print("❌ OS detection failed")
            return False
        
        print("✅ Scanner basic functionality working")
        return True
        
    except Exception as e:
        print(f"❌ Scanner test failed: {e}")
        return False

def test_ai_engine():
    """Test AI engine functionality"""
    print("🧪 Testing AI engine...")
    
    try:
        from core.config import ConfigManager
        from core.ai_engine import AIEngine
        
        config = ConfigManager()
        ai_engine = AIEngine(config)
        
        # Test with mock data
        mock_scan_data = {
            'hosts': [
                {
                    'ip': '192.168.1.1',
                    'hostname': 'router.local',
                    'ports': [22, 80, 443],
                    'os': 'Linux'
                }
            ],
            'network': '192.168.1.0/24',
            'scan_time': '2024-01-01 12:00:00'
        }
        
        # Test analysis (should work even without API key)
        analysis = ai_engine.analyze_network_scan(mock_scan_data)
        if not isinstance(analysis, dict):
            print("❌ AI analysis should return dict")
            return False
        
        print("✅ AI engine basic functionality working")
        return True
        
    except Exception as e:
        print(f"❌ AI engine test failed: {e}")
        return False

def test_osint():
    """Test OSINT functionality"""
    print("🧪 Testing OSINT...")
    
    try:
        from core.config import ConfigManager
        from core.osint import OSINTGatherer
        
        config = ConfigManager()
        osint = OSINTGatherer(config)
        
        # Test MAC address lookup (offline)
        mac_info = osint.lookup_mac_address("00:50:56:c0:00:01")
        if not isinstance(mac_info, dict):
            print("❌ MAC lookup should return dict")
            return False
        
        # Test IP analysis (offline)
        ip_info = osint.lookup_ip_address("8.8.8.8")
        if not isinstance(ip_info, dict):
            print("❌ IP lookup should return dict")
            return False
        
        print("✅ OSINT basic functionality working")
        return True
        
    except Exception as e:
        print(f"❌ OSINT test failed: {e}")
        return False

def test_detection():
    """Test attack detection functionality"""
    print("🧪 Testing attack detection...")
    
    try:
        from core.config import ConfigManager
        from core.detection import AttackDetector
        
        config = ConfigManager()
        detector = AttackDetector(config)
        
        # Test ARP entry tracking
        detector._update_arp_table("192.168.1.1", "00:11:22:33:44:55")
        if "192.168.1.1" not in detector.arp_table:
            print("❌ ARP table update failed")
            return False
        
        # Test traffic analysis
        detector._update_traffic_stats("192.168.1.1", 100)
        if "192.168.1.1" not in detector.traffic_stats:
            print("❌ Traffic stats update failed")
            return False
        
        print("✅ Attack detection basic functionality working")
        return True
        
    except Exception as e:
        print(f"❌ Attack detection test failed: {e}")
        return False

def test_interface():
    """Test interface functionality"""
    print("🧪 Testing interface...")
    
    try:
        from core.config import ConfigManager
        from core.interface import IntelProbeInterface
        
        config = ConfigManager()
        interface = IntelProbeInterface(config)
        
        # Test help display
        help_text = interface._display_help()
        if not help_text:
            print("❌ Help display failed")
            return False
        
        print("✅ Interface basic functionality working")
        return True
        
    except Exception as e:
        print(f"❌ Interface test failed: {e}")
        return False

def test_utilities():
    """Test utility functions"""
    print("🧪 Testing utilities...")
    
    try:
        from core import utils
        
        # Test IP validation
        if not utils.validate_ip("192.168.1.1"):
            print("❌ IP validation failed")
            return False
        
        if utils.validate_ip("invalid.ip"):
            print("❌ IP validation should have failed")
            return False
        
        # Test MAC validation
        if not utils.validate_mac("00:11:22:33:44:55"):
            print("❌ MAC validation failed")
            return False
        
        if utils.validate_mac("invalid:mac"):
            print("❌ MAC validation should have failed")
            return False
        
        # Test port range validation
        if not utils.validate_port_range("80"):
            print("❌ Port range validation failed")
            return False
        
        if not utils.validate_port_range("1-1000"):
            print("❌ Port range validation failed")
            return False
        
        # Test MAC normalization
        normalized = utils.normalize_mac_address("00-11-22-33-44-55")
        if normalized != "00:11:22:33:44:55":
            print("❌ MAC normalization failed")
            return False
        
        print("✅ Utilities working correctly")
        return True
        
    except Exception as e:
        print(f"❌ Utilities test failed: {e}")
        return False

def test_directory_structure():
    """Test directory structure creation"""
    print("🧪 Testing directory structure...")
    
    try:
        from core import utils
        
        utils.create_directory_structure()
        
        required_dirs = ["reports", "logs", "sessions", "alerts", "models", "cache"]
        for directory in required_dirs:
            if not Path(directory).exists():
                print(f"❌ Directory not created: {directory}")
                return False
        
        print("✅ Directory structure created successfully")
        return True
        
    except Exception as e:
        print(f"❌ Directory structure test failed: {e}")
        return False

def test_dependencies():
    """Test dependency availability"""
    print("🧪 Testing dependencies...")
    
    try:
        from core import utils
        
        deps = utils.check_dependencies()
        required_deps = ['pandas', 'requests', 'rich']
        
        missing_deps = []
        for dep in required_deps:
            if not deps.get(dep, False):
                missing_deps.append(dep)
        
        if missing_deps:
            print(f"⚠️ Missing dependencies: {missing_deps}")
            print("💡 Run: pip install -r requirements.txt")
        else:
            print("✅ All critical dependencies available")
        
        return True
        
    except Exception as e:
        print(f"❌ Dependency check failed: {e}")
        return False

def run_all_tests():
    """Run all tests"""
    print("🚀 IntelProbe Test Suite")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_config,
        test_scanner,
        test_ai_engine,
        test_osint,
        test_detection,
        test_interface,
        test_utilities,
        test_directory_structure,
        test_dependencies
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
            failed += 1
        print()
    
    print("=" * 50)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! IntelProbe is ready to use.")
        print("\n📋 Next steps:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Configure API keys in config.ini")
        print("3. Run IntelProbe: python intelprobe.py --help")
        print("4. Start scanning: python intelprobe.py scan -t 192.168.1.0/24")
    else:
        print("⚠️ Some tests failed. Please check the errors above.")
    
    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
