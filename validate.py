#!/usr/bin/env python3
"""
IntelProbe Validation Test Suite
Comprehensive testing to ensure full functionality

Author: Lintshiwe Slade (@lintshiwe)
"""

import sys
import os
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Test results tracking
tests_passed = 0
tests_failed = 0
test_results = []


def test(name: str, condition: bool, message: str = ""):
    """Record test result"""
    global tests_passed, tests_failed
    status = "✅ PASS" if condition else "❌ FAIL"
    if condition:
        tests_passed += 1
    else:
        tests_failed += 1
    result = f"{status}: {name}"
    if message:
        result += f" - {message}"
    print(result)
    test_results.append((name, condition, message))
    return condition


def run_all_tests():
    """Run comprehensive test suite"""
    print("=" * 60)
    print("🧪 IntelProbe Validation Test Suite")
    print("=" * 60)
    print()
    
    # ========================
    # Module Import Tests
    # ========================
    print("📦 Testing Module Imports...")
    print("-" * 40)
    
    try:
        from core.super_scanner import SuperScanner, ScanSpeed, ThreatLevel
        test("SuperScanner import", True)
    except ImportError as e:
        test("SuperScanner import", False, str(e))
    
    try:
        from run import IntelProbeRunner
        test("IntelProbeRunner import", True)
    except ImportError as e:
        test("IntelProbeRunner import", False, str(e))
    
    try:
        from utils import quick_scan, port_scan, check_setup, IntelProbe
        test("Utils import", True)
    except ImportError as e:
        test("Utils import", False, str(e))
    
    try:
        from core.ai_engine import AIEngine
        test("AIEngine import", True)
    except ImportError as e:
        test("AIEngine import", False, str(e))
    
    try:
        from core.detection import AttackDetector, DetectionAlert
        test("Detection module import", True)
    except ImportError as e:
        test("Detection module import", False, str(e))
    
    try:
        from core.config import ConfigManager
        test("ConfigManager import", True)
    except ImportError as e:
        test("ConfigManager import", False, str(e))
    
    print()
    
    # ========================
    # Core Functionality Tests
    # ========================
    print("⚙️ Testing Core Functionality...")
    print("-" * 40)
    
    # SuperScanner initialization
    try:
        from core.super_scanner import SuperScanner, ScanSpeed
        scanner = SuperScanner()
        test("SuperScanner initialization", True)
        
        # Test speed settings
        scanner.set_speed(ScanSpeed.FAST)
        test("Speed configuration", scanner.speed == ScanSpeed.FAST)
        
        # Test port presets
        test("Port presets available", len(scanner.port_presets) >= 5, 
             f"{len(scanner.port_presets)} presets found")
        
        # Test service database
        test("Service database loaded", scanner.db is not None)
        
    except Exception as e:
        test("SuperScanner functionality", False, str(e))
    
    # Runner initialization
    try:
        from run import IntelProbeRunner
        runner = IntelProbeRunner(quiet=True)
        test("IntelProbeRunner initialization", True)
        test("Runner has scanner property", hasattr(runner, 'scanner'))
        test("Runner has ai_engine property", hasattr(runner, 'ai_engine'))
    except Exception as e:
        test("IntelProbeRunner functionality", False, str(e))
    
    # Utils check_setup
    try:
        from utils import check_setup
        status = check_setup()
        test("check_setup execution", 'ready' in status)
        test("Core modules status", status.get('ready', False))
    except Exception as e:
        test("Utils functionality", False, str(e))
    
    print()
    
    # ========================
    # Network Info Tests
    # ========================
    print("🌐 Testing Network Information...")
    print("-" * 40)
    
    try:
        from utils import get_network_info
        info = get_network_info()
        test("get_network_info execution", 'local_ip' in info)
        test("Local IP detection", info.get('local_ip') is not None, 
             f"IP: {info.get('local_ip', 'None')}")
        test("Network calculation", info.get('network') is not None,
             f"Network: {info.get('network', 'None')}")
    except Exception as e:
        test("Network info functionality", False, str(e))
    
    print()
    
    # ========================
    # Port Scanning Tests
    # ========================
    print("🔍 Testing Port Scanning...")
    print("-" * 40)
    
    try:
        from utils import port_scan
        # Quick scan of localhost
        start_time = time.time()
        result = port_scan('127.0.0.1', ports=[80, 443, 22])
        elapsed = time.time() - start_time
        
        test("port_scan execution", 'host' in result)
        test("Scan returns host", result.get('host') == '127.0.0.1')
        test("Scan returns open_ports", 'open_ports' in result)
        test("Scan performance", elapsed < 10, f"{elapsed:.2f}s")
    except Exception as e:
        test("Port scan functionality", False, str(e))
    
    print()
    
    # ========================
    # Scanner Feature Tests
    # ========================
    print("🎯 Testing Scanner Features...")
    print("-" * 40)
    
    try:
        from core.super_scanner import SuperScanner, ServiceDatabase
        
        # Service database tests
        db = ServiceDatabase()
        
        # Test known services
        ssh_info = db.get_service(22)
        test("Service lookup (SSH)", ssh_info is not None and ssh_info[0] == 'ssh')
        
        http_info = db.get_service(80)
        test("Service lookup (HTTP)", http_info is not None and http_info[0] == 'http')
        
        https_info = db.get_service(443)
        test("Service lookup (HTTPS)", https_info is not None)
        
        # Test vulnerability info
        smb_vulns = db.get_vulnerabilities('smb')
        test("Vulnerability data exists", len(smb_vulns) > 0)
        
    except Exception as e:
        test("Scanner features", False, str(e))
    
    print()
    
    # ========================
    # AI Engine Tests
    # ========================
    print("🤖 Testing AI Engine...")
    print("-" * 40)
    
    try:
        from core.ai_engine import AIEngine, ThreatAnalysis
        from core.config import ConfigManager
        
        config = ConfigManager()
        ai_engine = AIEngine(config)
        
        test("AIEngine initialization", ai_engine is not None)
        test("AI provider detection", hasattr(ai_engine, 'ai_provider'),
             f"Provider: {getattr(ai_engine, 'ai_provider', 'None')}")
        
        # Test analysis with mock data
        mock_results = [
            {'ip': '192.168.1.1', 'ports': [22, 80, 443], 'os': 'Linux'},
            {'ip': '192.168.1.2', 'ports': [3389], 'os': 'Windows'}
        ]
        
        analysis = ai_engine.analyze_network_scan(mock_results)
        test("Network analysis execution", analysis is not None)
        test("Analysis returns threat_level", hasattr(analysis, 'threat_level'))
        test("Analysis returns threats", hasattr(analysis, 'threats'))
        
    except Exception as e:
        test("AI Engine functionality", False, str(e))
    
    print()
    
    # ========================
    # Detection Module Tests
    # ========================
    print("🛡️ Testing Detection Module...")
    print("-" * 40)
    
    try:
        from core.detection import AttackDetector, DetectionAlert, AttackSignature
        from core.config import ConfigManager
        
        config = ConfigManager()
        detector = AttackDetector(config)
        
        test("AttackDetector initialization", detector is not None)
        test("Attack signatures loaded", len(detector.signatures) > 0,
             f"{len(detector.signatures)} signatures")
        
        # Test alert creation
        alert = DetectionAlert(
            alert_type="Test Alert",
            severity="medium",
            source_ip="192.168.1.100",
            description="Test alert for validation"
        )
        test("DetectionAlert creation", alert is not None)
        test("Alert has timestamp", bool(alert.timestamp))
        
        # Test detection summary
        summary = detector.get_detection_summary()
        test("Detection summary", 'monitoring_status' in summary)
        
    except Exception as e:
        test("Detection functionality", False, str(e))
    
    print()
    
    # ========================
    # File/Directory Tests
    # ========================
    print("📁 Testing File Structure...")
    print("-" * 40)
    
    required_files = [
        'run.py',
        'utils.py',
        'intelprobe.py',
        'core/super_scanner.py',
        'core/ai_engine.py',
        'core/detection.py',
        'core/config.py',
        'requirements.txt'
    ]
    
    for filepath in required_files:
        exists = Path(PROJECT_ROOT / filepath).exists()
        test(f"File exists: {filepath}", exists)
    
    required_dirs = ['core', 'config', 'reports', 'logs']
    for dirname in required_dirs:
        exists = Path(PROJECT_ROOT / dirname).exists()
        test(f"Directory exists: {dirname}", exists)
    
    print()
    
    # ========================
    # Summary
    # ========================
    print("=" * 60)
    total = tests_passed + tests_failed
    success_rate = (tests_passed / total * 100) if total > 0 else 0
    
    print(f"""
🏁 Test Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Passed: {tests_passed}
❌ Failed: {tests_failed}
📊 Total:  {total}
📈 Success Rate: {success_rate:.1f}%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
    
    if tests_failed == 0:
        print("🎉 ALL TESTS PASSED! IntelProbe is fully functional!")
    else:
        print(f"⚠️ {tests_failed} test(s) failed. Review output above.")
    
    print("=" * 60)
    
    return tests_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
