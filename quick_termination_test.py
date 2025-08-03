#!/usr/bin/env python3
"""
Minimal test to verify multitask_scanner terminates properly
"""

import time
import threading
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_scanner_termination():
    """Test scanner termination with minimal network"""
    print("🧪 Testing scanner termination with limited scope...")
    
    try:
        import multitask_scanner
        
        # Create scanner
        scanner = multitask_scanner.AdvancedNetworkScanner()
        
        # Override the discover_networks method to return a small test network
        def limited_discover():
            return ["127.0.0.1/32"]  # Just localhost
        
        scanner.discover_networks = limited_discover
        
        print("🔍 Starting limited scan (localhost only)...")
        start_time = time.time()
        
        # Run the scan in a separate thread with timeout
        def run_scan():
            try:
                networks = scanner.discover_networks()
                scanner.start_multitasking_scan(networks)
                scanner.generate_comprehensive_report()
                print("✅ Scan completed successfully")
                return True
            except Exception as e:
                print(f"❌ Scan error: {e}")
                return False
        
        # Start scan thread
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        # Wait for completion with timeout
        scan_thread.join(timeout=30)
        
        end_time = time.time()
        
        if scan_thread.is_alive():
            print("❌ Scanner did not terminate within 30 seconds")
            print("⚠️ Termination issue still exists")
            return False
        else:
            print(f"✅ Scanner terminated successfully in {end_time - start_time:.2f} seconds")
            return True
            
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🎯 MULTITASK SCANNER TERMINATION TEST")
    print("=" * 50)
    
    success = test_scanner_termination()
    
    if success:
        print("\n🎉 SUCCESS: Scanner termination issue is FIXED!")
        print("✅ The multitask_scanner.py now terminates properly")
    else:
        print("\n⚠️ ISSUE: Scanner still has termination problems")
        print("❌ Additional debugging needed")
    
    print("\n" + "=" * 50)
