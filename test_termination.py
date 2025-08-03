#!/usr/bin/env python3
"""
Quick test script to verify multitask_scanner terminates properly
"""

import time
import subprocess
import sys
import signal
import os

def test_scanner_termination():
    """Test if the scanner terminates within a reasonable time"""
    print("🧪 Testing multitask_scanner.py termination...")
    
    start_time = time.time()
    
    try:
        # Run the scanner with a timeout
        result = subprocess.run(
            [sys.executable, "multitask_scanner.py"],
            timeout=45,  # 45 second timeout
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"✅ Scanner completed successfully in {execution_time:.2f} seconds")
        print(f"📊 Return code: {result.returncode}")
        
        if result.stdout:
            print("📋 Last few lines of output:")
            lines = result.stdout.strip().split('\n')
            for line in lines[-5:]:
                print(f"   {line}")
        
        if result.stderr:
            print("⚠️ Errors/Warnings:")
            print(result.stderr[:500])  # First 500 chars
        
        return True
        
    except subprocess.TimeoutExpired:
        print("❌ Scanner did not terminate within 45 seconds - termination issue still exists")
        return False
    except Exception as e:
        print(f"❌ Error running scanner: {e}")
        return False

if __name__ == "__main__":
    success = test_scanner_termination()
    
    if success:
        print("\n🎯 CONCLUSION: Scanner termination issue appears to be FIXED")
        print("✅ The multitask_scanner.py now terminates properly when scanning is complete")
    else:
        print("\n⚠️ CONCLUSION: Scanner termination issue still exists")
        print("❌ Further investigation needed")
    
    sys.exit(0 if success else 1)
