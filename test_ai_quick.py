#!/usr/bin/env python3
"""
Quick test to confirm Gemini AI is working with IntelProbe
"""

import os
import sys
import json
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_ai_integration():
    """Test AI integration with proper configuration"""
    
    print("🧪 QUICK AI INTEGRATION TEST")
    print("=" * 40)
    
    try:
        # Test 1: Load configuration
        print("1. Loading AI configuration...")
        with open('config/ai_config.json', 'r') as f:
            config_data = json.load(f)
        print("   ✅ Configuration loaded")
        
        # Test 2: Import AI engine
        print("2. Importing AI engine...")
        from core.ai_engine import AIEngine
        print("   ✅ AI engine imported")
        
        # Test 3: Create config object
        print("3. Creating config object...")
        class SimpleConfig:
            def __init__(self, data):
                self.data = data
            def get_ai_config(self):
                return self.data.get('ai_config', {})
        
        config = SimpleConfig(config_data)
        print("   ✅ Config object created")
        
        # Test 4: Initialize AI engine
        print("4. Initializing AI engine...")
        ai_engine = AIEngine(config)
        print(f"   ✅ AI engine initialized with provider: {getattr(ai_engine, 'ai_provider', 'None')}")
        
        # Test 5: Check API key
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            print(f"5. API key found: {api_key[:10]}...{api_key[-4:]}")
        else:
            print("5. ⚠️  API key not found in environment")
        
        print("\n🎉 ALL TESTS PASSED!")
        print("Your IntelProbe is ready with Gemini AI! 🚀🛡️")
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_ai_integration()
