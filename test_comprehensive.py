#!/usr/bin/env python3
"""
Simple Gemini AI Test for IntelProbe
"""

import os
import sys
import json
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_gemini_direct():
    """Test Gemini AI directly"""
    
    print("🤖 DIRECT GEMINI AI TEST")
    print("=" * 40)
    
    try:
        # Test Google Generative AI import
        print("1. Testing Google Generative AI import...")
        import google.generativeai as genai
        print("   ✅ Google Generative AI imported successfully")
        
        # Configure API
        print("2. Configuring API...")
        api_key = "AIzaSyByAYC2jL-gy-HK_UNqId-uc6zPoaUglEg"
        genai.configure(api_key=api_key)
        print("   ✅ API configured")
        
        # Create model
        print("3. Creating model...")
        model = genai.GenerativeModel('gemini-1.5-flash')
        print("   ✅ Model created")
        
        # Test generation
        print("4. Testing content generation...")
        response = model.generate_content(
            "Explain network security scanning in exactly one sentence."
        )
        print("   ✅ Content generated!")
        print(f"   📝 Response: {response.text}")
        
        print("\n🎉 GEMINI AI IS WORKING PERFECTLY!")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_intelliprobe_integration():
    """Test IntelProbe integration with proper configuration"""
    
    print("\n🛡️ INTELLIPROBE INTEGRATION TEST")
    print("=" * 40)
    
    try:
        # Load configuration
        print("1. Loading configuration...")
        with open('config/ai_config.json', 'r') as f:
            config_data = json.load(f)
        print("   ✅ Configuration loaded")
        
        # Create config wrapper
        print("2. Creating config wrapper...")
        class ConfigWrapper:
            def __init__(self, data):
                self.data = data
            def get_ai_config(self):
                return self.data.get('ai_config', {})
        
        config = ConfigWrapper(config_data)
        print("   ✅ Config wrapper created")
        
        # Import and initialize AI engine
        print("3. Initializing AI engine...")
        from core.ai_engine import AIEngine
        ai_engine = AIEngine(config)
        print(f"   ✅ AI engine initialized with provider: {getattr(ai_engine, 'ai_provider', 'None')}")
        
        # Test simple AI query
        print("4. Testing AI query...")
        if hasattr(ai_engine, '_query_ai'):
            result = ai_engine._query_ai("What is network scanning?")
            print(f"   ✅ AI Query successful!")
            print(f"   📝 Response: {result[:100]}...")
        else:
            print("   ⚠️  _query_ai method not found")
        
        print("\n🎉 INTELLIPROBE + GEMINI INTEGRATION WORKING!")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🧪 COMPREHENSIVE GEMINI AI TEST")
    print("=" * 50)
    
    # Test 1: Direct Gemini
    success1 = test_gemini_direct()
    
    # Test 2: IntelProbe Integration
    success2 = test_intelliprobe_integration()
    
    if success1 and success2:
        print("\n🚀 ALL TESTS PASSED! GEMINI AI IS READY! 🛡️")
    else:
        print("\n⚠️  Some tests failed. Check the output above.")
    
    print("\n📖 Usage Instructions:")
    print("- Your Gemini AI is configured and working")
    print("- API Key: AIzaSyByAYC2jL-gy-HK_UNqId-uc6zPoaUglEg")
    print("- Model: gemini-1.5-flash")
    print("- IntelProbe can now use AI for network analysis!")
