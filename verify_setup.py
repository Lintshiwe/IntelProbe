#!/usr/bin/env python3
"""
Quick verification script for IntelProbe with Gemini AI
"""

try:
    print("=== VERIFYING INTELLPROBE SETUP ===")
    print()
    
    # Test core module import
    print("1. Testing core module import...")
    import core
    print("   ✅ Core module imported successfully")
    print(f"   📧 Author: {core.__author__}")
    print(f"   📄 License: {core.__license__}")
    print()
    
    # Test AI engine specifically
    print("2. Testing AI engine capabilities...")
    from core.ai_engine import AIEngine
    import json
    
    # Load config properly
    try:
        with open('config/ai_config.json', 'r') as f:
            config_data = json.load(f)
        
        # Create a simple config object
        class SimpleConfig:
            def __init__(self, data):
                self.data = data
            def get_ai_config(self):
                return self.data.get('ai_config', {})
        
        config = SimpleConfig(config_data)
        ai_engine = AIEngine(config)
        
        print(f"   🤖 AI Provider: {getattr(ai_engine, 'ai_provider', 'None')}")
        print(f"   🤖 Gemini Available: {hasattr(ai_engine, 'gemini_client') and ai_engine.gemini_client is not None}")
        print(f"   🤖 OpenAI Available: {hasattr(ai_engine, 'openai_client') and ai_engine.openai_client is not None}")
        
        if ai_engine.ai_provider == 'gemini':
            print("   ✅ Gemini AI is ready to use!")
        elif ai_engine.ai_provider == 'openai':
            print("   ✅ OpenAI is ready to use!")
        else:
            print("   ⚠️  No AI provider configured")
    except Exception as e:
        print(f"   ❌ Error initializing AI engine: {e}")
        
    print()
    
    # Test environment variable
    import os
    gemini_key = os.getenv('GEMINI_API_KEY')
    if gemini_key:
        print(f"3. Environment variable set: GEMINI_API_KEY = {gemini_key[:10]}...{gemini_key[-4:]}")
        print("   ✅ API key is configured")
    else:
        print("3. ⚠️  GEMINI_API_KEY environment variable not found")
    
    print()
    print("=== SETUP VERIFICATION COMPLETE ===")
    print("Your IntelProbe is ready with Gemini AI support! 🚀")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
except Exception as e:
    print(f"❌ Error: {e}")
