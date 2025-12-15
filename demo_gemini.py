#!/usr/bin/env python3
"""
Demo script showing IntelProbe with Gemini AI in action
"""

import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def demo_gemini_analysis():
    """Demonstrate Gemini AI analysis capabilities"""
    
    print("🚀 IntelProbe + Gemini AI Demo")
    print("=" * 50)
    
    try:
        from core.ai_engine import AIEngine
        import json
        
        # Load config properly
        with open('config/ai_config.json', 'r') as f:
            config_data = json.load(f)
        
        # Create a simple config object
        class SimpleConfig:
            def __init__(self, data):
                self.data = data
            def get_ai_config(self):
                return self.data.get('ai_config', {})
        
        config = SimpleConfig(config_data)
        
        # Initialize AI engine
        ai_engine = AIEngine(config)
        
        print(f"🤖 AI Provider: {getattr(ai_engine, 'ai_provider', 'None')}")
        print(f"🤖 Gemini Available: {hasattr(ai_engine, 'gemini_client') and ai_engine.gemini_client is not None}")
        print(f"🤖 OpenAI Available: {hasattr(ai_engine, 'openai_client') and ai_engine.openai_client is not None}")
        
        if not ai_engine.ai_provider:
            print("❌ No AI providers available")
            return
            
        # Demo analysis request
        sample_data = {
            "network_info": {
                "active_connections": 15,
                "open_ports": [22, 80, 443, 8080],
                "suspicious_processes": ["unknown_service.exe"],
                "network_interfaces": 3
            },
            "security_findings": [
                "High number of active connections detected",
                "Unusual process running on system",
                "Multiple network interfaces active"
            ]
        }
        
        print("\n📊 Analyzing sample network data with AI...")
        print("Sample data:", sample_data)
        
        # Get AI analysis
        analysis = ai_engine.analyze_network_scan(
            scan_results=[sample_data]
        )
        
        print("\n🧠 AI Analysis Results:")
        print("-" * 30)
        print(analysis)
        
        print("\n✅ Demo completed successfully!")
        
    except Exception as e:
        print(f"❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    demo_gemini_analysis()
