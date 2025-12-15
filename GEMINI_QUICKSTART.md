# 🤖 Correct Gemini AI Usage for IntelProbe

## ❌ Your Code Issues:

```python
# WRONG - Don't do this!
from google import genai  # ❌ Wrong import
client = genai.Client(api_key="AIzaSy...") # ❌ Wrong client, exposed API key
response = client.models.generate_content(...)  # ❌ Wrong syntax
```

## ✅ Correct Gemini AI Usage:

### 1. Install Gemini AI

```bash
pip install google-generativeai
```

### 2. Correct Basic Usage

```python
import google.generativeai as genai  # ✅ Correct import
import os

# ✅ Secure API key from environment
api_key = os.getenv('GEMINI_API_KEY')

# ✅ Configure Gemini
genai.configure(api_key=api_key)

# ✅ Create model instance
model = genai.GenerativeModel('gemini-1.5-flash')

# ✅ Generate content
response = model.generate_content("Explain how AI works in a few words")
print(response.text)
```

### 3. Set API Key Securely (Windows)

```cmd
# Set environment variable (secure way)
set GEMINI_API_KEY=your-actual-api-key-here

# Then run Python script
python your_script.py
```

### 4. Using with IntelProbe

**Step 1: Install Gemini**

```bash
pip install google-generativeai
```

**Step 2: Run Setup Script**

```bash
python setup_ai.py
```

**Step 3: Configure**
Update `config/ai_config.json`:

```json
{
  "ai_config": {
    "gemini_enabled": true,
    "gemini_api_key": "your-api-key-here",
    "gemini_model": "gemini-1.5-flash"
  }
}
```

**Step 4: Test**

```bash
python test_gemini.py
```

## 🔑 Get Your FREE API Key

1. Go to: https://makersuite.google.com/app/apikey
2. Sign in with Google
3. Click "Create API Key"
4. Copy the key (starts with "AIza...")

## 🎯 Available Models

- `gemini-1.5-flash` - ⚡ **Fastest & Free**
- `gemini-1.5-pro` - 🎯 **Best Quality**
- `gemini-2.0-flash` - 🚀 **Latest Version**

## 🛡️ Security Tips

- ❌ **Never** hardcode API keys in scripts
- ✅ **Always** use environment variables
- ✅ **Never** commit API keys to git
- ✅ **Use** `.env` files for local development

## 🚀 Quick Test

```python
import os
import google.generativeai as genai

# Set your API key
genai.configure(api_key="YOUR_API_KEY_HERE")

# Create model
model = genai.GenerativeModel('gemini-1.5-flash')

# Test
response = model.generate_content("Hello from IntelProbe!")
print(response.text)
```

---

**Ready to use Gemini with IntelProbe?** Run `python setup_ai.py` to get started! 🎉
