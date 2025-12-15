"""
IntelProbe Core Package
Enhanced network forensics and AI-powered analysis
"""

from .interface import IntelProbeInterface
from .config import ConfigManager
from .utils import *

# Try to import optional modules
try:
    from .scanner import EnhancedScanner
except ImportError:
    EnhancedScanner = None

try:
    from .ai_engine import AIEngine
except ImportError:
    AIEngine = None

try:
    from .detection import AttackDetector
except ImportError:
    AttackDetector = None

try:
    from .osint import OSINTGatherer
except ImportError:
    OSINTGatherer = None

# Always available
from .production_scanner import ProductionScanner

__version__ = "1.0.0"
__author__ = "Lintshiwe Slade"
__email__ = "lintshiwe.slade@intelprobe.dev"
__github__ = "https://github.com/lintshiwe"
__repository__ = "https://github.com/lintshiwe/IntelProbe"
__license__ = "MIT License"
__copyright__ = "Copyright (c) 2025 Lintshiwe Slade"
__description__ = "AI-Powered Network Forensics CLI"

# Core modules initialization
__all__ = [
    'IntelProbeInterface',
    'ConfigManager', 
    'EnhancedScanner',
    'AIEngine',
    'AttackDetector',
    'OSINTGatherer'
]
