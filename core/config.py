"""Configuration Manager for IntelProbe.

Handles configuration loading, validation, and management.
Provides typed access to configuration values with fallback defaults.

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License
"""

import configparser
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import json
import logging

class ConfigManager:
    """Manages configuration for IntelProbe application.
    
    Provides typed access to configuration values with automatic
    fallback to defaults when values are missing or invalid.
    
    Attributes:
        config_path: Path to the configuration file.
        config: ConfigParser instance with loaded configuration.
    """
    
    def __init__(self, config_path: str = "config.ini") -> None:
        """Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file (default: config.ini).
        """
        self.config_path = Path(config_path)
        self.config = configparser.ConfigParser()
        self._defaults = self._get_default_config()
        self.load_config()
        
    def _get_default_config(self) -> Dict[str, Dict[str, Any]]:
        """Get default configuration values"""
        return {
            'Network': {
                'DefaultInterface': 'wlan0' if sys.platform != 'win32' else 'Wi-Fi',
                'ScanTimeout': 30,
                'ThreadCount': 100,
                'MaxHosts': 1000,
                'PacketDelay': 0.1
            },
            'AI': {
                'EnableAI': True,
                'Provider': 'openai',
                'Model': 'gpt-4-mini',
                'ApiKey': '',
                'MaxTokens': 2000,
                'Temperature': 0.3,
                'EnablePredictions': True,
                'EnableReports': True
            },
            'Output': {
                'LogLevel': 'INFO',
                'OutputFormat': 'json',
                'SaveReports': True,
                'ReportPath': './reports/',
                'LogToFile': True,
                'ColorOutput': True,
                'VerboseMode': False
            },
            'Scanning': {
                'PortRange': '1-65535',
                'ScanSpeed': 'fast',
                'ServiceDetection': True,
                'OSDetection': True,
                'VulnScanning': False,
                'MaxRetries': 3
            },
            'Detection': {
                'ARPSpoofing': True,
                'DDoSDetection': True,
                'AnomalyDetection': True,
                'MITMDetection': True,
                'ThresholdPackets': 100,
                'AlertLevel': 'medium'
            },
            'OSINT': {
                'EnableGeoIP': True,
                'EnableThreatIntel': True,
                'EnableSocialRecon': False,
                'APITimeout': 10,
                'MaxResults': 50
            },
            'Security': {
                'RequireAuth': False,
                'APIKeyEncryption': True,
                'LogSensitiveData': False,
                'SecureReports': True
            },
            'Performance': {
                'EnableCaching': True,
                'CacheTimeout': 3600,
                'MaxConcurrentScans': 5,
                'MemoryLimit': 1024
            }
        }
    
    def load_config(self) -> None:
        """Load configuration from file or create default"""
        try:
            if self.config_path.exists():
                self.config.read(self.config_path)
                self._validate_config()
            else:
                self._create_default_config()
                
        except Exception as e:
            logging.warning(f"Error loading config: {e}. Using defaults.")
            self._create_default_config()
    
    def _create_default_config(self) -> None:
        """Create default configuration file"""
        try:
            for section, options in self._defaults.items():
                self.config.add_section(section)
                for key, value in options.items():
                    self.config.set(section, key, str(value))
            
            # Create config directory if it doesn't exist
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                self.config.write(f)
                
            print(f"Created default configuration: {self.config_path}")
            
        except Exception as e:
            logging.error(f"Failed to create default config: {e}")
    
    def _validate_config(self) -> None:
        """Validate configuration values"""
        # Ensure all required sections exist
        for section in self._defaults:
            if not self.config.has_section(section):
                self.config.add_section(section)
                for key, value in self._defaults[section].items():
                    self.config.set(section, key, str(value))
    
    def get(self, section: str, option: str, fallback: Any = None) -> Any:
        """
        Get configuration value with type conversion
        
        Args:
            section: Configuration section
            option: Configuration option
            fallback: Fallback value if option not found
            
        Returns:
            Configuration value with proper type
        """
        try:
            if not self.config.has_option(section, option):
                return fallback or self._defaults.get(section, {}).get(option)
            
            value = self.config.get(section, option)
            
            # Try to convert to appropriate type
            return self._convert_value(value)
            
        except Exception:
            return fallback or self._defaults.get(section, {}).get(option)
    
    def _convert_value(self, value: str) -> Any:
        """Convert string value to appropriate type"""
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        try:
            # Try integer conversion
            if '.' not in value:
                return int(value)
            else:
                return float(value)
        except ValueError:
            return value
    
    def set(self, section: str, option: str, value: Any) -> None:
        """
        Set configuration value
        
        Args:
            section: Configuration section
            option: Configuration option
            value: Value to set
        """
        if not self.config.has_section(section):
            self.config.add_section(section)
        
        self.config.set(section, option, str(value))
    
    def save(self) -> None:
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                self.config.write(f)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")
    
    def get_ai_config(self) -> Dict[str, Any]:
        """Get AI-specific configuration"""
        return {
            'enabled': self.get('AI', 'EnableAI'),
            'provider': self.get('AI', 'Provider'),
            'model': self.get('AI', 'Model'),
            'api_key': self.get('AI', 'ApiKey'),
            'max_tokens': self.get('AI', 'MaxTokens'),
            'temperature': self.get('AI', 'Temperature'),
            'enable_predictions': self.get('AI', 'EnablePredictions'),
            'enable_reports': self.get('AI', 'EnableReports'),
            
            # Gemini specific
            'gemini_enabled': self.get('AI', 'GeminiEnabled', fallback=True),
            'gemini_api_key': self.get('AI', 'GeminiApiKey', fallback=''),
            'gemini_model': self.get('AI', 'GeminiModel', fallback='gemini-1.5-flash'),
            
            # OpenAI specific
            'openai_enabled': self.get('AI', 'Provider', fallback='').lower() == 'openai',
            'openai_api_key': self.get('AI', 'OpenAIApiKey', fallback=''),
            'openai_model': self.get('AI', 'OpenAIModel', fallback='gpt-4-mini')
        }
    
    def get_network_config(self) -> Dict[str, Any]:
        """Get network-specific configuration"""
        return {
            'default_interface': self.get('Network', 'DefaultInterface'),
            'scan_timeout': self.get('Network', 'ScanTimeout'),
            'thread_count': self.get('Network', 'ThreadCount'),
            'max_hosts': self.get('Network', 'MaxHosts'),
            'packet_delay': self.get('Network', 'PacketDelay')
        }
    
    def get_scanning_config(self) -> Dict[str, Any]:
        """Get scanning-specific configuration"""
        return {
            'port_range': self.get('Scanning', 'PortRange'),
            'scan_speed': self.get('Scanning', 'ScanSpeed'),
            'service_detection': self.get('Scanning', 'ServiceDetection'),
            'os_detection': self.get('Scanning', 'OSDetection'),
            'vuln_scanning': self.get('Scanning', 'VulnScanning'),
            'max_retries': self.get('Scanning', 'MaxRetries')
        }
    
    def get_output_config(self) -> Dict[str, Any]:
        """Get output-specific configuration"""
        return {
            'log_level': self.get('Output', 'LogLevel'),
            'output_format': self.get('Output', 'OutputFormat'),
            'save_reports': self.get('Output', 'SaveReports'),
            'report_path': self.get('Output', 'ReportPath'),
            'log_to_file': self.get('Output', 'LogToFile'),
            'color_output': self.get('Output', 'ColorOutput'),
            'verbose_mode': self.get('Output', 'VerboseMode')
        }
    
    def to_dict(self) -> Dict[str, Dict[str, Any]]:
        """Convert configuration to dictionary.
        
        Returns:
            Nested dictionary with all configuration sections and options.
        """
        result = {}
        for section in self.config.sections():
            result[section] = {}
            for option in self.config.options(section):
                result[section][option] = self._convert_value(
                    self.config.get(section, option)
                )
        return result
    
    def __str__(self) -> str:
        """Return string representation of configuration.
        
        Returns:
            JSON-formatted configuration string.
        """
        return json.dumps(self.to_dict(), indent=2)

