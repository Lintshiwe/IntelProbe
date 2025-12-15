"""
AI Engine for IntelProbe
Provides AI-powered analysis, threat prediction, and intelligent insights
"""

import json
import logging
import time
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from pathlib import Path
import threading
import asyncio
import pickle

# Try to import optional AI dependencies with graceful fallback
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("⚠️ Warning: OpenAI not available. OpenAI-powered analysis features will be disabled.")

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("⚠️ Warning: Google Gemini not available. Gemini-powered analysis features will be disabled.")

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("⚠️ Warning: NumPy not available. Advanced mathematical operations will be limited.")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("⚠️ Warning: scikit-learn not available. Machine learning features will be disabled.")

@dataclass
class ThreatAnalysis:
    """Data class for threat analysis results"""
    threat_level: str  # low, medium, high, critical
    confidence: float  # 0-1
    threats: List[str]
    recommendations: List[str]
    analysis: str
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

@dataclass
class NetworkInsight:
    """Data class for network insights"""
    insight_type: str
    description: str
    impact: str
    recommendation: str
    confidence: float
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

class AIEngine:
    """AI-powered analysis engine for network forensics"""
    
    def __init__(self, config):
        """Initialize AI engine with configuration"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.ai_config = config.get_ai_config()
        
        # Initialize AI providers
        self.openai_client = None
        self.gemini_client = None
        self.ai_provider = None
        
        # Try to initialize OpenAI first
        if OPENAI_AVAILABLE and self.ai_config.get('openai_enabled', False) and self.ai_config.get('openai_api_key'):
            try:
                openai.api_key = self.ai_config['openai_api_key']
                self.openai_client = openai
                self.ai_provider = 'openai'
                self.logger.info("✅ AI engine initialized with OpenAI")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize OpenAI: {e}")
        
        # Try to initialize Gemini if OpenAI is not available or configured
        if not self.ai_provider and GEMINI_AVAILABLE and self.ai_config.get('gemini_enabled', False) and self.ai_config.get('gemini_api_key'):
            try:
                genai.configure(api_key=self.ai_config['gemini_api_key'])
                self.gemini_client = genai.GenerativeModel(
                    model_name=self.ai_config.get('gemini_model', 'gemini-1.5-flash')
                )
                self.ai_provider = 'gemini'
                self.logger.info("✅ AI engine initialized with Google Gemini")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize Gemini: {e}")
        
        # Fallback to legacy configuration format for backward compatibility
        if not self.ai_provider and self.ai_config.get('enabled', False) and self.ai_config.get('api_key'):
            if OPENAI_AVAILABLE:
                try:
                    openai.api_key = self.ai_config['api_key']
                    self.openai_client = openai
                    self.ai_provider = 'openai'
                    self.logger.info("✅ AI engine initialized with OpenAI (legacy config)")
                except Exception as e:
                    self.logger.warning(f"⚠️ Failed to initialize OpenAI (legacy): {e}")
        
        if not self.ai_provider:
            self.logger.info("ℹ️ No AI provider configured - AI analysis features disabled")
        
        # Initialize anomaly detection model if scikit-learn is available
        if SKLEARN_AVAILABLE:
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            self.scaler = StandardScaler()
            self.is_trained = False
        else:
            self.anomaly_detector = None
            self.scaler = None
            self.is_trained = False
            self.logger.info("ℹ️ scikit-learn not available - anomaly detection disabled")
        
        # Load pre-trained models if available
        self._load_models()
    
    def _query_ai(self, prompt: str, max_tokens: int = 1000, temperature: float = 0.3) -> str:
        """Unified method to query AI providers (OpenAI or Gemini)"""
        if not self.ai_provider:
            return "AI analysis unavailable - no AI provider configured."
        
        try:
            if self.ai_provider == 'openai' and self.openai_client:
                response = self.openai_client.ChatCompletion.create(
                    model=self.ai_config.get('openai_model', 'gpt-3.5-turbo'),
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert specializing in network security analysis."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                return response.choices[0].message.content.strip()
                
            elif self.ai_provider == 'gemini' and self.gemini_client:
                response = self.gemini_client.generate_content(
                    prompt,
                    generation_config={
                        'max_output_tokens': max_tokens,
                        'temperature': temperature,
                    }
                )
                return response.text.strip()
                
        except Exception as e:
            self.logger.warning(f"AI query failed: {e}")
            
        return "AI analysis failed due to technical issues."
    
    def _load_models(self) -> None:
        """Load pre-trained ML models"""
        try:
            models_path = Path("models")
            if models_path.exists():
                anomaly_path = models_path / "anomaly_detector.pkl"
                scaler_path = models_path / "scaler.pkl"
                
                if anomaly_path.exists() and scaler_path.exists():
                    with open(anomaly_path, 'rb') as f:
                        self.anomaly_detector = pickle.load(f)
                    with open(scaler_path, 'rb') as f:
                        self.scaler = pickle.load(f)
                    self.is_trained = True
                    self.logger.info("✅ Loaded pre-trained anomaly detection models")
        except Exception as e:
            self.logger.debug(f"Could not load pre-trained models: {e}")
    
    def analyze_network_scan(self, scan_results: List[Dict[str, Any]]) -> ThreatAnalysis:
        """
        Analyze network scan results for threats and anomalies
        
        Args:
            scan_results: List of scan result dictionaries
            
        Returns:
            ThreatAnalysis object with findings
        """
        self.logger.info("🤖 Analyzing network scan results with AI")
        
        try:
            # Extract features for analysis
            features = self._extract_network_features(scan_results)
            
            # Perform threat analysis
            threats = []
            recommendations = []
            threat_level = "low"
            confidence = 0.8
            
            # Analyze open ports and services
            port_analysis = self._analyze_ports(scan_results)
            threats.extend(port_analysis['threats'])
            recommendations.extend(port_analysis['recommendations'])
            
            # Analyze network topology
            topology_analysis = self._analyze_topology(scan_results)
            threats.extend(topology_analysis['threats'])
            recommendations.extend(topology_analysis['recommendations'])
            
            # Anomaly detection if model is trained
            if self.is_trained and features:
                anomalies = self._detect_anomalies(features)
                if anomalies:
                    threats.append(f"Detected {len(anomalies)} network anomalies")
                    recommendations.append("Investigate anomalous network behavior")
            
            # Determine overall threat level
            if len(threats) > 5:
                threat_level = "critical"
            elif len(threats) > 3:
                threat_level = "high"
            elif len(threats) > 1:
                threat_level = "medium"
            
            # Generate AI analysis if OpenAI is available
            analysis = "Basic rule-based analysis completed"
            if self.openai_client:
                analysis = self._generate_ai_analysis(scan_results, threats, recommendations)
            
            return ThreatAnalysis(
                threat_level=threat_level,
                confidence=confidence,
                threats=threats,
                recommendations=recommendations,
                analysis=analysis
            )
            
        except Exception as e:
            self.logger.error(f"❌ AI analysis failed: {e}")
            return ThreatAnalysis(
                threat_level="unknown",
                confidence=0.0,
                threats=[f"Analysis failed: {str(e)}"],
                recommendations=["Retry analysis with different parameters"],
                analysis="Analysis could not be completed due to technical issues"
            )
    
    def _extract_network_features(self, scan_results: List[Dict[str, Any]]) -> Any:
        """Extract numerical features for ML analysis"""
        if not NUMPY_AVAILABLE:
            # Return simple list when NumPy is not available
            features = []
            for result in scan_results:
                feature_vector = [
                    len(result.get('ports', [])),  # Number of open ports
                    result.get('response_time', 0),  # Response time
                    1 if result.get('os', '').lower() == 'unknown' else 0,  # Unknown OS flag
                    len(result.get('services', {})),  # Number of services
                ]
                features.append(feature_vector)
            return features
        
        # Use NumPy when available
        features = []
        for result in scan_results:
            feature_vector = [
                len(result.get('ports', [])),  # Number of open ports
                result.get('response_time', 0),  # Response time
                1 if result.get('os', '').lower() == 'unknown' else 0,  # Unknown OS flag
                len(result.get('services', {})),  # Number of services
            ]
            features.append(feature_vector)
        
        return np.array(features) if features else np.array([]).reshape(0, 4)
    
    def _analyze_ports(self, scan_results: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Analyze open ports for security threats"""
        threats = []
        recommendations = []
        
        # Define risky ports
        risky_ports = {
            21: "FTP - Unencrypted file transfer",
            23: "Telnet - Unencrypted remote access",
            135: "RPC - Windows RPC endpoint",
            139: "NetBIOS - File sharing vulnerability",
            445: "SMB - File sharing, potential for attacks",
            1433: "MSSQL - Database server exposed",
            3389: "RDP - Remote desktop access",
            5900: "VNC - Remote desktop access"
        }
        
        for result in scan_results:
            open_ports = result.get('ports', [])
            
            # Check for risky ports
            for port in open_ports:
                if port in risky_ports:
                    threats.append(f"Host {result.get('ip', 'unknown')} has risky port {port} open: {risky_ports[port]}")
                    recommendations.append(f"Consider securing or disabling port {port} on {result.get('ip', 'unknown')}")
            
            # Check for excessive open ports
            if len(open_ports) > 20:
                threats.append(f"Host {result.get('ip', 'unknown')} has {len(open_ports)} open ports - potential over-exposure")
                recommendations.append(f"Review and minimize open ports on {result.get('ip', 'unknown')}")
        
        return {'threats': threats, 'recommendations': recommendations}
    
    def _analyze_topology(self, scan_results: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Analyze network topology for security issues"""
        threats = []
        recommendations = []
        
        total_hosts = len(scan_results)
        
        # Check for network size concerns
        if total_hosts > 100:
            threats.append(f"Large network detected ({total_hosts} hosts) - increased attack surface")
            recommendations.append("Consider network segmentation to reduce attack surface")
        
        # Analyze OS distribution
        os_counts = {}
        for result in scan_results:
            os_type = result.get('os', 'Unknown').split(' ')[0]
            os_counts[os_type] = os_counts.get(os_type, 0) + 1
        
        # Check for OS diversity
        if len(os_counts) == 1 and 'Unknown' not in os_counts:
            threats.append("Homogeneous OS environment detected - single point of failure risk")
            recommendations.append("Consider OS diversity to reduce systemic vulnerabilities")
        
        # Check for unidentified systems
        unknown_count = os_counts.get('Unknown', 0)
        if unknown_count > total_hosts * 0.3:
            threats.append(f"{unknown_count} systems with unidentified OS - potential security blind spots")
            recommendations.append("Investigate and identify unknown systems")
        
        return {'threats': threats, 'recommendations': recommendations}
    
    def _detect_anomalies(self, features: Any) -> List[int]:
        """Detect anomalies in network features"""
        if not SKLEARN_AVAILABLE or not self.is_trained or not features:
            return []
        
        # Check if features is a list (fallback mode) or numpy array
        if not NUMPY_AVAILABLE:
            # Simple threshold-based anomaly detection when scikit-learn/numpy not available
            anomalies = []
            for i, feature_vector in enumerate(features):
                # Simple heuristic: flag hosts with unusually high port counts
                if len(feature_vector) > 0 and feature_vector[0] > 20:  # More than 20 open ports
                    anomalies.append(i)
            return anomalies
        
        try:
            # Normalize features
            features_scaled = self.scaler.transform(features)
            
            # Detect anomalies
            anomaly_scores = self.anomaly_detector.decision_function(features_scaled)
            anomalies = self.anomaly_detector.predict(features_scaled)
            
            # Return indices of anomalous samples
            return [i for i, is_anomaly in enumerate(anomalies) if is_anomaly == -1]
            
        except Exception as e:
            self.logger.debug(f"Anomaly detection failed: {e}")
            return []
    
    def _generate_ai_analysis(self, scan_results: List[Dict[str, Any]], 
                            threats: List[str], recommendations: List[str]) -> str:
        """Generate AI-powered analysis using available AI provider"""
        if not self.ai_provider:
            return f"AI analysis unavailable. {len(threats)} threats detected requiring attention."
            
        try:
            # Prepare context for AI
            context = {
                'total_hosts': len(scan_results),
                'threats_found': len(threats),
                'top_threats': threats[:5],  # Limit to top 5 threats
                'key_recommendations': recommendations[:5],
                'scan_summary': self._get_scan_summary(scan_results)
            }
            
            prompt = f"""
            As a cybersecurity expert, analyze the following network scan results and provide insights:
            
            Network Summary:
            - Total hosts discovered: {context['total_hosts']}
            - Threats identified: {context['threats_found']}
            
            Key Threats:
            {chr(10).join(f"- {threat}" for threat in context['top_threats'])}
            
            Recommendations:
            {chr(10).join(f"- {rec}" for rec in context['key_recommendations'])}
            
            Scan Details:
            {json.dumps(context['scan_summary'], indent=2)}
            
            Please provide:
            1. Overall security assessment
            2. Priority actions
            3. Long-term security strategy recommendations
            
            Keep the response concise but comprehensive.
            """
            
            return self._query_ai(prompt, max_tokens=800, temperature=0.3)
            
        except Exception as e:
            self.logger.warning(f"AI analysis generation failed: {e}")
            return f"AI analysis unavailable. {len(threats)} threats detected requiring attention."
    
    def _get_scan_summary(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary statistics from scan results"""
        if not scan_results:
            return {}
        
        total_ports = sum(len(result.get('ports', [])) for result in scan_results)
        os_distribution = {}
        
        for result in scan_results:
            os_type = result.get('os', 'Unknown').split(' ')[0]
            os_distribution[os_type] = os_distribution.get(os_type, 0) + 1
        
        return {
            'total_hosts': len(scan_results),
            'total_open_ports': total_ports,
            'average_ports_per_host': total_ports / len(scan_results) if scan_results else 0,
            'os_distribution': os_distribution,
            'hosts_with_services': len([r for r in scan_results if r.get('services')])
        }
    
    def generate_report(self, scan_data: Dict[str, Any], analysis: ThreatAnalysis) -> Dict[str, Any]:
        """
        Generate comprehensive security report
        
        Args:
            scan_data: Complete scan data
            analysis: Threat analysis results
            
        Returns:
            Formatted report dictionary
        """
        self.logger.info("📊 Generating AI-powered security report")
        
        try:
            # Basic report structure
            report = {
                'executive_summary': {
                    'threat_level': analysis.threat_level,
                    'confidence': analysis.confidence,
                    'total_threats': len(analysis.threats),
                    'scan_timestamp': analysis.timestamp
                },
                'findings': {
                    'threats': analysis.threats,
                    'recommendations': analysis.recommendations
                },
                'technical_details': scan_data,
                'ai_analysis': analysis.analysis
            }
            
            # Enhanced analysis if AI is available
            if self.openai_client:
                try:
                    enhanced_summary = self._generate_executive_summary(scan_data, analysis)
                    report['executive_summary']['ai_summary'] = enhanced_summary
                except Exception as e:
                    self.logger.warning(f"Failed to generate AI summary: {e}")
            
            return report
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return {
                'error': f"Report generation failed: {str(e)}",
                'basic_analysis': analysis.__dict__,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            }
    
    def _generate_executive_summary(self, scan_data: Dict[str, Any], 
                                  analysis: ThreatAnalysis) -> str:
        """Generate executive summary using AI"""
        if not self.ai_provider:
            return f"Network assessment completed with {analysis.threat_level} threat level. {len(analysis.threats)} issues require attention."
            
        try:
            prompt = f"""
            Generate a concise executive summary for the following network security assessment:
            
            Threat Level: {analysis.threat_level}
            Confidence: {analysis.confidence:.2f}
            Total Threats: {len(analysis.threats)}
            
            Key Issues:
            {chr(10).join(f"- {threat}" for threat in analysis.threats[:3])}
            
            Provide a 2-3 sentence executive summary suitable for management, focusing on:
            - Overall security posture
            - Most critical risks
            - Recommended next steps
            """
            
            return self._query_ai(prompt, max_tokens=200, temperature=0.3)
            
        except Exception as e:
            self.logger.debug(f"Executive summary generation failed: {e}")
            return f"Network assessment completed with {analysis.threat_level} threat level. {len(analysis.threats)} issues require attention."
    
    def train_anomaly_model(self, training_data: List[Dict[str, Any]]) -> bool:
        """
        Train anomaly detection model with normal network data
        
        Args:
            training_data: List of normal network scan results
            
        Returns:
            True if training successful
        """
        if not SKLEARN_AVAILABLE:
            self.logger.info("ℹ️ scikit-learn not available - anomaly detection training skipped")
            return False
            
        try:
            self.logger.info("🤖 Training anomaly detection model")
            
            # Extract features
            features = self._extract_network_features(training_data)
            
            if not NUMPY_AVAILABLE:
                # Simple validation for list-based features
                if len(features) < 10:
                    self.logger.warning("Insufficient training data for anomaly detection")
                    return False
                self.is_trained = True
                self.logger.info(f"✅ Simple anomaly detection enabled with {len(features)} samples")
                return True
            
            if len(features) < 10:
                self.logger.warning("Insufficient training data for anomaly detection")
                return False
            
            # Fit scaler and model
            features_scaled = self.scaler.fit_transform(features)
            self.anomaly_detector.fit(features_scaled)
            self.is_trained = True
            
            # Save models
            self._save_models()
            
            self.logger.info(f"✅ Anomaly detection model trained with {len(features)} samples")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Model training failed: {e}")
            return False
    
    def _save_models(self) -> None:
        """Save trained models to disk"""
        try:
            models_path = Path("models")
            models_path.mkdir(exist_ok=True)
            
            with open(models_path / "anomaly_detector.pkl", 'wb') as f:
                pickle.dump(self.anomaly_detector, f)
            
            with open(models_path / "scaler.pkl", 'wb') as f:
                pickle.dump(self.scaler, f)
                
            self.logger.debug("Models saved successfully")
            
        except Exception as e:
            self.logger.warning(f"Failed to save models: {e}")
    
    def predict_threats(self, network_data: Dict[str, Any]) -> List[NetworkInsight]:
        """
        Predict potential future threats based on current network state
        
        Args:
            network_data: Current network scan data
            
        Returns:
            List of predicted threat insights
        """
        self.logger.info("🔮 Generating threat predictions")
        
        insights = []
        
        try:
            # Rule-based predictions
            scan_results = network_data.get('scan_results', [])
            
            # Predict based on open services
            for result in scan_results:
                services = result.get('services', {})
                
                # Check for vulnerable service combinations
                if 80 in result.get('ports', []) and 443 not in result.get('ports', []):
                    insights.append(NetworkInsight(
                        insight_type="vulnerability_prediction",
                        description=f"Host {result.get('ip')} runs HTTP without HTTPS",
                        impact="High risk of data interception",
                        recommendation="Implement HTTPS to encrypt web traffic",
                        confidence=0.8
                    ))
                
                # Predict potential attack vectors
                if 22 in result.get('ports', []) and result.get('os', '').startswith('Linux'):
                    insights.append(NetworkInsight(
                        insight_type="attack_vector",
                        description=f"SSH service exposed on {result.get('ip')}",
                        impact="Potential target for brute force attacks",
                        recommendation="Implement key-based authentication and fail2ban",
                        confidence=0.7
                    ))
            
            # AI-enhanced predictions if available
            if self.ai_provider and len(insights) > 0:
                try:
                    ai_insights = self._generate_ai_predictions(network_data, insights)
                    insights.extend(ai_insights)
                except Exception as e:
                    self.logger.debug(f"AI prediction enhancement failed: {e}")
            
            return insights
            
        except Exception as e:
            self.logger.error(f"Threat prediction failed: {e}")
            return []
    
    def _generate_ai_predictions(self, network_data: Dict[str, Any], 
                               base_insights: List[NetworkInsight]) -> List[NetworkInsight]:
        """Generate AI-enhanced threat predictions"""
        if not self.ai_provider:
            return []  # Return empty list when no AI provider available
            
        try:
            context = json.dumps({
                'network_summary': self._get_scan_summary(network_data.get('scan_results', [])),
                'current_insights': [insight.description for insight in base_insights[:3]]
            }, indent=2)
            
            prompt = f"""
            Based on the following network security data, predict 2-3 additional potential threats or security concerns:
            
            {context}
            
            For each prediction, provide:
            1. Threat description
            2. Potential impact
            3. Recommended mitigation
            
            Focus on realistic, actionable predictions based on the network topology and services.
            """
            
            # Use unified AI query method
            ai_response = self._query_ai(prompt, max_tokens=500, temperature=0.4)
            
            # Create a general AI insight for now
            return [NetworkInsight(
                insight_type="ai_prediction",
                description="AI-generated threat prediction",
                impact="Varies based on specific prediction",
                recommendation=ai_response[:200] + "...",  # Truncate for brevity
                confidence=0.6
            )]
            
        except Exception as e:
            self.logger.debug(f"AI prediction generation failed: {e}")
            return []
