import numpy as np
import pandas as pd
from collections import deque
import time
import logging
from typing import List, Dict, Tuple, Optional
import threading

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealTimeMonitor:
    """
    Real-time monitoring class for continuous DoS attack detection
    """

    def __init__(self, window_size: int = 100, threshold: float = 0.7):
        self.window_size = window_size
        self.threshold = threshold
        self.traffic_window = deque(maxlen=window_size)
        self.attack_history = []
        self.is_monitoring = False
        self.monitor_thread = None

    def add_traffic_sample(self, features: np.ndarray, prediction: int, score: float):
        """
        Add a new traffic sample to the monitoring window
        """
        sample = {
            'timestamp': time.time(),
            'features': features.tolist() if isinstance(features, np.ndarray) else features,
            'prediction': int(prediction),
            'score': float(score)
        }

        self.traffic_window.append(sample)

        # Check for attack patterns
        attack_detected = self._detect_attack_pattern()
        if attack_detected:
            self.attack_history.append({
                'timestamp': sample['timestamp'],
                'attack_type': 'DoS',
                'severity': self._calculate_severity()
            })

        return attack_detected

    def _detect_attack_pattern(self) -> bool:
        """
        Detect DoS attack patterns in the current window
        """
        if len(self.traffic_window) < 10:  # Need minimum samples
            return False

        # Calculate attack ratio in current window
        attack_count = sum(1 for sample in self.traffic_window if sample['prediction'] == 1)
        attack_ratio = attack_count / len(self.traffic_window)

        # Check for sudden spikes
        recent_samples = list(self.traffic_window)[-20:]  # Last 20 samples
        recent_attack_ratio = sum(1 for sample in recent_samples if sample['prediction'] == 1) / len(recent_samples)

        # Attack detected if either condition is met
        return attack_ratio > self.threshold or recent_attack_ratio > (self.threshold * 1.5)

    def _calculate_severity(self) -> str:
        """
        Calculate the severity of detected attack
        """
        if len(self.traffic_window) < 5:
            return "Low"

        attack_scores = [sample['score'] for sample in self.traffic_window if sample['prediction'] == 1]

        if not attack_scores:
            return "Low"

        avg_score = np.mean(attack_scores)
        attack_ratio = len(attack_scores) / len(self.traffic_window)

        if avg_score > 0.8 and attack_ratio > 0.5:
            return "Critical"
        elif avg_score > 0.6 and attack_ratio > 0.3:
            return "High"
        elif avg_score > 0.4 and attack_ratio > 0.2:
            return "Medium"
        else:
            return "Low"

    def get_monitoring_stats(self) -> Dict:
        """
        Get current monitoring statistics
        """
        if not self.traffic_window:
            return {'status': 'No data'}

        attack_count = sum(1 for sample in self.traffic_window if sample['prediction'] == 1)
        normal_count = len(self.traffic_window) - attack_count

        recent_attacks = [attack for attack in self.attack_history[-10:]]  # Last 10 attacks

        return {
            'total_samples': len(self.traffic_window),
            'attack_count': attack_count,
            'normal_count': normal_count,
            'attack_ratio': attack_count / len(self.traffic_window),
            'recent_attacks': recent_attacks,
            'current_severity': self._calculate_severity() if attack_count > 0 else "Normal"
        }

    def start_monitoring(self):
        """Start the monitoring process"""
        if self.is_monitoring:
            logger.warning("Monitoring already running")
            return

        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info("Real-time monitoring started")

    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        logger.info("Real-time monitoring stopped")

    def _monitoring_loop(self):
        """Main monitoring loop (for future real-time data integration)"""
        while self.is_monitoring:
            # This would be where real-time data collection happens
            # For now, it's a placeholder for future implementation
            time.sleep(1)

class AttackClassifier:
    """
    Advanced attack classification for different types of DoS attacks
    """

    def __init__(self):
        self.attack_patterns = {
            'SYN_Flood': {
                'features': ['syn_flag_ratio', 'connection_rate'],
                'thresholds': {'syn_flag_ratio': 0.8, 'connection_rate': 1000}
            },
            'UDP_Flood': {
                'features': ['udp_packet_ratio', 'packet_rate'],
                'thresholds': {'udp_packet_ratio': 0.9, 'packet_rate': 5000}
            },
            'HTTP_Flood': {
                'features': ['http_request_ratio', 'request_rate'],
                'thresholds': {'http_request_ratio': 0.8, 'request_rate': 100}
            },
            'ICMP_Flood': {
                'features': ['icmp_packet_ratio', 'packet_rate'],
                'thresholds': {'icmp_packet_ratio': 0.9, 'packet_rate': 10000}
            }
        }

    def classify_attack(self, features: np.ndarray, feature_names: List[str]) -> str:
        """
        Classify the type of DoS attack based on traffic patterns
        """
        # This is a simplified classification - in practice, you'd use
        # more sophisticated ML models for attack classification

        feature_dict = dict(zip(feature_names, features))

        # Check each attack pattern
        for attack_type, pattern in self.attack_patterns.items():
            if self._matches_pattern(feature_dict, pattern):
                return attack_type

        return "Unknown_DoS"

    def _matches_pattern(self, features: Dict, pattern: Dict) -> bool:
        """
        Check if traffic features match a specific attack pattern
        """
        for feature, threshold in pattern['thresholds'].items():
            if feature in features:
                if features[feature] < threshold:
                    return False
        return True

class AlertSystem:
    """
    Alert system for DoS attack notifications
    """

    def __init__(self, alert_threshold: float = 0.7):
        self.alert_threshold = alert_threshold
        self.alert_history = []
        self.active_alerts = set()

    def check_alert(self, detection_results: Dict) -> Optional[Dict]:
        """
        Check if an alert should be triggered based on detection results
        """
        attack_percentage = detection_results.get('attack_percentage', 0)

        if attack_percentage > self.alert_threshold:
            alert = {
                'timestamp': time.time(),
                'alert_type': 'DoS_Attack_Detected',
                'severity': self._calculate_alert_severity(attack_percentage),
                'message': f"DoS attack detected: {attack_percentage:.2f}% malicious traffic",
                'details': detection_results
            }

            self.alert_history.append(alert)
            self.active_alerts.add(alert['timestamp'])

            return alert

        return None

    def _calculate_alert_severity(self, attack_percentage: float) -> str:
        """Calculate alert severity based on attack percentage"""
        if attack_percentage > 50:
            return "Critical"
        elif attack_percentage > 30:
            return "High"
        elif attack_percentage > 15:
            return "Medium"
        else:
            return "Low"

    def get_active_alerts(self) -> List[Dict]:
        """Get list of active alerts"""
        return [alert for alert in self.alert_history
                if alert['timestamp'] in self.active_alerts]

    def resolve_alert(self, alert_timestamp: float):
        """Mark an alert as resolved"""
        if alert_timestamp in self.active_alerts:
            self.active_alerts.remove(alert_timestamp)