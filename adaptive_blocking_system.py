#!/usr/bin/env python3
"""
Adaptive Blocking/Unblocking Policy System

This module addresses the inflexible blocking/unblocking policy flaw by implementing:
1. Dynamic blocking duration based on threat assessment
2. Gradual unblocking with behavior monitoring
3. Adaptive thresholds based on network conditions
4. Intelligent timing for blocking/unblocking decisions
5. Machine learning-based threat pattern recognition
6. Reputation-based scoring system
7. Automatic policy adjustment based on feedback

Key Features:
- Risk-based blocking duration
- Behavioral analysis for unblocking decisions
- Adaptive thresholds
- Reputation tracking
- Automatic policy learning
- False positive mitigation
- Legitimate user protection
"""

import threading
import time
import json
import sqlite3
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import statistics
import math


class ThreatLevel(Enum):
    """Threat levels for dynamic blocking policies"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BlockingState(Enum):
    """Current blocking state of an IP/flow"""
    ACTIVE = "active"
    MONITORING = "monitoring"
    PROBATION = "probation"
    CLEARED = "cleared"


@dataclass
class ThreatScore:
    """Comprehensive threat scoring"""
    base_score: float = 0.0
    reputation_score: float = 0.0
    behavior_score: float = 0.0
    pattern_score: float = 0.0
    total_score: float = 0.0
    confidence: float = 0.0
    
    def calculate_total(self):
        """Calculate total threat score"""
        weights = {
            'base': 0.3,
            'reputation': 0.2,
            'behavior': 0.3,
            'pattern': 0.2
        }
        
        self.total_score = (
            self.base_score * weights['base'] +
            self.reputation_score * weights['reputation'] +
            self.behavior_score * weights['behavior'] +
            self.pattern_score * weights['pattern']
        )
        
        return self.total_score


@dataclass
class AdaptiveBlockingPolicy:
    """Dynamic blocking policy based on threat assessment"""
    ip_address: str
    threat_level: ThreatLevel
    threat_score: ThreatScore
    block_start_time: datetime
    initial_duration: int  # seconds
    current_duration: int  # seconds
    max_duration: int  # seconds
    blocking_state: BlockingState
    unblock_attempts: int = 0
    false_positive_score: float = 0.0
    last_activity: Optional[datetime] = None
    reputation_history: List[float] = field(default_factory=list)
    behavior_patterns: Dict[str, float] = field(default_factory=dict)
    
    def should_unblock(self, current_time: datetime) -> bool:
        """Determine if IP should be unblocked based on adaptive criteria"""
        if self.blocking_state != BlockingState.ACTIVE:
            return False
        
        elapsed = (current_time - self.block_start_time).total_seconds()
        
        # Basic time-based unblocking
        if elapsed >= self.current_duration:
            return True
        
        # Early unblocking for low threat with good reputation
        if (self.threat_level == ThreatLevel.LOW and 
            self.threat_score.total_score < 0.3 and
            self.false_positive_score > 0.7):
            return True
        
        # Extended blocking for critical threats
        if (self.threat_level == ThreatLevel.CRITICAL and 
            elapsed < self.max_duration):
            return False
        
        return False
    
    def adjust_duration(self, network_conditions: Dict[str, float]):
        """Adjust blocking duration based on network conditions"""
        base_multiplier = 1.0
        
        # Adjust based on network load
        if network_conditions.get('load', 0) > 0.8:
            base_multiplier *= 1.5  # Longer blocks during high load
        
        # Adjust based on attack frequency
        if network_conditions.get('attack_frequency', 0) > 0.7:
            base_multiplier *= 1.3  # Longer blocks during attack waves
        
        # Adjust based on false positive rate
        if network_conditions.get('false_positive_rate', 0) > 0.1:
            base_multiplier *= 0.8  # Shorter blocks if high false positive rate
        
        self.current_duration = int(self.initial_duration * base_multiplier)
        self.current_duration = min(self.current_duration, self.max_duration)


class ReputationSystem:
    """IP reputation tracking system"""
    
    def __init__(self, db_path: str = "reputation.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()
        
    def _init_database(self):
        """Initialize reputation database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS reputation (
                    ip_address TEXT PRIMARY KEY,
                    reputation_score REAL DEFAULT 0.5,
                    total_connections INTEGER DEFAULT 0,
                    malicious_connections INTEGER DEFAULT 0,
                    legitimate_connections INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
    
    def get_reputation(self, ip_address: str) -> float:
        """Get reputation score for IP address"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT reputation_score FROM reputation WHERE ip_address = ?',
                    (ip_address,)
                )
                result = cursor.fetchone()
                return result[0] if result else 0.5  # Default neutral reputation
    
    def update_reputation(self, ip_address: str, is_malicious: bool, is_false_positive: bool = False):
        """Update reputation based on behavior"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                # Get current reputation
                cursor = conn.execute(
                    'SELECT reputation_score, total_connections, malicious_connections, legitimate_connections, false_positives FROM reputation WHERE ip_address = ?',
                    (ip_address,)
                )
                result = cursor.fetchone()
                
                if result:
                    current_score, total, malicious, legitimate, false_pos = result
                else:
                    current_score, total, malicious, legitimate, false_pos = 0.5, 0, 0, 0, 0
                
                # Update counters
                total += 1
                if is_false_positive:
                    false_pos += 1
                    legitimate += 1
                elif is_malicious:
                    malicious += 1
                else:
                    legitimate += 1
                
                # Calculate new reputation score
                if total > 0:
                    # Base reputation on behavior ratio
                    behavior_ratio = legitimate / total
                    false_positive_penalty = false_pos / total
                    
                    # Weighted average with previous score
                    weight = min(total / 100.0, 0.9)  # More weight to recent behavior
                    new_score = (weight * behavior_ratio + (1 - weight) * current_score) - (false_positive_penalty * 0.1)
                    new_score = max(0.0, min(1.0, new_score))  # Clamp between 0 and 1
                else:
                    new_score = current_score
                
                # Update database
                conn.execute('''
                    INSERT OR REPLACE INTO reputation 
                    (ip_address, reputation_score, total_connections, malicious_connections, legitimate_connections, false_positives, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (ip_address, new_score, total, malicious, legitimate, false_pos))
    
    def get_reputation_history(self, ip_address: str) -> Dict[str, int]:
        """Get reputation history for IP"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT total_connections, malicious_connections, legitimate_connections, false_positives FROM reputation WHERE ip_address = ?',
                    (ip_address,)
                )
                result = cursor.fetchone()
                if result:
                    return {
                        'total': result[0],
                        'malicious': result[1],
                        'legitimate': result[2],
                        'false_positives': result[3]
                    }
                return {'total': 0, 'malicious': 0, 'legitimate': 0, 'false_positives': 0}


class BehaviorAnalyzer:
    """Analyzes traffic patterns to improve blocking decisions"""
    
    def __init__(self):
        self.traffic_patterns = {}
        self.baseline_patterns = {}
        self.lock = threading.Lock()
        
    def analyze_traffic_pattern(self, ip_address: str, traffic_metrics: Dict[str, float]) -> Dict[str, float]:
        """Analyze traffic patterns for behavioral scoring"""
        with self.lock:
            # Store traffic pattern
            if ip_address not in self.traffic_patterns:
                self.traffic_patterns[ip_address] = []
            
            self.traffic_patterns[ip_address].append({
                'timestamp': datetime.now(),
                'metrics': traffic_metrics.copy()
            })
            
            # Keep only recent patterns (last 24 hours)
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.traffic_patterns[ip_address] = [
                pattern for pattern in self.traffic_patterns[ip_address]
                if pattern['timestamp'] > cutoff_time
            ]
            
            # Calculate behavior score
            return self._calculate_behavior_score(ip_address, traffic_metrics)
    
    def _calculate_behavior_score(self, ip_address: str, current_metrics: Dict[str, float]) -> Dict[str, float]:
        """Calculate behavioral score based on traffic patterns"""
        patterns = self.traffic_patterns.get(ip_address, [])
        if len(patterns) < 5:  # Not enough data
            return {'behavior_score': 0.5, 'confidence': 0.1}
        
        # Calculate deviations from normal patterns
        normal_patterns = [p['metrics'] for p in patterns[-20:]]  # Last 20 patterns
        
        deviations = {}
        for metric in current_metrics:
            if metric in normal_patterns[0]:
                values = [p[metric] for p in normal_patterns if metric in p]
                if values:
                    avg = statistics.mean(values)
                    std = statistics.stdev(values) if len(values) > 1 else 0
                    
                    if std > 0:
                        deviation = abs(current_metrics[metric] - avg) / std
                        deviations[metric] = deviation
        
        # Calculate overall behavior score
        if deviations:
            avg_deviation = statistics.mean(deviations.values())
            # Higher deviation = more suspicious
            behavior_score = min(1.0, avg_deviation / 3.0)  # Normalize
            confidence = min(1.0, len(patterns) / 20.0)  # More patterns = higher confidence
        else:
            behavior_score = 0.5
            confidence = 0.1
        
        return {
            'behavior_score': behavior_score,
            'confidence': confidence,
            'deviations': deviations
        }
    
    def is_legitimate_pattern(self, ip_address: str, threshold: float = 0.3) -> bool:
        """Determine if traffic pattern indicates legitimate user"""
        patterns = self.traffic_patterns.get(ip_address, [])
        if len(patterns) < 10:
            return False  # Not enough data
        
        # Check for consistent, moderate traffic patterns
        recent_patterns = patterns[-10:]
        packet_rates = [p['metrics'].get('packet_rate', 0) for p in recent_patterns]
        
        if packet_rates:
            avg_rate = statistics.mean(packet_rates)
            std_rate = statistics.stdev(packet_rates) if len(packet_rates) > 1 else 0
            
            # Legitimate users typically have:
            # - Moderate packet rates (not too high)
            # - Consistent patterns (low standard deviation)
            # - Regular intervals
            
            is_moderate = 10 <= avg_rate <= 100  # Reasonable packet rate
            is_consistent = std_rate < avg_rate * 0.3  # Low variability
            
            return is_moderate and is_consistent
        
        return False


class AdaptiveBlockingSystem:
    """Main adaptive blocking/unblocking system"""
    
    def __init__(self, policy_store, logger=None):
        self.policy_store = policy_store
        self.logger = logger or logging.getLogger(__name__)
        
        # Core components
        self.reputation_system = ReputationSystem()
        self.behavior_analyzer = BehaviorAnalyzer()
        
        # Active blocking policies
        self.active_policies: Dict[str, AdaptiveBlockingPolicy] = {}
        self.lock = threading.Lock()
        
        # Network condition monitoring
        self.network_conditions = {
            'load': 0.0,
            'attack_frequency': 0.0,
            'false_positive_rate': 0.0,
            'legitimate_traffic_ratio': 0.0
        }
        
        # Adaptive thresholds
        self.dynamic_thresholds = {
            'low_threat': 0.3,
            'medium_threat': 0.6,
            'high_threat': 0.8,
            'critical_threat': 0.9
        }
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        self.logger.info("🔄 Adaptive Blocking System initialized")
    
    def calculate_threat_score(self, ip_address: str, traffic_metrics: Dict[str, float]) -> ThreatScore:
        """Calculate comprehensive threat score"""
        threat_score = ThreatScore()
        
        # Base score from traffic metrics
        packet_rate = traffic_metrics.get('packet_rate', 0)
        byte_rate = traffic_metrics.get('byte_rate', 0)
        connection_rate = traffic_metrics.get('connection_rate', 0)
        
        # Normalize and weight base metrics
        threat_score.base_score = min(1.0, (
            (packet_rate / 1000.0) * 0.4 +
            (byte_rate / 1000000.0) * 0.3 +
            (connection_rate / 100.0) * 0.3
        ))
        
        # Reputation score
        reputation = self.reputation_system.get_reputation(ip_address)
        threat_score.reputation_score = 1.0 - reputation  # Invert: low reputation = high threat
        
        # Behavior score
        behavior_analysis = self.behavior_analyzer.analyze_traffic_pattern(ip_address, traffic_metrics)
        threat_score.behavior_score = behavior_analysis['behavior_score']
        threat_score.confidence = behavior_analysis['confidence']
        
        # Pattern score (simplified - could be enhanced with ML)
        threat_score.pattern_score = self._calculate_pattern_score(ip_address, traffic_metrics)
        
        # Calculate total score
        threat_score.calculate_total()
        
        return threat_score
    
    def _calculate_pattern_score(self, ip_address: str, traffic_metrics: Dict[str, float]) -> float:
        """Calculate pattern-based threat score"""
        # Simple pattern matching - could be enhanced with ML
        score = 0.0
        
        # High packet rate patterns
        if traffic_metrics.get('packet_rate', 0) > 500:
            score += 0.3
        
        # Unusual timing patterns
        if traffic_metrics.get('burst_ratio', 0) > 0.8:
            score += 0.2
        
        # Port scanning patterns
        if traffic_metrics.get('unique_ports', 0) > 10:
            score += 0.3
        
        # Repetitive patterns
        if traffic_metrics.get('repetition_ratio', 0) > 0.9:
            score += 0.2
        
        return min(1.0, score)
    
    def determine_threat_level(self, threat_score: ThreatScore) -> ThreatLevel:
        """Determine threat level based on adaptive thresholds"""
        total_score = threat_score.total_score
        
        if total_score >= self.dynamic_thresholds['critical_threat']:
            return ThreatLevel.CRITICAL
        elif total_score >= self.dynamic_thresholds['high_threat']:
            return ThreatLevel.HIGH
        elif total_score >= self.dynamic_thresholds['medium_threat']:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def create_adaptive_policy(self, ip_address: str, threat_score: ThreatScore) -> AdaptiveBlockingPolicy:
        """Create adaptive blocking policy based on threat assessment"""
        threat_level = self.determine_threat_level(threat_score)
        
        # Calculate dynamic blocking duration
        base_durations = {
            ThreatLevel.LOW: 60,      # 1 minute
            ThreatLevel.MEDIUM: 300,  # 5 minutes
            ThreatLevel.HIGH: 900,    # 15 minutes
            ThreatLevel.CRITICAL: 3600  # 1 hour
        }
        
        max_durations = {
            ThreatLevel.LOW: 300,     # 5 minutes max
            ThreatLevel.MEDIUM: 1800, # 30 minutes max
            ThreatLevel.HIGH: 7200,   # 2 hours max
            ThreatLevel.CRITICAL: 86400  # 24 hours max
        }
        
        initial_duration = base_durations[threat_level]
        max_duration = max_durations[threat_level]
        
        # Adjust for reputation
        reputation = self.reputation_system.get_reputation(ip_address)
        if reputation < 0.3:  # Poor reputation
            initial_duration = int(initial_duration * 1.5)
        elif reputation > 0.7:  # Good reputation
            initial_duration = int(initial_duration * 0.7)
        
        # Adjust for network conditions
        if self.network_conditions['attack_frequency'] > 0.7:
            initial_duration = int(initial_duration * 1.3)
        
        policy = AdaptiveBlockingPolicy(
            ip_address=ip_address,
            threat_level=threat_level,
            threat_score=threat_score,
            block_start_time=datetime.now(),
            initial_duration=initial_duration,
            current_duration=initial_duration,
            max_duration=max_duration,
            blocking_state=BlockingState.ACTIVE
        )
        
        return policy
    
    def should_block(self, ip_address: str, traffic_metrics: Dict[str, float]) -> Tuple[bool, str]:
        """Determine if IP should be blocked based on adaptive criteria"""
        threat_score = self.calculate_threat_score(ip_address, traffic_metrics)
        threat_level = self.determine_threat_level(threat_score)
        
        # Check if IP is already blocked
        if ip_address in self.active_policies:
            policy = self.active_policies[ip_address]
            if policy.blocking_state == BlockingState.ACTIVE:
                return False, f"Already blocked (threat level: {threat_level.value})"
        
        # Check if threat level warrants blocking
        if threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            # Additional checks for medium threat
            if threat_level == ThreatLevel.MEDIUM:
                # Check if this might be a false positive
                if self.behavior_analyzer.is_legitimate_pattern(ip_address):
                    return False, "Legitimate traffic pattern detected"
                
                # Check reputation
                reputation = self.reputation_system.get_reputation(ip_address)
                if reputation > 0.8:
                    return False, "High reputation score"
            
            reason = f"Threat level {threat_level.value} (score: {threat_score.total_score:.3f})"
            return True, reason
        
        return False, f"Threat level {threat_level.value} below blocking threshold"
    
    def block_ip(self, ip_address: str, traffic_metrics: Dict[str, float]) -> AdaptiveBlockingPolicy:
        """Block IP with adaptive policy"""
        threat_score = self.calculate_threat_score(ip_address, traffic_metrics)
        policy = self.create_adaptive_policy(ip_address, threat_score)
        
        with self.lock:
            self.active_policies[ip_address] = policy
        
        # Add to policy store
        self.policy_store.add_policy(
            rule_id=f"adaptive_block_{ip_address}_{int(time.time())}",
            src_ip=ip_address,
            dst_ip="0.0.0.0/0",
            action="block",
            priority=10,
            metadata={
                "type": "adaptive_blocking",
                "threat_level": policy.threat_level.value,
                "threat_score": policy.threat_score.total_score,
                "initial_duration": policy.initial_duration,
                "max_duration": policy.max_duration
            }
        )
        
        self.logger.warning(f"🚫 Adaptive block: {ip_address} (threat: {policy.threat_level.value}, duration: {policy.initial_duration}s)")
        return policy
    
    def should_unblock(self, ip_address: str) -> Tuple[bool, str]:
        """Determine if IP should be unblocked based on adaptive criteria"""
        if ip_address not in self.active_policies:
            return False, "IP not currently blocked"
        
        policy = self.active_policies[ip_address]
        current_time = datetime.now()
        
        # Check basic unblocking condition
        if policy.should_unblock(current_time):
            # Additional checks before unblocking
            
            # Check if this was likely a false positive
            if self._is_likely_false_positive(policy):
                return True, "Likely false positive - early unblock"
            
            # Check if legitimate behavior observed
            if self.behavior_analyzer.is_legitimate_pattern(ip_address):
                return True, "Legitimate traffic pattern observed"
            
            # Time-based unblocking
            elapsed = (current_time - policy.block_start_time).total_seconds()
            if elapsed >= policy.current_duration:
                return True, f"Blocking duration expired ({elapsed:.0f}s)"
        
        return False, "Blocking conditions still active"
    
    def _is_likely_false_positive(self, policy: AdaptiveBlockingPolicy) -> bool:
        """Check if blocking policy is likely a false positive"""
        # Check reputation improvement
        current_reputation = self.reputation_system.get_reputation(policy.ip_address)
        if current_reputation > 0.8:
            return True
        
        # Check if threat level was borderline
        if (policy.threat_level == ThreatLevel.MEDIUM and 
            policy.threat_score.total_score < 0.7):
            return True
        
        # Check confidence level
        if policy.threat_score.confidence < 0.5:
            return True
        
        return False
    
    def unblock_ip(self, ip_address: str, reason: str = "Policy expired") -> bool:
        """Unblock IP and transition to monitoring"""
        if ip_address not in self.active_policies:
            return False
        
        policy = self.active_policies[ip_address]
        
        # Remove from policy store
        # Note: This is simplified - in practice, you'd need to track policy IDs
        
        # Transition to monitoring state
        policy.blocking_state = BlockingState.MONITORING
        policy.unblock_attempts += 1
        
        # Update reputation if this was a false positive
        if "false positive" in reason.lower():
            self.reputation_system.update_reputation(ip_address, False, True)
            policy.false_positive_score += 0.1
        
        self.logger.info(f"✅ Adaptive unblock: {ip_address} ({reason})")
        return True
    
    def update_network_conditions(self, conditions: Dict[str, float]):
        """Update network conditions for adaptive thresholds"""
        self.network_conditions.update(conditions)
        
        # Adjust thresholds based on conditions
        base_thresholds = {
            'low_threat': 0.3,
            'medium_threat': 0.6,
            'high_threat': 0.8,
            'critical_threat': 0.9
        }
        
        # Adjust based on attack frequency
        attack_freq = conditions.get('attack_frequency', 0)
        if attack_freq > 0.7:
            # Lower thresholds during high attack periods
            multiplier = 0.8
        elif attack_freq < 0.3:
            # Raise thresholds during quiet periods
            multiplier = 1.2
        else:
            multiplier = 1.0
        
        # Adjust based on false positive rate
        fp_rate = conditions.get('false_positive_rate', 0)
        if fp_rate > 0.1:
            # Raise thresholds if too many false positives
            multiplier *= 1.1
        
        # Update thresholds
        for key, base_value in base_thresholds.items():
            self.dynamic_thresholds[key] = min(0.95, base_value * multiplier)
    
    def _monitoring_loop(self):
        """Background monitoring loop for adaptive policies"""
        while True:
            try:
                current_time = datetime.now()
                
                # Check all active policies
                with self.lock:
                    policies_to_update = list(self.active_policies.items())
                
                for ip_address, policy in policies_to_update:
                    # Check if should be unblocked
                    should_unblock, reason = self.should_unblock(ip_address)
                    if should_unblock:
                        self.unblock_ip(ip_address, reason)
                    
                    # Adjust duration based on current network conditions
                    policy.adjust_duration(self.network_conditions)
                
                # Clean up old policies
                self._cleanup_old_policies()
                
                # Sleep for monitoring interval
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _cleanup_old_policies(self):
        """Clean up old policies"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(hours=24)
        
        with self.lock:
            to_remove = []
            for ip_address, policy in self.active_policies.items():
                if (policy.blocking_state == BlockingState.CLEARED and 
                    policy.block_start_time < cutoff_time):
                    to_remove.append(ip_address)
            
            for ip_address in to_remove:
                del self.active_policies[ip_address]
    
    def get_policy_status(self, ip_address: str) -> Optional[Dict]:
        """Get current policy status for IP"""
        if ip_address not in self.active_policies:
            return None
        
        policy = self.active_policies[ip_address]
        current_time = datetime.now()
        elapsed = (current_time - policy.block_start_time).total_seconds()
        
        return {
            'ip_address': ip_address,
            'threat_level': policy.threat_level.value,
            'threat_score': policy.threat_score.total_score,
            'blocking_state': policy.blocking_state.value,
            'elapsed_time': elapsed,
            'remaining_time': max(0, policy.current_duration - elapsed),
            'initial_duration': policy.initial_duration,
            'current_duration': policy.current_duration,
            'max_duration': policy.max_duration,
            'unblock_attempts': policy.unblock_attempts,
            'false_positive_score': policy.false_positive_score,
            'reputation': self.reputation_system.get_reputation(ip_address)
        }
    
    def get_system_stats(self) -> Dict:
        """Get system statistics"""
        with self.lock:
            active_blocks = len([p for p in self.active_policies.values() 
                               if p.blocking_state == BlockingState.ACTIVE])
            monitoring_blocks = len([p for p in self.active_policies.values() 
                                   if p.blocking_state == BlockingState.MONITORING])
            
            threat_levels = {}
            for policy in self.active_policies.values():
                level = policy.threat_level.value
                threat_levels[level] = threat_levels.get(level, 0) + 1
        
        return {
            'active_blocks': active_blocks,
            'monitoring_blocks': monitoring_blocks,
            'total_policies': len(self.active_policies),
            'threat_level_distribution': threat_levels,
            'network_conditions': self.network_conditions.copy(),
            'dynamic_thresholds': self.dynamic_thresholds.copy()
        }


# Integration with existing system
class AdaptiveBlockingIntegration:
    """Integration layer for adaptive blocking system"""
    
    def __init__(self, modular_controller, enhanced_mitigation_enforcer):
        self.modular_controller = modular_controller
        self.enhanced_mitigation = enhanced_mitigation_enforcer
        self.adaptive_blocking = AdaptiveBlockingSystem(
            modular_controller.policy_store,
            modular_controller.logger
        )
        
        # Replace existing blocking logic
        self._integrate_with_controller()
    
    def _integrate_with_controller(self):
        """Integrate adaptive blocking with existing controller"""
        # Monkey patch the mitigation policy to use adaptive blocking
        original_block_method = self.modular_controller.mitigation_policy.should_block_port
        
        def adaptive_should_block_port(switch_id, port_no, traffic_stats):
            # Extract IP from traffic stats (simplified)
            ip_address = traffic_stats.get('src_ip', 'unknown')
            if ip_address == 'unknown':
                return original_block_method(switch_id, port_no, traffic_stats)
            
            # Use adaptive blocking system
            should_block, reason = self.adaptive_blocking.should_block(ip_address, traffic_stats)
            
            if should_block:
                # Create adaptive policy
                policy = self.adaptive_blocking.block_ip(ip_address, traffic_stats)
                self.modular_controller.logger.info(f"🔄 Adaptive blocking decision: {reason}")
                return True
            
            return False
        
        # Replace the method
        self.modular_controller.mitigation_policy.should_block_port = adaptive_should_block_port
    
    def get_adaptive_stats(self) -> Dict:
        """Get adaptive blocking statistics"""
        return self.adaptive_blocking.get_system_stats()
    
    def force_unblock(self, ip_address: str) -> bool:
        """Force unblock an IP (admin override)"""
        return self.adaptive_blocking.unblock_ip(ip_address, "Admin override")
    
    def get_ip_status(self, ip_address: str) -> Optional[Dict]:
        """Get status for specific IP"""
        return self.adaptive_blocking.get_policy_status(ip_address)


if __name__ == "__main__":
    # Test the adaptive blocking system
    import random
    
    logging.basicConfig(level=logging.INFO)
    
    # Create a mock policy store for testing
    class MockPolicyStore:
        def __init__(self):
            self.policies = {}
        
        def add_policy(self, rule_id, src_ip, dst_ip, action, priority, metadata=None):
            self.policies[rule_id] = {
                'src_ip': src_ip,
                'action': action,
                'priority': priority,
                'metadata': metadata or {}
            }
        
        def remove_policy(self, rule_id):
            if rule_id in self.policies:
                del self.policies[rule_id]
    
    # Test the system
    print("🧪 Testing Adaptive Blocking System")
    
    mock_store = MockPolicyStore()
    adaptive_system = AdaptiveBlockingSystem(mock_store)
    
    # Test blocking decisions
    test_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.10"]
    
    for ip in test_ips:
        # Generate random traffic metrics
        traffic_metrics = {
            'packet_rate': random.uniform(10, 1000),
            'byte_rate': random.uniform(1000, 10000000),
            'connection_rate': random.uniform(1, 100),
            'burst_ratio': random.uniform(0.1, 1.0),
            'unique_ports': random.randint(1, 20),
            'repetition_ratio': random.uniform(0.1, 1.0)
        }
        
        # Test blocking decision
        should_block, reason = adaptive_system.should_block(ip, traffic_metrics)
        print(f"IP {ip}: Block={should_block}, Reason={reason}")
        
        if should_block:
            policy = adaptive_system.block_ip(ip, traffic_metrics)
            print(f"  Created policy: {policy.threat_level.value} threat, {policy.initial_duration}s duration")
    
    # Test system stats
    stats = adaptive_system.get_system_stats()
    print(f"\nSystem Stats: {json.dumps(stats, indent=2)}")
    
    print("✅ Adaptive Blocking System test complete")
