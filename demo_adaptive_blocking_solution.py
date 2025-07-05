#!/usr/bin/env python3
"""
Demonstration of Adaptive Blocking/Unblocking Policy Solution

This script demonstrates how the adaptive blocking system addresses the 
inflexible blocking/unblocking policy flaw by providing intelligent, 
context-aware blocking and unblocking decisions.
"""

import sys
import os
import time
import threading
import random
from datetime import datetime, timedelta

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 70)
print("🔄 ADAPTIVE BLOCKING/UNBLOCKING POLICY DEMONSTRATION")
print("Addressing the Inflexible Blocking/Unblocking Policy Flaw")
print("=" * 70)

try:
    from adaptive_blocking_system import AdaptiveBlockingSystem, ThreatLevel, BlockingState
    from external_policy_system import PolicyStore
    print("✅ Adaptive blocking system imported successfully")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


class AdaptiveBlockingDemo:
    """Demonstration of adaptive blocking system capabilities"""
    
    def __init__(self):
        self.policy_store = PolicyStore()
        self.adaptive_system = AdaptiveBlockingSystem(self.policy_store)
        self.demo_running = False
        
    def demonstrate_problem_and_solution(self):
        """Demonstrate the problem and how the solution addresses it"""
        print("\n1. PROBLEM ANALYSIS")
        print("-" * 40)
        
        print("\n📋 Original Inflexible Policy Problems:")
        print("   ❌ Fixed blocking duration regardless of threat level")
        print("   ❌ No consideration of user reputation or history")
        print("   ❌ Unblocking either too early (allowing attackers back) or too late (blocking legitimate users)")
        print("   ❌ No adaptive thresholds based on network conditions")
        print("   ❌ No differentiation between false positives and real threats")
        print("   ❌ No behavioral analysis for unblocking decisions")
        
        print("\n🎯 Adaptive Solution Features:")
        print("   ✅ Dynamic blocking duration based on threat assessment")
        print("   ✅ Reputation-based scoring system")
        print("   ✅ Behavioral analysis for legitimate user detection")
        print("   ✅ Adaptive thresholds based on network conditions")
        print("   ✅ Graduated response (monitor → rate limit → block)")
        print("   ✅ Machine learning-based pattern recognition")
        print("   ✅ False positive detection and mitigation")
        print("   ✅ Automatic policy adjustment based on feedback")
        
    def demonstrate_threat_levels(self):
        """Demonstrate different threat levels and their blocking policies"""
        print("\n2. THREAT LEVEL DEMONSTRATION")
        print("-" * 40)
        
        # Simulate different threat scenarios
        scenarios = [
            {
                "name": "Low Threat - Legitimate User",
                "ip": "10.0.1.100",
                "metrics": {
                    "packet_rate": 20,
                    "byte_rate": 5000,
                    "connection_rate": 2,
                    "burst_ratio": 0.2,
                    "unique_ports": 3,
                    "repetition_ratio": 0.1
                },
                "expected_level": ThreatLevel.LOW
            },
            {
                "name": "Medium Threat - Suspicious Activity",
                "ip": "10.0.1.101",
                "metrics": {
                    "packet_rate": 200,
                    "byte_rate": 500000,
                    "connection_rate": 20,
                    "burst_ratio": 0.6,
                    "unique_ports": 8,
                    "repetition_ratio": 0.5
                },
                "expected_level": ThreatLevel.MEDIUM
            },
            {
                "name": "High Threat - Attack Pattern",
                "ip": "10.0.1.102",
                "metrics": {
                    "packet_rate": 800,
                    "byte_rate": 2000000,
                    "connection_rate": 60,
                    "burst_ratio": 0.9,
                    "unique_ports": 15,
                    "repetition_ratio": 0.8
                },
                "expected_level": ThreatLevel.HIGH
            },
            {
                "name": "Critical Threat - DDoS Attack",
                "ip": "10.0.1.103",
                "metrics": {
                    "packet_rate": 1500,
                    "byte_rate": 8000000,
                    "connection_rate": 100,
                    "burst_ratio": 0.95,
                    "unique_ports": 20,
                    "repetition_ratio": 0.95
                },
                "expected_level": ThreatLevel.CRITICAL
            }
        ]
        
        for scenario in scenarios:
            print(f"\n🔍 Scenario: {scenario['name']}")
            print(f"   IP: {scenario['ip']}")
            print(f"   Traffic Metrics: {scenario['metrics']}")
            
            # Calculate threat score
            threat_score = self.adaptive_system.calculate_threat_score(
                scenario['ip'], scenario['metrics']
            )
            threat_level = self.adaptive_system.determine_threat_level(threat_score)
            
            print(f"   📊 Threat Score: {threat_score.total_score:.3f}")
            print(f"   🎯 Threat Level: {threat_level.value}")
            print(f"   📈 Confidence: {threat_score.confidence:.3f}")
            
            # Check blocking decision
            should_block, reason = self.adaptive_system.should_block(scenario['ip'], scenario['metrics'])
            print(f"   🚫 Block Decision: {should_block} ({reason})")
            
            if should_block:
                policy = self.adaptive_system.block_ip(scenario['ip'], scenario['metrics'])
                print(f"   ⏱️  Initial Duration: {policy.initial_duration}s")
                print(f"   ⏱️  Max Duration: {policy.max_duration}s")
                print(f"   📋 Policy State: {policy.blocking_state.value}")
    
    def demonstrate_reputation_system(self):
        """Demonstrate reputation-based blocking adjustments"""
        print("\n3. REPUTATION SYSTEM DEMONSTRATION")
        print("-" * 40)
        
        test_ip = "10.0.1.200"
        
        print(f"\n🔍 Testing IP: {test_ip}")
        
        # Initial reputation (neutral)
        initial_reputation = self.adaptive_system.reputation_system.get_reputation(test_ip)
        print(f"   📊 Initial Reputation: {initial_reputation:.3f}")
        
        # Simulate legitimate behavior
        print("\n   🟢 Simulating legitimate behavior...")
        for i in range(5):
            self.adaptive_system.reputation_system.update_reputation(test_ip, False, False)
            reputation = self.adaptive_system.reputation_system.get_reputation(test_ip)
            print(f"   📈 After {i+1} legitimate connections: {reputation:.3f}")
        
        # Test blocking decision with good reputation
        traffic_metrics = {
            "packet_rate": 150,
            "byte_rate": 300000,
            "connection_rate": 15,
            "burst_ratio": 0.5,
            "unique_ports": 5,
            "repetition_ratio": 0.4
        }
        
        should_block, reason = self.adaptive_system.should_block(test_ip, traffic_metrics)
        print(f"   🚫 Block Decision (good reputation): {should_block} ({reason})")
        
        # Simulate malicious behavior
        print("\n   🔴 Simulating malicious behavior...")
        for i in range(3):
            self.adaptive_system.reputation_system.update_reputation(test_ip, True, False)
            reputation = self.adaptive_system.reputation_system.get_reputation(test_ip)
            print(f"   📉 After {i+1} malicious connections: {reputation:.3f}")
        
        # Test blocking decision with poor reputation
        should_block, reason = self.adaptive_system.should_block(test_ip, traffic_metrics)
        print(f"   🚫 Block Decision (poor reputation): {should_block} ({reason})")
        
        # Demonstrate false positive handling
        print("\n   🟡 Simulating false positive...")
        self.adaptive_system.reputation_system.update_reputation(test_ip, False, True)
        reputation = self.adaptive_system.reputation_system.get_reputation(test_ip)
        print(f"   📊 After false positive correction: {reputation:.3f}")
    
    def demonstrate_behavioral_analysis(self):
        """Demonstrate behavioral analysis for unblocking decisions"""
        print("\n4. BEHAVIORAL ANALYSIS DEMONSTRATION")
        print("-" * 40)
        
        test_ip = "10.0.1.250"
        
        print(f"\n🔍 Testing behavioral analysis for: {test_ip}")
        
        # Simulate consistent legitimate traffic patterns
        print("\n   📊 Building traffic pattern history...")
        for i in range(15):
            # Simulate consistent, moderate traffic
            traffic_metrics = {
                "packet_rate": 25 + random.uniform(-5, 5),
                "byte_rate": 8000 + random.uniform(-2000, 2000),
                "connection_rate": 3 + random.uniform(-1, 1),
                "burst_ratio": 0.3 + random.uniform(-0.1, 0.1),
                "unique_ports": 2,
                "repetition_ratio": 0.2 + random.uniform(-0.05, 0.05)
            }
            
            behavior_analysis = self.adaptive_system.behavior_analyzer.analyze_traffic_pattern(
                test_ip, traffic_metrics
            )
            
            if i % 5 == 4:  # Show progress every 5 iterations
                print(f"   📈 Pattern {i+1}: Score={behavior_analysis['behavior_score']:.3f}, "
                      f"Confidence={behavior_analysis['confidence']:.3f}")
        
        # Test legitimate pattern detection
        is_legitimate = self.adaptive_system.behavior_analyzer.is_legitimate_pattern(test_ip)
        print(f"   ✅ Legitimate pattern detected: {is_legitimate}")
        
        # Test with anomalous traffic
        print("\n   🚨 Testing anomalous traffic pattern...")
        anomalous_metrics = {
            "packet_rate": 500,  # Sudden spike
            "byte_rate": 1000000,
            "connection_rate": 50,
            "burst_ratio": 0.9,
            "unique_ports": 15,
            "repetition_ratio": 0.8
        }
        
        behavior_analysis = self.adaptive_system.behavior_analyzer.analyze_traffic_pattern(
            test_ip, anomalous_metrics
        )
        
        print(f"   📊 Anomaly Score: {behavior_analysis['behavior_score']:.3f}")
        print(f"   🎯 Confidence: {behavior_analysis['confidence']:.3f}")
        print(f"   📈 Deviations: {behavior_analysis.get('deviations', {})}")
    
    def demonstrate_adaptive_thresholds(self):
        """Demonstrate adaptive thresholds based on network conditions"""
        print("\n5. ADAPTIVE THRESHOLDS DEMONSTRATION")
        print("-" * 40)
        
        # Show initial thresholds
        print("\n📊 Initial Dynamic Thresholds:")
        for level, threshold in self.adaptive_system.dynamic_thresholds.items():
            print(f"   {level}: {threshold:.3f}")
        
        # Simulate high attack frequency
        print("\n🚨 Simulating high attack frequency...")
        network_conditions = {
            'load': 0.4,
            'attack_frequency': 0.8,  # High attack frequency
            'false_positive_rate': 0.05,
            'legitimate_traffic_ratio': 0.3
        }
        
        self.adaptive_system.update_network_conditions(network_conditions)
        
        print("📊 Adjusted Thresholds (stricter during attacks):")
        for level, threshold in self.adaptive_system.dynamic_thresholds.items():
            print(f"   {level}: {threshold:.3f}")
        
        # Simulate high false positive rate
        print("\n🟡 Simulating high false positive rate...")
        network_conditions = {
            'load': 0.3,
            'attack_frequency': 0.2,
            'false_positive_rate': 0.15,  # High false positive rate
            'legitimate_traffic_ratio': 0.8
        }
        
        self.adaptive_system.update_network_conditions(network_conditions)
        
        print("📊 Adjusted Thresholds (more lenient to reduce false positives):")
        for level, threshold in self.adaptive_system.dynamic_thresholds.items():
            print(f"   {level}: {threshold:.3f}")
    
    def demonstrate_unblocking_intelligence(self):
        """Demonstrate intelligent unblocking decisions"""
        print("\n6. INTELLIGENT UNBLOCKING DEMONSTRATION")
        print("-" * 40)
        
        # Create a test blocking scenario
        test_ip = "10.0.1.300"
        
        # Simulate medium threat traffic
        traffic_metrics = {
            "packet_rate": 200,
            "byte_rate": 400000,
            "connection_rate": 20,
            "burst_ratio": 0.6,
            "unique_ports": 6,
            "repetition_ratio": 0.5
        }
        
        print(f"\n🔍 Testing intelligent unblocking for: {test_ip}")
        
        # Block the IP
        should_block, reason = self.adaptive_system.should_block(test_ip, traffic_metrics)
        if should_block:
            policy = self.adaptive_system.block_ip(test_ip, traffic_metrics)
            print(f"   🚫 IP blocked: {reason}")
            print(f"   ⏱️  Initial duration: {policy.initial_duration}s")
            print(f"   📋 Threat level: {policy.threat_level.value}")
        
        # Simulate good reputation building
        print("\n   📈 Building positive reputation...")
        for i in range(3):
            self.adaptive_system.reputation_system.update_reputation(test_ip, False, False)
        
        # Add legitimate traffic patterns
        print("   📊 Establishing legitimate traffic patterns...")
        for i in range(10):
            legitimate_metrics = {
                "packet_rate": 20 + random.uniform(-3, 3),
                "byte_rate": 6000 + random.uniform(-1000, 1000),
                "connection_rate": 2 + random.uniform(-0.5, 0.5),
                "burst_ratio": 0.2 + random.uniform(-0.05, 0.05),
                "unique_ports": 2,
                "repetition_ratio": 0.15 + random.uniform(-0.03, 0.03)
            }
            self.adaptive_system.behavior_analyzer.analyze_traffic_pattern(test_ip, legitimate_metrics)
        
        # Check unblocking decision
        should_unblock, unblock_reason = self.adaptive_system.should_unblock(test_ip)
        print(f"   ✅ Should unblock: {should_unblock} ({unblock_reason})")
        
        # Get current policy status
        status = self.adaptive_system.get_policy_status(test_ip)
        if status:
            print(f"   📊 Policy Status:")
            print(f"      - State: {status['blocking_state']}")
            print(f"      - Elapsed: {status['elapsed_time']:.0f}s")
            print(f"      - Remaining: {status['remaining_time']:.0f}s")
            print(f"      - Reputation: {status['reputation']:.3f}")
            print(f"      - False Positive Score: {status['false_positive_score']:.3f}")
    
    def demonstrate_system_integration(self):
        """Demonstrate system integration and statistics"""
        print("\n7. SYSTEM INTEGRATION & STATISTICS")
        print("-" * 40)
        
        # Get system statistics
        stats = self.adaptive_system.get_system_stats()
        
        print("\n📊 System Statistics:")
        print(f"   🚫 Active Blocks: {stats['active_blocks']}")
        print(f"   👁️  Monitoring: {stats['monitoring_blocks']}")
        print(f"   📋 Total Policies: {stats['total_policies']}")
        
        print("\n📈 Threat Level Distribution:")
        for level, count in stats['threat_level_distribution'].items():
            print(f"   {level}: {count}")
        
        print("\n🌐 Network Conditions:")
        for condition, value in stats['network_conditions'].items():
            print(f"   {condition}: {value:.3f}")
        
        print("\n🎯 Dynamic Thresholds:")
        for threshold, value in stats['dynamic_thresholds'].items():
            print(f"   {threshold}: {value:.3f}")
    
    def demonstrate_comparison(self):
        """Demonstrate comparison with inflexible system"""
        print("\n8. COMPARISON WITH INFLEXIBLE SYSTEM")
        print("-" * 40)
        
        comparison_data = [
            {
                "aspect": "Blocking Duration",
                "inflexible": "Fixed 5 minutes for all threats",
                "adaptive": "60s-24h based on threat level & reputation"
            },
            {
                "aspect": "Threat Assessment",
                "inflexible": "Simple packet rate threshold",
                "adaptive": "Multi-factor scoring: traffic, reputation, behavior, patterns"
            },
            {
                "aspect": "Unblocking Decision",
                "inflexible": "Time-based only",
                "adaptive": "Reputation + behavior + false positive detection"
            },
            {
                "aspect": "False Positive Handling",
                "inflexible": "No mechanism",
                "adaptive": "Automatic detection & reputation adjustment"
            },
            {
                "aspect": "Network Adaptation",
                "inflexible": "Static thresholds",
                "adaptive": "Dynamic thresholds based on network conditions"
            },
            {
                "aspect": "User Experience",
                "inflexible": "Legitimate users blocked for fixed duration",
                "adaptive": "Legitimate users get shorter blocks or early release"
            }
        ]
        
        for item in comparison_data:
            print(f"\n📊 {item['aspect']}:")
            print(f"   ❌ Inflexible: {item['inflexible']}")
            print(f"   ✅ Adaptive: {item['adaptive']}")
    
    def run_complete_demonstration(self):
        """Run complete demonstration"""
        try:
            self.demonstrate_problem_and_solution()
            self.demonstrate_threat_levels()
            self.demonstrate_reputation_system()
            self.demonstrate_behavioral_analysis()
            self.demonstrate_adaptive_thresholds()
            self.demonstrate_unblocking_intelligence()
            self.demonstrate_system_integration()
            self.demonstrate_comparison()
            
            print("\n" + "=" * 70)
            print("🎉 DEMONSTRATION COMPLETE")
            print("=" * 70)
            
            print("\n✅ KEY ACHIEVEMENTS:")
            print("   🔄 Dynamic blocking duration based on threat assessment")
            print("   📊 Reputation-based policy adjustment")
            print("   🧠 Behavioral analysis for legitimate user detection")
            print("   🎯 Adaptive thresholds responding to network conditions")
            print("   🚨 False positive detection and mitigation")
            print("   ⚡ Real-time policy adjustment")
            print("   🔧 Seamless integration with existing system")
            
            print("\n🎯 INFLEXIBLE BLOCKING/UNBLOCKING POLICY FLAW RESOLVED!")
            print("The system now provides intelligent, context-aware blocking decisions")
            print("that adapt to network conditions and user behavior patterns.")
            
        except Exception as e:
            print(f"❌ Error during demonstration: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            # Cleanup
            self.policy_store.close()
    
    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, 'policy_store'):
            self.policy_store.close()


def main():
    """Main demonstration function"""
    demo = AdaptiveBlockingDemo()
    
    try:
        demo.run_complete_demonstration()
    except KeyboardInterrupt:
        print("\n🛑 Demonstration interrupted by user")
    except Exception as e:
        print(f"❌ Demonstration error: {e}")
    finally:
        demo.cleanup()


if __name__ == "__main__":
    main()
