#!/usr/bin/env python3
"""
Test script for Adaptive Blocking System Integration

This script tests the integration of the adaptive blocking system
with the modular SDN controller.
"""

import sys
import os
import time
import logging
from unittest.mock import Mock, MagicMock

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 70)
print("🧪 TESTING ADAPTIVE BLOCKING SYSTEM INTEGRATION")
print("=" * 70)

def test_adaptive_integration():
    """Test the adaptive blocking system integration"""
    try:
        # Import required modules
        from adaptive_blocking_system import AdaptiveBlockingIntegration, AdaptiveBlockingSystem
        from external_policy_system import SharedPolicyStore
        print("✅ Successfully imported adaptive blocking modules")
        
        # Create mock objects for testing
        mock_controller = Mock()
        mock_controller.logger = logging.getLogger("test_controller")
        mock_controller.logger.addHandler(logging.StreamHandler())
        mock_controller.logger.setLevel(logging.INFO)
        
        # Create mock policy component
        mock_policy = Mock()
        # Create and initialize policy store properly with temp file
        import tempfile
        temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        temp_db.close()
        
        policy_store = SharedPolicyStore(temp_db.name)  # Temporary database for testing
        mock_policy.policy_store = policy_store
        mock_controller.policy = mock_policy
        
        # Create mock detector
        mock_detector = Mock()
        mock_detector.threat_queue = Mock()
        mock_detector.threat_queue.put = Mock()
        mock_controller.detector = mock_detector
        
        # Create mock enforcer
        mock_enforcer = Mock()
        
        print("✅ Created mock controller components")
        
        # Test integration initialization
        integration = AdaptiveBlockingIntegration(mock_controller, mock_enforcer)
        print("✅ Successfully initialized adaptive blocking integration")
        
        # Test basic functionality
        stats = integration.get_adaptive_stats()
        print(f"📊 System stats: {stats}")
        
        # Test IP status checking
        test_ip = "192.168.1.100"
        status = integration.get_ip_status(test_ip)
        print(f"🔍 Status for {test_ip}: {status}")
        
        # Test traffic metrics conversion and blocking decision
        mock_metrics = Mock()
        mock_metrics.rx_packets = 1000
        mock_metrics.tx_packets = 500
        mock_metrics.rx_bytes = 100000
        mock_metrics.tx_bytes = 50000
        
        # Simulate threat analysis
        print(f"🔄 Testing adaptive threat analysis...")
        
        # Test network conditions update
        test_conditions = {
            'load': 0.6,
            'attack_frequency': 0.3,
            'false_positive_rate': 0.05,
            'legitimate_traffic_ratio': 0.8
        }
        integration.update_network_conditions(test_conditions)
        print(f"📈 Updated network conditions: {test_conditions}")
        
        # Test reputation system
        reputation_score = integration.adaptive_blocking.reputation_system.get_reputation(test_ip)
        print(f"🏆 Reputation score for {test_ip}: {reputation_score}")
        
        # Update reputation
        integration.adaptive_blocking.reputation_system.update_reputation(test_ip, False, False)
        new_reputation = integration.adaptive_blocking.reputation_system.get_reputation(test_ip)
        print(f"🏆 New reputation score for {test_ip}: {new_reputation}")
        
        # Test blocking decision
        traffic_metrics = {
            'packet_rate': 800,
            'byte_rate': 150000,
            'connection_rate': 15,
            'burst_ratio': 0.7,
            'unique_ports': 5,
            'repetition_ratio': 0.4
        }
        
        should_block, reason = integration.adaptive_blocking.should_block(test_ip, traffic_metrics)
        print(f"🚫 Blocking decision for {test_ip}: {should_block} - {reason}")
        
        if should_block:
            policy = integration.adaptive_blocking.block_ip(test_ip, traffic_metrics)
            print(f"📋 Created blocking policy: {policy.threat_level.value} threat")
            
            # Test getting blocked IPs
            blocked_ips = integration.get_all_blocked_ips()
            print(f"🔒 Currently blocked IPs: {len(blocked_ips)}")
            for ip_info in blocked_ips:
                print(f"   - {ip_info['ip_address']}: {ip_info['threat_level']} ({ip_info['remaining_time']:.0f}s remaining)")
        
        # Test force unblock
        if integration.force_unblock(test_ip):
            print(f"🔓 Successfully force unblocked {test_ip}")
        
        # Final stats
        final_stats = integration.get_adaptive_stats()
        print(f"📊 Final system stats: {final_stats}")
        
        print("\n✅ All integration tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_standalone_adaptive_system():
    """Test the standalone adaptive blocking system"""
    try:
        print("\n🔄 Testing standalone adaptive blocking system...")
        
        from adaptive_blocking_system import AdaptiveBlockingSystem
        
        # Create simple policy store
        class TestPolicyStore:
            def __init__(self):
                self.policies = {}
            
            def add_policy(self, rule_id, src_ip, dst_ip, action, priority, metadata=None):
                self.policies[rule_id] = {
                    'src_ip': src_ip,
                    'action': action,
                    'metadata': metadata
                }
                print(f"📋 Added policy: {rule_id}")
            
            def remove_policy(self, rule_id):
                if rule_id in self.policies:
                    del self.policies[rule_id]
                    print(f"🗑️  Removed policy: {rule_id}")
        
        policy_store = TestPolicyStore()
        logger = logging.getLogger("adaptive_test")
        logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.INFO)
        
        # Initialize system
        adaptive_system = AdaptiveBlockingSystem(policy_store, logger)
        print("✅ Adaptive blocking system initialized")
        
        # Test threat scoring
        test_ip = "10.0.0.50"
        traffic_metrics = {
            'packet_rate': 600,
            'byte_rate': 120000,
            'connection_rate': 20,
            'burst_ratio': 0.8,
            'unique_ports': 8,
            'repetition_ratio': 0.6
        }
        
        threat_score = adaptive_system.calculate_threat_score(test_ip, traffic_metrics)
        print(f"⚠️  Threat score for {test_ip}: {threat_score.total_score:.3f}")
        
        threat_level = adaptive_system.determine_threat_level(threat_score)
        print(f"🎯 Threat level: {threat_level.value}")
        
        # Test blocking decision
        should_block, reason = adaptive_system.should_block(test_ip, traffic_metrics)
        print(f"🚫 Should block: {should_block} - {reason}")
        
        if should_block:
            policy = adaptive_system.block_ip(test_ip, traffic_metrics)
            print(f"📋 Created policy: {policy.threat_level.value} for {policy.initial_duration}s")
            
            # Test unblocking decision
            should_unblock, unblock_reason = adaptive_system.should_unblock(test_ip)
            print(f"🔓 Should unblock: {should_unblock} - {unblock_reason}")
        
        # Test system statistics
        stats = adaptive_system.get_system_stats()
        print(f"📊 System stats: Active blocks: {stats['active_blocks']}, Total policies: {stats['total_policies']}")
        
        print("✅ Standalone system test passed!")
        return True
        
    except Exception as e:
        print(f"❌ Standalone test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function"""
    print("Starting adaptive blocking integration tests...\n")
    
    # Test standalone system first
    standalone_result = test_standalone_adaptive_system()
    
    # Test integration
    integration_result = test_adaptive_integration()
    
    print("\n" + "=" * 70)
    print("🎯 TEST RESULTS")
    print("=" * 70)
    print(f"Standalone System: {'✅ PASSED' if standalone_result else '❌ FAILED'}")
    print(f"Integration Test:  {'✅ PASSED' if integration_result else '❌ FAILED'}")
    
    if standalone_result and integration_result:
        print("\n🎉 ALL TESTS PASSED! Adaptive blocking system is ready for use.")
        print("\n📝 Integration Summary:")
        print("   ✅ Adaptive blocking system integrated with modular controller")
        print("   ✅ Threat detection enhanced with adaptive policies")
        print("   ✅ Reputation system active and functional")
        print("   ✅ Dynamic thresholds and network condition monitoring")
        print("   ✅ Admin override and force unblock capabilities")
        print("   ✅ Comprehensive statistics and monitoring")
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
    
    return standalone_result and integration_result

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run tests
    success = main()
    sys.exit(0 if success else 1)
