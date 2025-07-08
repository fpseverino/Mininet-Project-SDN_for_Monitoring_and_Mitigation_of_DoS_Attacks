#!/usr/bin/env python3
"""
Simple Integration Test for Adaptive Blocking System
"""

import sys
import os

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_simple_integration():
    """Simple test of the adaptive blocking integration"""
    print("🔄 Testing Adaptive Blocking System Integration...")
    
    try:
        # Test basic imports
        from adaptive_blocking_system import AdaptiveBlockingSystem, AdaptiveBlockingIntegration
        from external_policy_system import SharedPolicyStore
        print("✅ Successfully imported adaptive blocking modules")
        
        # Create simple policy store
        class SimplePolicyStore:
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
        
        # Test AdaptiveBlockingSystem
        import logging
        logger = logging.getLogger("test")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        logger.addHandler(handler)
        
        policy_store = SimplePolicyStore()
        adaptive_system = AdaptiveBlockingSystem(policy_store, logger)
        print("✅ Created AdaptiveBlockingSystem")
        
        # Test threat scoring
        test_ip = "192.168.1.100"
        traffic_metrics = {
            'packet_rate': 500,
            'byte_rate': 200000,
            'connection_rate': 20,
            'burst_ratio': 0.7,
            'unique_ports': 5,
            'repetition_ratio': 0.4
        }
        
        threat_score = adaptive_system.calculate_threat_score(test_ip, traffic_metrics)
        print(f"📊 Threat score for {test_ip}: {threat_score.total_score:.3f}")
        
        should_block, reason = adaptive_system.should_block(test_ip, traffic_metrics)
        print(f"🚫 Should block: {should_block} - {reason}")
        
        if should_block:
            policy = adaptive_system.block_ip(test_ip, traffic_metrics)
            print(f"📋 Created blocking policy: {policy.threat_level.value}")
        
        stats = adaptive_system.get_system_stats()
        print(f"📈 System stats: {stats['active_blocks']} active blocks, {stats['total_policies']} total policies")
        
        print("✅ All tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_simple_integration()
    print("\n" + "="*60)
    if success:
        print("🎉 INTEGRATION SUCCESS!")
        print("The Adaptive Blocking System is ready to use with the modular controller.")
        print("\nTo use it:")
        print("1. Start the controller: ryu-manager modular_controller.py")
        print("2. The adaptive blocking system will be automatically integrated")
        print("3. Monitor logs for adaptive blocking decisions")
    else:
        print("❌ INTEGRATION FAILED!")
        print("Please check the errors above and fix any issues.")
    print("="*60)
