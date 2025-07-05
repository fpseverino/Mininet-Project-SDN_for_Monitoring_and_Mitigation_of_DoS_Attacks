#!/usr/bin/env python3
"""
Test script for External Policy System

This script verifies that the external policy system is properly integrated
and functioning correctly.
"""

import unittest
import threading
import time
import tempfile
import os
import json
from datetime import datetime, timedelta
from external_policy_system import (
    SharedPolicyStore, PolicyAPI, AdminInterface, ExternalPolicyConnector,
    PolicyRule, PolicySource, PolicyAction
)

class TestExternalPolicySystem(unittest.TestCase):
    """Test cases for the external policy system"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary database for testing
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db_path = self.temp_db.name
        
        # Initialize policy store
        self.policy_store = SharedPolicyStore(self.db_path)
        
        # Initialize components
        self.admin_interface = AdminInterface(self.policy_store)
        self.external_connector = ExternalPolicyConnector(self.policy_store)
        
        # Start API server on a test port
        self.api_server = PolicyAPI(self.policy_store, port=8082)
        self.api_server.start()
        
        # Wait for server to start
        time.sleep(0.5)
    
    def tearDown(self):
        """Clean up test environment"""
        # Stop API server
        self.api_server.stop()
        
        # Remove temporary database
        try:
            os.unlink(self.db_path)
        except:
            pass
    
    def test_policy_store_basic_operations(self):
        """Test basic policy store operations"""
        # Create a test policy
        policy = PolicyRule(
            id="test_policy_001",
            source=PolicySource.ADMIN,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value="10.0.0.1",
            priority=50,
            reason="Test policy"
        )
        
        # Add policy
        result = self.policy_store.add_policy(policy)
        self.assertTrue(result)
        
        # Retrieve policy
        retrieved_policy = self.policy_store.get_policy("test_policy_001")
        self.assertIsNotNone(retrieved_policy)
        self.assertEqual(retrieved_policy.target_value, "10.0.0.1")
        self.assertEqual(retrieved_policy.action, PolicyAction.BLOCK)
        
        # Remove policy
        result = self.policy_store.remove_policy("test_policy_001")
        self.assertTrue(result)
        
        # Verify removal
        retrieved_policy = self.policy_store.get_policy("test_policy_001")
        self.assertIsNone(retrieved_policy)
    
    def test_policy_priority_resolution(self):
        """Test priority-based policy resolution"""
        target_ip = "10.0.0.2"
        
        # Create policies with different priorities
        low_priority = PolicyRule(
            id="low_priority",
            source=PolicySource.CONTROLLER,
            action=PolicyAction.MONITOR,
            target_type="ip",
            target_value=target_ip,
            priority=30,
            reason="Low priority"
        )
        
        high_priority = PolicyRule(
            id="high_priority",
            source=PolicySource.ADMIN,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value=target_ip,
            priority=90,
            reason="High priority"
        )
        
        # Add policies
        self.policy_store.add_policy(low_priority)
        self.policy_store.add_policy(high_priority)
        
        # Get effective action
        effective_action = self.policy_store.get_effective_action("ip", target_ip)
        
        # Should be the high priority action
        self.assertEqual(effective_action, PolicyAction.BLOCK)
    
    def test_expired_policy_cleanup(self):
        """Test automatic cleanup of expired policies"""
        # Create an expired policy
        expired_policy = PolicyRule(
            id="expired_policy",
            source=PolicySource.ADMIN,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value="10.0.0.3",
            priority=50,
            expiry=datetime.now() - timedelta(hours=1),  # Already expired
            reason="Expired policy"
        )
        
        # Try to add expired policy
        result = self.policy_store.add_policy(expired_policy)
        self.assertFalse(result)  # Should fail to add expired policy
        
        # Verify it's not in store
        retrieved_policy = self.policy_store.get_policy("expired_policy")
        self.assertIsNone(retrieved_policy)
    
    def test_policy_change_notifications(self):
        """Test policy change notifications"""
        # Set up notification listener
        notifications = []
        
        def notification_listener(action, policy):
            notifications.append((action, policy.id))
        
        self.policy_store.add_listener(notification_listener)
        
        # Add a policy
        policy = PolicyRule(
            id="notification_test",
            source=PolicySource.ADMIN,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value="10.0.0.4",
            priority=50,
            reason="Notification test"
        )
        
        self.policy_store.add_policy(policy)
        
        # Remove the policy
        self.policy_store.remove_policy("notification_test")
        
        # Check notifications
        self.assertEqual(len(notifications), 2)
        self.assertEqual(notifications[0], ("add", "notification_test"))
        self.assertEqual(notifications[1], ("remove", "notification_test"))
    
    def test_persistence(self):
        """Test policy persistence across store restarts"""
        # Add a policy
        policy = PolicyRule(
            id="persistent_policy",
            source=PolicySource.ADMIN,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value="10.0.0.5",
            priority=50,
            reason="Persistence test"
        )
        
        self.policy_store.add_policy(policy)
        
        # Create a new policy store with same database
        new_store = SharedPolicyStore(self.db_path)
        
        # Verify policy is loaded
        retrieved_policy = new_store.get_policy("persistent_policy")
        self.assertIsNotNone(retrieved_policy)
        self.assertEqual(retrieved_policy.target_value, "10.0.0.5")
        self.assertEqual(retrieved_policy.action, PolicyAction.BLOCK)
    
    def test_external_connector_integration(self):
        """Test external policy connector"""
        # Simulate external threat intelligence
        threat_ips = ["192.168.1.100", "192.168.1.101"]
        
        # Add threat intelligence policies
        for ip in threat_ips:
            policy = PolicyRule(
                id=f"threat_intel_{ip.replace('.', '_')}",
                source=PolicySource.THREAT_INTEL,
                action=PolicyAction.BLOCK,
                target_type="ip",
                target_value=ip,
                priority=85,
                reason="Threat intelligence feed"
            )
            self.policy_store.add_policy(policy)
        
        # Verify policies were added
        all_policies = self.policy_store.get_all_policies()
        threat_policies = [p for p in all_policies if p.source == PolicySource.THREAT_INTEL]
        self.assertEqual(len(threat_policies), 2)
        
        # Test effective actions
        for ip in threat_ips:
            effective_action = self.policy_store.get_effective_action("ip", ip)
            self.assertEqual(effective_action, PolicyAction.BLOCK)
    
    def test_admin_override_scenario(self):
        """Test administrator override scenario"""
        target_ip = "10.0.0.6"
        
        # Step 1: Controller blocks IP
        controller_policy = PolicyRule(
            id="controller_block",
            source=PolicySource.CONTROLLER,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value=target_ip,
            priority=30,
            reason="Controller: DoS detected"
        )
        
        self.policy_store.add_policy(controller_policy)
        
        # Verify controller decision
        effective_action = self.policy_store.get_effective_action("ip", target_ip)
        self.assertEqual(effective_action, PolicyAction.BLOCK)
        
        # Step 2: Admin overrides with allow
        admin_policy = PolicyRule(
            id="admin_override",
            source=PolicySource.ADMIN,
            action=PolicyAction.ALLOW,
            target_type="ip",
            target_value=target_ip,
            priority=100,
            reason="Admin: False positive override"
        )
        
        self.policy_store.add_policy(admin_policy)
        
        # Verify admin override
        effective_action = self.policy_store.get_effective_action("ip", target_ip)
        self.assertEqual(effective_action, PolicyAction.ALLOW)
        
        # Verify both policies exist
        policies = self.policy_store.get_policies_for_target("ip", target_ip)
        self.assertEqual(len(policies), 2)
        
        # Verify highest priority wins
        self.assertEqual(policies[0].action, PolicyAction.ALLOW)
        self.assertEqual(policies[0].priority, 100)

def run_integration_test():
    """Run integration test with controller components"""
    print("Running External Policy System Integration Test...")
    print("=" * 60)
    
    # Test basic functionality
    temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
    temp_db.close()
    db_path = temp_db.name
    
    try:
        # Initialize components
        policy_store = SharedPolicyStore(db_path)
        admin_interface = AdminInterface(policy_store)
        
        # Test scenario: Admin blocks malicious IP
        print("\n1. Testing admin policy addition...")
        admin_policy = PolicyRule(
            id="integration_test_block",
            source=PolicySource.ADMIN,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value="203.0.113.1",
            priority=90,
            reason="Integration test: Malicious IP"
        )
        
        result = policy_store.add_policy(admin_policy)
        print(f"   Admin policy added: {result}")
        
        # Test effective action
        effective_action = policy_store.get_effective_action("ip", "203.0.113.1")
        print(f"   Effective action: {effective_action}")
        
        # Test external app integration
        print("\n2. Testing external application integration...")
        external_policy = PolicyRule(
            id="integration_test_ids",
            source=PolicySource.IDS,
            action=PolicyAction.QUARANTINE,
            target_type="ip",
            target_value="203.0.113.2",
            priority=75,
            reason="Integration test: IDS detection"
        )
        
        result = policy_store.add_policy(external_policy)
        print(f"   External policy added: {result}")
        
        # Test priority resolution
        print("\n3. Testing priority resolution...")
        # Add lower priority policy for same IP
        low_priority_policy = PolicyRule(
            id="integration_test_low",
            source=PolicySource.CONTROLLER,
            action=PolicyAction.MONITOR,
            target_type="ip",
            target_value="203.0.113.2",
            priority=30,
            reason="Integration test: Controller monitoring"
        )
        
        policy_store.add_policy(low_priority_policy)
        
        # Check effective action (should be quarantine from IDS)
        effective_action = policy_store.get_effective_action("ip", "203.0.113.2")
        print(f"   Effective action with multiple policies: {effective_action}")
        
        # Test policy listing
        print("\n4. Testing policy listing...")
        all_policies = policy_store.get_all_policies()
        print(f"   Total policies: {len(all_policies)}")
        for policy in all_policies:
            print(f"   - {policy.id}: {policy.action.value} {policy.target_value} "
                  f"(Priority: {policy.priority})")
        
        print(f"\n✅ Integration test completed successfully!")
        
    finally:
        # Clean up
        try:
            os.unlink(db_path)
        except:
            pass

def main():
    """Main test function"""
    print("External Policy System Test Suite")
    print("=" * 50)
    
    # Run unit tests
    print("\n🧪 Running Unit Tests...")
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run integration test
    print("\n🔗 Running Integration Test...")
    run_integration_test()
    
    print(f"\n✅ All tests completed!")

if __name__ == "__main__":
    main()
