#!/usr/bin/env python3
"""
Test script for Enhanced Mitigation System

This script tests the enhanced flow-level mitigation system
that addresses the over-blocking flaw.
"""

import unittest
import tempfile
import os
import logging
from unittest.mock import Mock, MagicMock
from enhanced_mitigation_enforcer import (
    FlowSignature, FlowStats, FlowAnalyzer, EnhancedMitigationEnforcer
)
from datetime import datetime, timedelta

class TestFlowSignature(unittest.TestCase):
    """Test FlowSignature class"""
    
    def test_flow_signature_creation(self):
        """Test creating flow signatures"""
        flow = FlowSignature(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol=6,
            src_port=8080,
            dst_port=80
        )
        
        self.assertEqual(flow.src_mac, "00:00:00:00:00:01")
        self.assertEqual(flow.dst_mac, "00:00:00:00:00:02")
        self.assertEqual(flow.src_ip, "10.0.0.1")
        self.assertEqual(flow.dst_ip, "10.0.0.2")
        self.assertEqual(flow.protocol, 6)
        self.assertEqual(flow.src_port, 8080)
        self.assertEqual(flow.dst_port, 80)
    
    def test_flow_signature_string_representation(self):
        """Test string representation of flow signature"""
        flow = FlowSignature(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=8080,
            dst_port=80
        )
        
        expected = "10.0.0.1:8080 -> 10.0.0.2:80"
        self.assertEqual(flow.to_string(), expected)
    
    def test_flow_signature_mac_only(self):
        """Test flow signature with MAC addresses only"""
        flow = FlowSignature(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02"
        )
        
        expected = "00:00:00:00:00:01 -> 00:00:00:00:00:02"
        self.assertEqual(flow.to_string(), expected)

class TestFlowStats(unittest.TestCase):
    """Test FlowStats class"""
    
    def test_flow_stats_initialization(self):
        """Test flow statistics initialization"""
        stats = FlowStats()
        
        self.assertEqual(stats.packet_count, 0)
        self.assertEqual(stats.byte_count, 0)
        self.assertIsNotNone(stats.first_seen)
        self.assertIsNotNone(stats.last_seen)
    
    def test_flow_stats_update(self):
        """Test updating flow statistics"""
        stats = FlowStats()
        initial_time = stats.last_seen
        
        # Small delay to ensure time difference
        import time
        time.sleep(0.01)
        
        stats.update(10, 1500)
        
        self.assertEqual(stats.packet_count, 10)
        self.assertEqual(stats.byte_count, 1500)
        self.assertGreater(stats.last_seen, initial_time)
        self.assertGreater(stats.rate_pps, 0)
        self.assertGreater(stats.rate_bps, 0)

class TestFlowAnalyzer(unittest.TestCase):
    """Test FlowAnalyzer class"""
    
    def setUp(self):
        """Set up test environment"""
        self.logger = logging.getLogger('test')
        self.analyzer = FlowAnalyzer(self.logger)
    
    def test_whitelist_operations(self):
        """Test whitelist operations"""
        # Test adding to whitelist
        self.analyzer.add_to_whitelist("10.0.0.100")
        self.analyzer.add_to_whitelist("00:00:00:00:01:00")
        
        self.assertIn("10.0.0.100", self.analyzer.whitelist)
        self.assertIn("00:00:00:00:01:00", self.analyzer.whitelist)
        
        # Test whitelist checking
        whitelisted_flow = FlowSignature(
            src_mac="00:00:00:00:01:00",
            dst_mac="00:00:00:00:00:ff",
            src_ip="10.0.0.100",
            dst_ip="10.0.0.1"
        )
        
        non_whitelisted_flow = FlowSignature(
            src_mac="00:00:00:00:00:99",
            dst_mac="00:00:00:00:00:ff",
            src_ip="10.0.0.99",
            dst_ip="10.0.0.1"
        )
        
        self.assertTrue(self.analyzer.is_whitelisted(whitelisted_flow))
        self.assertFalse(self.analyzer.is_whitelisted(non_whitelisted_flow))
    
    def test_blacklist_operations(self):
        """Test blacklist operations"""
        # Test adding to blacklist
        self.analyzer.add_to_blacklist("192.168.1.100")
        self.analyzer.add_to_blacklist("00:00:00:00:99:99")
        
        self.assertIn("192.168.1.100", self.analyzer.blacklist)
        self.assertIn("00:00:00:00:99:99", self.analyzer.blacklist)
        
        # Test blacklist checking
        blacklisted_flow = FlowSignature(
            src_mac="00:00:00:00:99:99",
            dst_mac="00:00:00:00:00:ff",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1"
        )
        
        clean_flow = FlowSignature(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:ff",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2"
        )
        
        self.assertTrue(self.analyzer.is_blacklisted(blacklisted_flow))
        self.assertFalse(self.analyzer.is_blacklisted(clean_flow))
    
    def test_threat_assessment(self):
        """Test threat level assessment"""
        # Create a flow signature
        flow = FlowSignature(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2"
        )
        
        # Test benign traffic
        threat_level = self.analyzer._assess_threat_level(flow, 64)
        self.assertEqual(threat_level, "benign")
        
        # Test blacklisted traffic
        self.analyzer.add_to_blacklist("10.0.0.1")
        threat_level = self.analyzer._assess_threat_level(flow, 64)
        self.assertEqual(threat_level, "malicious")
        
        # Remove from blacklist and test whitelisted traffic
        self.analyzer.blacklist.remove("10.0.0.1")
        self.analyzer.add_to_whitelist("10.0.0.1")
        threat_level = self.analyzer._assess_threat_level(flow, 64)
        self.assertEqual(threat_level, "benign")
    
    def test_flow_cleanup(self):
        """Test old flow cleanup"""
        # Create old flow
        old_flow = FlowSignature(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02"
        )
        
        # Add to analyzer with old timestamp
        old_stats = FlowStats()
        old_stats.last_seen = datetime.now() - timedelta(seconds=400)
        self.analyzer.flow_stats[old_flow] = old_stats
        
        # Create recent flow
        recent_flow = FlowSignature(
            src_mac="00:00:00:00:00:03",
            dst_mac="00:00:00:00:00:04"
        )
        
        recent_stats = FlowStats()
        self.analyzer.flow_stats[recent_flow] = recent_stats
        
        # Run cleanup
        self.analyzer.cleanup_old_flows(max_age_seconds=300)
        
        # Check results
        self.assertNotIn(old_flow, self.analyzer.flow_stats)
        self.assertIn(recent_flow, self.analyzer.flow_stats)

class TestEnhancedMitigationEnforcer(unittest.TestCase):
    """Test EnhancedMitigationEnforcer class"""
    
    def setUp(self):
        """Set up test environment"""
        self.logger = logging.getLogger('test')
        self.datapaths = {}
        self.enforcer = EnhancedMitigationEnforcer(self.logger, self.datapaths)
    
    def test_enforcer_initialization(self):
        """Test enforcer initialization"""
        self.assertIsNotNone(self.enforcer.flow_analyzer)
        self.assertEqual(len(self.enforcer.blocked_flows), 0)
        self.assertEqual(len(self.enforcer.rate_limited_flows), 0)
    
    def test_whitelist_management(self):
        """Test whitelist management through enforcer"""
        self.enforcer.add_to_whitelist("10.0.0.100")
        self.assertIn("10.0.0.100", self.enforcer.flow_analyzer.whitelist)
    
    def test_blacklist_management(self):
        """Test blacklist management through enforcer"""
        self.enforcer.add_to_blacklist("192.168.1.100")
        self.assertIn("192.168.1.100", self.enforcer.flow_analyzer.blacklist)
    
    def test_flow_statistics(self):
        """Test flow statistics reporting"""
        # Add some test flows
        test_flow = FlowSignature(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02"
        )
        
        self.enforcer.blocked_flows.add(test_flow)
        self.enforcer.rate_limited_flows.add(test_flow)
        
        stats = self.enforcer.get_flow_statistics()
        
        self.assertEqual(stats['blocked_flows'], 1)
        self.assertEqual(stats['rate_limited_flows'], 1)
        self.assertIn('total_flows', stats)
        self.assertIn('whitelisted_addresses', stats)
        self.assertIn('blacklisted_addresses', stats)
    
    def test_detailed_flow_info(self):
        """Test detailed flow information"""
        # Add some test data
        test_flow = FlowSignature(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2"
        )
        
        self.enforcer.blocked_flows.add(test_flow)
        self.enforcer.add_to_whitelist("10.0.0.100")
        self.enforcer.add_to_blacklist("192.168.1.100")
        
        info = self.enforcer.get_detailed_flow_info()
        
        self.assertIn('blocked_flows', info)
        self.assertIn('whitelist', info)
        self.assertIn('blacklist', info)
        self.assertIn("10.0.0.100", info['whitelist'])
        self.assertIn("192.168.1.100", info['blacklist'])

def run_integration_test():
    """Run integration test with realistic scenario"""
    print("Running Enhanced Mitigation Integration Test...")
    print("=" * 60)
    
    # Initialize system
    logger = logging.getLogger('integration')
    datapaths = {}
    enforcer = EnhancedMitigationEnforcer(logger, datapaths)
    
    # Test scenario: University network with mixed traffic
    print("\n1. Setting up university network scenario...")
    
    # Add legitimate servers to whitelist
    enforcer.add_to_whitelist("10.0.0.100")  # Database server
    enforcer.add_to_whitelist("10.0.0.101")  # Web server
    enforcer.add_to_whitelist("00:00:00:00:01:00")  # Server MAC
    
    # Add known malicious IPs to blacklist
    enforcer.add_to_blacklist("192.168.1.100")  # Compromised host
    enforcer.add_to_blacklist("00:00:00:00:99:99")  # Attacker MAC
    
    print("   → Added legitimate servers to whitelist")
    print("   → Added known malicious sources to blacklist")
    
    # Test flow analysis
    print("\n2. Testing flow analysis...")
    
    # Create legitimate flow
    legitimate_flow = FlowSignature(
        src_mac="00:00:00:00:01:00",
        dst_mac="00:00:00:00:00:ff",
        src_ip="10.0.0.100",
        dst_ip="10.0.0.1"
    )
    
    # Create malicious flow
    malicious_flow = FlowSignature(
        src_mac="00:00:00:00:99:99",
        dst_mac="00:00:00:00:00:ff",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1"
    )
    
    # Test whitelist protection
    legitimate_protected = enforcer.flow_analyzer.is_whitelisted(legitimate_flow)
    print(f"   → Legitimate flow protected: {legitimate_protected}")
    
    # Test blacklist detection
    malicious_blocked = enforcer.flow_analyzer.is_blacklisted(malicious_flow)
    print(f"   → Malicious flow blocked: {malicious_blocked}")
    
    # Test statistics
    print("\n3. Testing statistics...")
    stats = enforcer.get_flow_statistics()
    print(f"   → Whitelisted addresses: {stats['whitelisted_addresses']}")
    print(f"   → Blacklisted addresses: {stats['blacklisted_addresses']}")
    print(f"   → Total flows tracked: {stats['total_flows']}")
    
    # Test detailed information
    print("\n4. Testing detailed flow information...")
    info = enforcer.get_detailed_flow_info()
    print(f"   → Whitelist entries: {len(info['whitelist'])}")
    print(f"   → Blacklist entries: {len(info['blacklist'])}")
    
    print(f"\n✅ Integration test completed successfully!")
    print("Enhanced mitigation system is working correctly.")

def main():
    """Main test function"""
    print("Enhanced Mitigation System Test Suite")
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
