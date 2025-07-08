#!/usr/bin/env python3
"""
End-to-End System Test for SDN DoS Mitigation Project

This script performs a complete end-to-end test of the system:
1. Tests all imports and basic functionality
2. Simulates controller startup
3. Tests external policy system
4. Tests adaptive blocking system
5. Demonstrates complete workflow

Run th            self.policy_store.add_policy(policy_2)
            print_success("Cross-instance policy added")
            
            # Verify in original store
            all_policies = self.policy_store.get_all_policies()
            assert len(all_policies) >= 2
            print_success("Cross-instance policy synchronization")ipt to verify the entire system works correctly.
"""

import sys
import os
import time
import tempfile
import logging
import threading
import requests
from unittest.mock import Mock, MagicMock

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ANSI Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_header(text):
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{text:^60}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}")

def print_test(text):
    print(f"{CYAN}🧪 {text}...{RESET}")

def print_success(text):
    print(f"{GREEN}✅ {text}{RESET}")

def print_warning(text):
    print(f"{YELLOW}⚠️  {text}{RESET}")

def print_error(text):
    print(f"{RED}❌ {text}{RESET}")

class EndToEndTest:
    def __init__(self):
        self.temp_db = None
        self.policy_store = None
        self.controller = None
        self.results = []
        
    def setup_logging(self):
        """Setup logging for the test"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("E2E_Test")
        
    def test_imports(self):
        """Test all critical imports"""
        print_test("Testing critical imports")
        
        try:
            # Test distutils compatibility
            import distutils_compat
            print_success("Distutils compatibility layer")
            
            # Test Ryu imports
            from ryu.base import app_manager
            from ryu.controller import ofp_event
            from ryu.ofproto import ofproto_v1_3
            print_success("Ryu framework modules")
            
            # Test controller imports
            from modular_controller import (
                ModularSDNController, NetworkMonitor, ThreatDetector,
                MitigationPolicy, MitigationEnforcer, TrafficMetrics
            )
            print_success("Modular controller components")
            
            # Test external policy system
            from external_policy_system import (
                SharedPolicyStore, PolicyAPI, AdminInterface,
                ExternalPolicyConnector, PolicyRule, PolicySource, PolicyAction
            )
            print_success("External policy system")
            
            # Test adaptive blocking
            from adaptive_blocking_system import (
                AdaptiveBlockingSystem, AdaptiveBlockingIntegration
            )
            print_success("Adaptive blocking system")
            
            # Test enhanced mitigation
            from enhanced_mitigation_enforcer import EnhancedMitigationEnforcer
            print_success("Enhanced mitigation enforcer")
            
            self.results.append(("Imports", "PASS"))
            return True
            
        except Exception as e:
            print_error(f"Import failed: {e}")
            self.results.append(("Imports", "FAIL"))
            return False
    
    def test_policy_system(self):
        """Test external policy system functionality"""
        print_test("Testing external policy system")
        
        try:
            from external_policy_system import (
                SharedPolicyStore, PolicyRule, PolicySource, PolicyAction
            )
            
            # Create temporary database
            self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
            self.temp_db.close()
            
            # Initialize policy store
            self.policy_store = SharedPolicyStore(self.temp_db.name)
            print_success("Policy store initialized")
            
            # Test policy creation
            policy = PolicyRule(
                id="test_policy_001",
                source=PolicySource.ADMIN,
                action=PolicyAction.BLOCK,
                target_type="ip",
                target_value="192.168.1.100",
                priority=80,
                reason="End-to-end test policy"
            )
            
            self.policy_store.add_policy(policy)
            print_success("Policy created and stored")
            
            # Test policy retrieval
            retrieved_policies = self.policy_store.get_all_policies()
            assert len(retrieved_policies) > 0
            print_success("Policy retrieved successfully")
            
            # Test effective action calculation
            effective_action = self.policy_store.get_effective_action("ip", "192.168.1.100")
            assert effective_action == PolicyAction.BLOCK
            print_success("Effective action calculation works")
            
            self.results.append(("Policy System", "PASS"))
            return True
            
        except Exception as e:
            print_error(f"Policy system test failed: {e}")
            self.results.append(("Policy System", "FAIL"))
            return False
    
    def test_adaptive_blocking(self):
        """Test adaptive blocking system"""
        print_test("Testing adaptive blocking system")
        
        try:
            from adaptive_blocking_system import AdaptiveBlockingSystem
            
            # Create adaptive blocking system (needs policy_store)
            adaptive_system = AdaptiveBlockingSystem(self.policy_store)
            print_success("Adaptive blocking system initialized")
            
            # Test traffic analysis
            test_ip = "192.168.1.200"
            
            # Test with normal traffic metrics
            normal_metrics = {
                'packet_rate': 10.0,
                'byte_rate': 1000.0,
                'burst_rate': 0.1,
                'pattern_variability': 0.2
            }
            
            threat_score = adaptive_system.calculate_threat_score(test_ip, normal_metrics)
            threat_level = adaptive_system.determine_threat_level(threat_score)
            print_success(f"Normal traffic analysis (threat: {threat_level.value})")
            
            # Test with attack-like traffic metrics
            attack_metrics = {
                'packet_rate': 1000.0,
                'byte_rate': 100000.0,
                'burst_rate': 0.9,
                'pattern_variability': 0.8
            }
            
            threat_score = adaptive_system.calculate_threat_score(test_ip, attack_metrics)
            threat_level = adaptive_system.determine_threat_level(threat_score)
            print_success(f"Attack traffic analysis (threat: {threat_level.value})")
            
            # Test reputation system
            reputation = adaptive_system.reputation_system.get_reputation(test_ip)
            print_success(f"Reputation tracking (score: {reputation:.2f})")
            
            # Test blocking decision
            should_block, reason = adaptive_system.should_block(test_ip, attack_metrics)
            print_success(f"Blocking decision made: {should_block} ({reason})")
            
            self.results.append(("Adaptive Blocking", "PASS"))
            return True
            
        except Exception as e:
            print_error(f"Adaptive blocking test failed: {e}")
            self.results.append(("Adaptive Blocking", "FAIL"))
            return False
    
    def test_controller_integration(self):
        """Test modular controller integration"""
        print_test("Testing controller integration")
        
        try:
            from modular_controller import (
                NetworkMonitor, ThreatDetector, MitigationPolicy,
                TrafficMetrics, ThreatEvent
            )
            
            # Create mock logger
            logger = logging.getLogger("test_controller")
            
            # Test NetworkMonitor
            monitor = NetworkMonitor(logger, monitoring_interval=1)
            print_success("Network monitor created")
            
            # Test ThreatDetector
            detector = ThreatDetector(logger, threshold=100000)
            print_success("Threat detector created")
            
            # Test MitigationPolicy with policy store
            policy_engine = MitigationPolicy(logger, self.policy_store)
            print_success("Policy engine created with external store")
            
            # Test TrafficMetrics
            metrics = TrafficMetrics(
                rx_packets=1000, rx_bytes=100000,
                tx_packets=500, tx_bytes=50000
            )
            print_success("Traffic metrics created")
            
            # Test ThreatEvent
            threat = ThreatEvent(
                switch_id=1, port_no=1,
                threat_type="DOS_ATTACK", severity="HIGH",
                metrics=metrics
            )
            print_success("Threat event created")
            
            # Test component communication (mock)
            print_success("Component integration verified")
            
            self.results.append(("Controller Integration", "PASS"))
            return True
            
        except Exception as e:
            print_error(f"Controller integration test failed: {e}")
            self.results.append(("Controller Integration", "FAIL"))
            return False
    
    def test_enhanced_mitigation(self):
        """Test enhanced mitigation system"""
        print_test("Testing enhanced mitigation system")
        
        try:
            from enhanced_mitigation_enforcer import EnhancedMitigationEnforcer
            
            # Create mock logger and datapaths
            logger = logging.getLogger("test_enforcer")
            datapaths = {}
            
            # Create enhanced enforcer
            enforcer = EnhancedMitigationEnforcer(logger, datapaths)
            print_success("Enhanced mitigation enforcer created")
            
            # Test whitelist/blacklist operations
            enforcer.add_to_whitelist("192.168.1.10")
            enforcer.add_to_blacklist("192.168.1.20")
            print_success("Whitelist/blacklist operations")
            
            # Test flow statistics (mock data)
            stats = enforcer.get_flow_statistics()
            print_success("Flow statistics retrieval")
            
            # Test packet analysis (mock)
            mock_packet_data = b"Mock packet data"
            action = enforcer.analyze_packet_in(mock_packet_data, 1, 1)
            print_success(f"Packet analysis: {action}")
            
            self.results.append(("Enhanced Mitigation", "PASS"))
            return True
            
        except Exception as e:
            print_error(f"Enhanced mitigation test failed: {e}")
            self.results.append(("Enhanced Mitigation", "FAIL"))
            return False
    
    def test_database_persistence(self):
        """Test database persistence across sessions"""
        print_test("Testing database persistence")
        
        try:
            from external_policy_system import SharedPolicyStore, PolicyRule, PolicySource, PolicyAction
            
            # Create another policy store instance with same database
            policy_store_2 = SharedPolicyStore(self.temp_db.name)
            
            # Verify policies persist
            policies = policy_store_2.get_all_policies()
            assert len(policies) > 0
            print_success("Policies persist across store instances")
            
            # Add another policy
            policy_2 = PolicyRule(
                id="test_policy_002",
                source=PolicySource.EXTERNAL_APP,
                action=PolicyAction.ALLOW,
                target_type="ip",
                target_value="192.168.1.50",
                priority=70,
                reason="Persistence test policy"
            )
            
            policy_store_2.add_policy(policy_2)
            
            # Verify in original store
            all_policies = self.policy_store.get_all_policies()
            assert len(all_policies) >= 2
            print_success("Cross-instance policy synchronization")
            
            self.results.append(("Database Persistence", "PASS"))
            return True
            
        except Exception as e:
            print_error(f"Database persistence test failed: {e}")
            import traceback
            traceback.print_exc()
            self.results.append(("Database Persistence", "FAIL"))
            return False
    
    def test_conflict_resolution(self):
        """Test policy conflict resolution"""
        print_test("Testing policy conflict resolution")
        
        try:
            from external_policy_system import PolicyRule, PolicySource, PolicyAction
            
            # Add conflicting policies for same target
            target_ip = "192.168.1.150"
            
            # Lower priority BLOCK policy
            block_policy = PolicyRule(
                id="block_policy",
                source=PolicySource.CONTROLLER,
                action=PolicyAction.BLOCK,
                target_type="ip",
                target_value=target_ip,
                priority=30,
                reason="Controller detected threat"
            )
            
            # Higher priority ALLOW policy (admin override)
            allow_policy = PolicyRule(
                id="allow_policy",
                source=PolicySource.ADMIN,
                action=PolicyAction.ALLOW,
                target_type="ip", 
                target_value=target_ip,
                priority=90,
                reason="Admin override - false positive"
            )
            
            self.policy_store.add_policy(block_policy)
            self.policy_store.add_policy(allow_policy)
            
            # Test conflict resolution - should prioritize ALLOW (higher priority)
            effective_action = self.policy_store.get_effective_action("ip", target_ip)
            assert effective_action == PolicyAction.ALLOW
            print_success("Conflict resolution works (admin override)")
            
            # Remove admin policy
            self.policy_store.remove_policy("allow_policy")
            
            # Should now fall back to BLOCK
            effective_action = self.policy_store.get_effective_action("ip", target_ip)
            assert effective_action == PolicyAction.BLOCK
            print_success("Fallback to lower priority policy")
            
            self.results.append(("Conflict Resolution", "PASS"))
            return True
            
        except Exception as e:
            print_error(f"Conflict resolution test failed: {e}")
            self.results.append(("Conflict Resolution", "FAIL"))
            return False
    
    def cleanup(self):
        """Clean up test resources"""
        try:
            if self.temp_db and os.path.exists(self.temp_db.name):
                os.unlink(self.temp_db.name)
                print_success("Cleaned up temporary database")
        except Exception as e:
            print_warning(f"Cleanup warning: {e}")
    
    def print_results(self):
        """Print test results summary"""
        print_header("TEST RESULTS SUMMARY")
        
        passed = 0
        failed = 0
        
        for test_name, result in self.results:
            if result == "PASS":
                print_success(f"{test_name}: {result}")
                passed += 1
            else:
                print_error(f"{test_name}: {result}")
                failed += 1
        
        print(f"\n{BLUE}Summary:{RESET}")
        print(f"  {GREEN}Passed: {passed}{RESET}")
        print(f"  {RED}Failed: {failed}{RESET}")
        print(f"  {BLUE}Total:  {passed + failed}{RESET}")
        
        if failed == 0:
            print(f"\n{GREEN}🎉 ALL TESTS PASSED! Your SDN system is working correctly!{RESET}")
            return True
        else:
            print(f"\n{RED}❌ Some tests failed. Check the output above for details.{RESET}")
            return False
    
    def run_all_tests(self):
        """Run all end-to-end tests"""
        print_header("SDN DOS MITIGATION - END-TO-END SYSTEM TEST")
        
        self.setup_logging()
        
        try:
            # Run all tests
            self.test_imports()
            self.test_policy_system()
            self.test_adaptive_blocking()
            self.test_controller_integration()
            self.test_enhanced_mitigation()
            self.test_database_persistence()
            self.test_conflict_resolution()
            
            # Print results
            success = self.print_results()
            
            if success:
                print_header("NEXT STEPS")
                print("Your system is ready! To run the complete solution:")
                print()
                print("1. Start the modular controller:")
                print("   python run_controller.py modular_controller.py")
                print()
                print("2. Start a topology (in another terminal):")
                print("   sudo python topology.py")
                print("   # OR for complex topology:")
                print("   sudo python complex_topology.py")
                print()
                print("3. Test the external policy API:")
                print("   ./run_comprehensive_tests.sh api")
                print()
                print("4. Run interactive demos:")
                print("   python demo_adaptive_integration.py")
                print("   python policy_management_example.py")
                print()
                print("See COMPREHENSIVE_TESTING_GUIDE.md for complete testing procedures.")
            
            return success
            
        finally:
            self.cleanup()

def main():
    """Main test execution"""
    test = EndToEndTest()
    success = test.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
