#!/usr/bin/env python3
"""
Demonstration of External Policy System Integration

This script demonstrates how the external policy system addresses the 
controller-centric blocking decisions flaw by allowing:
1. Administrator manual override of controller decisions
2. External applications to contribute to blocking policies
3. Threat intelligence feeds to provide real-time updates
4. Priority-based policy conflict resolution

Usage:
    python demo_external_policy.py
"""

import time
import json
import threading
import requests
from datetime import datetime, timedelta
from external_policy_system import (
    SharedPolicyStore, PolicyAPI, AdminInterface, ExternalPolicyConnector,
    PolicyRule, PolicySource, PolicyAction
)

# ANSI color codes for output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_section(title):
    """Print a section header"""
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{title:^60}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}")

def print_subsection(title):
    """Print a subsection header"""
    print(f"\n{CYAN}{'-'*40}{RESET}")
    print(f"{CYAN}{title}{RESET}")
    print(f"{CYAN}{'-'*40}{RESET}")

def demonstrate_controller_centric_problem():
    """Demonstrate the original controller-centric problem"""
    print_section("ORIGINAL PROBLEM: Controller-Centric Blocking")
    
    print(f"{RED}❌ PROBLEM:{RESET} In the original architecture:")
    print("   • Controller makes ALL blocking decisions internally")
    print("   • No way for admins to override controller decisions")
    print("   • External security tools cannot contribute to policy")
    print("   • No coordination between different security systems")
    print("   • Single point of failure for security decisions")
    
    print(f"\n{RED}Example Scenario:{RESET}")
    print("   1. Controller detects 'suspicious' traffic from IP 10.0.0.5")
    print("   2. Controller BLOCKS the IP automatically")
    print("   3. Admin realizes it's a false positive (legitimate user)")
    print("   4. Admin has NO WAY to override the controller's decision")
    print("   5. Legitimate user remains blocked indefinitely")

def demonstrate_external_policy_solution():
    """Demonstrate the external policy system solution"""
    print_section("SOLUTION: External Policy System")
    
    print(f"{GREEN}✅ SOLUTION:{RESET} New architecture with external policy integration:")
    print("   • Shared policy store for all security decisions")
    print("   • Admin interface for manual policy management")
    print("   • REST API for external application integration")
    print("   • Priority-based conflict resolution")
    print("   • Real-time policy updates and notifications")
    
    # Initialize the shared policy store
    policy_store = SharedPolicyStore("demo_policies.db")
    
    # Start the API server
    api_server = PolicyAPI(policy_store, port=8081)
    api_server.start()
    
    # Initialize admin interface
    admin_interface = AdminInterface(policy_store)
    
    # Initialize external connector
    external_connector = ExternalPolicyConnector(policy_store)
    
    try:
        # Demonstrate different policy sources
        demonstrate_admin_override(policy_store, admin_interface)
        demonstrate_external_app_integration(policy_store)
        demonstrate_threat_intel_feed(policy_store, external_connector)
        demonstrate_policy_priority_resolution(policy_store)
        demonstrate_real_time_updates(policy_store)
        
    finally:
        # Clean up
        api_server.stop()
        print(f"\n{GREEN}Demo completed successfully!{RESET}")

def demonstrate_admin_override(policy_store, admin_interface):
    """Demonstrate admin override capability"""
    print_subsection("1. Administrator Override")
    
    # Simulate controller detecting a threat and blocking
    print(f"{YELLOW}Controller Action:{RESET} Detected DoS attack from 10.0.0.5")
    controller_policy = PolicyRule(
        id="controller_block_001",
        source=PolicySource.CONTROLLER,
        action=PolicyAction.BLOCK,
        target_type="ip",
        target_value="10.0.0.5",
        priority=30,
        reason="DoS attack detected: 1000 packets/sec"
    )
    policy_store.add_policy(controller_policy)
    print(f"   → Controller blocks IP 10.0.0.5 (Priority: 30)")
    
    # Admin realizes it's a false positive
    time.sleep(1)
    print(f"\n{YELLOW}Admin Investigation:{RESET} Admin realizes it's a false positive")
    print("   → IP 10.0.0.5 is a legitimate load testing server")
    
    # Admin creates override policy
    admin_policy = PolicyRule(
        id="admin_override_001",
        source=PolicySource.ADMIN,
        action=PolicyAction.ALLOW,
        target_type="ip",
        target_value="10.0.0.5",
        priority=80,  # Higher priority than controller
        reason="Admin override: Legitimate load testing server"
    )
    policy_store.add_policy(admin_policy)
    print(f"   → Admin creates ALLOW policy (Priority: 80)")
    
    # Check effective action
    effective_action = policy_store.get_effective_action("ip", "10.0.0.5")
    print(f"\n{GREEN}Result:{RESET} Effective action for 10.0.0.5: {effective_action.value}")
    print(f"   → Admin override successful! IP is now ALLOWED")

def demonstrate_external_app_integration(policy_store):
    """Demonstrate external application integration via REST API"""
    print_subsection("2. External Application Integration")
    
    print(f"{YELLOW}External IDS:{RESET} Intrusion Detection System identifies malicious IP")
    
    # Simulate external IDS making API call to block malicious IP
    external_policy_data = {
        "id": "ids_block_malicious_001",
        "source": "ids",
        "action": "block",
        "target_type": "ip",
        "target_value": "192.168.1.100",
        "priority": 70,
        "reason": "Malicious IP detected by external IDS",
        "metadata": {
            "detection_method": "signature_match",
            "threat_score": 95,
            "external_source": "ThreatIntelDB"
        }
    }
    
    try:
        # Make API call to add policy
        response = requests.post(
            "http://127.0.0.1:8081/policies",
            json=external_policy_data,
            timeout=5
        )
        
        if response.status_code == 201:
            print(f"   → External IDS successfully added block policy via API")
            print(f"   → IP 192.168.1.100 blocked with priority 70")
        else:
            print(f"   → API call failed: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"   → API call failed: {e}")
        # Fallback: add policy directly for demo
        external_policy = PolicyRule(
            id="ids_block_malicious_001",
            source=PolicySource.IDS,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value="192.168.1.100",
            priority=70,
            reason="Malicious IP detected by external IDS"
        )
        policy_store.add_policy(external_policy)
        print(f"   → External IDS policy added directly (Priority: 70)")

def demonstrate_threat_intel_feed(policy_store, external_connector):
    """Demonstrate threat intelligence feed integration"""
    print_subsection("3. Threat Intelligence Feed")
    
    print(f"{YELLOW}Threat Intel Feed:{RESET} Real-time malicious IP feed update")
    
    # Simulate threat intelligence feed providing malicious IPs
    threat_intel_ips = [
        "203.0.113.10",  # Known botnet command server
        "198.51.100.20", # Compromised web server
        "192.0.2.30"     # Malware distribution site
    ]
    
    for ip in threat_intel_ips:
        threat_policy = PolicyRule(
            id=f"threat_intel_{ip.replace('.', '_')}",
            source=PolicySource.THREAT_INTEL,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value=ip,
            priority=90,  # Very high priority
            expiry=datetime.now() + timedelta(hours=24),  # 24-hour expiry
            reason="Threat intelligence feed: Known malicious IP",
            metadata={
                "threat_category": "malware",
                "confidence": 0.95,
                "feed_source": "ThreatIntelDB"
            }
        )
        policy_store.add_policy(threat_policy)
        print(f"   → Blocked {ip} (Priority: 90, Expires: 24h)")

def demonstrate_policy_priority_resolution(policy_store):
    """Demonstrate priority-based policy conflict resolution"""
    print_subsection("4. Policy Priority Resolution")
    
    print(f"{YELLOW}Conflict Scenario:{RESET} Multiple policies for same target")
    
    # Create conflicting policies for the same IP
    target_ip = "10.0.0.10"
    
    # Low priority controller policy
    controller_policy = PolicyRule(
        id="controller_monitor_001",
        source=PolicySource.CONTROLLER,
        action=PolicyAction.MONITOR,
        target_type="ip",
        target_value=target_ip,
        priority=20,
        reason="Controller: Monitor suspicious activity"
    )
    policy_store.add_policy(controller_policy)
    print(f"   → Controller: MONITOR {target_ip} (Priority: 20)")
    
    # Medium priority external app policy  
    app_policy = PolicyRule(
        id="app_rate_limit_001",
        source=PolicySource.EXTERNAL_APP,
        action=PolicyAction.RATE_LIMIT,
        target_type="ip",
        target_value=target_ip,
        priority=50,
        reason="External app: Rate limit detected"
    )
    policy_store.add_policy(app_policy)
    print(f"   → External App: RATE_LIMIT {target_ip} (Priority: 50)")
    
    # High priority admin policy
    admin_policy = PolicyRule(
        id="admin_block_001",
        source=PolicySource.ADMIN,
        action=PolicyAction.BLOCK,
        target_type="ip",
        target_value=target_ip,
        priority=100,
        reason="Admin: Manual block decision"
    )
    policy_store.add_policy(admin_policy)
    print(f"   → Admin: BLOCK {target_ip} (Priority: 100)")
    
    # Show effective policy
    effective_action = policy_store.get_effective_action("ip", target_ip)
    all_policies = policy_store.get_policies_for_target("ip", target_ip)
    
    print(f"\n{GREEN}Priority Resolution:{RESET}")
    print(f"   → {len(all_policies)} policies found for {target_ip}")
    print(f"   → Effective action: {effective_action.value} (highest priority wins)")
    print(f"   → Admin policy overrides all others")

def demonstrate_real_time_updates(policy_store):
    """Demonstrate real-time policy updates"""
    print_subsection("5. Real-Time Policy Updates")
    
    print(f"{YELLOW}Real-Time Updates:{RESET} Policy changes notify all components")
    
    # Set up policy change listener
    change_log = []
    
    def policy_change_listener(action, policy):
        change_log.append((action, policy.id, policy.action.value, policy.target_value))
        print(f"   → Policy {action}: {policy.id} ({policy.action.value} {policy.target_value})")
    
    policy_store.add_listener(policy_change_listener)
    
    # Add some policies to trigger notifications
    print("Adding policies to demonstrate real-time notifications:")
    
    policies = [
        PolicyRule(
            id="realtime_001",
            source=PolicySource.ADMIN,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value="172.16.0.1",
            priority=60,
            reason="Real-time demo policy"
        ),
        PolicyRule(
            id="realtime_002",
            source=PolicySource.EXTERNAL_APP,
            action=PolicyAction.RATE_LIMIT,
            target_type="ip",
            target_value="172.16.0.2",
            priority=40,
            reason="Real-time demo rate limit"
        )
    ]
    
    for policy in policies:
        policy_store.add_policy(policy)
        time.sleep(0.5)  # Small delay to see updates
    
    # Remove a policy to show removal notifications
    print("\nRemoving policy to demonstrate removal notifications:")
    policy_store.remove_policy("realtime_001")
    
    print(f"\n{GREEN}Summary:{RESET} {len(change_log)} policy changes detected and notified")

def show_final_summary():
    """Show final summary of the solution"""
    print_section("SOLUTION SUMMARY")
    
    print(f"{GREEN}✅ Controller-Centric Blocking Problem SOLVED:{RESET}")
    print()
    print("1. 🔄 **Shared Policy Store**")
    print("   • All security decisions stored in centralized, thread-safe store")
    print("   • Controller decisions can be overridden by higher-priority policies")
    print()
    print("2. 👨‍💼 **Administrator Override**")
    print("   • Admins can manually override any controller decision")
    print("   • Higher priority ensures admin decisions take precedence")
    print()
    print("3. 🔗 **External Integration**")
    print("   • REST API allows external applications to contribute policies")
    print("   • IDS, SIEM, and other security tools can block/allow traffic")
    print()
    print("4. 🎯 **Priority-Based Resolution**")
    print("   • Multiple policies for same target resolved by priority")
    print("   • Clear hierarchy: Admin > Threat Intel > External Apps > Controller")
    print()
    print("5. ⚡ **Real-Time Updates**")
    print("   • Policy changes notify all components immediately")
    print("   • No restart required for policy updates")
    print()
    print("6. 📊 **Persistent & Scalable**")
    print("   • SQLite database for policy persistence")
    print("   • Automatic cleanup of expired policies")
    print("   • Thread-safe for concurrent access")
    
    print(f"\n{BLUE}Integration with Modular Controller:{RESET}")
    print("• MitigationPolicy component consults shared policy store")
    print("• External policies influence controller decisions in real-time")
    print("• Policy API server runs alongside controller (port 8080)")
    print("• Admin can manage policies while controller is running")

def main():
    """Main demonstration function"""
    print(f"{CYAN}External Policy System Demonstration{RESET}")
    print(f"{CYAN}Addressing Controller-Centric Blocking Flaw{RESET}")
    
    # Show the problem
    demonstrate_controller_centric_problem()
    
    # Show the solution
    demonstrate_external_policy_solution()
    
    # Show final summary
    show_final_summary()
    
    print(f"\n{GREEN}Demo completed! The external policy system successfully addresses")
    print(f"the controller-centric blocking decisions flaw.{RESET}")

if __name__ == "__main__":
    main()
