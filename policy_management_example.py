#!/usr/bin/env python3
"""
Practical Example: External Policy Management

This script shows practical examples of how to manage policies
while the modular controller is running.

Usage:
    # Terminal 1: Start the modular controller
    python run_controller.py
    
    # Terminal 2: Run this script for policy management
    python policy_management_example.py
"""

import time
import json
import requests
from datetime import datetime, timedelta
from external_policy_system import (
    SharedPolicyStore, AdminInterface, ExternalPolicyConnector,
    PolicyRule, PolicySource, PolicyAction
)

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

class PolicyManager:
    """Utility class for managing policies"""
    
    def __init__(self, api_base_url="http://127.0.0.1:8080"):
        self.api_base_url = api_base_url
        self.policy_store = SharedPolicyStore("controller_policies.db")
        self.admin_interface = AdminInterface(self.policy_store)
    
    def check_api_status(self):
        """Check if the policy API is running"""
        try:
            response = requests.get(f"{self.api_base_url}/policies", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def add_policy_via_api(self, policy_data):
        """Add a policy via REST API"""
        try:
            response = requests.post(
                f"{self.api_base_url}/policies",
                json=policy_data,
                timeout=5
            )
            return response.status_code == 201
        except Exception as e:
            print(f"API Error: {e}")
            return False
    
    def get_all_policies_via_api(self):
        """Get all policies via REST API"""
        try:
            response = requests.get(f"{self.api_base_url}/policies", timeout=5)
            if response.status_code == 200:
                return response.json().get("policies", [])
            return []
        except Exception as e:
            print(f"API Error: {e}")
            return []
    
    def remove_policy_via_api(self, policy_id):
        """Remove a policy via REST API"""
        try:
            response = requests.delete(
                f"{self.api_base_url}/policies/{policy_id}",
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            print(f"API Error: {e}")
            return False

def print_section(title):
    """Print a section header"""
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{title:^60}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}")

def example_admin_policy_management():
    """Example of admin policy management"""
    print_section("Administrator Policy Management")
    
    policy_manager = PolicyManager()
    
    # Check if controller is running
    if not policy_manager.check_api_status():
        print(f"{RED}❌ Controller not running or API not accessible{RESET}")
        print("Please start the controller first: python run_controller.py")
        return
    
    print(f"{GREEN}✅ Controller is running, API accessible{RESET}")
    
    # Example 1: Block a malicious IP
    print(f"\n{YELLOW}Example 1: Admin blocks malicious IP{RESET}")
    malicious_ip_policy = {
        "id": "admin_block_malicious_192_168_1_50",
        "source": "admin",
        "action": "block",
        "target_type": "ip",
        "target_value": "192.168.1.50",
        "priority": 90,
        "reason": "Admin decision: Confirmed malicious activity",
        "metadata": {
            "admin_user": "security_admin",
            "incident_id": "INC-2024-001",
            "threat_level": "high"
        }
    }
    
    success = policy_manager.add_policy_via_api(malicious_ip_policy)
    if success:
        print(f"   → Successfully blocked IP 192.168.1.50")
    else:
        print(f"   → Failed to add policy")
    
    # Example 2: Allow a legitimate server
    print(f"\n{YELLOW}Example 2: Admin allows legitimate server{RESET}")
    legitimate_server_policy = {
        "id": "admin_allow_server_10_0_0_100",
        "source": "admin",
        "action": "allow",
        "target_type": "ip",
        "target_value": "10.0.0.100",
        "priority": 95,
        "reason": "Admin whitelist: Critical business server",
        "metadata": {
            "server_type": "database",
            "business_critical": True,
            "admin_user": "db_admin"
        }
    }
    
    success = policy_manager.add_policy_via_api(legitimate_server_policy)
    if success:
        print(f"   → Successfully whitelisted server 10.0.0.100")
    else:
        print(f"   → Failed to add policy")
    
    # Example 3: Temporary rate limit
    print(f"\n{YELLOW}Example 3: Admin sets temporary rate limit{RESET}")
    rate_limit_policy = {
        "id": "admin_rate_limit_temp_10_0_0_200",
        "source": "admin",
        "action": "rate_limit",
        "target_type": "ip",
        "target_value": "10.0.0.200",
        "priority": 70,
        "expiry": (datetime.now() + timedelta(hours=2)).isoformat(),
        "reason": "Admin: Temporary rate limit during peak hours",
        "metadata": {
            "rate_limit_pps": 100,
            "duration_hours": 2
        }
    }
    
    success = policy_manager.add_policy_via_api(rate_limit_policy)
    if success:
        print(f"   → Rate limit applied to 10.0.0.200 (expires in 2 hours)")
    else:
        print(f"   → Failed to add rate limit policy")
    
    # Show all current policies
    print(f"\n{CYAN}Current Policies:{RESET}")
    policies = policy_manager.get_all_policies_via_api()
    for policy in policies:
        print(f"   • {policy['id']}: {policy['action'].upper()} {policy['target_value']} "
              f"(Priority: {policy['priority']}, Source: {policy['source']})")

def example_external_app_integration():
    """Example of external application integration"""
    print_section("External Application Integration")
    
    policy_manager = PolicyManager()
    
    if not policy_manager.check_api_status():
        print(f"{RED}❌ Controller not running{RESET}")
        return
    
    # Simulate different external applications
    external_apps = [
        {
            "name": "Intrusion Detection System",
            "policies": [
                {
                    "id": "ids_block_scanner_203_0_113_10",
                    "source": "ids",
                    "action": "block",
                    "target_type": "ip",
                    "target_value": "203.0.113.10",
                    "priority": 80,
                    "reason": "IDS: Port scanning detected",
                    "metadata": {
                        "scan_type": "tcp_syn_scan",
                        "ports_scanned": 1000,
                        "detection_confidence": 0.95
                    }
                }
            ]
        },
        {
            "name": "Threat Intelligence Feed",
            "policies": [
                {
                    "id": "threat_intel_botnet_198_51_100_20",
                    "source": "threat_intel",
                    "action": "block",
                    "target_type": "ip",
                    "target_value": "198.51.100.20",
                    "priority": 85,
                    "expiry": (datetime.now() + timedelta(days=1)).isoformat(),
                    "reason": "Threat Intel: Known botnet command server",
                    "metadata": {
                        "threat_family": "Mirai",
                        "first_seen": "2024-01-15",
                        "intel_source": "ThreatDB"
                    }
                }
            ]
        },
        {
            "name": "Honeypot System",
            "policies": [
                {
                    "id": "honeypot_attacker_192_0_2_30",
                    "source": "honeypot",
                    "action": "quarantine",
                    "target_type": "ip",
                    "target_value": "192.0.2.30",
                    "priority": 75,
                    "reason": "Honeypot: Attacker interaction detected",
                    "metadata": {
                        "honeypot_type": "ssh",
                        "attack_attempts": 25,
                        "attack_duration": "15 minutes"
                    }
                }
            ]
        }
    ]
    
    # Add policies from external apps
    for app in external_apps:
        print(f"\n{YELLOW}{app['name']} Integration:{RESET}")
        for policy in app['policies']:
            success = policy_manager.add_policy_via_api(policy)
            if success:
                print(f"   → {policy['action'].upper()} {policy['target_value']} "
                      f"(Priority: {policy['priority']})")
                print(f"     Reason: {policy['reason']}")
            else:
                print(f"   → Failed to add policy for {policy['target_value']}")

def example_policy_override_scenario():
    """Example of policy override scenario"""
    print_section("Policy Override Scenario")
    
    policy_manager = PolicyManager()
    
    if not policy_manager.check_api_status():
        print(f"{RED}❌ Controller not running{RESET}")
        return
    
    target_ip = "10.0.0.50"
    
    # Step 1: Controller detects suspicious activity
    print(f"{YELLOW}Step 1: Controller detects suspicious activity{RESET}")
    controller_policy = {
        "id": f"controller_suspicious_{target_ip.replace('.', '_')}",
        "source": "controller",
        "action": "monitor",
        "target_type": "ip",
        "target_value": target_ip,
        "priority": 30,
        "reason": "Controller: Suspicious traffic pattern detected"
    }
    
    policy_manager.add_policy_via_api(controller_policy)
    print(f"   → Controller: MONITOR {target_ip} (Priority: 30)")
    
    time.sleep(1)
    
    # Step 2: External IDS escalates to block
    print(f"\n{YELLOW}Step 2: External IDS escalates to block{RESET}")
    ids_policy = {
        "id": f"ids_block_{target_ip.replace('.', '_')}",
        "source": "ids",
        "action": "block",
        "target_type": "ip",
        "target_value": target_ip,
        "priority": 60,
        "reason": "IDS: Multiple attack signatures matched"
    }
    
    policy_manager.add_policy_via_api(ids_policy)
    print(f"   → IDS: BLOCK {target_ip} (Priority: 60)")
    
    time.sleep(1)
    
    # Step 3: Admin investigates and overrides
    print(f"\n{YELLOW}Step 3: Admin investigates and overrides{RESET}")
    print(f"   → Admin discovers IP belongs to authorized penetration testing")
    
    admin_policy = {
        "id": f"admin_override_{target_ip.replace('.', '_')}",
        "source": "admin",
        "action": "allow",
        "target_type": "ip",
        "target_value": target_ip,
        "priority": 100,
        "reason": "Admin override: Authorized penetration testing",
        "metadata": {
            "pentest_id": "PENTEST-2024-Q1",
            "authorized_by": "security_manager",
            "valid_until": "2024-12-31"
        }
    }
    
    policy_manager.add_policy_via_api(admin_policy)
    print(f"   → Admin: ALLOW {target_ip} (Priority: 100)")
    
    # Show final state
    print(f"\n{CYAN}Final Policy State for {target_ip}:{RESET}")
    policies = policy_manager.get_all_policies_via_api()
    target_policies = [p for p in policies if p['target_value'] == target_ip]
    
    if target_policies:
        # Sort by priority
        target_policies.sort(key=lambda x: x['priority'], reverse=True)
        print(f"   → {len(target_policies)} policies found")
        for policy in target_policies:
            print(f"     • {policy['source'].upper()}: {policy['action'].upper()} "
                  f"(Priority: {policy['priority']})")
        
        effective_action = target_policies[0]['action']
        print(f"\n   → Effective Action: {effective_action.upper()}")
        print(f"   → {GREEN}Admin override successful!{RESET}")

def example_cleanup_policies():
    """Example of cleaning up demo policies"""
    print_section("Cleanup Demo Policies")
    
    policy_manager = PolicyManager()
    
    if not policy_manager.check_api_status():
        print(f"{RED}❌ Controller not running{RESET}")
        return
    
    # Get all policies
    policies = policy_manager.get_all_policies_via_api()
    demo_policies = [p for p in policies if any(keyword in p['id'].lower() 
                    for keyword in ['demo', 'example', 'admin_block', 'admin_allow', 
                                   'admin_rate', 'ids_block', 'threat_intel', 
                                   'honeypot', 'controller_suspicious', 'admin_override'])]
    
    if demo_policies:
        print(f"Found {len(demo_policies)} demo policies to clean up:")
        for policy in demo_policies:
            print(f"   • {policy['id']}: {policy['action'].upper()} {policy['target_value']}")
        
        print(f"\n{YELLOW}Removing demo policies...{RESET}")
        removed_count = 0
        for policy in demo_policies:
            if policy_manager.remove_policy_via_api(policy['id']):
                removed_count += 1
                print(f"   → Removed {policy['id']}")
        
        print(f"\n{GREEN}Cleanup complete: {removed_count} policies removed{RESET}")
    else:
        print(f"No demo policies found to clean up")

def interactive_policy_management():
    """Interactive policy management interface"""
    print_section("Interactive Policy Management")
    
    policy_manager = PolicyManager()
    
    if not policy_manager.check_api_status():
        print(f"{RED}❌ Controller not running{RESET}")
        print("Please start the controller first: python run_controller.py")
        return
    
    while True:
        print(f"\n{CYAN}Policy Management Options:{RESET}")
        print("1. View all policies")
        print("2. Add block policy")
        print("3. Add allow policy")
        print("4. Add rate limit policy")
        print("5. Remove policy")
        print("6. Cleanup demo policies")
        print("7. Exit")
        
        try:
            choice = input(f"\n{YELLOW}Enter your choice (1-7): {RESET}").strip()
            
            if choice == "1":
                policies = policy_manager.get_all_policies_via_api()
                print(f"\n{CYAN}Current Policies ({len(policies)} total):{RESET}")
                for policy in policies:
                    print(f"   • {policy['id']}: {policy['action'].upper()} {policy['target_value']} "
                          f"(Priority: {policy['priority']}, Source: {policy['source']})")
            
            elif choice == "2":
                ip = input("Enter IP to block: ").strip()
                reason = input("Enter reason: ").strip()
                policy_data = {
                    "id": f"manual_block_{ip.replace('.', '_')}_{int(time.time())}",
                    "source": "admin",
                    "action": "block",
                    "target_type": "ip",
                    "target_value": ip,
                    "priority": 90,
                    "reason": reason or "Manual admin block"
                }
                if policy_manager.add_policy_via_api(policy_data):
                    print(f"{GREEN}✅ Successfully blocked {ip}{RESET}")
                else:
                    print(f"{RED}❌ Failed to block {ip}{RESET}")
            
            elif choice == "3":
                ip = input("Enter IP to allow: ").strip()
                reason = input("Enter reason: ").strip()
                policy_data = {
                    "id": f"manual_allow_{ip.replace('.', '_')}_{int(time.time())}",
                    "source": "admin",
                    "action": "allow",
                    "target_type": "ip",
                    "target_value": ip,
                    "priority": 95,
                    "reason": reason or "Manual admin allow"
                }
                if policy_manager.add_policy_via_api(policy_data):
                    print(f"{GREEN}✅ Successfully allowed {ip}{RESET}")
                else:
                    print(f"{RED}❌ Failed to allow {ip}{RESET}")
            
            elif choice == "4":
                ip = input("Enter IP to rate limit: ").strip()
                hours = input("Enter duration in hours (default 1): ").strip()
                reason = input("Enter reason: ").strip()
                
                try:
                    hours = int(hours) if hours else 1
                    expiry = datetime.now() + timedelta(hours=hours)
                except:
                    hours = 1
                    expiry = datetime.now() + timedelta(hours=1)
                
                policy_data = {
                    "id": f"manual_rate_limit_{ip.replace('.', '_')}_{int(time.time())}",
                    "source": "admin",
                    "action": "rate_limit",
                    "target_type": "ip",
                    "target_value": ip,
                    "priority": 70,
                    "expiry": expiry.isoformat(),
                    "reason": reason or "Manual admin rate limit"
                }
                if policy_manager.add_policy_via_api(policy_data):
                    print(f"{GREEN}✅ Successfully rate limited {ip} for {hours} hours{RESET}")
                else:
                    print(f"{RED}❌ Failed to rate limit {ip}{RESET}")
            
            elif choice == "5":
                policy_id = input("Enter policy ID to remove: ").strip()
                if policy_manager.remove_policy_via_api(policy_id):
                    print(f"{GREEN}✅ Successfully removed policy {policy_id}{RESET}")
                else:
                    print(f"{RED}❌ Failed to remove policy {policy_id}{RESET}")
            
            elif choice == "6":
                example_cleanup_policies()
            
            elif choice == "7":
                print("Goodbye!")
                break
            
            else:
                print(f"{RED}Invalid choice. Please enter 1-7.{RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Interrupted by user{RESET}")
            break
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")

def main():
    """Main function"""
    print(f"{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}Practical Policy Management Examples{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    
    print(f"\n{GREEN}Available Examples:{RESET}")
    print("1. Administrator Policy Management")
    print("2. External Application Integration")
    print("3. Policy Override Scenario")
    print("4. Interactive Policy Management")
    print("5. Cleanup Demo Policies")
    print("6. Run All Examples")
    
    try:
        choice = input(f"\n{YELLOW}Enter your choice (1-6): {RESET}").strip()
        
        if choice == "1":
            example_admin_policy_management()
        elif choice == "2":
            example_external_app_integration()
        elif choice == "3":
            example_policy_override_scenario()
        elif choice == "4":
            interactive_policy_management()
        elif choice == "5":
            example_cleanup_policies()
        elif choice == "6":
            example_admin_policy_management()
            example_external_app_integration()
            example_policy_override_scenario()
        else:
            print(f"{RED}Invalid choice{RESET}")
            
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted by user{RESET}")
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")

if __name__ == "__main__":
    main()
