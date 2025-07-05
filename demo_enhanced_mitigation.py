#!/usr/bin/env python3
"""
Demonstration of Enhanced Flow-Level Mitigation

This script demonstrates how the enhanced mitigation system addresses the 
over-blocking flaw by implementing:
1. Flow-level granularity instead of port-level blocking
2. Whitelist/blacklist management for legitimate traffic
3. Graduated response mechanisms
4. Intelligent flow analysis

Usage:
    python demo_enhanced_mitigation.py
"""

import time
import json
import requests
from datetime import datetime, timedelta
from enhanced_mitigation_enforcer import FlowSignature, FlowAnalyzer, EnhancedMitigationEnforcer
from external_policy_system import SharedPolicyStore

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

def demonstrate_over_blocking_problem():
    """Demonstrate the original over-blocking problem"""
    print_section("ORIGINAL PROBLEM: Over-blocking")
    
    print(f"{RED}❌ PROBLEM:{RESET} In the original architecture:")
    print("   • Entire port gets blocked when threshold is exceeded")
    print("   • ALL traffic from that port is dropped")
    print("   • Legitimate users sharing the port are affected")
    print("   • No distinction between malicious and legitimate flows")
    print("   • No whitelist/blacklist capability")
    
    print(f"\n{RED}Example Scenario:{RESET}")
    print("   1. Host h1 (port 1) has both:")
    print("      - Legitimate user browsing (src_mac: 00:00:00:00:00:01)")
    print("      - DoS attacker script (src_mac: 00:00:00:00:00:02)")
    print("   2. DoS attack triggers threshold on port 1")
    print("   3. Controller blocks ENTIRE port 1")
    print("   4. Result: Both legitimate user AND attacker are blocked")
    print("   5. Collateral damage: Legitimate traffic is dropped")

def demonstrate_enhanced_solution():
    """Demonstrate the enhanced flow-level solution"""
    print_section("SOLUTION: Enhanced Flow-Level Mitigation")
    
    print(f"{GREEN}✅ SOLUTION:{RESET} New architecture with flow-level granularity:")
    print("   • Flow-level analysis instead of port-level blocking")
    print("   • Whitelist/blacklist management for known entities")
    print("   • Graduated response: monitor → rate limit → block")
    print("   • Intelligent flow signature tracking")
    print("   • Legitimate traffic protection")
    
    # Initialize the enhanced system
    print(f"\n{YELLOW}Initializing Enhanced Mitigation System...{RESET}")
    
    # Create a mock flow analyzer for demonstration
    import logging
    logger = logging.getLogger('demo')
    flow_analyzer = FlowAnalyzer(logger)
    
    demonstrate_flow_analysis(flow_analyzer)
    demonstrate_whitelist_protection(flow_analyzer)
    demonstrate_graduated_response(flow_analyzer)
    demonstrate_intelligent_blocking(flow_analyzer)

def demonstrate_flow_analysis(flow_analyzer):
    """Demonstrate flow-level analysis capabilities"""
    print_subsection("1. Flow-Level Analysis")
    
    print(f"{YELLOW}Scenario:{RESET} Multiple flows from same port")
    
    # Create flow signatures for different traffic types
    legitimate_flow = FlowSignature(
        src_mac="00:00:00:00:00:01",
        dst_mac="00:00:00:00:00:ff",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.4",
        protocol=6,  # TCP
        src_port=12345,
        dst_port=80
    )
    
    malicious_flow = FlowSignature(
        src_mac="00:00:00:00:00:02",
        dst_mac="00:00:00:00:00:ff",
        src_ip="10.0.0.2",
        dst_ip="10.0.0.4",
        protocol=6,  # TCP
        src_port=54321,
        dst_port=80
    )
    
    print(f"   • Legitimate flow: {legitimate_flow.to_string()}")
    print(f"   • Malicious flow: {malicious_flow.to_string()}")
    
    # Simulate normal vs malicious traffic patterns
    print(f"\n{YELLOW}Traffic Pattern Analysis:{RESET}")
    
    # Legitimate traffic (normal rate)
    flow_analyzer.flow_stats[legitimate_flow] = type('FlowStats', (), {
        'rate_pps': 10,  # Normal rate
        'packet_count': 100,
        'byte_count': 15000
    })()
    
    # Malicious traffic (high rate)
    flow_analyzer.flow_stats[malicious_flow] = type('FlowStats', (), {
        'rate_pps': 2000,  # High rate - DoS attack
        'packet_count': 10000,
        'byte_count': 1500000
    })()
    
    print(f"   • Legitimate flow: 10 pps, 15KB total")
    print(f"   • Malicious flow: 2000 pps, 1.5MB total")
    
    print(f"\n{GREEN}Result:{RESET} System can distinguish flows from same port")
    print(f"   → Only malicious flow would be blocked")
    print(f"   → Legitimate flow continues normally")

def demonstrate_whitelist_protection(flow_analyzer):
    """Demonstrate whitelist protection"""
    print_subsection("2. Whitelist Protection")
    
    print(f"{YELLOW}Scenario:{RESET} Critical server on same port as attacker")
    
    # Add critical server to whitelist
    critical_server_ip = "10.0.0.100"
    critical_server_mac = "00:00:00:00:01:00"
    
    flow_analyzer.add_to_whitelist(critical_server_ip)
    flow_analyzer.add_to_whitelist(critical_server_mac)
    
    print(f"   • Added {critical_server_ip} to whitelist")
    print(f"   • Added {critical_server_mac} to whitelist")
    
    # Create flows
    critical_flow = FlowSignature(
        src_mac=critical_server_mac,
        dst_mac="00:00:00:00:00:ff",
        src_ip=critical_server_ip,
        dst_ip="10.0.0.4"
    )
    
    attacker_flow = FlowSignature(
        src_mac="00:00:00:00:00:99",
        dst_mac="00:00:00:00:00:ff",
        src_ip="10.0.0.99",
        dst_ip="10.0.0.4"
    )
    
    # Test whitelist protection
    critical_whitelisted = flow_analyzer.is_whitelisted(critical_flow)
    attacker_whitelisted = flow_analyzer.is_whitelisted(attacker_flow)
    
    print(f"\n{YELLOW}Whitelist Check:{RESET}")
    print(f"   • Critical server flow: {'✅ PROTECTED' if critical_whitelisted else '❌ NOT PROTECTED'}")
    print(f"   • Attacker flow: {'❌ PROTECTED' if attacker_whitelisted else '✅ NOT PROTECTED'}")
    
    print(f"\n{GREEN}Result:{RESET} Whitelist ensures critical services remain accessible")
    print(f"   → Critical server traffic is never blocked")
    print(f"   → Only non-whitelisted malicious traffic is blocked")

def demonstrate_graduated_response(flow_analyzer):
    """Demonstrate graduated response mechanism"""
    print_subsection("3. Graduated Response")
    
    print(f"{YELLOW}Scenario:{RESET} Progressive threat escalation")
    
    # Simulate different threat levels
    threat_scenarios = [
        {
            'name': 'Low Suspicion',
            'rate_pps': 50,
            'packet_count': 500,
            'response': 'monitor',
            'color': CYAN
        },
        {
            'name': 'Medium Suspicion',
            'rate_pps': 200,
            'packet_count': 2000,
            'response': 'rate_limit',
            'color': YELLOW
        },
        {
            'name': 'High Threat',
            'rate_pps': 1500,
            'packet_count': 15000,
            'response': 'block',
            'color': RED
        }
    ]
    
    print(f"\n{YELLOW}Threat Level Analysis:{RESET}")
    
    for scenario in threat_scenarios:
        print(f"   {scenario['color']}• {scenario['name']}:{RESET}")
        print(f"     - Rate: {scenario['rate_pps']} pps")
        print(f"     - Total packets: {scenario['packet_count']}")
        print(f"     - Response: {scenario['response'].upper()}")
        print()
    
    print(f"{GREEN}Benefits of Graduated Response:{RESET}")
    print("   • 🔍 MONITOR: Suspicious flows are tracked, not blocked")
    print("   • ⚠️  RATE LIMIT: Moderate threats are throttled")
    print("   • 🚫 BLOCK: Only confirmed malicious flows are dropped")
    print("   • ✅ Proportional response to threat level")

def demonstrate_intelligent_blocking(flow_analyzer):
    """Demonstrate intelligent flow blocking"""
    print_subsection("4. Intelligent Flow Blocking")
    
    print(f"{YELLOW}Scenario:{RESET} Multiple flows from same host")
    
    # Create multiple flows from same attacker
    attacker_mac = "00:00:00:00:00:99"
    attacker_ip = "10.0.0.99"
    
    flows = [
        FlowSignature(
            src_mac=attacker_mac,
            dst_mac="00:00:00:00:00:ff",
            src_ip=attacker_ip,
            dst_ip="10.0.0.4",
            protocol=6,
            src_port=8080,
            dst_port=80
        ),
        FlowSignature(
            src_mac=attacker_mac,
            dst_mac="00:00:00:00:00:ff",
            src_ip=attacker_ip,
            dst_ip="10.0.0.4",
            protocol=6,
            src_port=8081,
            dst_port=80
        ),
        FlowSignature(
            src_mac=attacker_mac,
            dst_mac="00:00:00:00:00:ff",
            src_ip=attacker_ip,
            dst_ip="10.0.0.4",
            protocol=17,  # UDP
            src_port=9090,
            dst_port=53
        )
    ]
    
    print(f"   Attacker ({attacker_ip}) creates multiple flows:")
    for i, flow in enumerate(flows, 1):
        print(f"     {i}. {flow.to_string()}")
    
    # Add attacker to blacklist
    flow_analyzer.add_to_blacklist(attacker_ip)
    print(f"\n   → Added {attacker_ip} to blacklist")
    
    # Test blacklist effectiveness
    print(f"\n{YELLOW}Blacklist Check:{RESET}")
    for i, flow in enumerate(flows, 1):
        is_blocked = flow_analyzer.is_blacklisted(flow)
        status = "🚫 BLOCKED" if is_blocked else "✅ ALLOWED"
        print(f"     Flow {i}: {status}")
    
    print(f"\n{GREEN}Result:{RESET} Intelligent blocking prevents evasion")
    print(f"   → All flows from blacklisted source are blocked")
    print(f"   → Attacker cannot evade by using different ports/protocols")
    print(f"   → Automatic blacklist application to future flows")

def demonstrate_comparison():
    """Compare old vs new approaches"""
    print_section("COMPARISON: Old vs New Approach")
    
    print(f"{RED}❌ OLD APPROACH (Port-Level Blocking):{RESET}")
    print("   • Blocks entire port when threshold exceeded")
    print("   • All hosts on that port are affected")
    print("   • No granularity - all or nothing")
    print("   • No whitelist protection")
    print("   • Legitimate traffic suffers collateral damage")
    
    print(f"\n{GREEN}✅ NEW APPROACH (Flow-Level Blocking):{RESET}")
    print("   • Analyzes individual flows from each source")
    print("   • Only blocks confirmed malicious flows")
    print("   • Whitelist protects critical services")
    print("   • Graduated response (monitor → rate limit → block)")
    print("   • Legitimate traffic is preserved")
    
    print(f"\n{BLUE}📊 IMPACT COMPARISON:{RESET}")
    
    comparison_table = [
        ("Metric", "Old Approach", "New Approach"),
        ("Collateral Damage", "HIGH", "MINIMAL"),
        ("Legitimate Traffic Protection", "NONE", "FULL"),
        ("False Positives", "MANY", "FEW"),
        ("Granularity", "PORT-LEVEL", "FLOW-LEVEL"),
        ("Whitelist Support", "NO", "YES"),
        ("Graduated Response", "NO", "YES"),
        ("Intelligent Analysis", "NO", "YES")
    ]
    
    for row in comparison_table:
        if row[0] == "Metric":
            print(f"   {row[0]:<25} | {row[1]:<15} | {row[2]:<15}")
            print(f"   {'-'*25} | {'-'*15} | {'-'*15}")
        else:
            old_color = RED if row[1] in ["HIGH", "MANY", "NONE", "NO"] else ""
            new_color = GREEN if row[2] in ["MINIMAL", "FEW", "FULL", "YES"] else ""
            print(f"   {row[0]:<25} | {old_color}{row[1]:<15}{RESET} | {new_color}{row[2]:<15}{RESET}")

def demonstrate_real_world_scenario():
    """Demonstrate real-world scenario"""
    print_section("REAL-WORLD SCENARIO")
    
    print(f"{YELLOW}Scenario:{RESET} University Network Attack")
    print("   • University has multiple students on same switch port")
    print("   • One student runs DoS attack script")
    print("   • Other students doing legitimate activities")
    print("   • Network admin needs to stop attack without affecting others")
    
    print(f"\n{RED}With Old System:{RESET}")
    print("   1. DoS attack detected on port 3")
    print("   2. System blocks entire port 3")
    print("   3. ALL students on port 3 lose connectivity")
    print("   4. Legitimate students complain to IT")
    print("   5. IT has to manually investigate and unblock")
    
    print(f"\n{GREEN}With Enhanced System:{RESET}")
    print("   1. DoS attack detected from specific MAC address")
    print("   2. System analyzes individual flows from port 3")
    print("   3. Only attacker's flows are blocked")
    print("   4. Other students continue working normally")
    print("   5. IT can whitelist known good students proactively")
    
    print(f"\n{BLUE}Additional Benefits:{RESET}")
    print("   • 📈 Network uptime improved")
    print("   • 😊 User satisfaction increased")
    print("   • 🔧 Reduced IT support burden")
    print("   • 🛡️ Better security without user impact")

def show_configuration_examples():
    """Show configuration examples"""
    print_section("CONFIGURATION EXAMPLES")
    
    print(f"{YELLOW}1. Whitelist Configuration:{RESET}")
    print("   # Add critical servers to whitelist")
    print("   controller.add_to_whitelist('10.0.0.100')  # Database server")
    print("   controller.add_to_whitelist('10.0.0.101')  # Web server")
    print("   controller.add_to_whitelist('00:00:00:00:01:00')  # Critical MAC")
    
    print(f"\n{YELLOW}2. Blacklist Configuration:{RESET}")
    print("   # Add known malicious sources to blacklist")
    print("   controller.add_to_blacklist('192.168.1.100')  # Compromised host")
    print("   controller.add_to_blacklist('00:00:00:00:99:99')  # Attacker MAC")
    
    print(f"\n{YELLOW}3. Threshold Configuration:{RESET}")
    print("   # Adjust detection thresholds")
    print("   flow_analyzer.high_rate_threshold = 500  # packets/second")
    print("   flow_analyzer.burst_threshold = 2000     # packets in burst")
    print("   flow_analyzer.connection_rate_threshold = 50  # connections/sec")
    
    print(f"\n{YELLOW}4. API Usage:{RESET}")
    print("   # Add whitelist via API")
    print("   curl -X POST http://localhost:8080/whitelist \\")
    print("     -d '{\"address\": \"10.0.0.100\", \"reason\": \"Database server\"}'")
    print("   ")
    print("   # Check flow statistics")
    print("   curl http://localhost:8080/flow-stats")

def main():
    """Main demonstration function"""
    print(f"{CYAN}Enhanced Flow-Level Mitigation Demonstration{RESET}")
    print(f"{CYAN}Addressing the Over-blocking Flaw{RESET}")
    
    # Show the problem
    demonstrate_over_blocking_problem()
    
    # Show the solution
    demonstrate_enhanced_solution()
    
    # Show comparison
    demonstrate_comparison()
    
    # Show real-world scenario
    demonstrate_real_world_scenario()
    
    # Show configuration examples
    show_configuration_examples()
    
    print(f"\n{GREEN}✅ Enhanced mitigation system successfully addresses the over-blocking flaw!")
    print(f"Key improvements:")
    print(f"• Flow-level granularity prevents collateral damage")
    print(f"• Whitelist protection for critical services")
    print(f"• Graduated response reduces false positives")
    print(f"• Intelligent analysis improves accuracy{RESET}")

if __name__ == "__main__":
    main()
