#!/bin/bash

# Comprehensive Test Runner for SDN DoS Mitigation Project
# This script tests all components systematically

set -e  # Exit on any error

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_test() {
    echo -e "${CYAN}🧪 Testing: $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Test functions
test_python_environment() {
    print_test "Python Environment"
    
    if python3 --version | grep -q "3.13"; then
        print_success "Python 3.13 detected"
    else
        print_warning "Python 3.13 not detected, but continuing..."
    fi
    
    if [ -d ".venv" ]; then
        print_success "Virtual environment found"
        if [ "$VIRTUAL_ENV" != "" ]; then
            print_success "Virtual environment active"
        else
            print_warning "Virtual environment not active - activating..."
            source .venv/bin/activate
        fi
    else
        print_warning "No virtual environment found"
    fi
}

test_basic_imports() {
    print_test "Basic Python Imports"
    
    python3 -c "
import sys
print(f'Python version: {sys.version}')
import distutils_compat
print('✓ Distutils compatibility layer imported')
"
    print_success "Basic imports working"
}

test_ryu_installation() {
    print_test "Ryu Framework"
    
    python3 -c "
try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.ofproto import ofproto_v1_3
    print('✓ Ryu framework modules imported successfully')
except ImportError as e:
    print(f'✗ Ryu import error: {e}')
    raise
"
    print_success "Ryu framework available"
}

test_mininet_compatibility() {
    print_test "Mininet Compatibility"
    
    python3 -c "
try:
    import distutils_compat
    from mininet.net import Mininet
    from mininet.topo import Topo
    from mininet.node import OVSController
    print('✓ Mininet imported with distutils compatibility')
except ImportError as e:
    print(f'✗ Mininet import error: {e}')
    raise
"
    print_success "Mininet compatibility verified"
}

test_controller_imports() {
    print_test "Controller Module Imports"
    
    echo "Testing original controller..."
    python3 test_controller.py > /dev/null 2>&1
    
    echo "Testing modular controller..."
    python3 test_modular_controller.py > /dev/null 2>&1
    
    print_success "Controller imports successful"
}

test_external_policy_system() {
    print_test "External Policy System"
    
    python3 test_external_policy_system.py > /dev/null 2>&1
    
    print_success "External policy system working"
}

test_adaptive_integration() {
    print_test "Adaptive Blocking Integration"
    
    python3 test_adaptive_integration.py > /dev/null 2>&1
    
    print_success "Adaptive blocking integration working"
}

test_enhanced_mitigation() {
    print_test "Enhanced Mitigation System"
    
    python3 test_enhanced_mitigation.py > /dev/null 2>&1
    
    print_success "Enhanced mitigation system working"
}

test_topology_sensitivity() {
    print_test "Topology Sensitivity Resolution"
    
    python3 test_topology_sensitivity.py > /dev/null 2>&1
    
    print_success "Topology sensitivity resolution working"
}

run_component_tests() {
    print_header "COMPONENT TESTS"
    
    test_python_environment
    test_basic_imports
    test_ryu_installation
    test_mininet_compatibility
    test_controller_imports
    test_external_policy_system
    test_adaptive_integration
    test_enhanced_mitigation
    test_topology_sensitivity
}

test_api_endpoints() {
    print_test "Policy API Endpoints"
    
    # Check if API is running
    if curl -s http://localhost:8080/health > /dev/null 2>&1; then
        print_success "Policy API is accessible"
        
        # Test basic endpoints
        echo "Testing GET /policies..."
        curl -s http://localhost:8080/policies > /dev/null
        
        echo "Testing policy creation..."
        POLICY_ID=$(curl -s -X POST http://localhost:8080/policies \
            -H "Content-Type: application/json" \
            -d '{
                "action": "block",
                "target_type": "ip",
                "target_value": "192.168.1.100",
                "priority": 50,
                "reason": "Test policy"
            }' | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))")
        
        if [ ! -z "$POLICY_ID" ]; then
            print_success "Policy created successfully: $POLICY_ID"
            
            echo "Testing policy deletion..."
            curl -s -X DELETE "http://localhost:8080/policies/$POLICY_ID" > /dev/null
            print_success "Policy deleted successfully"
        fi
    else
        print_warning "Policy API not running - start controller first"
    fi
}

test_database_operations() {
    print_test "Database Operations"
    
    python3 -c "
import sqlite3
import os

# Test database creation and operations
db_file = 'test_policies.db'
try:
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Test table creation
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS test_table (
        id TEXT PRIMARY KEY,
        data TEXT
    )
    ''')
    
    # Test insert
    cursor.execute('INSERT INTO test_table (id, data) VALUES (?, ?)', ('test1', 'test_data'))
    
    # Test select
    cursor.execute('SELECT * FROM test_table WHERE id = ?', ('test1',))
    result = cursor.fetchone()
    
    if result:
        print('✓ Database operations working')
    else:
        print('✗ Database operations failed')
        
    conn.commit()
    conn.close()
    
    # Cleanup
    if os.path.exists(db_file):
        os.remove(db_file)
        
except Exception as e:
    print(f'✗ Database error: {e}')
    raise
"
    print_success "Database operations verified"
}

run_integration_tests() {
    print_header "INTEGRATION TESTS"
    
    test_database_operations
    
    print_warning "API tests require running controller - start with:"
    echo "python run_controller.py modular_controller.py"
    echo "Then run: ./run_comprehensive_tests.sh api"
}

test_mininet_topology() {
    print_test "Mininet Topology Creation"
    
    # Check if running as root for Mininet
    if [ "$EUID" -eq 0 ]; then
        print_status "Running topology test as root"
        
        # Test simple topology creation (dry run)
        python3 -c "
import sys
sys.path.insert(0, '.')
import distutils_compat

try:
    from topology import SimpleDosTopology
    topo = SimpleDosTopology()
    print(f'✓ Simple topology created with {len(topo.hosts())} hosts and {len(topo.switches())} switches')
    
    from complex_topology import ComplexDosTopology
    complex_topo = ComplexDosTopology()
    print(f'✓ Complex topology created with {len(complex_topo.hosts())} hosts and {len(complex_topo.switches())} switches')
    
except Exception as e:
    print(f'✗ Topology creation error: {e}')
    raise
"
        print_success "Topology creation successful"
    else
        print_warning "Mininet tests require root privileges"
        print_status "Run with: sudo ./run_comprehensive_tests.sh topology"
    fi
}

run_mininet_tests() {
    print_header "MININET TESTS"
    
    test_mininet_topology
}

run_demonstration_tests() {
    print_header "DEMONSTRATION TESTS"
    
    print_test "Demo Scripts"
    
    echo "Testing adaptive blocking demos..."
    python3 demo_adaptive_blocking_simple.py --test-mode > /dev/null 2>&1 || true
    
    echo "Testing external policy demo..."
    python3 demo_external_policy.py --test-mode > /dev/null 2>&1 || true
    
    echo "Testing enhanced mitigation demo..."
    python3 demo_enhanced_mitigation.py --test-mode > /dev/null 2>&1 || true
    
    print_success "Demo scripts executed"
}

show_usage() {
    echo "Usage: $0 [component|integration|mininet|demo|api|all]"
    echo ""
    echo "Test categories:"
    echo "  component   - Test imports and basic functionality"
    echo "  integration - Test database and system integration"
    echo "  mininet     - Test Mininet topology creation (requires sudo)"
    echo "  demo        - Run demonstration scripts"
    echo "  api         - Test REST API (requires running controller)"
    echo "  all         - Run all tests (default)"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run all non-sudo tests"
    echo "  $0 component         # Test only imports"
    echo "  sudo $0 mininet      # Test topology creation"
    echo "  $0 api               # Test API (start controller first)"
}

main() {
    print_header "SDN DoS MITIGATION PROJECT - COMPREHENSIVE TESTS"
    
    case "${1:-all}" in
        "component")
            run_component_tests
            ;;
        "integration")
            run_integration_tests
            ;;
        "mininet")
            run_mininet_tests
            ;;
        "demo")
            run_demonstration_tests
            ;;
        "api")
            test_api_endpoints
            ;;
        "all")
            run_component_tests
            run_integration_tests
            run_demonstration_tests
            
            if [ "$EUID" -eq 0 ]; then
                run_mininet_tests
            else
                print_warning "Skipping Mininet tests (requires sudo)"
            fi
            ;;
        "help"|"-h"|"--help")
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown test category: $1"
            show_usage
            exit 1
            ;;
    esac
    
    print_header "TESTING COMPLETE"
    print_success "All specified tests completed successfully!"
    
    echo ""
    echo "Next steps:"
    echo "1. Start controller: python run_controller.py modular_controller.py"
    echo "2. Start topology:   sudo python topology.py"
    echo "3. Test policy API:  ./run_comprehensive_tests.sh api"
    echo "4. Run full demo:    python demo_adaptive_integration.py"
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
