#!/bin/bash
"""
Complete SDN Setup Script
This script sets up and runs both the Ryu controller and Mininet topology
"""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"

echo -e "${GREEN}=== SDN for DoS Attack Monitoring Setup ===${NC}"
echo

# Check if virtual environment exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo -e "${RED}Error: Virtual environment not found at $VENV_PYTHON${NC}"
    echo "Please run the setup first."
    exit 1
fi

# Function to run controller
run_controller() {
    echo -e "${YELLOW}Starting Ryu Controller...${NC}"
    echo "Controller will listen on port 6633 for OpenFlow connections"
    echo "Press Ctrl+C to stop the controller"
    echo
    
    cd "$SCRIPT_DIR"
    PYTHONPATH="$SCRIPT_DIR" "$VENV_PYTHON" run_controller.py controller.py
}

# Function to run topology
run_topology() {
    sudo mn -c
    echo -e "${YELLOW}Starting Mininet Topology...${NC}"
    echo "This requires sudo privileges for network simulation"
    echo "Make sure the controller is running on port 6633"
    echo
    
    cd "$SCRIPT_DIR"
    sudo PYTHONPATH="$SCRIPT_DIR" "$VENV_PYTHON" -c "
import distutils_compat
exec(open('topology.py').read())
"
}

# Function to test setup
test_setup() {
    echo -e "${YELLOW}Testing SDN Setup...${NC}"
    cd "$SCRIPT_DIR"
    "$VENV_PYTHON" test_controller.py
    echo
    "$VENV_PYTHON" test_mininet.py
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTION]"
    echo
    echo "Options:"
    echo "  controller    Start the Ryu controller"
    echo "  topology      Start the Mininet topology (requires sudo)"
    echo "  test          Test the setup"
    echo "  help          Show this help message"
    echo
    echo "Complete workflow:"
    echo "  1. $0 test         # Test that everything is working"
    echo "  2. $0 controller   # Start controller in one terminal"
    echo "  3. $0 topology     # Start topology in another terminal"
    echo
}

# Main script logic
case "${1:-help}" in
    "controller")
        run_controller
        ;;
    "topology")
        run_topology
        ;;
    "test")
        test_setup
        ;;
    "help"|"--help"|"-h")
        show_help
        ;;
    *)
        echo -e "${RED}Unknown option: $1${NC}"
        echo
        show_help
        exit 1
        ;;
esac
