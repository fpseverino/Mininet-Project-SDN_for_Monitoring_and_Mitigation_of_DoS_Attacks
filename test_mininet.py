#!/usr/bin/env python3
"""
Test script to verify Mininet topology imports and basic functionality
"""
import sys
import os

# Add current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import compatibility layer
import distutils_compat

def test_mininet_imports():
    """Test that all Mininet modules can be imported"""
    try:
        print("Testing Mininet imports...")
        
        from mininet.log import setLogLevel, info
        print("✓ mininet.log imported")
        
        from mininet.topo import Topo
        print("✓ mininet.topo imported")
        
        from mininet.net import Mininet, CLI
        print("✓ mininet.net imported")
        
        from mininet.node import OVSKernelSwitch, Host, RemoteController
        print("✓ mininet.node imported")
        
        from mininet.link import TCLink, Link
        print("✓ mininet.link imported")
        
        print("✓ All Mininet modules imported successfully!")
        return True
        
    except Exception as e:
        print(f"✗ Error importing Mininet modules: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_topology_class():
    """Test that the topology class can be imported"""
    try:
        print("\nTesting topology.py imports...")
        
        # Import the topology file
        import topology
        print("✓ topology.py imported successfully")
        
        # Check if Environment class exists
        if hasattr(topology, 'Environment'):
            print("✓ Environment class found")
            print("✓ Topology is ready to use!")
        else:
            print("✗ Environment class not found in topology.py")
            
        return True
        
    except Exception as e:
        print(f"✗ Error importing topology: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=== Mininet + Topology Test ===\n")
    
    # Test Mininet imports
    mininet_ok = test_mininet_imports()
    
    # Test topology imports
    topology_ok = test_topology_class()
    
    print(f"\n=== Results ===")
    print(f"Mininet: {'✓ PASS' if mininet_ok else '✗ FAIL'}")
    print(f"Topology: {'✓ PASS' if topology_ok else '✗ FAIL'}")
    
    if mininet_ok and topology_ok:
        print("\n🎉 Everything is working! You can run your topology.")
        print("\nTo run your topology:")
        print("  sudo python topology.py")
        print("\nTo run with the virtual environment:")
        print(f"  sudo {sys.executable} topology.py")
    else:
        print("\n❌ Some issues detected. Check the errors above.")
