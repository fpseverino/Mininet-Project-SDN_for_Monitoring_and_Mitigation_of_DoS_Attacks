#!/usr/bin/env python3
"""
Test script for the modular SDN controller
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import distutils compatibility layer
import distutils_compat

try:
    print("Testing modular controller imports...")
    
    # Test individual module imports
    from modular_controller import TrafficMetrics, ThreatEvent, MitigationAction
    print("✓ Data structures imported")
    
    from modular_controller import NetworkMonitor, ThreatDetector, MitigationPolicy, MitigationEnforcer
    print("✓ Individual modules imported")
    
    from modular_controller import ModularSDNController
    print("✓ Main controller class imported")
    
    # Test Ryu imports
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    print("✓ Ryu modules imported")
    
    print("\n✅ All imports successful!")
    print("\n🎉 The modular controller is ready to use!")
    
    print("\nModular Architecture Benefits:")
    print("• Separate monitoring, detection, policy, and enforcement")
    print("• Each module can be modified independently")
    print("• Better testability and maintainability")
    print("• Thread-safe communication between modules")
    print("• Configurable thresholds and policies")
    
    print("\nTo run the modular controller:")
    print("  python run_controller.py modular_controller.py")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
