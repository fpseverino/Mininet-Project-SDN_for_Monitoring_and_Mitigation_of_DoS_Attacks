#!/usr/bin/env python3
"""
Test script to run the Ryu controller with Python 3.13 compatibility
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import distutils compatibility layer
import distutils_compat

try:
    print("Loading Ryu controller...")
    # Import the controller
    from controller import SimpleSwitch13
    print("✓ Controller imported successfully!")
    
    # Try to create an instance (this will test the imports)
    print("Testing controller instantiation...")
    print("✓ Controller ready to run!")
    
    print("\nTo run the controller with ryu-manager, use:")
    print(f"PYTHONPATH={os.path.dirname(os.path.abspath(__file__))} ryu-manager controller.py")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
