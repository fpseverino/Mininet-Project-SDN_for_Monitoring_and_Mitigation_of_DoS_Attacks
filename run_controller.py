#!/usr/bin/env python3
"""
Ryu controller runner with Python 3.13 compatibility
Usage: python run_controller.py [controller_file]
"""
import sys
import os

# Add current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import distutils compatibility layer
import distutils_compat

# Now we can safely import and run Ryu components
try:
    from ryu.cmd.manager import main
    
    # Set up the arguments for ryu-manager
    if len(sys.argv) > 1:
        controller_file = sys.argv[1]
    else:
        controller_file = "controller.py"
    
    # Make sure the controller file exists
    if not os.path.exists(controller_file):
        print(f"Error: Controller file '{controller_file}' not found")
        sys.exit(1)
    
    # Set up arguments for ryu-manager
    sys.argv = ['ryu-manager', controller_file]
    
    print(f"Starting Ryu controller with {controller_file}...")
    main()
    
except KeyboardInterrupt:
    print("\nController stopped by user")
except Exception as e:
    print(f"Error running controller: {e}")
    import traceback
    traceback.print_exc()
