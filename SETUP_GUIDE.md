# SDN Project Setup Guide for Python 3.13

## Problem Solved
You encountered the "externally-managed-environment" error when trying to install Ryu with `pip install .` and "Import mininet.log could not be resolved" errors in VS Code. These were due to:
1. Python 3.13+ restrictions on system-wide package installation
2. Missing distutils module (removed in Python 3.13)
3. VS Code language server not recognizing the virtual environment packages

## Solution
I've set up a complete working environment with both Ryu and Mininet compatible with Python 3.13.

## What was done:

1. **Created a virtual environment**: Python virtual environment configured in `.venv/`

2. **Fixed Ryu compatibility**: 
   - Cloned Ryu from source and applied Python 3.13 compatibility patches
   - Fixed `setuptools.command.easy_install.get_script_args` AttributeError

3. **Fixed Mininet compatibility**:
   - Created comprehensive distutils compatibility layer (`distutils_compat.py`)
   - Added support for both `LooseVersion` and `StrictVersion` classes
   - Integrated compatibility layer into topology.py

4. **Installed all dependencies**: Both Ryu and Mininet with all required packages

## How to use:

### Option 1: Use the setup script (Recommended)
```bash
# Test everything is working
./sdn_setup.sh test

# Start the controller (in one terminal)
./sdn_setup.sh controller

# Start the topology (in another terminal - requires sudo)
./sdn_setup.sh topology
```

### Option 2: Manual execution
```bash
# Test the setup
python test_controller.py
python test_mininet.py

# Run controller
python run_controller.py controller.py

# Run topology (requires sudo)
sudo python topology.py
```

## Complete Workflow:

### Using the Original Controller:
1. **Test Setup**: `./sdn_setup.sh test`
2. **Terminal 1**: `./sdn_setup.sh controller` (starts Ryu controller)
3. **Terminal 2**: `./sdn_setup.sh topology` (starts Mininet topology)

### Using the Modular Controller (Recommended):
1. **Test Setup**: `python test_modular_controller.py`
2. **Terminal 1**: `python run_controller.py modular_controller.py`
3. **Terminal 2**: `./sdn_setup.sh topology` (starts Mininet topology)

The controller will listen on port 6633, and the topology will connect to it automatically.

## Controller Options:

### Original Controller (`controller.py`)
- Monolithic design
- Basic DoS detection and mitigation
- All functionality in one class

### Modular Controller (`modular_controller.py`) - **Recommended**
- Modular architecture with separate components
- Better maintainability and extensibility
- Thread-safe inter-module communication
- Configurable policies and thresholds
- See `MODULAR_ARCHITECTURE.md` for detailed documentation

## Files created:
- `distutils_compat.py` - Compatibility layer for Python 3.13
- `run_controller.py` - Controller runner script  
- `test_controller.py` - Test script to verify controller imports
- `requirements.txt` - Project dependencies
- `.venv/` - Virtual environment with patched Ryu installation

## Notes:
- The virtual environment is already configured and activated for your workspace
- Your original controller.py is unchanged and should work as expected
- All dependencies are installed and tested with Python 3.13
- Use the scripts provided to avoid command-line compatibility issues
