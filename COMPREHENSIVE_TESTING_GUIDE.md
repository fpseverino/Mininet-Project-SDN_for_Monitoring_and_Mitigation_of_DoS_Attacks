# 🧪 Comprehensive Testing Guide for SDN DoS Mitigation Project

## 📋 Overview

This guide provides a complete testing strategy to verify all components of your SDN project work correctly. The project includes multiple controllers, external policy systems, adaptive blocking, and complex topologies.

## 🚀 Quick Start - Complete System Test

### 1. Environment Setup Test
```bash
# Test Python 3.13 compatibility and all imports
python test_controller.py
python test_modular_controller.py
python test_mininet.py

# Test external systems
python test_external_policy_system.py
python test_enhanced_mitigation.py
python test_adaptive_integration.py
```

### 2. Basic Functionality Test
```bash
# Test simple setup with original controller
./sdn_setup.sh test
```

## 🎯 Testing Strategy by Component

### A. Core Controller Testing

#### 1. Original Controller (`controller.py`)
```bash
# Terminal 1: Start controller
python run_controller.py controller.py

# Terminal 2: Start simple topology
sudo python topology.py

# Terminal 3: Run DoS simulation
python -c "
import os
os.system('sudo mn --test pingall')  # Test connectivity
"
```

#### 2. Modular Controller (`modular_controller.py`) - **RECOMMENDED**
```bash
# Test imports and basic functionality
python test_modular_controller.py

# Terminal 1: Start modular controller
python run_controller.py modular_controller.py

# Terminal 2: Start topology (simple or complex)
sudo python topology.py
# OR for complex topology:
sudo python complex_topology.py

# Terminal 3: Test policy management
python policy_management_example.py
```

### B. Topology Testing

#### 1. Simple Topology Test
```bash
# Test basic 4-switch topology
sudo python topology.py

# In Mininet CLI:
# Test connectivity
pingall

# Test DoS simulation
h1 ping -c 100 -i 0.01 h4 &  # High-frequency ping from h1
h3 ping -c 100 -i 0.01 h4 &  # High-frequency ping from h3
```

#### 2. Complex Topology Test (Enterprise Scale)
```bash
# Test 10-switch enterprise topology
sudo python complex_topology.py

# In Mininet CLI:
# Test full connectivity
pingall

# Test distributed DoS attack
h1 ping -c 200 -i 0.005 h14 &   # Attacker 1
h5 ping -c 200 -i 0.005 h14 &   # Attacker 2
h9 ping -c 200 -i 0.005 h14 &   # Attacker 3
h13 ping -c 200 -i 0.005 h14 &  # Attacker 4
h15 ping -c 200 -i 0.005 h14 &  # Attacker 5
```

#### 3. Topology Sensitivity Testing
```bash
# Test the solution to topology sensitivity flaw
python test_topology_sensitivity.py
python demo_topology_sensitivity_solution.py
```

### C. External Policy System Testing

#### 1. Policy Store Testing
```bash
# Test basic policy operations
python test_external_policy_system.py

# Interactive policy management
python policy_management_example.py
```

#### 2. REST API Testing
```bash
# Start controller with external policy system
python run_controller.py modular_controller.py

# Test API endpoints (in another terminal)
# Get all policies
curl http://localhost:8080/policies

# Add a blocking policy
curl -X POST http://localhost:8080/policies \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "target_type": "ip", 
    "target_value": "192.168.1.100",
    "priority": 80,
    "reason": "Test blocking policy"
  }'

# Get policies for specific target
curl "http://localhost:8080/policies?target_type=ip&target_value=192.168.1.100"

# Remove policy
curl -X DELETE http://localhost:8080/policies/test_policy_id
```

#### 3. External Integration Demo
```bash
# Comprehensive external policy demonstration
python demo_external_policy.py
```

### D. Adaptive Blocking System Testing

#### 1. Integration Testing
```bash
# Test adaptive blocking integration with controller
python test_adaptive_integration.py

# Interactive demo of adaptive features
python demo_adaptive_integration.py
```

#### 2. Standalone Adaptive System Testing
```bash
# Simple adaptive blocking demonstration
python demo_adaptive_blocking_simple.py

# Complete adaptive blocking solution demo
python demo_adaptive_blocking_solution.py
```

#### 3. Over-blocking Solution Testing
```bash
# Test the solution to over-blocking flaw
python demo_over_blocking_solution.py
```

### E. Enhanced Mitigation Testing

#### 1. Flow-level Mitigation Testing
```bash
# Test enhanced flow-based mitigation
python test_enhanced_mitigation.py
python demo_enhanced_mitigation.py
```

#### 2. Integration with Modular Controller
```bash
# The enhanced mitigation is integrated in modular_controller.py
# Test by running the modular controller and observing flow-level blocking
python run_controller.py modular_controller.py
```

## 🔬 Comprehensive Integration Testing

### Scenario 1: Complete DoS Detection and Mitigation
```bash
# Terminal 1: Start modular controller
python run_controller.py modular_controller.py

# Terminal 2: Start topology
sudo python complex_topology.py

# Terminal 3: Policy management (optional)
python policy_management_example.py

# Terminal 4: Attack simulation
# Wait for topology to be ready, then:
sudo mn --test pingall  # Verify connectivity

# In Mininet CLI:
# Start legitimate traffic
h2 ping h14 &
h6 ping h14 &
h10 ping h14 &

# Start DoS attacks (distributed)
h1 ping -c 1000 -i 0.001 h14 &  # High-frequency attack
h5 ping -c 1000 -i 0.001 h14 &  # High-frequency attack
h9 ping -c 1000 -i 0.001 h14 &  # High-frequency attack

# Observe controller logs for:
# 1. Traffic monitoring
# 2. Threat detection
# 3. Policy decisions
# 4. Enforcement actions
# 5. Adaptive blocking decisions
```

### Scenario 2: External Policy Override Testing
```bash
# With controller and topology running:

# 1. Let system detect and block an attacker
# 2. Use external policy to override the block
curl -X POST http://localhost:8080/policies \
  -H "Content-Type: application/json" \
  -d '{
    "action": "allow",
    "target_type": "switch_port",
    "target_value": "1:1",
    "priority": 90,
    "reason": "Admin override - false positive"
  }'

# 3. Observe unblocking in controller logs
# 4. Remove override policy
curl -X DELETE http://localhost:8080/policies/{policy_id}

# 5. Observe re-blocking if attack continues
```

### Scenario 3: Adaptive Blocking Testing
```bash
# With modular controller running:
# In Python shell or script:

import requests
import time

# Get adaptive stats
print("Initial stats:")
# Monitor controller logs for adaptive decisions

# Simulate reputation building
# Start light traffic from IP, observe no blocking
# Gradually increase traffic intensity
# Observe adaptive thresholds and blocking decisions

# Force unblock via admin
# curl -X POST http://localhost:8080/admin/unblock \
#   -H "Content-Type: application/json" \
#   -d '{"ip": "192.168.1.100"}'

# Check reputation scores in controller logs
```

## 📊 Expected Test Results

### ✅ Successful Test Indicators

#### Controller Startup
- All modules (Monitor, Detector, Policy, Enforcer) start successfully
- External policy system initializes on port 8080
- Database connections established
- No import errors

#### Topology Connection
- Switches connect to controller
- Port statistics collection begins
- Basic switching functionality works (pingall succeeds)

#### DoS Detection
- Traffic threshold violations logged
- Threat events generated after 3 consecutive violations
- Policy decisions made based on threat events

#### Mitigation Actions
- Flow rules installed for blocking
- External policies respected
- Adaptive blocking decisions logged
- Reputation system updates

#### External Integration
- REST API responds to requests
- Policies persist in database
- Priority-based conflict resolution works
- Real-time policy updates affect controller behavior

### ❌ Common Issues and Solutions

#### Import Errors
```bash
# Solution: Ensure virtual environment is activated
source .venv/bin/activate

# Or run setup script
./sdn_setup.sh test
```

#### Mininet Connection Issues
```bash
# Solution: Clean Mininet and restart
sudo mn -c
sudo python topology.py
```

#### Port Already in Use (8080)
```bash
# Solution: Kill existing processes
sudo lsof -ti:8080 | xargs kill -9
```

#### Database Lock Issues
```bash
# Solution: Remove lock files
rm -f *.db-lock
rm -f controller_policies.db-lock
```

## 🎮 Interactive Testing Commands

### Quick Test Suite
```bash
# Run all tests in sequence
./run_comprehensive_tests.sh
```

### Individual Component Tests
```bash
# Test only imports and basic functionality
python test_controller.py && python test_modular_controller.py

# Test only external policy system
python test_external_policy_system.py

# Test only adaptive integration
python test_adaptive_integration.py

# Test only topology
sudo python test_mininet.py
```

### Performance Testing
```bash
# Monitor system resources during testing
htop  # Monitor CPU/Memory
ss -tuln | grep 8080  # Check API port
tail -f /var/log/syslog | grep mininet  # Monitor Mininet logs
```

## 📈 Success Metrics

- **✅ Import Success**: All modules import without errors
- **✅ Connectivity**: Topology establishes full connectivity
- **✅ Detection**: DoS attacks detected within 30 seconds
- **✅ Mitigation**: Blocking occurs after 3 threshold violations
- **✅ Adaptive**: Reputation-based decisions logged
- **✅ External**: API accepts and applies policies
- **✅ Integration**: All systems work together seamlessly

## 🏁 Final Validation

After running all tests, you should have:

1. **Functional Controllers**: Both original and modular controllers work
2. **Working Topologies**: Both simple and complex topologies connect
3. **DoS Detection**: System detects and responds to attacks
4. **Policy Management**: External policies can be added/removed
5. **Adaptive Behavior**: System shows intelligent blocking decisions
6. **API Integration**: REST API accepts external policy inputs
7. **Database Persistence**: Policies persist across restarts

This confirms your SDN DoS mitigation system is fully functional and ready for production use!

---

**🎯 Remember**: This is a sophisticated system with multiple integrated components. Test each layer individually before testing the complete integration to isolate any issues.
