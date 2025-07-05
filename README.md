# Mininet Project - SDN for Monitoring and Mitigation of DoS Attacks

## 🚀 **Enhanced Architecture with External Policy System**

This project has been **completely refactored** to address critical architectural flaws and provide a modern, extensible SDN controller solution for DoS detection and mitigation.

### 🎯 **Key Improvements**

1. **✅ Modular Architecture**: Separated concerns into independent, testable components
2. **✅ External Policy System**: Eliminates controller-centric blocking decisions
3. **✅ Python 3.13 Compatibility**: Updated for latest Python with full compatibility
4. **✅ Administrator Override**: Real-time policy management capabilities
5. **✅ External Integration**: REST API for security tools and applications
6. **✅ Priority-Based Resolution**: Intelligent conflict resolution system

### 📊 **Architecture Overview**

The project consists of a Mininet topology with 4 hosts and 4 OVS switches:
- **h1, h3** → s1 (DoS attackers)
- **h2** → s2 (Client)
- **s1, s2** → s3 (Aggregation)
- **s3** → s4 → **h4** (Server)

### 🏗️ **Controller Evolution**

#### **Original Controller** (`controller.py`)
- Monolithic design with mixed concerns
- Controller-centric blocking decisions
- No external policy input capability
- Hard to maintain and extend

#### **Modular Controller** (`modular_controller.py`) - **🌟 RECOMMENDED**
- **NetworkMonitor**: Traffic statistics collection
- **ThreatDetector**: DoS attack pattern analysis
- **MitigationPolicy**: Policy decision engine with external integration
- **MitigationEnforcer**: Action execution and flow rule management
- **External Policy System**: Admin override and external application integration

### 🔄 **External Policy System**

Addresses the critical **controller-centric blocking flaw**:

#### **Problem Solved**
- ❌ **Before**: Controller made ALL blocking decisions internally
- ❌ **Before**: No way for admins to override false positives
- ❌ **Before**: External security tools couldn't contribute to policies
- ❌ **Before**: Single point of failure for security decisions

#### **Solution Implemented**
- ✅ **Shared Policy Store**: Thread-safe, persistent policy management
- ✅ **Administrator Override**: Manual policy control with high priority
- ✅ **REST API**: External applications can contribute policies
- ✅ **Priority Resolution**: Clear hierarchy for conflicting policies
- ✅ **Real-time Updates**: Policy changes without controller restart

### 📚 **Documentation**

| Document | Description |
|----------|-------------|
| **[SETUP_GUIDE.md](SETUP_GUIDE.md)** | Complete setup instructions for Python 3.13 |
| **[MODULAR_ARCHITECTURE.md](MODULAR_ARCHITECTURE.md)** | Detailed architecture documentation |
| **[EXTERNAL_POLICY_SYSTEM.md](EXTERNAL_POLICY_SYSTEM.md)** | External policy system guide |
| **[DoS_ATTACK_SIMULATION.md](DoS_ATTACK_SIMULATION.md)** | Attack simulation and testing |
| **[MODULAR_IMPLEMENTATION_SUMMARY.md](MODULAR_IMPLEMENTATION_SUMMARY.md)** | Implementation summary |

## 🚀 **Quick Start**

### **1. Environment Setup**
```bash
# Test the complete setup
./sdn_setup.sh test

# Or test individual components
python test_modular_controller.py
python test_external_policy_system.py
```

### **2. Run the System**
```bash
# Terminal 1: Start the modular controller
python run_controller.py modular_controller.py

# Terminal 2: Start the topology
./sdn_setup.sh topology

# Terminal 3: Policy management (optional)
python policy_management_example.py
```

### **3. External Policy Management**
```bash
# Interactive policy management
python policy_management_example.py

# Block malicious IP via API
curl -X POST http://localhost:8080/policies \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "target_type": "ip",
    "target_value": "192.168.1.100",
    "priority": 80,
    "reason": "Manual admin block"
  }'

# View all policies
curl http://localhost:8080/policies
```

### **4. Run Demonstrations**
```bash
# External policy system demo
python demo_external_policy.py

# DoS attack simulation
# See DoS_ATTACK_SIMULATION.md for detailed instructions
```

## 🎯 **Key Features**

### **Modular Design**
- **Independent Components**: Each module can be developed and tested separately
- **Queue-based Communication**: Thread-safe message passing
- **Pluggable Architecture**: Easy to extend with new detection algorithms

### **External Policy Integration**
- **Admin Override**: High-priority policies override controller decisions
- **External Apps**: IDS, SIEM, and security tools contribute via REST API
- **Threat Intelligence**: Real-time malicious IP feed integration
- **Priority System**: Clear hierarchy for policy conflicts

### **Real-time Management**
- **Policy API**: RESTful interface on port 8080
- **Live Updates**: Policy changes without controller restart
- **Persistent Storage**: SQLite database for policy persistence
- **Automatic Cleanup**: Expired policies removed automatically

## 📊 **Priority Hierarchy**

| Priority | Source | Example Use Case |
|----------|--------|------------------|
| 90-100 | Administrator | Emergency blocks, false positive overrides |
| 80-89 | Threat Intelligence | Known malicious IPs, botnet C&C |
| 70-79 | External IDS/SIEM | Automated threat detection |
| 60-69 | Honeypot | Attacker interaction detection |
| 50-59 | External Apps | Custom security tools |
| 30-49 | Controller | Internal DoS detection |
| 1-29 | Default | Baseline policies |

## 🔧 **Python 3.13 Compatibility**

The project has been fully updated for Python 3.13:
- ✅ **Ryu Framework**: Custom compatibility patches applied
- ✅ **Mininet**: Full compatibility with `distutils_compat.py`
- ✅ **All Dependencies**: Tested and working with Python 3.13
- ✅ **Virtual Environment**: Isolated environment setup

## 🧪 **Testing**

```bash
# Test all components
python test_controller.py
python test_modular_controller.py
python test_external_policy_system.py
python test_mininet.py

# Run demonstrations
python demo_external_policy.py
python policy_management_example.py
```

## 📋 **Requirements**

- Python 3.13+
- Mininet
- Ryu SDN Framework (patched for Python 3.13)
- SQLite3
- Additional dependencies in `requirements.txt`

## 🌟 **Benefits of the New Architecture**

1. **🔧 Maintainability**: Clear separation of concerns, easy to debug
2. **🚀 Extensibility**: New detection algorithms, policy sources easily added
3. **👨‍💼 Operability**: Admin can override automated decisions in real-time
4. **🔗 Integration**: External security tools contribute to policy decisions
5. **📈 Scalability**: Thread-safe, persistent, distributed policy management
6. **🛡️ Reliability**: Multiple fallback mechanisms, no single point of failure

## 🎬 **Legacy Information**

The original project evolution (preserved for reference):
- **First Version**: Port-based DoS detection with simple threshold
- **Second Version**: Flow-based detection with MAC address blocking
- **Third Version**: Telegram bot integration for monitoring

**Current Version**: Complete architectural refactor with modular design and external policy system.

---

**🎯 This enhanced architecture successfully addresses the original flaws while providing a robust, extensible, and maintainable SDN controller solution.**
