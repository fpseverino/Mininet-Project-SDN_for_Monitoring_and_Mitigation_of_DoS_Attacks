# External Policy System Architecture

## Overview

The External Policy System addresses the **controller-centric blocking decisions flaw** by providing a shared, extensible policy management framework that allows multiple sources (administrators, external applications, threat intelligence feeds) to contribute to security decisions.

## Problem Addressed

### Original Flaw: Controller-Centric Blocking
- **Issue**: The controller made all blocking decisions internally with no external input
- **Limitation**: Administrators couldn't override controller decisions
- **Impact**: False positives remained blocked, legitimate traffic was denied
- **Scalability**: Single point of failure for all security decisions

### Solution: Distributed Policy Management
- **Shared Policy Store**: Centralized but accessible policy repository
- **Multiple Sources**: Admin, external apps, threat intel can contribute
- **Priority System**: Conflict resolution through priority-based decisions
- **Real-time Updates**: Policies can be changed without restarting controller

## Architecture Components

### 1. SharedPolicyStore
**Purpose**: Thread-safe, persistent storage for all security policies

**Features**:
- SQLite database for persistence
- Thread-safe concurrent access
- Automatic cleanup of expired policies
- Policy change notifications
- Priority-based conflict resolution

**Key Methods**:
```python
# Add a new policy
store.add_policy(policy_rule)

# Get effective action for a target
action = store.get_effective_action("ip", "10.0.0.1")

# Listen for policy changes
store.add_listener(callback_function)
```

### 2. PolicyAPI
**Purpose**: RESTful API for external application integration

**Endpoints**:
- `GET /policies` - List all policies
- `POST /policies` - Add new policy
- `DELETE /policies/{id}` - Remove policy

**Example Usage**:
```bash
# Block malicious IP via API
curl -X POST http://localhost:8080/policies \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "target_type": "ip", 
    "target_value": "192.168.1.100",
    "priority": 80,
    "reason": "External IDS detection"
  }'
```

### 3. AdminInterface
**Purpose**: Command-line interface for administrators

**Capabilities**:
- Add/remove policies interactively
- View current policy state
- Override controller decisions
- Set temporary policies with expiration

### 4. ExternalPolicyConnector
**Purpose**: Interface for external security systems

**Integration Points**:
- Threat intelligence feeds
- Intrusion detection systems
- SIEM platforms
- Honeypot systems

## Policy Priority System

### Priority Hierarchy (Higher number = Higher priority)

| Priority Range | Source | Use Case |
|---------------|---------|-----------|
| 90-100 | Admin | Manual overrides, emergency actions |
| 80-89 | Threat Intelligence | Known malicious IPs, confirmed threats |
| 70-79 | External IDS/SIEM | Automated threat detection |
| 60-69 | Honeypot | Attacker interaction detection |
| 50-59 | External Applications | Custom security tools |
| 30-49 | Controller | Internal DoS detection |
| 1-29 | Default/Fallback | Baseline policies |

### Conflict Resolution Example

```python
# Multiple policies for same IP
policies = [
    PolicyRule(source=CONTROLLER, action=MONITOR, priority=30),
    PolicyRule(source=EXTERNAL_APP, action=RATE_LIMIT, priority=50),
    PolicyRule(source=ADMIN, action=ALLOW, priority=100)
]

# Result: ALLOW action wins (highest priority)
effective_action = store.get_effective_action("ip", "10.0.0.1")
# Returns: PolicyAction.ALLOW
```

## Integration with Modular Controller

### MitigationPolicy Component Enhancement

The `MitigationPolicy` component now consults the shared policy store:

```python
class MitigationPolicy:
    def __init__(self, logger, policy_store):
        self.policy_store = policy_store
        
    def determine_action(self, threat_event):
        # Check external policies first
        external_action = self.policy_store.get_effective_action(
            "switch_port", 
            f"{threat_event.switch_id}:{threat_event.port_no}"
        )
        
        if external_action:
            return external_action  # External policy overrides
        
        # Fallback to controller logic
        return self._internal_threat_assessment(threat_event)
```

### Real-time Policy Updates

The controller responds to policy changes immediately:

```python
def _on_external_policy_change(self, action, policy):
    """Handle external policy changes"""
    if action == "add" and policy.action == PolicyAction.BLOCK:
        # Immediately enforce new block policy
        self._enforce_block_policy(policy)
    elif action == "remove":
        # Remove enforcement if policy deleted
        self._remove_enforcement(policy)
```

## Usage Scenarios

### 1. Administrator Override
```python
# Controller blocks IP due to high traffic
controller_policy = PolicyRule(
    source=PolicySource.CONTROLLER,
    action=PolicyAction.BLOCK,
    target_value="10.0.0.5",
    priority=30,
    reason="DoS attack detected"
)

# Admin realizes it's legitimate load testing
admin_policy = PolicyRule(
    source=PolicySource.ADMIN,
    action=PolicyAction.ALLOW,
    target_value="10.0.0.5",
    priority=100,  # Higher priority
    reason="Legitimate load testing"
)

# Result: IP is allowed (admin override wins)
```

### 2. External IDS Integration
```python
# External IDS detects malicious activity
import requests

policy_data = {
    "source": "ids",
    "action": "block",
    "target_type": "ip",
    "target_value": "192.168.1.100",
    "priority": 80,
    "reason": "Malware C&C communication detected"
}

response = requests.post(
    "http://localhost:8080/policies",
    json=policy_data
)
# IP is immediately blocked by controller
```

### 3. Threat Intelligence Feed
```python
# Automated threat intel updates
for malicious_ip in threat_intel_feed:
    policy = PolicyRule(
        source=PolicySource.THREAT_INTEL,
        action=PolicyAction.BLOCK,
        target_value=malicious_ip,
        priority=85,
        expiry=datetime.now() + timedelta(days=1)
    )
    policy_store.add_policy(policy)
```

## Benefits

### 1. Flexibility
- **Multi-source policies**: Not limited to controller decisions
- **Real-time updates**: No restart required for policy changes
- **Temporary policies**: Automatic expiration for time-limited rules

### 2. Scalability
- **Distributed decision making**: Multiple systems contribute
- **Priority-based resolution**: Clear conflict resolution
- **Persistent storage**: Policies survive controller restarts

### 3. Operability
- **Admin override**: Manual control over automated decisions
- **External integration**: API for other security tools
- **Audit trail**: All policy changes are logged

### 4. Extensibility
- **New sources**: Easy to add new policy sources
- **Custom actions**: Support for new action types
- **Plugin architecture**: External connectors for various systems

## Deployment

### Starting the System
```bash
# Terminal 1: Start controller with external policy system
python run_controller.py

# Terminal 2: Manage policies interactively
python policy_management_example.py

# Terminal 3: External application integration
curl -X POST http://localhost:8080/policies -d '{...}'
```

### Configuration
```python
# Controller startup
policy_store = SharedPolicyStore("policies.db")
controller = ModularController(policy_store=policy_store)

# Start policy API
policy_api = PolicyAPI(policy_store, port=8080)
policy_api.start()
```

## Monitoring and Maintenance

### Policy Cleanup
- Expired policies are automatically removed
- Database compaction runs periodically
- Policy change notifications for auditing

### Performance Considerations
- SQLite database with indexes for fast queries
- Thread-safe operations with minimal locking
- Efficient priority-based sorting

### Security
- API access control can be added
- Policy validation prevents invalid rules
- Audit logging for all policy changes

## Conclusion

The External Policy System successfully addresses the controller-centric blocking flaw by:

1. **Enabling external input**: Admins and external systems can contribute
2. **Providing override capability**: Higher priority policies win
3. **Supporting real-time updates**: Immediate policy enforcement
4. **Maintaining persistence**: Policies survive system restarts
5. **Ensuring scalability**: Multiple sources can contribute simultaneously

This architecture transforms the controller from a single decision-maker into a policy enforcement engine that considers input from multiple authoritative sources.
