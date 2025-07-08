# Modular SDN Controller Architecture

## Overview
The modular controller addresses the design flaws in the original monolithic controller by separating concerns into distinct, loosely-coupled modules.

## Architecture Components

### 1. NetworkMonitor Module
**Responsibility**: Collect and store network traffic statistics
- Manages datapath connections
- Requests port statistics at regular intervals
- Stores traffic history for analysis
- Provides clean API for accessing metrics

**Key Features**:
- Thread-safe operation
- Configurable monitoring intervals
- Efficient data storage using TrafficMetrics objects
- Queue-based communication with other modules

### 2. ThreatDetector Module
**Responsibility**: Analyze traffic patterns and detect DoS attacks
- Monitors traffic rates against configurable thresholds
- Implements sliding window detection (3 strikes in 30 seconds)
- Generates structured threat events
- Supports multiple detection algorithms

**Key Features**:
- Configurable threshold values
- Gradual escalation/de-escalation
- Structured threat event generation
- Extensible for new detection algorithms

### 3. MitigationPolicy Module
**Responsibility**: Decide on appropriate mitigation actions
- Processes threat events from detector
- Implements policy rules for response
- Tracks active mitigation states
- Provides manual override capabilities

**Key Features**:
- Rule-based policy engine
- State tracking for active mitigations
- Manual intervention support
- Extensible policy framework

### 4. MitigationEnforcer Module
**Responsibility**: Implement mitigation actions on the network
- Executes blocking/unblocking actions
- Manages OpenFlow rule installation
- Handles rate limiting (extensible)
- Maintains enforcement state

**Key Features**:
- OpenFlow rule management
- Multiple enforcement strategies
- Error handling and recovery
- Audit trail of actions

## Communication Flow

```
NetworkMonitor → ThreatDetector → MitigationPolicy → MitigationEnforcer
     ↓                ↓                  ↓                    ↓
  Stats Queue    Threat Queue     Policy Queue         OpenFlow Rules
```

## Benefits of Modular Design

### 1. Separation of Concerns
- Each module has a single, well-defined responsibility
- Changes to one module don't affect others
- Easier to understand and maintain

### 2. Testability
- Each module can be tested independently
- Mock objects can be used for unit testing
- Integration testing is more focused

### 3. Extensibility
- New detection algorithms can be added to ThreatDetector
- New enforcement strategies can be added to MitigationEnforcer
- New policy rules can be added to MitigationPolicy

### 4. Maintainability
- Clear interfaces between modules
- Well-documented data structures
- Consistent error handling

### 5. Scalability
- Each module runs in its own thread
- Queue-based communication prevents blocking
- Can be distributed across multiple processes if needed

## Data Structures

### TrafficMetrics
Encapsulates port traffic statistics with timestamp information.

### ThreatEvent
Represents a detected security threat with context information.

### MitigationAction
Represents an action to be taken by the enforcement module.

## Configuration

All modules accept configuration parameters:
- Monitoring interval (NetworkMonitor)
- Detection threshold (ThreatDetector)
- Policy rules (MitigationPolicy)
- Enforcement strategies (MitigationEnforcer)

## Usage

### Running the Modular Controller
```bash
python run_controller.py modular_controller.py
```

### Testing Individual Modules
```bash
python test_modular_controller.py
```

### Manual Intervention
The controller provides APIs for manual intervention:
```python
# Manually unblock a port
controller.manual_unblock(switch_id=1, port_no=1)
```

## Comparison with Original Controller

| Aspect | Original Controller | Modular Controller |
|--------|-------------------|-------------------|
| **Structure** | Monolithic | Modular |
| **Separation** | Mixed responsibilities | Clear separation |
| **Testability** | Difficult | Easy |
| **Extensibility** | Hard to extend | Easy to extend |
| **Maintainability** | Poor | Good |
| **Threading** | Single thread | Multi-threaded |
| **Communication** | Direct coupling | Queue-based |
| **Configuration** | Hardcoded | Configurable |

## Future Enhancements

1. **Machine Learning Integration**: Add ML-based detection algorithms
2. **Distributed Architecture**: Scale across multiple controllers
3. **Policy Management**: Web-based policy configuration
4. **Alerting System**: Integration with monitoring systems
5. **Forensics**: Detailed attack analysis and reporting

## Conclusion

The modular architecture provides a solid foundation for a production-ready SDN controller that can detect and mitigate DoS attacks while remaining maintainable and extensible.
