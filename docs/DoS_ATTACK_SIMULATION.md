# DoS Attack Simulation Guide

## Overview
This guide explains how to simulate DoS attacks in your Mininet topology to test the modular controller's detection and mitigation capabilities.

## Prerequisites
1. Controller running: `python run_controller.py modular_controller.py`
2. Topology running: `./sdn_setup.sh topology`
3. Both controller and topology should be connected

## Attack Simulation Methods

### Method 1: TCP SYN Flood (Recommended)
**Most effective for triggering the controller's detection**

```bash
# In Mininet CLI
mininet> h1 hping3 -c 10000 -d 120 -S -w 64 -p 80 --flood --rand-source 10.0.0.3
```

**Parameters**:
- `-c 10000`: Send 10,000 packets
- `-d 120`: Packet size 120 bytes
- `-S`: SYN flag
- `-w 64`: Window size
- `-p 80`: Target port 80
- `--flood`: Send as fast as possible
- `--rand-source`: Randomize source addresses

### Method 2: UDP Flood
**High-volume traffic to overwhelm bandwidth**

```bash
# In Mininet CLI
mininet> h1 hping3 --udp --flood -p 53 10.0.0.3
```

### Method 3: ICMP Flood
**Simple ping flood**

```bash
# In Mininet CLI
mininet> h1 ping -f -c 5000 10.0.0.3
```

### Method 4: Bandwidth Exhaustion with iperf3
**Sustained high bandwidth attack**

```bash
# On h3 (target) - start server
mininet> h3 iperf3 -s -p 5001 &

# On h1 (attacker) - generate traffic
mininet> h1 iperf3 -c 10.0.0.3 -p 5001 -t 60 -b 100M
```

### Method 5: Custom Python Script
**Programmable attack for testing specific scenarios**

```bash
# In Mininet CLI
mininet> h1 python3 -c "
import socket
import threading
import time
import random

def tcp_flood():
    target = '10.0.0.3'
    port = 80
    
    for i in range(1000):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((target, port))
            sock.send(b'GET / HTTP/1.1\r\nHost: target\r\n\r\n' * 50)
            sock.close()
        except:
            pass
        time.sleep(0.001)

# Launch multiple attack threads
for i in range(5):
    threading.Thread(target=tcp_flood).start()
" &
```

## Monitoring the Attack

### Controller Output
Watch the controller terminal for:
- **YELLOW**: Threshold exceeded warnings
- **RED**: Port blocking actions
- **GREEN**: Port unblocking actions
- **BLUE**: Regular monitoring updates

### Expected Detection Flow
1. **Phase 1** (0-10s): Normal traffic monitoring
2. **Phase 2** (10-30s): Threshold exceeded warnings (yellow)
3. **Phase 3** (30s+): Port blocking triggered (red)
4. **Phase 4** (after attack stops): Port unblocking (green)

### Testing Connectivity During Attack
```bash
# Test connectivity from h2 to h3 (should work)
mininet> h2 ping -c 3 10.0.0.3

# Test connectivity from h1 to h3 (should fail after blocking)
mininet> h1 ping -c 3 10.0.0.3
```

## Configuring Attack Sensitivity

### Adjusting Detection Threshold
The default threshold is 700,000 bytes/second. To modify:

```python
# In modular_controller.py, line ~218
self.detector = ThreatDetector(self.logger, threshold=500000)  # Lower = more sensitive
```

### Adjusting Detection Time Window
The default is 3 violations in 30 seconds. To modify:

```python
# In modular_controller.py, line ~298
if counter >= 2:  # Trigger after 2 violations instead of 3
```

## Advanced Testing Scenarios

### Scenario 1: Gradual Attack Escalation
```bash
# Start with light traffic
mininet> h1 iperf3 -c 10.0.0.3 -b 1M -t 30 &

# Escalate to moderate traffic
mininet> h1 iperf3 -c 10.0.0.3 -b 5M -t 30 &

# Escalate to heavy traffic (should trigger detection)
mininet> h1 iperf3 -c 10.0.0.3 -b 50M -t 30 &
```

### Scenario 2: Multi-Host Attack
```bash
# Attack from multiple hosts
mininet> h1 hping3 --flood -S -p 80 10.0.0.3 &
mininet> h2 hping3 --flood -S -p 80 10.0.0.3 &
```

### Scenario 3: Attack Recovery Testing
```bash
# 1. Start attack
mininet> h1 hping3 --flood -S -p 80 10.0.0.3 &

# 2. Wait for blocking (watch controller output)

# 3. Stop attack
mininet> h1 killall hping3

# 4. Verify automatic unblocking after traffic normalizes
mininet> h1 ping -c 3 10.0.0.3
```

## Troubleshooting

### Attack Not Detected
- Check if traffic exceeds threshold (700,000 bytes/second)
- Verify attack duration (needs 30 seconds of sustained traffic)
- Check controller is receiving port statistics

### Port Not Blocked
- Verify attack is coming from correct port
- Check OpenFlow rules: `mininet> sh ovs-ofctl dump-flows s1`
- Ensure controller is connected to switches

### Attack Still Successful After Blocking
- Verify drop rules are installed correctly
- Check if traffic is being rerouted through other paths
- Confirm blocking is on correct switch and port

## Manual Testing Commands

### Check OpenFlow Rules
```bash
# In separate terminal
sudo ovs-ofctl dump-flows s1
sudo ovs-ofctl dump-flows s2
sudo ovs-ofctl dump-flows s3
sudo ovs-ofctl dump-flows s4
```

### Monitor Network Traffic
```bash
# In separate terminal
sudo tcpdump -i s1-eth1 -n
```

### Manual Port Unblocking
```python
# In controller debug mode
controller.manual_unblock(switch_id=1, port_no=1)
```

## Expected Results

### Successful Attack Detection
- Controller logs show threshold exceeded warnings
- Port is blocked within 30 seconds
- Attack traffic is dropped
- Normal traffic continues to flow

### Successful Attack Mitigation
- Blocked port prevents further attack traffic
- Network performance returns to normal
- Legitimate traffic is unaffected
- Port is unblocked when attack stops

## Performance Metrics

Track these metrics during testing:
- **Detection Time**: Time from attack start to first warning
- **Mitigation Time**: Time from attack start to port blocking
- **False Positives**: Legitimate traffic being blocked
- **False Negatives**: Attacks not being detected
- **Recovery Time**: Time from attack stop to port unblocking

## Conclusion

The modular controller provides robust DoS detection and mitigation capabilities. Use these simulation methods to verify proper operation and tune the system for your specific network requirements.
