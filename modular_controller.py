"""
Modular SDN Controller for DoS Attack Detection and Mitigation

This module provides a modular architecture with separate components for:
1. Network Monitoring - Collects traffic statistics
2. Threat Detection - Analyzes traffic patterns for DoS attacks  
3. Mitigation Policy - Decides on appropriate responses
4. Enforcement - Implements mitigation actions

Author: Refactored for modularity and maintainability
"""

# Import compatibility layer for Python 3.13
import distutils_compat

import threading
import time
import queue
from collections import defaultdict
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub

# Import external policy system
from external_policy_system import (
    SharedPolicyStore, PolicyAPI, AdminInterface, ExternalPolicyConnector,
    PolicyRule, PolicySource, PolicyAction
)

# Import enhanced mitigation enforcer
from enhanced_mitigation_enforcer import EnhancedMitigationEnforcer

# Import adaptive blocking system
from adaptive_blocking_system import AdaptiveBlockingIntegration

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


class TrafficMetrics:
    """Data structure to hold traffic metrics for a port"""
    def __init__(self, rx_packets=0, rx_bytes=0, rx_errors=0, 
                 tx_packets=0, tx_bytes=0, tx_errors=0, timestamp=None):
        self.rx_packets = rx_packets
        self.rx_bytes = rx_bytes
        self.rx_errors = rx_errors
        self.tx_packets = tx_packets
        self.tx_bytes = tx_bytes
        self.tx_errors = tx_errors
        self.timestamp = timestamp or time.time()
    
    def calculate_rates(self, previous_metrics, time_delta):
        """Calculate traffic rates compared to previous metrics"""
        if time_delta <= 0:
            return 0, 0
        
        rx_rate = (self.rx_bytes - previous_metrics.rx_bytes) / time_delta
        tx_rate = (self.tx_bytes - previous_metrics.tx_bytes) / time_delta
        return rx_rate, tx_rate


class ThreatEvent:
    """Represents a detected threat event"""
    def __init__(self, switch_id, port_no, threat_type, severity, metrics):
        self.switch_id = switch_id
        self.port_no = port_no
        self.threat_type = threat_type
        self.severity = severity
        self.metrics = metrics
        self.timestamp = time.time()


class MitigationAction:
    """Represents a mitigation action to be taken"""
    def __init__(self, action_type, switch_id, port_no, priority=1):
        self.action_type = action_type  # 'BLOCK', 'UNBLOCK', 'RATE_LIMIT'
        self.switch_id = switch_id
        self.port_no = port_no
        self.priority = priority
        self.timestamp = time.time()


class NetworkMonitor:
    """
    Responsible for collecting and storing network traffic statistics
    """
    def __init__(self, logger, monitoring_interval=10):
        self.logger = logger
        self.monitoring_interval = monitoring_interval
        self.datapaths = {}
        self.traffic_history = defaultdict(dict)  # {switch_id: {port_no: [TrafficMetrics]}}
        self.stats_queue = queue.Queue()
        self.running = False
        self.monitor_thread = None
        
    def start(self):
        """Start the monitoring thread"""
        self.running = True
        self.monitor_thread = hub.spawn(self._monitor_loop)
        
    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.kill()
    
    def register_datapath(self, datapath):
        """Register a new datapath for monitoring"""
        self.datapaths[datapath.id] = datapath
        self.logger.info(f"{GREEN}Registered datapath: {datapath.id:016x}{RESET}")
    
    def unregister_datapath(self, datapath_id):
        """Unregister a datapath"""
        if datapath_id in self.datapaths:
            del self.datapaths[datapath_id]
            self.logger.info(f"{YELLOW}Unregistered datapath: {datapath_id:016x}{RESET}")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                for datapath in self.datapaths.values():
                    self._request_stats(datapath)
                self.logger.info(f"{BLUE}{'='*60}{RESET}")
                hub.sleep(self.monitoring_interval)
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
    
    def _request_stats(self, datapath):
        """Request port statistics from a datapath"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    def process_stats_reply(self, ev):
        """Process incoming statistics reply"""
        body = ev.msg.body
        datapath_id = ev.msg.datapath.id
        current_time = time.time()
        
        current_metrics = {}
        for stat in body:
            if stat.port_no == 0xfffffffe:  # Skip LOCAL port
                continue
                
            metrics = TrafficMetrics(
                rx_packets=stat.rx_packets,
                rx_bytes=stat.rx_bytes,
                rx_errors=stat.rx_errors,
                tx_packets=stat.tx_packets,
                tx_bytes=stat.tx_bytes,
                tx_errors=stat.tx_errors,
                timestamp=current_time
            )
            current_metrics[stat.port_no] = metrics
        
        # Store metrics and put in queue for analysis
        self.traffic_history[datapath_id] = current_metrics
        self.stats_queue.put((datapath_id, current_metrics))
    
    def get_latest_metrics(self, switch_id, port_no):
        """Get the latest metrics for a specific port"""
        return self.traffic_history.get(switch_id, {}).get(port_no)


class ThreatDetector:
    """
    Responsible for analyzing traffic patterns and detecting DoS attacks
    """
    def __init__(self, logger, threshold=700000):
        self.logger = logger
        self.threshold = threshold
        self.previous_metrics = defaultdict(dict)  # {switch_id: {port_no: TrafficMetrics}}
        self.threat_counters = defaultdict(dict)  # {switch_id: {port_no: counter}}
        self.threat_queue = queue.Queue()
        self.running = False
        self.detector_thread = None
        
    def start(self, stats_queue):
        """Start the threat detection thread"""
        self.running = True
        self.stats_queue = stats_queue
        self.detector_thread = hub.spawn(self._detection_loop)
        
    def stop(self):
        """Stop the threat detection thread"""
        self.running = False
        if self.detector_thread:
            self.detector_thread.kill()
    
    def _detection_loop(self):
        """Main detection loop"""
        while self.running:
            try:
                # Get stats from monitoring module
                datapath_id, current_metrics = self.stats_queue.get(timeout=1)
                self._analyze_traffic(datapath_id, current_metrics)
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in detection loop: {e}")
    
    def _analyze_traffic(self, datapath_id, current_metrics):
        """Analyze traffic metrics for potential threats"""
        previous = self.previous_metrics.get(datapath_id, {})
        
        for port_no, metrics in current_metrics.items():
            if port_no in previous:
                prev_metrics = previous[port_no]
                time_delta = metrics.timestamp - prev_metrics.timestamp
                
                if time_delta > 0:
                    rx_rate, tx_rate = metrics.calculate_rates(prev_metrics, time_delta)
                    
                    # Check for DoS attack indicators
                    if rx_rate > self.threshold or tx_rate > self.threshold:
                        self._handle_threshold_exceeded(datapath_id, port_no, rx_rate, tx_rate, metrics)
                    else:
                        self._handle_normal_traffic(datapath_id, port_no)
        
        # Update previous metrics
        self.previous_metrics[datapath_id] = current_metrics
    
    def _handle_threshold_exceeded(self, datapath_id, port_no, rx_rate, tx_rate, metrics):
        """Handle traffic that exceeds threshold"""
        if datapath_id not in self.threat_counters:
            self.threat_counters[datapath_id] = {}
        if port_no not in self.threat_counters[datapath_id]:
            self.threat_counters[datapath_id][port_no] = 0
        
        self.threat_counters[datapath_id][port_no] += 1
        counter = self.threat_counters[datapath_id][port_no]
        
        self.logger.warning(f"{YELLOW}Threshold exceeded on switch {datapath_id:016x} port {port_no}: "
                           f"RX={rx_rate:.0f} TX={tx_rate:.0f} (counter: {counter}){RESET}")
        
        # Trigger threat event after 3 consecutive violations (30 seconds)
        if counter >= 3:
            threat_event = ThreatEvent(
                switch_id=datapath_id,
                port_no=port_no,
                threat_type="DOS_ATTACK",
                severity="HIGH",
                metrics=metrics
            )
            self.threat_queue.put(threat_event)
    
    def _handle_normal_traffic(self, datapath_id, port_no):
        """Handle normal traffic - reduce threat counter"""
        if (datapath_id in self.threat_counters and 
            port_no in self.threat_counters[datapath_id] and 
            self.threat_counters[datapath_id][port_no] > 0):
            
            self.threat_counters[datapath_id][port_no] -= 1
            counter = self.threat_counters[datapath_id][port_no]
            
            if counter == 0:
                self.logger.info(f"{GREEN}Traffic normalized on switch {datapath_id:016x} port {port_no}{RESET}")


class MitigationPolicy:
    """
    Enhanced policy engine that integrates with external policy system
    Supports multiple policy sources and priority-based conflict resolution
    """
    def __init__(self, logger, policy_store: SharedPolicyStore = None):
        self.logger = logger
        self.active_blocks = set()  # Track currently blocked ports
        self.policy_queue = queue.Queue()
        self.running = False
        self.policy_thread = None
        
        # External policy integration
        self.policy_store = policy_store or SharedPolicyStore("controller_policies.db")
        self.policy_store.add_listener(self._on_external_policy_change)
        
        # Initialize admin and external interfaces
        self.admin_interface = AdminInterface(self.policy_store)
        self.external_connector = ExternalPolicyConnector(self.policy_store)
        
        # Start policy API server
        self.policy_api = PolicyAPI(self.policy_store, port=8080)
        self.policy_api.start()
        
        self.logger.info(f"{GREEN}Enhanced policy engine with external integration started{RESET}")
        
    def start(self, threat_queue):
        """Start the policy decision thread"""
        self.running = True
        self.threat_queue = threat_queue
        self.policy_thread = hub.spawn(self._policy_loop)
        
    def stop(self):
        """Stop the policy decision thread"""
        self.running = False
        if self.policy_thread:
            self.policy_thread.kill()
        if self.policy_api:
            self.policy_api.stop()
    
    def _policy_loop(self):
        """Main policy decision loop"""
        while self.running:
            try:
                threat_event = self.threat_queue.get(timeout=1)
                self._process_threat_event(threat_event)
            except queue.Empty:
                # Check for external policy changes periodically
                self._check_external_policies()
                continue
            except Exception as e:
                self.logger.error(f"Error in policy loop: {e}")
    
    def _process_threat_event(self, threat_event):
        """Process a threat event and decide on mitigation action"""
        switch_id = threat_event.switch_id
        port_no = threat_event.port_no
        port_key = (switch_id, port_no)
        
        # Check if there's an external policy for this specific port
        switch_port_target = f"{switch_id}:{port_no}"
        external_action = self.policy_store.get_effective_action("switch_port", switch_port_target)
        
        if external_action == PolicyAction.ALLOW:
            self.logger.info(f"{GREEN}External policy allows traffic on port {port_no} - skipping controller block{RESET}")
            return
        elif external_action == PolicyAction.BLOCK:
            self.logger.warning(f"{YELLOW}External policy already blocks port {port_no} - enforcing{RESET}")
            self._enforce_external_block(switch_id, port_no)
            return
        
        # Process internal threat detection
        if threat_event.threat_type == "DOS_ATTACK":
            if port_key not in self.active_blocks:
                # Add controller-generated policy
                self._add_controller_policy(switch_id, port_no, threat_event)
                
                # Create enforcement action
                action = MitigationAction(
                    action_type="BLOCK",
                    switch_id=switch_id,
                    port_no=port_no,
                    priority=2
                )
                self.active_blocks.add(port_key)
                self.policy_queue.put(action)
                self.logger.error(f"{RED}BLOCKING port {port_no} on switch {switch_id:016x} (Controller Detection){RESET}")
        
        # Check if we should unblock any ports
        self._check_unblock_conditions()
    
    def _add_controller_policy(self, switch_id, port_no, threat_event):
        """Add a policy rule based on controller detection"""
        policy_id = f"controller_dos_{switch_id}_{port_no}_{int(time.time())}"
        target_value = f"{switch_id}:{port_no}"
        
        policy = PolicyRule(
            id=policy_id,
            source=PolicySource.CONTROLLER,
            action=PolicyAction.BLOCK,
            target_type="switch_port",
            target_value=target_value,
            priority=60,  # Medium priority for controller decisions
            reason=f"DoS attack detected: {threat_event.threat_type}",
            metadata={
                "threat_type": threat_event.threat_type,
                "severity": threat_event.severity,
                "detection_time": time.time(),
                "controller_generated": True
            }
        )
        
        self.policy_store.add_policy(policy)
        self.logger.info(f"{BLUE}Added controller policy: {policy_id}{RESET}")
    
    def _enforce_external_block(self, switch_id, port_no):
        """Enforce an external blocking policy"""
        port_key = (switch_id, port_no)
        if port_key not in self.active_blocks:
            action = MitigationAction(
                action_type="BLOCK",
                switch_id=switch_id,
                port_no=port_no,
                priority=3  # Higher priority for external policies
            )
            self.active_blocks.add(port_key)
            self.policy_queue.put(action)
            self.logger.warning(f"{YELLOW}ENFORCING external block on port {port_no} switch {switch_id:016x}{RESET}")
    
    def _check_external_policies(self):
        """Check for external policies that need enforcement"""
        # Get all blocking policies for switch ports
        all_policies = self.policy_store.get_all_policies()
        
        for policy in all_policies:
            if (policy.target_type == "switch_port" and 
                policy.action == PolicyAction.BLOCK and
                policy.source != PolicySource.CONTROLLER):
                
                # Parse switch_id:port_no
                try:
                    switch_id, port_no = policy.target_value.split(":")
                    switch_id = int(switch_id)
                    port_no = int(port_no)
                    self._enforce_external_block(switch_id, port_no)
                except ValueError:
                    self.logger.error(f"Invalid switch_port format: {policy.target_value}")
    
    def _on_external_policy_change(self, action, policy):
        """Handle external policy changes"""
        if policy.target_type == "switch_port":
            try:
                switch_id, port_no = policy.target_value.split(":")
                switch_id = int(switch_id)
                port_no = int(port_no)
                
                if action == "add" and policy.action == PolicyAction.BLOCK:
                    self.logger.warning(f"{YELLOW}External policy added: BLOCK {switch_id}:{port_no} "
                                      f"(source: {policy.source.value}, priority: {policy.priority}){RESET}")
                    self._enforce_external_block(switch_id, port_no)
                    
                elif action == "remove":
                    self.logger.info(f"{GREEN}External policy removed: {policy.id}{RESET}")
                    # Check if we should unblock
                    self._check_port_unblock(switch_id, port_no)
                    
            except ValueError:
                self.logger.error(f"Invalid switch_port format in external policy: {policy.target_value}")
    
    def _check_port_unblock(self, switch_id, port_no):
        """Check if a port should be unblocked based on current policies"""
        target_value = f"{switch_id}:{port_no}"
        effective_action = self.policy_store.get_effective_action("switch_port", target_value)
        
        port_key = (switch_id, port_no)
        if effective_action != PolicyAction.BLOCK and port_key in self.active_blocks:
            # No blocking policy exists, unblock the port
            action = MitigationAction(
                action_type="UNBLOCK",
                switch_id=switch_id,
                port_no=port_no,
                priority=2
            )
            self.active_blocks.remove(port_key)
            self.policy_queue.put(action)
            self.logger.info(f"{GREEN}UNBLOCKING port {port_no} on switch {switch_id:016x} (No blocking policy){RESET}")
    
    def _check_unblock_conditions(self):
        """Check if any blocked ports should be unblocked"""
        # Check all currently blocked ports
        for switch_id, port_no in list(self.active_blocks):
            self._check_port_unblock(switch_id, port_no)
    
    def request_unblock(self, switch_id, port_no):
        """Request to unblock a specific port (removes controller policies)"""
        target_value = f"{switch_id}:{port_no}"
        
        # Remove controller-generated policies for this port
        policies_to_remove = []
        for policy in self.policy_store.get_policies_for_target("switch_port", target_value):
            if policy.source == PolicySource.CONTROLLER:
                policies_to_remove.append(policy.id)
        
        for policy_id in policies_to_remove:
            self.policy_store.remove_policy(policy_id)
            self.logger.info(f"{GREEN}Removed controller policy: {policy_id}{RESET}")
        
        # Check if port should be unblocked
        self._check_port_unblock(switch_id, port_no)
    
    def get_admin_interface(self) -> AdminInterface:
        """Get the admin interface for manual policy management"""
        return self.admin_interface
    
    def get_external_connector(self) -> ExternalPolicyConnector:
        """Get the external connector for integration with other systems"""
        return self.external_connector
    
    def get_policy_status(self):
        """Get current policy status for debugging"""
        all_policies = self.policy_store.get_all_policies()
        return {
            "active_blocks": list(self.active_blocks),
            "total_policies": len(all_policies),
            "policy_sources": {source.value: len([p for p in all_policies if p.source == source]) 
                             for source in PolicySource},
            "api_port": self.policy_api.port if self.policy_api else None
        }


class MitigationEnforcer:
    """
    Responsible for implementing mitigation actions on the network
    """
    def __init__(self, logger, datapaths_dict):
        self.logger = logger
        self.datapaths = datapaths_dict
        self.running = False
        self.enforcer_thread = None
        
    def start(self, policy_queue):
        """Start the enforcement thread"""
        self.running = True
        self.policy_queue = policy_queue
        self.enforcer_thread = hub.spawn(self._enforcement_loop)
        
    def stop(self):
        """Stop the enforcement thread"""
        self.running = False
        if self.enforcer_thread:
            self.enforcer_thread.kill()
    
    def _enforcement_loop(self):
        """Main enforcement loop"""
        while self.running:
            try:
                action = self.policy_queue.get(timeout=1)
                self._execute_action(action)
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in enforcement loop: {e}")
    
    def _execute_action(self, action):
        """Execute a mitigation action"""
        if action.switch_id not in self.datapaths:
            self.logger.error(f"Switch {action.switch_id:016x} not found")
            return
        
        datapath = self.datapaths[action.switch_id]
        
        if action.action_type == "BLOCK":
            self._block_port(datapath, action.port_no, action.priority)
        elif action.action_type == "UNBLOCK":
            self._unblock_port(datapath, action.port_no, action.priority)
        elif action.action_type == "RATE_LIMIT":
            self._rate_limit_port(datapath, action.port_no, action.priority)
    
    def _block_port(self, datapath, port_no, priority):
        """Block traffic from a specific port"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(in_port=port_no)
        instructions = []  # Empty instructions = drop
        
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            command=ofproto.OFPFC_ADD,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )
        
        datapath.send_msg(flow_mod)
        self.logger.info(f"{RED}Blocked traffic on port {port_no} of switch {datapath.id:016x}{RESET}")
    
    def _unblock_port(self, datapath, port_no, priority):
        """Unblock traffic from a specific port"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(in_port=port_no)
        
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )
        
        datapath.send_msg(flow_mod)
        self.logger.info(f"{GREEN}Unblocked traffic on port {port_no} of switch {datapath.id:016x}{RESET}")
    
    def _rate_limit_port(self, datapath, port_no, priority):
        """Apply rate limiting to a specific port (placeholder)"""
        # This would require more complex OpenFlow rules or QoS configuration
        self.logger.info(f"{YELLOW}Rate limiting applied to port {port_no} of switch {datapath.id:016x}{RESET}")


class ModularSDNController(app_manager.RyuApp):
    """
    Main controller class that orchestrates all modules
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(ModularSDNController, self).__init__(*args, **kwargs)
        
        # Initialize modules
        self.monitor = NetworkMonitor(self.logger)
        self.detector = ThreatDetector(self.logger)
        self.policy = MitigationPolicy(self.logger)
        
        # Initialize enhanced mitigation enforcer (addresses over-blocking flaw)
        self.enforcer = EnhancedMitigationEnforcer(self.logger, self.monitor.datapaths)
        
        # Initialize adaptive blocking system integration
        self.adaptive_blocking = AdaptiveBlockingIntegration(self, self.enforcer)
        
        # Initialize legacy enforcer for backward compatibility
        self.legacy_enforcer = MitigationEnforcer(self.logger, self.monitor.datapaths)
        
        # For basic switching functionality
        self.mac_to_port = {}
        
        # Start modules
        self.monitor.start()
        self.detector.start(self.monitor.stats_queue)
        self.policy.start(self.detector.threat_queue)
        self.enforcer.start(self.policy.policy_queue)
        
        self.logger.info(f"{GREEN}Modular SDN Controller with Adaptive Blocking started successfully{RESET}")
    
    def close(self):
        """Clean shutdown of all modules"""
        self.monitor.stop()
        self.detector.stop()
        self.policy.stop()
        self.enforcer.stop()
        self.logger.info(f"{YELLOW}Modular SDN Controller stopped{RESET}")
    
    # OpenFlow event handlers
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Handle switch connection/disconnection"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.monitor.register_datapath(datapath)
        elif ev.state == DEAD_DISPATCHER:
            self.monitor.unregister_datapath(datapath.id)
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """Handle port statistics replies"""
        self.monitor.process_stats_reply(ev)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch features"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Add a flow entry to the switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle packet-in events with enhanced flow analysis"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        # Enhanced flow analysis for DoS detection
        recommended_action = self.enforcer.analyze_packet_in(msg.data, in_port, datapath.id)
        
        if recommended_action == "block":
            self.logger.warning(f"🚫 Blocking malicious packet from port {in_port}")
            return  # Drop the packet
        elif recommended_action == "rate_limit":
            self.logger.warning(f"⚠️  Rate limiting suspicious packet from port {in_port}")
            # Continue with normal processing but mark for rate limiting
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        self.mac_to_port.setdefault(dpid, {})
        
        # Learn MAC address
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def manual_unblock(self, switch_id, port_no):
        """Manually unblock a port (for testing/debugging)"""
        self.policy.request_unblock(switch_id, port_no)
    
    def add_to_whitelist(self, address: str):
        """Add address to whitelist (prevents blocking)"""
        self.enforcer.add_to_whitelist(address)
        self.logger.info(f"Added {address} to whitelist")
    
    def add_to_blacklist(self, address: str):
        """Add address to blacklist (immediate blocking)"""
        self.enforcer.add_to_blacklist(address)
        self.logger.info(f"Added {address} to blacklist")
    
    def get_flow_statistics(self):
        """Get current flow statistics"""
        return self.enforcer.get_flow_statistics()
    
    def get_detailed_flow_info(self):
        """Get detailed flow information"""
        return self.enforcer.get_detailed_flow_info()
    
    # Adaptive Blocking System Methods
    def get_adaptive_blocking_stats(self):
        """Get adaptive blocking system statistics"""
        return self.adaptive_blocking.get_adaptive_stats()
    
    def force_adaptive_unblock(self, ip_address: str):
        """Force unblock an IP using adaptive system (admin override)"""
        result = self.adaptive_blocking.force_unblock(ip_address)
        if result:
            self.logger.info(f"🔓 Admin override: Force unblocked {ip_address}")
        else:
            self.logger.warning(f"⚠️  Failed to force unblock {ip_address} - not found")
        return result
    
    def get_ip_blocking_status(self, ip_address: str):
        """Get current blocking status for specific IP"""
        return self.adaptive_blocking.get_ip_status(ip_address)
    
    def update_network_conditions(self, conditions: dict):
        """Update network conditions for adaptive threshold adjustment"""
        self.adaptive_blocking.adaptive_blocking.update_network_conditions(conditions)
        self.logger.info(f"📊 Updated network conditions: {conditions}")
    
    def get_reputation_score(self, ip_address: str):
        """Get reputation score for an IP address"""
        return self.adaptive_blocking.adaptive_blocking.reputation_system.get_reputation(ip_address)
    
    def update_ip_reputation(self, ip_address: str, is_malicious: bool, is_false_positive: bool = False):
        """Update reputation for an IP address"""
        self.adaptive_blocking.adaptive_blocking.reputation_system.update_reputation(
            ip_address, is_malicious, is_false_positive
        )
        action = "malicious" if is_malicious else "legitimate"
        if is_false_positive:
            action += " (false positive)"
        self.logger.info(f"📈 Updated reputation for {ip_address}: {action}")
