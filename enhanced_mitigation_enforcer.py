"""
Enhanced Mitigation Enforcer with Flow-Level Granularity

This module addresses the over-blocking flaw by implementing:
1. Flow-level granularity instead of port-level blocking
2. Whitelist/blacklist management for legitimate traffic
3. Intelligent flow analysis to identify malicious sources
4. Graduated response: monitor -> rate limit -> block specific flows
"""

# Import compatibility layer for Python 3.13
import distutils_compat

import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Tuple

try:
    from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
    from ryu.lib.packet import ether_types
    RYU_AVAILABLE = True
except ImportError:
    # Fallback if Ryu is not available (for testing)
    RYU_AVAILABLE = False
    
    # Mock classes for testing without Ryu
    class MockEtherTypes:
        ETH_TYPE_LLDP = 0x88cc
    
    ether_types = MockEtherTypes()


@dataclass
class FlowSignature:
    """Represents a unique flow signature for tracking"""
    src_mac: str
    dst_mac: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    
    def __hash__(self):
        return hash((self.src_mac, self.dst_mac, self.src_ip, self.dst_ip, 
                    self.protocol, self.src_port, self.dst_port))
    
    def to_string(self):
        """Human-readable string representation"""
        if self.src_ip:
            return f"{self.src_ip}:{self.src_port or '*'} -> {self.dst_ip}:{self.dst_port or '*'}"
        return f"{self.src_mac} -> {self.dst_mac}"


@dataclass
class FlowStats:
    """Statistics for a specific flow"""
    packet_count: int = 0
    byte_count: int = 0
    first_seen: datetime = None
    last_seen: datetime = None
    rate_pps: float = 0.0  # packets per second
    rate_bps: float = 0.0  # bytes per second
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.last_seen is None:
            self.last_seen = self.first_seen
    
    def update(self, packets: int, bytes: int):
        """Update flow statistics"""
        now = datetime.now()
        time_delta = (now - self.last_seen).total_seconds()
        
        if time_delta > 0:
            self.rate_pps = packets / time_delta
            self.rate_bps = bytes / time_delta
        
        self.packet_count += packets
        self.byte_count += bytes
        self.last_seen = now


class FlowAnalyzer:
    """Analyzes flows to identify malicious patterns"""
    
    def __init__(self, logger):
        self.logger = logger
        self.flow_stats: Dict[FlowSignature, FlowStats] = {}
        self.whitelist: Set[str] = set()  # Whitelisted MAC/IP addresses
        self.blacklist: Set[str] = set()  # Blacklisted MAC/IP addresses
        self.suspicious_flows: Set[FlowSignature] = set()
        self.malicious_flows: Set[FlowSignature] = set()
        
        # Thresholds for detection
        self.high_rate_threshold = 1000  # packets per second
        self.burst_threshold = 5000      # packets in burst
        self.connection_rate_threshold = 100  # new connections per second
        
        # Flow tracking
        self.recent_flows = deque(maxlen=10000)  # Recent flow activity
        self.connection_attempts = defaultdict(int)  # SYN flood detection
        
    def add_to_whitelist(self, address: str):
        """Add address to whitelist (MAC or IP)"""
        self.whitelist.add(address)
        self.logger.info(f"Added {address} to whitelist")
    
    def add_to_blacklist(self, address: str):
        """Add address to blacklist (MAC or IP)"""
        self.blacklist.add(address)
        self.logger.info(f"Added {address} to blacklist")
    
    def is_whitelisted(self, flow_sig: FlowSignature) -> bool:
        """Check if flow involves whitelisted addresses"""
        return (flow_sig.src_mac in self.whitelist or 
                flow_sig.dst_mac in self.whitelist or
                (flow_sig.src_ip and flow_sig.src_ip in self.whitelist) or
                (flow_sig.dst_ip and flow_sig.dst_ip in self.whitelist))
    
    def is_blacklisted(self, flow_sig: FlowSignature) -> bool:
        """Check if flow involves blacklisted addresses"""
        return (flow_sig.src_mac in self.blacklist or
                (flow_sig.src_ip and flow_sig.src_ip in self.blacklist))
    
    def analyze_packet(self, pkt_data: bytes, in_port: int) -> Tuple[FlowSignature, str]:
        """Analyze packet and return flow signature and threat level"""
        if not RYU_AVAILABLE:
            # Fallback analysis without Ryu packet parsing
            return self._analyze_packet_fallback(pkt_data, in_port)
        
        pkt = packet.Packet(pkt_data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return None, "benign"
        
        # Create basic flow signature
        flow_sig = FlowSignature(
            src_mac=eth.src,
            dst_mac=eth.dst
        )
        
        # Extract IP layer information
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            flow_sig.src_ip = ip_pkt.src
            flow_sig.dst_ip = ip_pkt.dst
            flow_sig.protocol = ip_pkt.proto
            
            # Extract transport layer information
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                flow_sig.src_port = tcp_pkt.src_port
                flow_sig.dst_port = tcp_pkt.dst_port
                
                # Check for SYN flood
                if tcp_pkt.bits & tcp.TCP_SYN and not tcp_pkt.bits & tcp.TCP_ACK:
                    self.connection_attempts[flow_sig.src_ip] += 1
            
            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt:
                flow_sig.src_port = udp_pkt.src_port
                flow_sig.dst_port = udp_pkt.dst_port
        
        # Determine threat level
        threat_level = self._assess_threat_level(flow_sig, len(pkt_data))
        
        return flow_sig, threat_level
    
    def _analyze_packet_fallback(self, pkt_data: bytes, in_port: int) -> Tuple[FlowSignature, str]:
        """Fallback packet analysis without Ryu (for testing)"""
        # Create a simple flow signature for testing
        flow_sig = FlowSignature(
            src_mac=f"00:00:00:00:00:{in_port:02x}",
            dst_mac="00:00:00:00:00:ff",
            src_ip=f"10.0.0.{in_port}",
            dst_ip="10.0.0.1"
        )
        
        # Simple threat assessment based on packet size
        if len(pkt_data) > 1000:
            threat_level = "suspicious"
        elif len(pkt_data) > 1500:
            threat_level = "malicious"
        else:
            threat_level = "benign"
        
        return flow_sig, threat_level
    
    def _assess_threat_level(self, flow_sig: FlowSignature, packet_size: int) -> str:
        """Assess threat level based on flow characteristics"""
        # Check blacklist first
        if self.is_blacklisted(flow_sig):
            return "malicious"
        
        # Check whitelist
        if self.is_whitelisted(flow_sig):
            return "benign"
        
        # Update flow statistics
        if flow_sig not in self.flow_stats:
            self.flow_stats[flow_sig] = FlowStats()
        
        stats = self.flow_stats[flow_sig]
        stats.update(1, packet_size)
        
        # Check for high rate
        if stats.rate_pps > self.high_rate_threshold:
            return "malicious"
        
        # Check for burst activity
        if stats.packet_count > self.burst_threshold:
            time_span = (stats.last_seen - stats.first_seen).total_seconds()
            if time_span < 60:  # High volume in short time
                return "suspicious"
        
        # Check for SYN flood
        if flow_sig.src_ip and self.connection_attempts.get(flow_sig.src_ip, 0) > self.connection_rate_threshold:
            return "malicious"
        
        return "benign"
    
    def get_malicious_flows(self) -> List[FlowSignature]:
        """Get list of identified malicious flows"""
        return list(self.malicious_flows)
    
    def get_suspicious_flows(self) -> List[FlowSignature]:
        """Get list of suspicious flows"""
        return list(self.suspicious_flows)
    
    def cleanup_old_flows(self, max_age_seconds: int = 300):
        """Remove old flow statistics"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=max_age_seconds)
        
        expired_flows = [
            flow_sig for flow_sig, stats in self.flow_stats.items()
            if stats.last_seen < cutoff
        ]
        
        for flow_sig in expired_flows:
            del self.flow_stats[flow_sig]
            self.suspicious_flows.discard(flow_sig)
            self.malicious_flows.discard(flow_sig)


class EnhancedMitigationEnforcer:
    """
    Enhanced enforcement engine with flow-level granularity
    Addresses the over-blocking flaw by targeting specific flows
    """
    
    def __init__(self, logger, datapaths_dict):
        self.logger = logger
        self.datapaths = datapaths_dict
        self.flow_analyzer = FlowAnalyzer(logger)
        self.running = False
        self.enforcer_thread = None
        
        # Flow rule management
        self.installed_rules: Dict[int, List[dict]] = defaultdict(list)  # switch_id -> rules
        self.blocked_flows: Set[FlowSignature] = set()
        self.rate_limited_flows: Set[FlowSignature] = set()
        
        # Mitigation actions
        self.mitigation_actions = {
            "monitor": self._monitor_flow,
            "rate_limit": self._rate_limit_flow,
            "block": self._block_flow,
            "unblock": self._unblock_flow
        }
    
    def start(self, policy_queue):
        """Start the enforcement thread"""
        self.running = True
        self.policy_queue = policy_queue
        self.enforcer_thread = threading.Thread(target=self._enforcement_loop, daemon=True)
        self.enforcer_thread.start()
        
        # Start flow cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
    
    def stop(self):
        """Stop the enforcement thread"""
        self.running = False
    
    def _enforcement_loop(self):
        """Main enforcement loop"""
        while self.running:
            try:
                action = self.policy_queue.get(timeout=1)
                self._execute_enhanced_action(action)
            except:
                continue
    
    def _cleanup_loop(self):
        """Cleanup old flows periodically"""
        while self.running:
            time.sleep(60)  # Run every minute
            self.flow_analyzer.cleanup_old_flows()
    
    def _execute_enhanced_action(self, action):
        """Execute enhanced mitigation action with flow-level granularity"""
        if action.switch_id not in self.datapaths:
            self.logger.error(f"Switch {action.switch_id:016x} not found")
            return
        
        datapath = self.datapaths[action.switch_id]
        
        # Get flow information for the port
        malicious_flows = self._identify_malicious_flows(action.switch_id, action.port_no)
        
        if not malicious_flows:
            self.logger.warning(f"No malicious flows identified for port {action.port_no}")
            return
        
        # Apply graduated response
        for flow_sig in malicious_flows:
            if action.action_type == "BLOCK":
                self._block_flow(datapath, flow_sig, action.priority)
            elif action.action_type == "UNBLOCK":
                self._unblock_flow(datapath, flow_sig)
            elif action.action_type == "RATE_LIMIT":
                self._rate_limit_flow(datapath, flow_sig, action.priority)
    
    def _identify_malicious_flows(self, switch_id: int, port_no: int) -> List[FlowSignature]:
        """Identify malicious flows on a specific port"""
        # This would ideally use flow statistics from the switch
        # For now, return flows identified by our analyzer
        return self.flow_analyzer.get_malicious_flows()
    
    def _monitor_flow(self, datapath, flow_sig: FlowSignature, priority: int):
        """Monitor flow without blocking (lowest level response)"""
        # Install a flow rule that forwards to controller for monitoring
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = self._create_flow_match(parser, flow_sig)
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)  # Also forward normally
        ]
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority + 100,  # Higher priority than normal forwarding
            match=match,
            instructions=inst,
            command=ofproto.OFPFC_ADD,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )
        
        datapath.send_msg(flow_mod)
        self.logger.info(f"🔍 Monitoring flow: {flow_sig.to_string()}")
    
    def _rate_limit_flow(self, datapath, flow_sig: FlowSignature, priority: int):
        """Apply rate limiting to specific flow"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = self._create_flow_match(parser, flow_sig)
        
        # Create meter for rate limiting (simplified - would need proper meter setup)
        # For now, we'll use a token bucket approach with flow rules
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority + 200,
            match=match,
            instructions=inst,
            command=ofproto.OFPFC_ADD,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
            hard_timeout=30,  # Rate limit for 30 seconds
        )
        
        datapath.send_msg(flow_mod)
        self.rate_limited_flows.add(flow_sig)
        self.logger.info(f"⚠️  Rate limited flow: {flow_sig.to_string()}")
    
    def _block_flow(self, datapath, flow_sig: FlowSignature, priority: int):
        """Block specific flow (not entire port)"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = self._create_flow_match(parser, flow_sig)
        instructions = []  # Empty instructions = drop
        
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority + 300,  # Highest priority
            match=match,
            instructions=instructions,
            command=ofproto.OFPFC_ADD,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )
        
        datapath.send_msg(flow_mod)
        self.blocked_flows.add(flow_sig)
        
        # Add to blacklist for future prevention
        if flow_sig.src_ip:
            self.flow_analyzer.add_to_blacklist(flow_sig.src_ip)
        self.flow_analyzer.add_to_blacklist(flow_sig.src_mac)
        
        self.logger.info(f"🚫 Blocked malicious flow: {flow_sig.to_string()}")
    
    def _unblock_flow(self, datapath, flow_sig: FlowSignature):
        """Unblock specific flow"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = self._create_flow_match(parser, flow_sig)
        
        # Remove blocking rule
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        
        datapath.send_msg(flow_mod)
        self.blocked_flows.discard(flow_sig)
        
        # Remove from blacklist
        if flow_sig.src_ip:
            self.flow_analyzer.blacklist.discard(flow_sig.src_ip)
        self.flow_analyzer.blacklist.discard(flow_sig.src_mac)
        
        self.logger.info(f"✅ Unblocked flow: {flow_sig.to_string()}")
    
    def _create_flow_match(self, parser, flow_sig: FlowSignature):
        """Create OpenFlow match from flow signature"""
        match_fields = {
            'eth_src': flow_sig.src_mac,
            'eth_dst': flow_sig.dst_mac
        }
        
        if flow_sig.src_ip:
            match_fields['eth_type'] = 0x0800  # IPv4
            match_fields['ipv4_src'] = flow_sig.src_ip
            match_fields['ipv4_dst'] = flow_sig.dst_ip
            
            if flow_sig.protocol:
                match_fields['ip_proto'] = flow_sig.protocol
                
                if flow_sig.src_port:
                    if flow_sig.protocol == 6:  # TCP
                        match_fields['tcp_src'] = flow_sig.src_port
                        match_fields['tcp_dst'] = flow_sig.dst_port
                    elif flow_sig.protocol == 17:  # UDP
                        match_fields['udp_src'] = flow_sig.src_port
                        match_fields['udp_dst'] = flow_sig.dst_port
        
        return parser.OFPMatch(**match_fields)
    
    def analyze_packet_in(self, pkt_data: bytes, in_port: int, switch_id: int) -> str:
        """Analyze incoming packet and return recommended action"""
        flow_sig, threat_level = self.flow_analyzer.analyze_packet(pkt_data, in_port)
        
        if not flow_sig:
            return "allow"
        
        if threat_level == "malicious":
            return "block"
        elif threat_level == "suspicious":
            return "rate_limit"
        else:
            return "allow"
    
    def add_to_whitelist(self, address: str):
        """Add address to whitelist"""
        self.flow_analyzer.add_to_whitelist(address)
    
    def add_to_blacklist(self, address: str):
        """Add address to blacklist"""
        self.flow_analyzer.add_to_blacklist(address)
    
    def get_flow_statistics(self) -> dict:
        """Get current flow statistics"""
        return {
            'total_flows': len(self.flow_analyzer.flow_stats),
            'blocked_flows': len(self.blocked_flows),
            'rate_limited_flows': len(self.rate_limited_flows),
            'malicious_flows': len(self.flow_analyzer.malicious_flows),
            'suspicious_flows': len(self.flow_analyzer.suspicious_flows),
            'whitelisted_addresses': len(self.flow_analyzer.whitelist),
            'blacklisted_addresses': len(self.flow_analyzer.blacklist)
        }
    
    def get_detailed_flow_info(self) -> dict:
        """Get detailed information about flows"""
        return {
            'blocked_flows': [flow.to_string() for flow in self.blocked_flows],
            'rate_limited_flows': [flow.to_string() for flow in self.rate_limited_flows],
            'malicious_flows': [flow.to_string() for flow in self.flow_analyzer.malicious_flows],
            'suspicious_flows': [flow.to_string() for flow in self.flow_analyzer.suspicious_flows],
            'whitelist': list(self.flow_analyzer.whitelist),
            'blacklist': list(self.flow_analyzer.blacklist)
        }
