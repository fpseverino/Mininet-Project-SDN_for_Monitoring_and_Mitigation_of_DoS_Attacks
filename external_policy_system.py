"""
External Policy Interface for Modular SDN Controller

This module provides a shared data structure and interfaces for external
applications and administrators to contribute to blocking policies.

Features:
1. Shared blocklist management
2. External policy API
3. Administrative interface
4. Policy priority and conflict resolution
5. Real-time policy updates
"""

import json
import threading
import time
import socket
import sqlite3
import os
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Callable


class PolicySource(Enum):
    """Source of a policy decision"""
    CONTROLLER = "controller"      # Internal controller detection
    ADMIN = "admin"               # Administrator manual decision
    EXTERNAL_APP = "external_app" # External application
    HONEYPOT = "honeypot"         # Honeypot detection
    IDS = "ids"                   # Intrusion Detection System
    THREAT_INTEL = "threat_intel" # Threat intelligence feed


class PolicyAction(Enum):
    """Action to take for a policy"""
    BLOCK = "block"
    ALLOW = "allow"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    MONITOR = "monitor"


@dataclass
class PolicyRule:
    """Represents a policy rule"""
    id: str
    source: PolicySource
    action: PolicyAction
    target_type: str  # "ip", "port", "switch_port", "mac"
    target_value: str
    priority: int  # Higher number = higher priority
    expiry: Optional[datetime] = None
    reason: str = ""
    metadata: Dict = None
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.metadata is None:
            self.metadata = {}
    
    def is_expired(self) -> bool:
        """Check if the policy rule has expired"""
        if self.expiry is None:
            return False
        return datetime.now() > self.expiry
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['source'] = self.source.value
        data['action'] = self.action.value
        if self.expiry:
            data['expiry'] = self.expiry.isoformat()
        if self.created_at:
            data['created_at'] = self.created_at.isoformat()
        return data


class SharedPolicyStore:
    """
    Thread-safe shared data structure for policy rules
    Supports multiple readers/writers and persistence
    """
    
    def __init__(self, db_path: str = "policy_store.db"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._policies: Dict[str, PolicyRule] = {}
        self._listeners: List[Callable] = []
        self._init_database()
        self._load_policies()
        
        # Start cleanup thread for expired policies
        self._cleanup_thread = threading.Thread(target=self._cleanup_expired, daemon=True)
        self._cleanup_thread.start()
    
    def _init_database(self):
        """Initialize SQLite database for persistence"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    expiry TEXT,
                    reason TEXT,
                    metadata TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target 
                ON policies(target_type, target_value)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_priority 
                ON policies(priority DESC)
            """)
    
    def _load_policies(self):
        """Load policies from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM policies")
            for row in cursor.fetchall():
                try:
                    policy = PolicyRule(
                        id=row[0],
                        source=PolicySource(row[1]),
                        action=PolicyAction(row[2]),
                        target_type=row[3],
                        target_value=row[4],
                        priority=row[5],
                        expiry=datetime.fromisoformat(row[6]) if row[6] else None,
                        reason=row[7] or "",
                        metadata=json.loads(row[8]) if row[8] else {},
                        created_at=datetime.fromisoformat(row[9])
                    )
                    if not policy.is_expired():
                        self._policies[policy.id] = policy
                except Exception as e:
                    print(f"Error loading policy {row[0]}: {e}")
    
    def _save_policy(self, policy: PolicyRule):
        """Save policy to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO policies 
                (id, source, action, target_type, target_value, priority, 
                 expiry, reason, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                policy.id,
                policy.source.value,
                policy.action.value,
                policy.target_type,
                policy.target_value,
                policy.priority,
                policy.expiry.isoformat() if policy.expiry else None,
                policy.reason,
                json.dumps(policy.metadata),
                policy.created_at.isoformat()
            ))
    
    def _delete_policy_from_db(self, policy_id: str):
        """Delete policy from database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
    
    def add_policy(self, policy: PolicyRule) -> bool:
        """Add a new policy rule"""
        with self._lock:
            if policy.is_expired():
                return False
            
            self._policies[policy.id] = policy
            self._save_policy(policy)
            self._notify_listeners('add', policy)
            return True
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy rule"""
        with self._lock:
            if policy_id in self._policies:
                policy = self._policies.pop(policy_id)
                self._delete_policy_from_db(policy_id)
                self._notify_listeners('remove', policy)
                return True
            return False
    
    def get_policy(self, policy_id: str) -> Optional[PolicyRule]:
        """Get a specific policy"""
        with self._lock:
            return self._policies.get(policy_id)
    
    def get_policies_for_target(self, target_type: str, target_value: str) -> List[PolicyRule]:
        """Get all policies for a specific target, sorted by priority"""
        with self._lock:
            policies = [
                p for p in self._policies.values()
                if p.target_type == target_type and p.target_value == target_value
                and not p.is_expired()
            ]
            return sorted(policies, key=lambda p: p.priority, reverse=True)
    
    def get_all_policies(self) -> List[PolicyRule]:
        """Get all active policies"""
        with self._lock:
            return [p for p in self._policies.values() if not p.is_expired()]
    
    def get_effective_action(self, target_type: str, target_value: str) -> Optional[PolicyAction]:
        """Get the effective action for a target (highest priority wins)"""
        policies = self.get_policies_for_target(target_type, target_value)
        if policies:
            return policies[0].action
        return None
    
    def add_listener(self, callback: Callable):
        """Add a listener for policy changes"""
        with self._lock:
            self._listeners.append(callback)
    
    def remove_listener(self, callback: Callable):
        """Remove a policy change listener"""
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)
    
    def _notify_listeners(self, action: str, policy: PolicyRule):
        """Notify all listeners of policy changes"""
        for listener in self._listeners:
            try:
                listener(action, policy)
            except Exception as e:
                print(f"Error notifying listener: {e}")
    
    def _cleanup_expired(self):
        """Cleanup thread to remove expired policies"""
        while True:
            try:
                time.sleep(60)  # Check every minute
                with self._lock:
                    expired_ids = [
                        policy_id for policy_id, policy in self._policies.items()
                        if policy.is_expired()
                    ]
                    for policy_id in expired_ids:
                        self.remove_policy(policy_id)
            except Exception as e:
                print(f"Error in cleanup thread: {e}")


class PolicyAPI:
    """
    RESTful API interface for external applications
    """
    
    def __init__(self, policy_store: SharedPolicyStore, host: str = "127.0.0.1", port: int = 8080):
        self.policy_store = policy_store
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.server_thread = None
    
    def start(self):
        """Start the API server"""
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()
        print(f"Policy API server started on {self.host}:{self.port}")
    
    def stop(self):
        """Stop the API server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
    
    def _run_server(self):
        """Run the HTTP server (simplified implementation)"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    threading.Thread(
                        target=self._handle_request, 
                        args=(client_socket,), 
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
        except Exception as e:
            print(f"Error starting server: {e}")
    
    def _handle_request(self, client_socket):
        """Handle HTTP request (simplified)"""
        try:
            request = client_socket.recv(4096).decode('utf-8')
            lines = request.split('\n')
            if not lines:
                return
            
            method, path, _ = lines[0].split()
            
            if method == "GET" and path == "/policies":
                self._handle_get_policies(client_socket)
            elif method == "POST" and path == "/policies":
                self._handle_add_policy(client_socket, request)
            elif method == "DELETE" and path.startswith("/policies/"):
                policy_id = path.split("/")[-1]
                self._handle_delete_policy(client_socket, policy_id)
            else:
                self._send_response(client_socket, 404, {"error": "Not found"})
        
        except Exception as e:
            self._send_response(client_socket, 500, {"error": str(e)})
        finally:
            client_socket.close()
    
    def _handle_get_policies(self, client_socket):
        """Handle GET /policies"""
        policies = [p.to_dict() for p in self.policy_store.get_all_policies()]
        self._send_response(client_socket, 200, {"policies": policies})
    
    def _handle_add_policy(self, client_socket, request):
        """Handle POST /policies"""
        try:
            # Extract JSON body (simplified)
            body_start = request.find('\r\n\r\n')
            if body_start == -1:
                self._send_response(client_socket, 400, {"error": "No body"})
                return
            
            body = request[body_start + 4:]
            data = json.loads(body)
            
            policy = PolicyRule(
                id=data.get('id', f"ext_{int(time.time())}"),
                source=PolicySource(data.get('source', 'external_app')),
                action=PolicyAction(data['action']),
                target_type=data['target_type'],
                target_value=data['target_value'],
                priority=data.get('priority', 50),
                expiry=datetime.fromisoformat(data['expiry']) if data.get('expiry') else None,
                reason=data.get('reason', ''),
                metadata=data.get('metadata', {})
            )
            
            if self.policy_store.add_policy(policy):
                self._send_response(client_socket, 201, {"status": "created", "id": policy.id})
            else:
                self._send_response(client_socket, 400, {"error": "Failed to add policy"})
        
        except Exception as e:
            self._send_response(client_socket, 400, {"error": str(e)})
    
    def _handle_delete_policy(self, client_socket, policy_id):
        """Handle DELETE /policies/{id}"""
        if self.policy_store.remove_policy(policy_id):
            self._send_response(client_socket, 200, {"status": "deleted"})
        else:
            self._send_response(client_socket, 404, {"error": "Policy not found"})
    
    def _send_response(self, client_socket, status_code, data):
        """Send HTTP response"""
        status_text = {200: "OK", 201: "Created", 400: "Bad Request", 
                      404: "Not Found", 500: "Internal Server Error"}
        
        response_body = json.dumps(data)
        response = f"""HTTP/1.1 {status_code} {status_text.get(status_code, 'Unknown')}
Content-Type: application/json
Content-Length: {len(response_body)}
Access-Control-Allow-Origin: *

{response_body}"""
        
        client_socket.send(response.encode('utf-8'))


class AdminInterface:
    """
    Command-line interface for administrators
    """
    
    def __init__(self, policy_store: SharedPolicyStore):
        self.policy_store = policy_store
    
    def add_block_rule(self, target_type: str, target_value: str, 
                      reason: str = "", duration_hours: int = None) -> str:
        """Add a blocking rule"""
        policy_id = f"admin_block_{int(time.time())}"
        expiry = None
        if duration_hours:
            expiry = datetime.now() + timedelta(hours=duration_hours)
        
        policy = PolicyRule(
            id=policy_id,
            source=PolicySource.ADMIN,
            action=PolicyAction.BLOCK,
            target_type=target_type,
            target_value=target_value,
            priority=90,  # High priority for admin rules
            expiry=expiry,
            reason=reason,
            metadata={"admin_action": True}
        )
        
        if self.policy_store.add_policy(policy):
            return policy_id
        return None
    
    def remove_rule(self, policy_id: str) -> bool:
        """Remove a policy rule"""
        return self.policy_store.remove_policy(policy_id)
    
    def list_rules(self) -> List[PolicyRule]:
        """List all active rules"""
        return self.policy_store.get_all_policies()
    
    def emergency_block_ip(self, ip_address: str, reason: str = "Emergency block") -> str:
        """Emergency block an IP address"""
        return self.add_block_rule("ip", ip_address, reason, duration_hours=1)
    
    def emergency_block_port(self, switch_id: str, port_no: str, 
                           reason: str = "Emergency block") -> str:
        """Emergency block a switch port"""
        target_value = f"{switch_id}:{port_no}"
        return self.add_block_rule("switch_port", target_value, reason, duration_hours=1)


class ExternalPolicyConnector:
    """
    Connector for external security applications
    """
    
    def __init__(self, policy_store: SharedPolicyStore):
        self.policy_store = policy_store
    
    def add_threat_intel_block(self, ip_address: str, threat_type: str, 
                              confidence: float, source: str = "threat_intel") -> str:
        """Add a block based on threat intelligence"""
        policy_id = f"intel_{threat_type}_{int(time.time())}"
        priority = int(confidence * 100)  # Convert confidence to priority
        
        policy = PolicyRule(
            id=policy_id,
            source=PolicySource.THREAT_INTEL,
            action=PolicyAction.BLOCK,
            target_type="ip",
            target_value=ip_address,
            priority=priority,
            expiry=datetime.now() + timedelta(hours=24),  # 24-hour default
            reason=f"Threat intelligence: {threat_type}",
            metadata={
                "threat_type": threat_type,
                "confidence": confidence,
                "intel_source": source
            }
        )
        
        if self.policy_store.add_policy(policy):
            return policy_id
        return None
    
    def add_ids_detection(self, target_type: str, target_value: str, 
                         attack_type: str, severity: str) -> str:
        """Add a policy based on IDS detection"""
        policy_id = f"ids_{attack_type}_{int(time.time())}"
        
        # Map severity to priority
        priority_map = {"low": 30, "medium": 60, "high": 80, "critical": 95}
        priority = priority_map.get(severity.lower(), 50)
        
        # Map severity to action
        action = PolicyAction.MONITOR if severity.lower() == "low" else PolicyAction.BLOCK
        
        policy = PolicyRule(
            id=policy_id,
            source=PolicySource.IDS,
            action=action,
            target_type=target_type,
            target_value=target_value,
            priority=priority,
            expiry=datetime.now() + timedelta(hours=2),
            reason=f"IDS detection: {attack_type} ({severity})",
            metadata={
                "attack_type": attack_type,
                "severity": severity,
                "detection_time": datetime.now().isoformat()
            }
        )
        
        if self.policy_store.add_policy(policy):
            return policy_id
        return None


# Example usage functions
def create_sample_policies(policy_store: SharedPolicyStore):
    """Create some sample policies for testing"""
    
    # Admin emergency block
    admin = AdminInterface(policy_store)
    admin.emergency_block_ip("192.168.1.100", "Suspicious activity detected")
    
    # Threat intelligence feed
    connector = ExternalPolicyConnector(policy_store)
    connector.add_threat_intel_block("10.0.0.50", "botnet", 0.95, "ThreatFeed-X")
    connector.add_ids_detection("ip", "10.0.0.25", "port_scan", "high")
    
    # Manual policy
    manual_policy = PolicyRule(
        id="manual_test_001",
        source=PolicySource.ADMIN,
        action=PolicyAction.RATE_LIMIT,
        target_type="ip",
        target_value="10.0.0.99",
        priority=70,
        reason="Testing rate limiting",
        metadata={"rate_limit_mbps": 10}
    )
    policy_store.add_policy(manual_policy)


if __name__ == "__main__":
    # Test the policy system
    print("Testing Shared Policy System...")
    
    # Create policy store
    store = SharedPolicyStore("test_policies.db")
    
    # Create sample policies
    create_sample_policies(store)
    
    # Test API
    api = PolicyAPI(store, port=8081)
    api.start()
    
    # Display current policies
    print("\nActive Policies:")
    for policy in store.get_all_policies():
        print(f"  {policy.id}: {policy.action.value} {policy.target_type}={policy.target_value} "
              f"(priority={policy.priority}, source={policy.source.value})")
    
    # Test conflict resolution
    print(f"\nEffective action for IP 10.0.0.50: {store.get_effective_action('ip', '10.0.0.50')}")
    
    print("\nPolicy API running on http://127.0.0.1:8081")
    print("Test with: curl http://127.0.0.1:8081/policies")
    
    try:
        # Keep running for testing
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        api.stop()
