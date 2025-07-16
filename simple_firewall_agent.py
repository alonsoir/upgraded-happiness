# simple_firewall_agent.py - Protobuf Integration
import json
import time
import threading
import queue
import zmq
import logging
import subprocess
import platform
import uuid
import os
import sys
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Add src to path for protobuf imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.protocols.protobuf import firewall_commands_pb2

    print("✅ Protobuf imports successful")
except ImportError as e:
    print(f"❌ Protobuf import failed: {e}")
    print("📁 Please ensure protobuf files are generated")
    sys.exit(1)

# Import our crypto/compression utils (when ready)
try:
    from crypto_utils import SecureEnvelope
    from compression_utils import CompressionEngine

    CRYPTO_AVAILABLE = True
except ImportError:
    print("⚠️ Crypto utils not available, running without encryption")
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class FirewallRule:
    """Data class for firewall rules"""
    rule_id: str
    command_id: str
    action: str
    target_ip: str
    target_port: Optional[int]
    duration_seconds: Optional[int]
    created_at: float
    expires_at: Optional[float]
    applied: bool
    rule_text: str


class FirewallManager:
    """Cross-platform firewall management"""

    def __init__(self, config: Dict):
        self.config = config
        self.platform = platform.system().lower()
        self.active_rules = {}
        self.rule_history = []

        # Platform-specific configuration
        self.firewall_type = self._detect_firewall_type()
        self.sudo_enabled = config.get("sudo_enabled", True)
        self.dry_run = config.get("dry_run", False)

        logger.info(f"Firewall Manager initialized - Platform: {self.platform}, Type: {self.firewall_type}")

    def _detect_firewall_type(self) -> str:
        """Detect the firewall type based on platform"""
        if self.platform == "linux":
            # Check for iptables
            try:
                result = subprocess.run(["which", "iptables"], capture_output=True, text=True)
                if result.returncode == 0:
                    return "iptables"
            except:
                pass

            # Check for ufw
            try:
                result = subprocess.run(["which", "ufw"], capture_output=True, text=True)
                if result.returncode == 0:
                    return "ufw"
            except:
                pass

            return "iptables"  # Default for Linux

        elif self.platform == "darwin":  # macOS
            return "pfctl"

        elif self.platform == "windows":
            return "netsh"

        else:
            return "unknown"

    def apply_block_rule(self, command_id: str, target_ip: str, target_port: Optional[int] = None,
                         duration: Optional[int] = None) -> Tuple[bool, str]:
        """Apply a block rule"""
        try:
            rule_id = str(uuid.uuid4())
            current_time = time.time()
            expires_at = current_time + duration if duration else None

            # Generate rule text based on firewall type
            rule_text = self._generate_block_rule(target_ip, target_port)

            # Apply the rule
            if self.dry_run:
                logger.info(f"[DRY RUN] Would apply rule: {rule_text}")
                success = True
                message = f"DRY RUN: Block rule would be applied for {target_ip}"
            else:
                success, message = self._execute_firewall_command(rule_text)

            # Track the rule
            if success:
                rule = FirewallRule(
                    rule_id=rule_id,
                    command_id=command_id,
                    action="BLOCK",
                    target_ip=target_ip,
                    target_port=target_port,
                    duration_seconds=duration,
                    created_at=current_time,
                    expires_at=expires_at,
                    applied=True,
                    rule_text=rule_text
                )

                self.active_rules[rule_id] = rule
                self.rule_history.append(rule)

                logger.info(f"Block rule applied: {target_ip} (Rule ID: {rule_id})")

            return success, message

        except Exception as e:
            logger.error(f"Error applying block rule: {e}")
            return False, f"Error applying block rule: {str(e)}"

    def apply_allow_rule(self, command_id: str, target_ip: str, target_port: Optional[int] = None,
                         duration: Optional[int] = None) -> Tuple[bool, str]:
        """Apply an allow rule"""
        try:
            rule_id = str(uuid.uuid4())
            current_time = time.time()
            expires_at = current_time + duration if duration else None

            # Generate rule text based on firewall type
            rule_text = self._generate_allow_rule(target_ip, target_port)

            # Apply the rule
            if self.dry_run:
                logger.info(f"[DRY RUN] Would apply rule: {rule_text}")
                success = True
                message = f"DRY RUN: Allow rule would be applied for {target_ip}"
            else:
                success, message = self._execute_firewall_command(rule_text)

            # Track the rule
            if success:
                rule = FirewallRule(
                    rule_id=rule_id,
                    command_id=command_id,
                    action="ALLOW",
                    target_ip=target_ip,
                    target_port=target_port,
                    duration_seconds=duration,
                    created_at=current_time,
                    expires_at=expires_at,
                    applied=True,
                    rule_text=rule_text
                )

                self.active_rules[rule_id] = rule
                self.rule_history.append(rule)

                logger.info(f"Allow rule applied: {target_ip} (Rule ID: {rule_id})")

            return success, message

        except Exception as e:
            logger.error(f"Error applying allow rule: {e}")
            return False, f"Error applying allow rule: {str(e)}"

    def apply_rate_limit_rule(self, command_id: str, target_ip: str, target_port: Optional[int] = None,
                              duration: Optional[int] = None) -> Tuple[bool, str]:
        """Apply a rate limit rule"""
        try:
            rule_id = str(uuid.uuid4())
            current_time = time.time()
            expires_at = current_time + duration if duration else None

            # Generate rule text based on firewall type
            rule_text = self._generate_rate_limit_rule(target_ip, target_port)

            # Apply the rule
            if self.dry_run:
                logger.info(f"[DRY RUN] Would apply rule: {rule_text}")
                success = True
                message = f"DRY RUN: Rate limit rule would be applied for {target_ip}"
            else:
                success, message = self._execute_firewall_command(rule_text)

            # Track the rule
            if success:
                rule = FirewallRule(
                    rule_id=rule_id,
                    command_id=command_id,
                    action="RATE_LIMIT",
                    target_ip=target_ip,
                    target_port=target_port,
                    duration_seconds=duration,
                    created_at=current_time,
                    expires_at=expires_at,
                    applied=True,
                    rule_text=rule_text
                )

                self.active_rules[rule_id] = rule
                self.rule_history.append(rule)

                logger.info(f"Rate limit rule applied: {target_ip} (Rule ID: {rule_id})")

            return success, message

        except Exception as e:
            logger.error(f"Error applying rate limit rule: {e}")
            return False, f"Error applying rate limit rule: {str(e)}"

    def _generate_block_rule(self, target_ip: str, target_port: Optional[int]) -> str:
        """Generate block rule text for the current firewall type"""
        if self.firewall_type == "iptables":
            if target_port:
                return f"iptables -A INPUT -s {target_ip} -p tcp --dport {target_port} -j DROP"
            else:
                return f"iptables -A INPUT -s {target_ip} -j DROP"

        elif self.firewall_type == "ufw":
            if target_port:
                return f"ufw deny from {target_ip} to any port {target_port}"
            else:
                return f"ufw deny from {target_ip}"

        elif self.firewall_type == "pfctl":
            if target_port:
                return f"echo 'block in quick from {target_ip} to any port {target_port}' | pfctl -f -"
            else:
                return f"echo 'block in quick from {target_ip}' | pfctl -f -"

        elif self.firewall_type == "netsh":
            if target_port:
                return f"netsh advfirewall firewall add rule name='Block_{target_ip}_{target_port}' dir=in action=block remoteip={target_ip} remoteport={target_port}"
            else:
                return f"netsh advfirewall firewall add rule name='Block_{target_ip}' dir=in action=block remoteip={target_ip}"

        else:
            return f"# Unknown firewall type: {self.firewall_type}"

    def _generate_allow_rule(self, target_ip: str, target_port: Optional[int]) -> str:
        """Generate allow rule text for the current firewall type"""
        if self.firewall_type == "iptables":
            if target_port:
                return f"iptables -A INPUT -s {target_ip} -p tcp --dport {target_port} -j ACCEPT"
            else:
                return f"iptables -A INPUT -s {target_ip} -j ACCEPT"

        elif self.firewall_type == "ufw":
            if target_port:
                return f"ufw allow from {target_ip} to any port {target_port}"
            else:
                return f"ufw allow from {target_ip}"

        elif self.firewall_type == "pfctl":
            if target_port:
                return f"echo 'pass in quick from {target_ip} to any port {target_port}' | pfctl -f -"
            else:
                return f"echo 'pass in quick from {target_ip}' | pfctl -f -"

        elif self.firewall_type == "netsh":
            if target_port:
                return f"netsh advfirewall firewall add rule name='Allow_{target_ip}_{target_port}' dir=in action=allow remoteip={target_ip} remoteport={target_port}"
            else:
                return f"netsh advfirewall firewall add rule name='Allow_{target_ip}' dir=in action=allow remoteip={target_ip}"

        else:
            return f"# Unknown firewall type: {self.firewall_type}"

    def _generate_rate_limit_rule(self, target_ip: str, target_port: Optional[int]) -> str:
        """Generate rate limit rule text for the current firewall type"""
        if self.firewall_type == "iptables":
            if target_port:
                return f"iptables -A INPUT -s {target_ip} -p tcp --dport {target_port} -m limit --limit 10/minute --limit-burst 5 -j ACCEPT"
            else:
                return f"iptables -A INPUT -s {target_ip} -m limit --limit 10/minute --limit-burst 5 -j ACCEPT"

        elif self.firewall_type == "ufw":
            # UFW doesn't have native rate limiting, so we'll use a basic allow
            if target_port:
                return f"ufw limit from {target_ip} to any port {target_port}"
            else:
                return f"ufw limit from {target_ip}"

        elif self.firewall_type == "pfctl":
            if target_port:
                return f"echo 'pass in quick from {target_ip} to any port {target_port} keep state (max-src-conn 10)' | pfctl -f -"
            else:
                return f"echo 'pass in quick from {target_ip} keep state (max-src-conn 10)' | pfctl -f -"

        elif self.firewall_type == "netsh":
            # Windows firewall doesn't have native rate limiting, so we'll use a basic allow
            if target_port:
                return f"netsh advfirewall firewall add rule name='RateLimit_{target_ip}_{target_port}' dir=in action=allow remoteip={target_ip} remoteport={target_port}"
            else:
                return f"netsh advfirewall firewall add rule name='RateLimit_{target_ip}' dir=in action=allow remoteip={target_ip}"

        else:
            return f"# Unknown firewall type: {self.firewall_type}"

    def _execute_firewall_command(self, rule_text: str) -> Tuple[bool, str]:
        """Execute a firewall command"""
        try:
            # Split command into parts
            if rule_text.startswith("echo"):
                # Handle piped commands (pfctl)
                parts = rule_text.split(" | ")
                if len(parts) == 2:
                    echo_cmd = parts[0].split()[1:]  # Remove 'echo'
                    pfctl_cmd = parts[1].split()

                    # Execute echo part
                    echo_result = subprocess.run(
                        ["echo"] + echo_cmd,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if echo_result.returncode == 0:
                        # Pipe to pfctl
                        pfctl_result = subprocess.run(
                            pfctl_cmd,
                            input=echo_result.stdout,
                            capture_output=True,
                            text=True,
                            timeout=30
                        )

                        if pfctl_result.returncode == 0:
                            return True, "Rule applied successfully"
                        else:
                            return False, f"pfctl error: {pfctl_result.stderr}"
                    else:
                        return False, f"echo error: {echo_result.stderr}"
            else:
                # Handle regular commands
                cmd_parts = rule_text.split()

                # Add sudo if enabled and not running as root
                if self.sudo_enabled and os.geteuid() != 0:
                    cmd_parts = ["sudo"] + cmd_parts

                # Execute command
                result = subprocess.run(
                    cmd_parts,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    return True, "Rule applied successfully"
                else:
                    return False, f"Command error: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, f"Execution error: {str(e)}"

    def cleanup_expired_rules(self):
        """Clean up expired rules"""
        current_time = time.time()
        expired_rules = []

        for rule_id, rule in self.active_rules.items():
            if rule.expires_at and current_time > rule.expires_at:
                expired_rules.append(rule_id)

        for rule_id in expired_rules:
            rule = self.active_rules.pop(rule_id)
            logger.info(f"Rule expired: {rule.target_ip} (Rule ID: {rule_id})")
            # TODO: Remove the actual firewall rule

    def get_active_rules(self) -> List[FirewallRule]:
        """Get list of active rules"""
        return list(self.active_rules.values())

    def get_rule_history(self) -> List[FirewallRule]:
        """Get rule history"""
        return self.rule_history[-100:]  # Last 100 rules


class SimpleFirewallAgent:
    """Simple firewall agent that processes protobuf commands"""

    def __init__(self, config_path: str):
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = json.load(f)

        self.node_id = self.config["node_id"]
        self.component_name = self.config["component"]["name"]
        self.agent_id = f"{self.node_id}_{int(time.time())}"

        # Initialize crypto/compression if available
        self.crypto_engine = None
        self.compression_engine = None

        if CRYPTO_AVAILABLE:
            if self.config.get("encryption", {}).get("enabled", False):
                self.crypto_engine = SecureEnvelope(self.config["encryption"])
            if self.config.get("compression", {}).get("enabled", False):
                self.compression_engine = CompressionEngine(self.config["compression"])

        # Initialize firewall manager
        firewall_config = self.config.get("firewall", {})
        self.firewall_manager = FirewallManager(firewall_config)

        # ZMQ setup
        self.zmq_context = zmq.Context()
        self.commands_socket = None
        self.responses_socket = None

        # Processing
        self.command_queue = queue.Queue()
        self.running = False
        self.threads = []

        # Metrics
        self.metrics = {
            "commands_received": 0,
            "commands_processed": 0,
            "responses_sent": 0,
            "rules_applied": 0,
            "errors": 0,
            "uptime_start": time.time()
        }

        # Initialize components
        self._setup_zmq_sockets()

        logger.info(f"Simple Firewall Agent initialized: {self.agent_id}")

    def _setup_zmq_sockets(self):
        """Setup ZMQ sockets based on configuration"""
        network_config = self.config.get("network", {})

        # Commands Input (from dashboard)
        if "commands_input" in network_config:
            cmd_config = network_config["commands_input"]
            self.commands_socket = self.zmq_context.socket(zmq.PULL)

            # Configure socket
            if "high_water_mark" in cmd_config:
                self.commands_socket.set_hwm(cmd_config["high_water_mark"])

            # Connect to dashboard
            cmd_address = f"tcp://{cmd_config['address']}:{cmd_config['port']}"
            self.commands_socket.connect(cmd_address)

            logger.info(f"Commands Input connected to: {cmd_address}")

        # Responses Output (to dashboard)
        if "responses_output" in network_config:
            resp_config = network_config["responses_output"]
            self.responses_socket = self.zmq_context.socket(zmq.PUSH)

            # Configure socket
            if "high_water_mark" in resp_config:
                self.responses_socket.set_hwm(resp_config["high_water_mark"])

            # Connect to dashboard
            resp_address = f"tcp://{resp_config['address']}:{resp_config['port']}"
            self.responses_socket.connect(resp_address)

            logger.info(f"Responses Output connected to: {resp_address}")

    def _decrypt_and_decompress(self, data: bytes) -> bytes:
        """Decrypt and decompress data if crypto is enabled"""
        if not data:
            return data

        try:
            # Decrypt if crypto is enabled
            if self.crypto_engine:
                data = self.crypto_engine.decrypt(data)

            # Decompress if compression is enabled
            if self.compression_engine:
                data = self.compression_engine.decompress(data)

            return data

        except Exception as e:
            logger.error(f"Failed to decrypt/decompress data: {e}")
            return data  # Return original data if decryption fails

    def _compress_and_encrypt(self, data: bytes) -> bytes:
        """Compress and encrypt data if crypto is enabled"""
        if not data:
            return data

        try:
            # Compress if compression is enabled
            if self.compression_engine:
                result = self.compression_engine.compress(data)
                data = result.compressed_data if hasattr(result, 'compressed_data') else result

            # Encrypt if crypto is enabled
            if self.crypto_engine:
                data = self.crypto_engine.encrypt(data)

            return data

        except Exception as e:
            logger.error(f"Failed to compress/encrypt data: {e}")
            return data  # Return original data if encryption fails

    def _commands_consumer(self):
        """Consumer thread for firewall commands"""
        logger.info("Commands consumer thread started")

        while self.running:
            try:
                if self.commands_socket:
                    try:
                        # Receive command with timeout
                        raw_data = self.commands_socket.recv(zmq.NOBLOCK)

                        # Decrypt and decompress
                        decrypted_data = self._decrypt_and_decompress(raw_data)

                        # Parse protobuf
                        pb_command = firewall_commands_pb2.FirewallCommand()
                        pb_command.ParseFromString(decrypted_data)

                        # Add to processing queue
                        self.command_queue.put(pb_command)

                        self.metrics["commands_received"] += 1

                    except zmq.Again:
                        # No message available, continue
                        pass
                    except Exception as e:
                        logger.error(f"Error receiving command: {e}")
                        self.metrics["errors"] += 1

                time.sleep(0.001)  # Small delay to prevent busy waiting

            except Exception as e:
                logger.error(f"Commands consumer error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _command_processor(self):
        """Processor thread for firewall commands"""
        logger.info("Command processor thread started")

        while self.running:
            try:
                # Get command from queue
                try:
                    pb_command = self.command_queue.get(timeout=1)
                except queue.Empty:
                    continue

                # Process command
                self._process_firewall_command(pb_command)

                self.metrics["commands_processed"] += 1

            except Exception as e:
                logger.error(f"Command processor error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _process_firewall_command(self, pb_command):
        """Process a firewall command"""
        try:
            command_id = pb_command.command_id
            action = pb_command.action
            target_ip = pb_command.target_ip
            target_port = pb_command.target_port if pb_command.target_port else None
            duration = pb_command.duration_seconds if pb_command.duration_seconds else None

            logger.info(f"Processing command: {command_id} - {action} {target_ip}")

            # Apply firewall rule
            if action == "BLOCK":
                success, message = self.firewall_manager.apply_block_rule(
                    command_id, target_ip, target_port, duration
                )
            elif action == "ALLOW":
                success, message = self.firewall_manager.apply_allow_rule(
                    command_id, target_ip, target_port, duration
                )
            elif action == "RATE_LIMIT":
                success, message = self.firewall_manager.apply_rate_limit_rule(
                    command_id, target_ip, target_port, duration
                )
            else:
                success = False
                message = f"Unknown action: {action}"

            # Send response
            self._send_response(command_id, success, message)

            if success:
                self.metrics["rules_applied"] += 1

        except Exception as e:
            logger.error(f"Error processing command: {e}")
            self._send_response(pb_command.command_id, False, f"Processing error: {str(e)}")

    def _send_response(self, command_id: str, success: bool, message: str):
        """Send response to dashboard"""
        try:
            if not self.responses_socket:
                logger.error("Responses socket not configured")
                return

            # Create response protobuf
            pb_response = firewall_commands_pb2.FirewallResponse()
            pb_response.command_id = command_id
            pb_response.agent_id = self.agent_id
            pb_response.success = success
            pb_response.message = message
            pb_response.timestamp = time.time()

            # Serialize
            serialized_data = pb_response.SerializeToString()

            # Compress and encrypt
            encrypted_data = self._compress_and_encrypt(serialized_data)

            # Send response
            self.responses_socket.send(encrypted_data, zmq.NOBLOCK)

            self.metrics["responses_sent"] += 1

            logger.info(f"Response sent: {command_id} - Success: {success}")

        except Exception as e:
            logger.error(f"Error sending response: {e}")
            self.metrics["errors"] += 1

    def _cleanup_thread(self):
        """Cleanup thread for expired rules"""
        logger.info("Cleanup thread started")

        while self.running:
            try:
                self.firewall_manager.cleanup_expired_rules()
                time.sleep(60)  # Check every minute

            except Exception as e:
                logger.error(f"Cleanup thread error: {e}")
                time.sleep(60)

    def start(self):
        """Start the firewall agent"""
        logger.info("Starting Simple Firewall Agent...")

        self.running = True

        # Start consumer thread
        if self.commands_socket:
            consumer_thread = threading.Thread(target=self._commands_consumer, daemon=True)
            consumer_thread.start()
            self.threads.append(consumer_thread)

        # Start processor thread
        processor_thread = threading.Thread(target=self._command_processor, daemon=True)
        processor_thread.start()
        self.threads.append(processor_thread)

        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_thread, daemon=True)
        cleanup_thread.start()
        self.threads.append(cleanup_thread)

        logger.info(f"Simple Firewall Agent started with {len(self.threads)} threads")

        # Main loop
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutdown requested by user")
            self.stop()

    def stop(self):
        """Stop the firewall agent"""
        logger.info("Stopping Simple Firewall Agent...")

        self.running = False

        # Close ZMQ sockets
        if self.commands_socket:
            self.commands_socket.close()
        if self.responses_socket:
            self.responses_socket.close()

        # Close ZMQ context
        self.zmq_context.term()

        logger.info("Simple Firewall Agent stopped")

    def get_status(self) -> Dict:
        """Get agent status"""
        return {
            "agent_id": self.agent_id,
            "node_id": self.node_id,
            "component_name": self.component_name,
            "running": self.running,
            "metrics": self.metrics,
            "uptime_seconds": time.time() - self.metrics["uptime_start"],
            "firewall_type": self.firewall_manager.firewall_type,
            "platform": self.firewall_manager.platform,
            "active_rules": len(self.firewall_manager.active_rules),
            "crypto_enabled": self.crypto_engine is not None,
            "compression_enabled": self.compression_engine is not None
        }


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description="Simple Firewall Agent - Protobuf Integration")
    parser.add_argument("config", help="Configuration file path")
    parser.add_argument("--log-level", default="INFO", help="Log level")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize and start agent
    agent = SimpleFirewallAgent(args.config)

    try:
        agent.start()
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
    except Exception as e:
        logger.error(f"Agent error: {e}")
    finally:
        agent.stop()


if __name__ == "__main__":
    main()