# real_zmq_dashboard_refactored.py - Core Pipeline Focus
import json
import time
import threading
import queue
import zmq
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit
import sys
import os

# Add src to path for protobuf imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.protocols.protobuf import network_event_extended_v2_pb2 as network_event_pb2
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
class MLEvent:
    """Data class for ML detector events"""
    event_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    packet_size: int
    src_country: str
    dst_country: str
    anomaly_score: float
    risk_level: str
    ml_prediction: str
    pipeline_latency: float
    component_path: List[str]

    @classmethod
    def from_protobuf(cls, pb_event) -> 'MLEvent':
        """Create MLEvent from protobuf"""
        return cls(
            event_id=pb_event.event_id,
            timestamp=pb_event.timestamp,
            src_ip=pb_event.src_ip,
            dst_ip=pb_event.dst_ip,
            dst_port=pb_event.dst_port,
            protocol=pb_event.protocol,
            packet_size=pb_event.packet_size,
            src_country=pb_event.src_country,
            dst_country=pb_event.dst_country,
            anomaly_score=pb_event.anomaly_score,
            risk_level=pb_event.risk_level,
            ml_prediction=pb_event.ml_prediction,
            pipeline_latency=pb_event.pipeline_latency,
            component_path=list(pb_event.component_path)
        )

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['timestamp_human'] = datetime.fromtimestamp(self.timestamp).isoformat()
        return data


@dataclass
class FirewallCommand:
    """Data class for firewall commands"""
    command_id: str
    timestamp: float
    action: str  # "BLOCK", "ALLOW", "RATE_LIMIT"
    target_ip: str
    target_port: Optional[int]
    duration_seconds: Optional[int]
    reason: str
    priority: int
    source_event_id: str

    def to_protobuf(self) -> firewall_commands_pb2.FirewallCommand:
        """Convert to protobuf"""
        pb_command = firewall_commands_pb2.FirewallCommand()
        pb_command.command_id = self.command_id
        pb_command.timestamp = self.timestamp
        pb_command.action = self.action
        pb_command.target_ip = self.target_ip
        if self.target_port:
            pb_command.target_port = self.target_port
        if self.duration_seconds:
            pb_command.duration_seconds = self.duration_seconds
        pb_command.reason = self.reason
        pb_command.priority = self.priority
        pb_command.source_event_id = self.source_event_id
        return pb_command


class DashboardCore:
    """Core dashboard functionality - ML events → Firewall commands"""

    def __init__(self, config_path: str):
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = json.load(f)

        self.node_id = self.config["node_id"]
        self.component_name = self.config["component"]["name"]

        # Initialize crypto/compression if available
        self.crypto_engine = None
        self.compression_engine = None

        if CRYPTO_AVAILABLE:
            if self.config.get("encryption", {}).get("enabled", False):
                self.crypto_engine = SecureEnvelope(self.config["encryption"])
            if self.config.get("compression", {}).get("enabled", False):
                self.compression_engine = CompressionEngine(self.config["compression"])

        # ZMQ setup
        self.zmq_context = zmq.Context()
        self.ml_input_socket = None
        self.firewall_output_socket = None
        self.firewall_response_socket = None

        # Event storage
        self.recent_events = queue.Queue(maxsize=1000)
        self.event_history = []
        self.pending_commands = {}

        # Threading
        self.running = False
        self.threads = []

        # Metrics
        self.metrics = {
            "events_received": 0,
            "events_processed": 0,
            "commands_sent": 0,
            "responses_received": 0,
            "errors": 0,
            "uptime_start": time.time()
        }

        # Initialize components
        self._setup_zmq_sockets()
        self._setup_web_interface()

        logger.info(f"Dashboard Core initialized: {self.node_id}")

    def _setup_zmq_sockets(self):
        """Setup ZMQ sockets based on configuration"""
        network_config = self.config.get("network", {})

        # ML Events Input (from ml_detector)
        if "ml_events_input" in network_config:
            ml_config = network_config["ml_events_input"]
            self.ml_input_socket = self.zmq_context.socket(zmq.PULL)

            # Configure socket
            if "high_water_mark" in ml_config:
                self.ml_input_socket.set_hwm(ml_config["high_water_mark"])

            # Bind to receive events
            ml_address = f"tcp://{ml_config['address']}:{ml_config['port']}"
            self.ml_input_socket.bind(ml_address)

            logger.info(f"ML Events Input bound to: {ml_address}")

        # Firewall Commands Output (to firewall_agent)
        if "firewall_commands_output" in network_config:
            fw_config = network_config["firewall_commands_output"]
            self.firewall_output_socket = self.zmq_context.socket(zmq.PUSH)

            # Configure socket
            if "high_water_mark" in fw_config:
                self.firewall_output_socket.set_hwm(fw_config["high_water_mark"])

            # Bind for firewall agents to connect
            fw_address = f"tcp://{fw_config['address']}:{fw_config['port']}"
            self.firewall_output_socket.bind(fw_address)

            logger.info(f"Firewall Commands Output bound to: {fw_address}")

        # Firewall Responses Input (from firewall_agent)
        if "firewall_responses_input" in network_config:
            resp_config = network_config["firewall_responses_input"]
            self.firewall_response_socket = self.zmq_context.socket(zmq.PULL)

            # Configure socket
            if "high_water_mark" in resp_config:
                self.firewall_response_socket.set_hwm(resp_config["high_water_mark"])

            # Bind for firewall agents to connect
            resp_address = f"tcp://{resp_config['address']}:{resp_config['port']}"
            self.firewall_response_socket.bind(resp_address)

            logger.info(f"Firewall Responses Input bound to: {resp_address}")

    def _setup_web_interface(self):
        """Setup Flask web interface"""
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'upgraded-happiness-dashboard'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")

        # Register routes
        self._register_routes()
        self._register_socketio_handlers()

        logger.info("Web interface configured")

    def _register_routes(self):
        """Register Flask routes"""

        @self.app.route('/')
        def index():
            return render_template('dashboard.html')

        @self.app.route('/api/status')
        def status():
            return jsonify({
                "node_id": self.node_id,
                "component_name": self.component_name,
                "running": self.running,
                "metrics": self.metrics,
                "uptime_seconds": time.time() - self.metrics["uptime_start"]
            })

        @self.app.route('/api/events')
        def get_events():
            """Get recent events"""
            limit = request.args.get('limit', 100, type=int)
            events = self.event_history[-limit:] if self.event_history else []
            return jsonify(events)

        @self.app.route('/api/metrics')
        def get_metrics():
            """Get dashboard metrics"""
            return jsonify(self.metrics)

        @self.app.route('/api/firewall/block', methods=['POST'])
        def block_ip():
            """Block an IP address"""
            data = request.json

            command = FirewallCommand(
                command_id=f"block_{int(time.time() * 1000)}",
                timestamp=time.time(),
                action="BLOCK",
                target_ip=data['ip'],
                target_port=data.get('port'),
                duration_seconds=data.get('duration', 3600),
                reason=data.get('reason', 'Manual block from dashboard'),
                priority=data.get('priority', 5),
                source_event_id=data.get('event_id', 'manual')
            )

            success = self._send_firewall_command(command)
            return jsonify({"success": success, "command_id": command.command_id})

        @self.app.route('/api/firewall/allow', methods=['POST'])
        def allow_ip():
            """Allow an IP address"""
            data = request.json

            command = FirewallCommand(
                command_id=f"allow_{int(time.time() * 1000)}",
                timestamp=time.time(),
                action="ALLOW",
                target_ip=data['ip'],
                target_port=data.get('port'),
                duration_seconds=data.get('duration'),
                reason=data.get('reason', 'Manual allow from dashboard'),
                priority=data.get('priority', 5),
                source_event_id=data.get('event_id', 'manual')
            )

            success = self._send_firewall_command(command)
            return jsonify({"success": success, "command_id": command.command_id})

    def _register_socketio_handlers(self):
        """Register SocketIO handlers for real-time updates"""

        @self.socketio.on('connect')
        def handle_connect():
            logger.info("Client connected to dashboard")
            emit('status', {'connected': True})

        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info("Client disconnected from dashboard")

        @self.socketio.on('request_events')
        def handle_request_events(data):
            """Send recent events to client"""
            limit = data.get('limit', 50)
            events = self.event_history[-limit:] if self.event_history else []
            emit('events_update', events)

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

    def _ml_events_consumer(self):
        """Consumer thread for ML detector events"""
        logger.info("ML Events consumer thread started")

        while self.running:
            try:
                if self.ml_input_socket:
                    # Receive event with timeout
                    try:
                        raw_data = self.ml_input_socket.recv(zmq.NOBLOCK)

                        # Decrypt and decompress
                        decrypted_data = self._decrypt_and_decompress(raw_data)

                        # Parse protobuf
                        pb_event = network_event_pb2.NetworkEvent()
                        pb_event.ParseFromString(decrypted_data)

                        # Convert to internal format
                        ml_event = MLEvent.from_protobuf(pb_event)

                        # Process event
                        self._process_ml_event(ml_event)

                        self.metrics["events_received"] += 1

                    except zmq.Again:
                        # No message available, continue
                        pass
                    except Exception as e:
                        logger.error(f"Error processing ML event: {e}")
                        self.metrics["errors"] += 1

                time.sleep(0.001)  # Small delay to prevent busy waiting

            except Exception as e:
                logger.error(f"ML Events consumer error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _process_ml_event(self, event: MLEvent):
        """Process ML detector event and decide on actions"""
        try:
            # Add to event history
            self.event_history.append(event.to_dict())

            # Keep only last 1000 events
            if len(self.event_history) > 1000:
                self.event_history.pop(0)

            # Add to recent events queue
            try:
                self.recent_events.put_nowait(event)
            except queue.Full:
                # Remove oldest event if queue is full
                try:
                    self.recent_events.get_nowait()
                    self.recent_events.put_nowait(event)
                except queue.Empty:
                    pass

            # Real-time update to web clients
            self.socketio.emit('new_event', event.to_dict())

            # Automatic threat response based on ML score
            self._evaluate_automatic_response(event)

            self.metrics["events_processed"] += 1

            logger.debug(f"Processed ML event: {event.event_id} - Score: {event.anomaly_score}")

        except Exception as e:
            logger.error(f"Error processing ML event: {e}")
            self.metrics["errors"] += 1

    def _evaluate_automatic_response(self, event: MLEvent):
        """Evaluate if automatic firewall response is needed"""
        try:
            # Get thresholds from config
            ml_config = self.config.get("ml_processing", {})
            auto_block_threshold = ml_config.get("auto_block_threshold", 0.9)
            auto_rate_limit_threshold = ml_config.get("auto_rate_limit_threshold", 0.7)

            # High risk - automatic block
            if event.anomaly_score >= auto_block_threshold:
                command = FirewallCommand(
                    command_id=f"auto_block_{event.event_id}",
                    timestamp=time.time(),
                    action="BLOCK",
                    target_ip=event.src_ip,
                    target_port=None,
                    duration_seconds=3600,  # 1 hour
                    reason=f"Automatic block - ML score: {event.anomaly_score:.2f}",
                    priority=1,  # High priority
                    source_event_id=event.event_id
                )

                self._send_firewall_command(command)

                # Emit alert to web clients
                self.socketio.emit('security_alert', {
                    'type': 'auto_block',
                    'event': event.to_dict(),
                    'command': asdict(command)
                })

                logger.info(f"Automatic block triggered for {event.src_ip} - Score: {event.anomaly_score}")

            # Medium risk - rate limiting
            elif event.anomaly_score >= auto_rate_limit_threshold:
                command = FirewallCommand(
                    command_id=f"auto_rate_limit_{event.event_id}",
                    timestamp=time.time(),
                    action="RATE_LIMIT",
                    target_ip=event.src_ip,
                    target_port=event.dst_port,
                    duration_seconds=1800,  # 30 minutes
                    reason=f"Automatic rate limit - ML score: {event.anomaly_score:.2f}",
                    priority=3,  # Medium priority
                    source_event_id=event.event_id
                )

                self._send_firewall_command(command)

                # Emit alert to web clients
                self.socketio.emit('security_alert', {
                    'type': 'auto_rate_limit',
                    'event': event.to_dict(),
                    'command': asdict(command)
                })

                logger.info(f"Automatic rate limit triggered for {event.src_ip} - Score: {event.anomaly_score}")

        except Exception as e:
            logger.error(f"Error in automatic response evaluation: {e}")

    def _send_firewall_command(self, command: FirewallCommand) -> bool:
        """Send firewall command to firewall agents"""
        try:
            if not self.firewall_output_socket:
                logger.error("Firewall output socket not configured")
                return False

            # Convert to protobuf
            pb_command = command.to_protobuf()

            # Serialize
            serialized_data = pb_command.SerializeToString()

            # Compress and encrypt
            encrypted_data = self._compress_and_encrypt(serialized_data)

            # Send to firewall agents
            self.firewall_output_socket.send(encrypted_data, zmq.NOBLOCK)

            # Track pending command
            self.pending_commands[command.command_id] = {
                'command': command,
                'sent_at': time.time(),
                'responses': []
            }

            self.metrics["commands_sent"] += 1

            logger.info(f"Firewall command sent: {command.command_id} - {command.action} {command.target_ip}")
            return True

        except Exception as e:
            logger.error(f"Error sending firewall command: {e}")
            self.metrics["errors"] += 1
            return False

    def _firewall_responses_consumer(self):
        """Consumer thread for firewall responses"""
        logger.info("Firewall Responses consumer thread started")

        while self.running:
            try:
                if self.firewall_response_socket:
                    try:
                        # Receive response with timeout
                        raw_data = self.firewall_response_socket.recv(zmq.NOBLOCK)

                        # Decrypt and decompress
                        decrypted_data = self._decrypt_and_decompress(raw_data)

                        # Parse protobuf response
                        pb_response = firewall_commands_pb2.FirewallResponse()
                        pb_response.ParseFromString(decrypted_data)

                        # Process response
                        self._process_firewall_response(pb_response)

                        self.metrics["responses_received"] += 1

                    except zmq.Again:
                        # No message available, continue
                        pass
                    except Exception as e:
                        logger.error(f"Error processing firewall response: {e}")
                        self.metrics["errors"] += 1

                time.sleep(0.001)  # Small delay to prevent busy waiting

            except Exception as e:
                logger.error(f"Firewall Responses consumer error: {e}")
                self.metrics["errors"] += 1
                time.sleep(1)

    def _process_firewall_response(self, pb_response):
        """Process firewall response"""
        try:
            command_id = pb_response.command_id

            # Find pending command
            if command_id in self.pending_commands:
                pending = self.pending_commands[command_id]

                # Add response to pending command
                response_data = {
                    'agent_id': pb_response.agent_id,
                    'success': pb_response.success,
                    'message': pb_response.message,
                    'timestamp': pb_response.timestamp
                }

                pending['responses'].append(response_data)

                # Emit response to web clients
                self.socketio.emit('firewall_response', {
                    'command_id': command_id,
                    'response': response_data,
                    'total_responses': len(pending['responses'])
                })

                logger.info(
                    f"Firewall response received: {command_id} - {pb_response.agent_id} - Success: {pb_response.success}")

        except Exception as e:
            logger.error(f"Error processing firewall response: {e}")

    def start(self):
        """Start the dashboard"""
        logger.info("Starting Dashboard Core...")

        self.running = True

        # Start consumer threads
        if self.ml_input_socket:
            ml_thread = threading.Thread(target=self._ml_events_consumer, daemon=True)
            ml_thread.start()
            self.threads.append(ml_thread)

        if self.firewall_response_socket:
            fw_thread = threading.Thread(target=self._firewall_responses_consumer, daemon=True)
            fw_thread.start()
            self.threads.append(fw_thread)

        # Start web interface
        web_config = self.config.get("web_interface", {})
        host = web_config.get("host", "0.0.0.0")
        port = web_config.get("port", 8080)
        debug = web_config.get("debug", False)

        logger.info(f"Starting web interface on {host}:{port}")

        try:
            self.socketio.run(self.app, host=host, port=port, debug=debug)
        except Exception as e:
            logger.error(f"Web interface error: {e}")

    def stop(self):
        """Stop the dashboard"""
        logger.info("Stopping Dashboard Core...")

        self.running = False

        # Close ZMQ sockets
        if self.ml_input_socket:
            self.ml_input_socket.close()
        if self.firewall_output_socket:
            self.firewall_output_socket.close()
        if self.firewall_response_socket:
            self.firewall_response_socket.close()

        # Close ZMQ context
        self.zmq_context.term()

        logger.info("Dashboard Core stopped")


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description="Dashboard Core - ML Events → Firewall Commands")
    parser.add_argument("config", help="Configuration file path")
    parser.add_argument("--log-level", default="INFO", help="Log level")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize and start dashboard
    dashboard = DashboardCore(args.config)

    try:
        dashboard.start()
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
    finally:
        dashboard.stop()


if __name__ == "__main__":
    main()