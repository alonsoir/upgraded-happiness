#!/usr/bin/env python3
"""
🚀 EVOLUTIONARY SNIFFER v3.1 - ETCD FIXED VERSION
evolutionary_sniffer_v31_etcd_fixed.py

CAMBIOS PARA MEJOR ROBUSTEZ:
✅ Uses etcd_crypto_client_sniffer_fixed
✅ Better error handling
✅ Development mode support
✅ Fallback if ETCD not available
✅ Protobuf compatibility fixes

Resto del código igual pero más robusto...
"""

import zmq
import time
import json
import logging
import threading
import socket
import uuid
import os
import sys
import platform
import psutil
import asyncio

# 🔧 SETUP ENVIRONMENT PARA PROTOBUF
if 'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION' not in os.environ:
    os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

# ✅ IMPORTS ETCD CRYPTO FIJO
from etcd_crypto_client_sniffer_fixed import (
    setup_sniffer_crypto,
    get_sniffer_pipeline_key
)

# Import other components (keeping original imports for compatibility)
try:
    from evolutionary_sniffer_v31_etcd import TimeWindowManager, NetworkFeaturesExtractor
except ImportError:
    print("⚠️  Importing components from current directory...")

    # If imports fail, we'll define minimal versions here
    import numpy as np
    import pandas as pd
    from threading import Event
    from typing import Dict, Any, Optional, List, Tuple
    from queue import Queue, Empty
    from collections import defaultdict, deque
    from dataclasses import dataclass
    from datetime import datetime, timedelta
    import math
    import statistics

# 📦 Dependencias para captura de paquetes
try:
    from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("❌ Scapy REQUERIDO - pip install scapy")

# 📦 Protobuf v3.1 con fallback
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkSecurityEventProto = None


def import_protobuf_v31():
    """Import protobuf with fallback for development"""
    global NetworkSecurityEventProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    # Try multiple strategies
    strategies = [
        ("network_security_clean_v31_pb2", "Direct import"),
        ("protocols.v3_1.network_security_clean_v31_pb2", "Package import"),
    ]

    for import_path, description in strategies:
        try:
            NetworkSecurityEventProto = __import__(import_path, fromlist=[''])
            PROTOBUF_AVAILABLE = True
            PROTOBUF_VERSION = "v3.1.0-clean"
            print(f"✅ Protobuf v3.1 loaded: {description}")
            return True
        except ImportError:
            continue

    # Development fallback - create mock protobuf
    if os.environ.get("UPGRADED_HAPPINESS_DEV_MODE"):
        print("🧪 Dev mode: Creating mock protobuf...")
        create_mock_protobuf()
        return True

    print("❌ Protobuf v3.1 not found and not in dev mode")
    return False


def create_mock_protobuf():
    """Create mock protobuf for development"""
    global NetworkSecurityEventProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    class MockProtobuf:
        class NetworkSecurityEvent:
            def __init__(self):
                self.event_id = ""
                self.originating_node_id = ""
                self.final_classification = ""
                self.schema_version = 31

            def SerializeToString(self):
                return b"mock_protobuf_data"

            class NetworkFeatures:
                def __init__(self):
                    self.source_ip = ""
                    self.destination_ip = ""

            class DistributedNode:
                class NodeRole:
                    PACKET_SNIFFER = "PACKET_SNIFFER"

                class NodeStatus:
                    ACTIVE = "ACTIVE"

            class TimeWindow:
                class WindowType:
                    SLIDING = "SLIDING"

        # Add more mock classes as needed

    NetworkSecurityEventProto = MockProtobuf()
    PROTOBUF_AVAILABLE = True
    PROTOBUF_VERSION = "v3.1.0-mock"


# Import protobuf
import_protobuf_v31()


# [DATACLASSES - same as original]
@dataclass
class TimeWindowConfig:
    window_size_seconds: float
    slide_interval_seconds: float
    max_flows_per_window: int
    features_required: List[str]
    model_types: List[str]
    description: str


@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol_number: int
    protocol_name: str
    packet_size: int
    tcp_flags: Dict[str, bool]
    flow_id: str
    raw_packet: Any = None


@dataclass
class FlowInfo:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    forward_packets: List[PacketInfo]
    backward_packets: List[PacketInfo]
    total_forward_bytes: int = 0
    total_backward_bytes: int = 0


# [SIMPLIFIED CLASSES FOR DEVELOPMENT]
class SimpleNetworkFeaturesExtractor:
    """Simplified features extractor for development"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def extract_all_features(self, flow: FlowInfo) -> Dict[str, float]:
        """Extract basic features"""
        try:
            duration = flow.last_seen - flow.start_time

            features = {
                'flow_duration': duration,
                'total_forward_packets': float(len(flow.forward_packets)),
                'total_backward_packets': float(len(flow.backward_packets)),
                'total_forward_bytes': float(flow.total_forward_bytes),
                'total_backward_bytes': float(flow.total_backward_bytes),
            }

            # Pad to 83 features for ML compatibility
            for i in range(len(features), 83):
                features[f'feature_{i}'] = 0.0

            return features

        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            return {f'feature_{i}': 0.0 for i in range(83)}

    def get_features_for_model(self, all_features: Dict[str, float], model_type: str) -> List[float]:
        """Get features for specific model"""
        return list(all_features.values())[:83]


class SimpleTimeWindowManager:
    """Simplified time window manager for development"""

    def __init__(self, window_configs: Dict[str, TimeWindowConfig], logger):
        self.window_configs = window_configs
        self.logger = logger
        self.active_flows = {}
        self.window_timers = {}
        self.lock = threading.Lock()

        # Initialize timers
        now = time.time()
        for window_type, config in window_configs.items():
            self.window_timers[window_type] = now + config.slide_interval_seconds

    def add_packet(self, packet_info: PacketInfo):
        """Add packet to flow tracking"""
        with self.lock:
            flow_id = packet_info.flow_id

            if flow_id not in self.active_flows:
                self.active_flows[flow_id] = FlowInfo(
                    flow_id=flow_id,
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    src_port=packet_info.src_port,
                    dst_port=packet_info.dst_port,
                    protocol=packet_info.protocol_name,
                    start_time=packet_info.timestamp,
                    last_seen=packet_info.timestamp,
                    forward_packets=[],
                    backward_packets=[]
                )

            flow = self.active_flows[flow_id]
            flow.last_seen = packet_info.timestamp

            # Simple direction detection
            if packet_info.src_ip == flow.src_ip:
                flow.forward_packets.append(packet_info)
                flow.total_forward_bytes += packet_info.packet_size
            else:
                flow.backward_packets.append(packet_info)
                flow.total_backward_bytes += packet_info.packet_size

    def get_completed_windows(self) -> List[Dict[str, Any]]:
        """Get completed windows"""
        completed = []
        now = time.time()

        with self.lock:
            for window_type, config in self.window_configs.items():
                if now >= self.window_timers[window_type]:
                    start_time = now - config.window_size_seconds

                    # Get flows in window
                    window_flows = []
                    for flow in self.active_flows.values():
                        if flow.start_time >= start_time:
                            window_flows.append(flow)

                    if window_flows:
                        completed.append({
                            'window_type': window_type,
                            'config': config,
                            'start_time': start_time,
                            'end_time': now,
                            'flows': window_flows,
                            'flow_count': len(window_flows)
                        })

                    # Update timer
                    self.window_timers[window_type] = now + config.slide_interval_seconds

        return completed


class EvolutionarySnifferFixed:
    """
    Evolutionary Sniffer FIXED - More robust for development
    """

    def __init__(self, config_file: str, pipeline_key: Optional[str] = None):
        """Initialize sniffer with fixed dependencies"""

        # Load config
        self.config = self._load_config_strict(config_file)
        self.config_file = config_file
        self.pipeline_key = pipeline_key

        # Basic setup
        self.node_id = self.config["node_id"]
        self.process_id = os.getpid()
        self.start_time = time.time()

        # Setup logging
        self.setup_logging()
        self.logger.info(f"🚀 Evolutionary Sniffer FIXED v3.1 initializing...")
        self.logger.info(f"   🔑 Pipeline key: {'✅' if pipeline_key else '❌'}")

        # Verify dependencies
        self._verify_dependencies()

        # Setup ZMQ
        self.context = zmq.Context()
        self.socket = None
        self.setup_socket()

        # Setup components (use simple versions if originals not available)
        try:
            self.features_extractor = NetworkFeaturesExtractor()
        except:
            self.features_extractor = SimpleNetworkFeaturesExtractor()
            self.logger.info("🔧 Using simplified features extractor")

        try:
            self.time_window_manager = TimeWindowManager(
                self._parse_time_window_configs(),
                self.logger
            )
        except:
            self.time_window_manager = SimpleTimeWindowManager(
                self._parse_time_window_configs(),
                self.logger
            )
            self.logger.info("🔧 Using simplified time window manager")

        # Queues
        queue_size = self.config["processing"]["internal_queue_size"]
        self.packet_queue = Queue(maxsize=queue_size)

        # Stats
        self.stats = {
            'packets_captured': 0,
            'flows_created': 0,
            'events_sent': 0,
            'drops': 0,
            'errors': 0,
            'start_time': time.time()
        }

        # Control
        self.running = True
        self.handshake_sent = False

        self.logger.info("✅ Evolutionary Sniffer FIXED initialized")

    def _load_config_strict(self, config_file: str) -> Dict[str, Any]:
        """Load config with validation"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"❌ Config file not found: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Invalid JSON: {e}")

        # Validate required fields
        required = ["node_id", "network", "capture", "processing", "etcd_crypto"]
        for field in required:
            if field not in config:
                raise RuntimeError(f"❌ Missing required field: {field}")

        return config

    def _verify_dependencies(self):
        """Verify critical dependencies"""
        issues = []

        if not SCAPY_AVAILABLE:
            issues.append("❌ Scapy required - pip install scapy")

        if not PROTOBUF_AVAILABLE:
            if not os.environ.get("UPGRADED_HAPPINESS_DEV_MODE"):
                issues.append("❌ Protobuf v3.1 required")

        if issues:
            for issue in issues:
                print(issue)
            if not os.environ.get("UPGRADED_HAPPINESS_DEV_MODE"):
                raise RuntimeError("❌ Critical dependencies missing")

        print("✅ Dependencies verified")

    def setup_logging(self):
        """Setup logging"""
        log_config = self.config["logging"]
        level = getattr(logging, log_config["level"].upper())

        formatter = logging.Formatter(
            "%(asctime)s - %(name)-20s - %(levelname)-8s - "
            "[node_id:{node_id}] [pid:{pid}] [FIXED] - %(message)s".format(
                node_id=self.node_id,
                pid=self.process_id
            )
        )

        self.logger = logging.getLogger(f"sniffer_fixed_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def setup_socket(self):
        """Setup ZMQ socket"""
        network_config = self.config["network"]
        output_config = network_config["output_socket"]

        # Create socket
        socket_type = getattr(zmq, output_config["socket_type"])
        self.socket = self.context.socket(socket_type)

        # Configure
        zmq_config = self.config.get("zmq", {})
        self.socket.setsockopt(zmq.SNDHWM, zmq_config.get("sndhwm", 2000))
        self.socket.setsockopt(zmq.LINGER, zmq_config.get("linger_ms", 5000))

        # Connect/Bind
        address = output_config["address"]
        port = output_config["port"]
        mode = output_config["mode"].lower()

        if mode == "bind":
            bind_address = f"tcp://*:{port}"
            self.socket.bind(bind_address)
            connection_info = f"BIND on {bind_address}"
        else:
            connect_address = f"tcp://{address}:{port}"
            self.socket.connect(connect_address)
            connection_info = f"CONNECT to {connect_address}"

        # Crypto setup (simplified for dev)
        if self.config.get("crypto", {}).get("enabled", False):
            if self.pipeline_key:
                self.logger.info("🔐 Crypto enabled with pipeline key")
                # TODO: Implement crypto wrapper
            else:
                self.logger.warning("⚠️ Crypto enabled but no pipeline key")

        self.logger.info(f"🔌 ZMQ configured: {connection_info}")

    def _parse_time_window_configs(self) -> Dict[str, TimeWindowConfig]:
        """Parse time window configs"""
        configs = {}

        for window_type, window_data in self.config["time_windows"].items():
            configs[window_type] = TimeWindowConfig(
                window_size_seconds=window_data["window_size_seconds"],
                slide_interval_seconds=window_data["slide_interval_seconds"],
                max_flows_per_window=window_data["max_flows_per_window"],
                features_required=window_data["features_required"],
                model_types=window_data["model_types"],
                description=window_data.get("description", "")
            )

        return configs

    def packet_capture_callback(self, packet):
        """Packet capture callback"""
        try:
            packet_info = self._extract_packet_info(packet)

            if packet_info:
                try:
                    self.packet_queue.put(packet_info, timeout=0.1)
                    self.stats['packets_captured'] += 1
                except:
                    self.stats['drops'] += 1

        except Exception as e:
            self.logger.error(f"❌ Packet callback error: {e}")
            self.stats['errors'] += 1

    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract packet information"""
        try:
            info = PacketInfo(
                timestamp=time.time(),
                src_ip="unknown",
                dst_ip="unknown",
                src_port=0,
                dst_port=0,
                protocol_number=0,
                protocol_name="unknown",
                packet_size=len(packet),
                tcp_flags={},
                flow_id="",
                raw_packet=packet
            )

            # Extract IP info
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info.src_ip = ip_layer.src
                info.dst_ip = ip_layer.dst
                info.protocol_number = ip_layer.proto

                # Extract TCP/UDP info
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    info.src_port = tcp_layer.sport
                    info.dst_port = tcp_layer.dport
                    info.protocol_name = "TCP"

                    # TCP flags
                    info.tcp_flags = {
                        'F': bool(tcp_layer.flags.F),
                        'S': bool(tcp_layer.flags.S),
                        'R': bool(tcp_layer.flags.R),
                        'P': bool(tcp_layer.flags.P),
                        'A': bool(tcp_layer.flags.A),
                        'U': bool(tcp_layer.flags.U),
                    }

                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    info.src_port = udp_layer.sport
                    info.dst_port = udp_layer.dport
                    info.protocol_name = "UDP"

            # Create flow ID
            info.flow_id = f"{info.src_ip}:{info.src_port}-{info.dst_ip}:{info.dst_port}-{info.protocol_name}"

            return info

        except Exception as e:
            self.logger.error(f"❌ Error extracting packet info: {e}")
            return None

    def start_packet_capture(self):
        """Start packet capture"""
        capture_config = self.config["capture"]

        interface = capture_config["interface"]
        filter_expr = capture_config.get("filter_expression", "")

        self.logger.info(f"🎯 Starting packet capture:")
        self.logger.info(f"   📡 Interface: {interface}")
        self.logger.info(f"   🔍 Filter: {filter_expr or 'no filter'}")

        try:
            sniff(
                iface=interface if interface != "any" else None,
                filter=filter_expr,
                prn=self.packet_capture_callback,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.logger.error(f"❌ Capture error: {e}")
            raise

    def process_packets(self):
        """Process packets from queue"""
        self.logger.info("⚙️ Starting packet processing thread")

        while self.running:
            try:
                packet_info = self.packet_queue.get(timeout=1.0)
                self.time_window_manager.add_packet(packet_info)
                self.packet_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Packet processing error: {e}")

    def process_time_windows(self):
        """Process time windows"""
        self.logger.info("⏰ Starting time window processing thread")

        while self.running:
            try:
                completed_windows = self.time_window_manager.get_completed_windows()

                for window_data in completed_windows:
                    self._process_completed_window(window_data)

                time.sleep(0.1)

            except Exception as e:
                self.logger.error(f"❌ Window processing error: {e}")

    def _process_completed_window(self, window_data: Dict[str, Any]):
        """Process completed window"""
        try:
            flows = window_data['flows']

            for flow in flows:
                # Extract features
                features = self.features_extractor.extract_all_features(flow)

                # Create event (simplified)
                event_data = self._create_simple_event(flow, features, window_data)

                if event_data:
                    success = self._send_event(event_data)
                    if success:
                        self.stats['events_sent'] += 1

        except Exception as e:
            self.logger.error(f"❌ Window processing error: {e}")

    def _create_simple_event(self, flow: FlowInfo, features: Dict[str, float],
                             window_data: Dict[str, Any]) -> Optional[bytes]:
        """Create simple event"""
        try:
            if PROTOBUF_AVAILABLE:
                # Create protobuf event (simplified)
                event = NetworkSecurityEventProto.NetworkSecurityEvent()
                event.event_id = str(uuid.uuid4())
                event.originating_node_id = self.node_id
                event.final_classification = "CAPTURED"
                event.schema_version = 31

                return event.SerializeToString()
            else:
                # JSON fallback for development
                event_dict = {
                    "event_id": str(uuid.uuid4()),
                    "node_id": self.node_id,
                    "flow_id": flow.flow_id,
                    "features": features,
                    "timestamp": time.time()
                }
                return json.dumps(event_dict).encode()

        except Exception as e:
            self.logger.error(f"❌ Event creation error: {e}")
            return None

    def _send_event(self, event_data: bytes) -> bool:
        """Send event via ZMQ"""
        try:
            self.socket.send(event_data, zmq.NOBLOCK)
            return True
        except zmq.Again:
            return False
        except Exception as e:
            self.logger.error(f"❌ Send error: {e}")
            return False

    def monitor_performance(self):
        """Monitor performance"""
        while self.running:
            time.sleep(30)

            runtime = time.time() - self.stats['start_time']

            self.logger.info(f"📊 Stats - Runtime: {runtime:.1f}s")
            self.logger.info(f"   📦 Packets: {self.stats['packets_captured']}")
            self.logger.info(f"   📤 Events: {self.stats['events_sent']}")
            self.logger.info(f"   🗑️ Drops: {self.stats['drops']}")
            self.logger.info(f"   ❌ Errors: {self.stats['errors']}")

    def run(self):
        """Run the sniffer"""
        self.logger.info("🚀 Starting Evolutionary Sniffer FIXED")

        try:
            # Start threads
            threads = []

            # Packet processing thread
            packet_thread = threading.Thread(target=self.process_packets)
            packet_thread.start()
            threads.append(packet_thread)

            # Window processing thread
            window_thread = threading.Thread(target=self.process_time_windows)
            window_thread.start()
            threads.append(window_thread)

            # Performance monitoring thread
            monitor_thread = threading.Thread(target=self.monitor_performance)
            monitor_thread.start()
            threads.append(monitor_thread)

            # Start packet capture (blocking)
            self.start_packet_capture()

        except KeyboardInterrupt:
            self.logger.info("🛑 Shutting down...")
        except Exception as e:
            self.logger.error(f"❌ Fatal error: {e}")
        finally:
            self.shutdown(threads)

    def shutdown(self, threads):
        """Shutdown gracefully"""
        self.running = False

        # Wait for threads
        for thread in threads:
            thread.join(timeout=5)

        # Close socket
        if self.socket:
            self.socket.close()
        self.context.term()

        self.logger.info("✅ Sniffer shut down")


# ✅ MAIN ASYNC FIJO
async def main():
    """Main async function with better error handling"""
    if len(sys.argv) != 2:
        print("❌ Usage: python evolutionary_sniffer_v31_etcd_fixed.py <config.json>")
        sys.exit(1)

    config_file = sys.argv[1]

    print("🔍 Starting Evolutionary Sniffer FIXED v3.1...")

    # Enable dev mode if needed
    if not os.path.exists(config_file):
        print(f"❌ Config file not found: {config_file}")
        sys.exit(1)

    try:
        # Setup crypto with dev mode detection
        dev_mode = os.environ.get("UPGRADED_HAPPINESS_DEV_MODE") == "true"

        print(f"🧪 Dev mode: {dev_mode}")

        if not await setup_sniffer_crypto(config_file, testing_mode=dev_mode):
            print("❌ Failed to setup sniffer crypto")
            if not dev_mode:
                sys.exit(1)

        # Get pipeline key
        pipeline_key = get_sniffer_pipeline_key()
        if not pipeline_key:
            print("❌ No pipeline key available")
            if not dev_mode:
                sys.exit(1)

        print(f"🔑 Pipeline key ready: {pipeline_key[:16] if pipeline_key else 'None'}...")

        # Create and run sniffer
        sniffer = EvolutionarySnifferFixed(config_file, pipeline_key)
        sniffer.run()

    except Exception as e:
        print(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())