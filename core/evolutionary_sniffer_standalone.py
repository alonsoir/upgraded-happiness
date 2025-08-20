#!/usr/bin/env python3
"""
🚀 EVOLUTIONARY SNIFFER ZMQ OPTIMIZED v3.1
evolutionary_sniffer_zmq_optimized.py

VERSIÓN OPTIMIZADA PARA ZMQ:
✅ Manejo inteligente de backpressure
✅ Rate limiting adaptativo
✅ Circuit breaker para ZMQ
✅ Batching de eventos
✅ Métricas avanzadas de rendimiento
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
from queue import Queue, Empty
from typing import Dict, Any, Optional, List
from datetime import datetime
from collections import deque
import statistics

# 🔧 SETUP ENVIRONMENT
if 'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION' not in os.environ:
    os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

# 📦 Protobuf v3.1.0 - REQUERIDO - Importación robusta
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkSecurityEventProto = None


def import_protobuf_module():
    """Importa el módulo protobuf v3.1.0 con múltiples estrategias"""
    global NetworkSecurityEventProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    import_strategies = [
        ("protocols.v3_1.network_security_clean_v31_pb2", "Paquete protocols.v3_1"),
        ("protocols.network_security_clean_v31_pb2", "Paquete protocols"),
        ("network_security_clean_v31_pb2", "Importación directa"),
    ]

    for import_path, description in import_strategies:
        try:
            NetworkSecurityEventProto = __import__(import_path, fromlist=[''])
            PROTOBUF_AVAILABLE = True
            PROTOBUF_VERSION = "v3.1.0"
            print(f"✅ Protobuf v3.1 cargado: {description} ({import_path})")
            return True
        except ImportError:
            continue

    # Estrategia 2: Path dinámico
    current_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [
        os.path.join(current_dir, '..', 'protocols', 'v3_1'),
        os.path.join(current_dir, 'protocols', 'v3_1'),
        os.path.join(os.getcwd(), 'protocols', 'v3_1'),
    ]

    for protocols_path in possible_paths:
        protocols_path = os.path.abspath(protocols_path)
        pb2_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')

        if os.path.exists(pb2_file):
            try:
                sys.path.insert(0, protocols_path)
                import network_security_clean_v31_pb2 as NetworkSecurityEventProto
                PROTOBUF_AVAILABLE = True
                PROTOBUF_VERSION = "v3.1.0"
                print(f"✅ Protobuf v3.1 cargado desde path: {protocols_path}")
                return True
            except ImportError as e:
                sys.path.remove(protocols_path)
                continue

    return False


import_protobuf_module()

# ✅ IMPORTS COMPONENTES
from etcd_crypto_client_sniffer_fixed import (
    setup_sniffer_crypto,
    get_sniffer_pipeline_key
)

from sniffer_components import (
    TimeWindowConfig,
    PacketInfo,
    FlowInfo,
    NetworkFeaturesExtractor,
    TimeWindowManager
)

# 📦 Scapy
try:
    from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("❌ Scapy REQUERIDO - pip install scapy")


class CircuitBreaker:
    """Circuit breaker para ZMQ sends"""

    def __init__(self, failure_threshold: int = 50, recovery_timeout: int = 30, half_open_max_calls: int = 5):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.half_open_calls = 0

    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        if self.state == "OPEN":
            if self._should_attempt_reset():
                self.state = "HALF_OPEN"
                self.half_open_calls = 0
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e

    def _on_success(self):
        """Handle successful call"""
        if self.state == "HALF_OPEN":
            self.half_open_calls += 1
            if self.half_open_calls >= self.half_open_max_calls:
                self.state = "CLOSED"
                self.failure_count = 0
        else:
            self.failure_count = 0

    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"

    def _should_attempt_reset(self) -> bool:
        """Check if should attempt to reset circuit"""
        return (self.last_failure_time and
                time.time() - self.last_failure_time >= self.recovery_timeout)


class AdaptiveRateLimiter:
    """Rate limiter adaptativo basado en éxito/fallo de ZMQ"""

    def __init__(self, initial_rate: float = 1000.0, min_rate: float = 10.0, max_rate: float = 10000.0):
        self.current_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.last_check = time.time()
        self.success_window = deque(maxlen=100)  # Last 100 attempts
        self.adjustment_factor = 1.1

    def should_allow(self) -> bool:
        """Check if current request should be allowed"""
        now = time.time()
        time_since_last = now - self.last_check

        if time_since_last < (1.0 / self.current_rate):
            return False

        self.last_check = now
        return True

    def record_attempt(self, success: bool):
        """Record attempt result"""
        self.success_window.append(success)
        self._adjust_rate()

    def _adjust_rate(self):
        """Adjust rate based on recent success rate"""
        if len(self.success_window) < 10:
            return

        recent_success_rate = sum(self.success_window) / len(self.success_window)

        if recent_success_rate > 0.95:  # >95% success -> increase rate
            self.current_rate = min(self.max_rate, self.current_rate * self.adjustment_factor)
        elif recent_success_rate < 0.80:  # <80% success -> decrease rate
            self.current_rate = max(self.min_rate, self.current_rate / self.adjustment_factor)

    def get_stats(self) -> Dict[str, float]:
        """Get rate limiter statistics"""
        if not self.success_window:
            return {"current_rate": self.current_rate, "success_rate": 0.0}

        return {
            "current_rate": self.current_rate,
            "success_rate": sum(self.success_window) / len(self.success_window),
            "attempts_tracked": len(self.success_window)
        }


class EventBatcher:
    """Batching de eventos para mejorar throughput ZMQ"""

    def __init__(self, max_batch_size: int = 10, max_wait_time: float = 0.1):
        self.max_batch_size = max_batch_size
        self.max_wait_time = max_wait_time
        self.events_buffer = []
        self.last_flush = time.time()

    def add_event(self, event_data: bytes) -> Optional[List[bytes]]:
        """Add event to batch, return batch if ready to send"""
        self.events_buffer.append(event_data)

        # Check if should flush
        if (len(self.events_buffer) >= self.max_batch_size or
                time.time() - self.last_flush >= self.max_wait_time):
            return self.flush()

        return None

    def flush(self) -> List[bytes]:
        """Flush current batch"""
        if not self.events_buffer:
            return []

        batch = self.events_buffer.copy()
        self.events_buffer.clear()
        self.last_flush = time.time()
        return batch

    def force_flush(self) -> List[bytes]:
        """Force flush remaining events"""
        return self.flush()


class ProtobufEnumHelper:
    """Helper para manejar enums de protobuf correctamente"""

    @staticmethod
    def get_window_type_enum(window_type_str: str) -> int:
        if not PROTOBUF_AVAILABLE:
            return 0
        try:
            window_type_mapping = {
                "SLIDING": NetworkSecurityEventProto.TimeWindow.WindowType.SLIDING,
                "TUMBLING": NetworkSecurityEventProto.TimeWindow.WindowType.TUMBLING,
                "SESSION_BASED": NetworkSecurityEventProto.TimeWindow.WindowType.SESSION_BASED,
                "ADAPTIVE": NetworkSecurityEventProto.TimeWindow.WindowType.ADAPTIVE,
            }
            return window_type_mapping.get(window_type_str.upper(), 0)
        except AttributeError:
            return 0

    @staticmethod
    def get_node_role_enum(role_str: str) -> int:
        if not PROTOBUF_AVAILABLE:
            return 0
        try:
            role_mapping = {
                "PACKET_SNIFFER": NetworkSecurityEventProto.DistributedNode.NodeRole.PACKET_SNIFFER,
                "FEATURE_PROCESSOR": NetworkSecurityEventProto.DistributedNode.NodeRole.FEATURE_PROCESSOR,
                "GEOIP_ENRICHER": NetworkSecurityEventProto.DistributedNode.NodeRole.GEOIP_ENRICHER,
                "ML_ANALYZER": NetworkSecurityEventProto.DistributedNode.NodeRole.ML_ANALYZER,
                "THREAT_DETECTOR": NetworkSecurityEventProto.DistributedNode.NodeRole.THREAT_DETECTOR,
                "FIREWALL_CONTROLLER": NetworkSecurityEventProto.DistributedNode.NodeRole.FIREWALL_CONTROLLER,
                "DATA_AGGREGATOR": NetworkSecurityEventProto.DistributedNode.NodeRole.DATA_AGGREGATOR,
                "DASHBOARD_VISUALIZER": NetworkSecurityEventProto.DistributedNode.NodeRole.DASHBOARD_VISUALIZER,
                "CLUSTER_COORDINATOR": NetworkSecurityEventProto.DistributedNode.NodeRole.CLUSTER_COORDINATOR,
            }
            return role_mapping.get(role_str.upper(), 0)
        except AttributeError:
            return 0

    @staticmethod
    def get_node_status_enum(status_str: str) -> int:
        if not PROTOBUF_AVAILABLE:
            return 0
        try:
            status_mapping = {
                "ACTIVE": NetworkSecurityEventProto.DistributedNode.NodeStatus.ACTIVE,
                "STARTING": NetworkSecurityEventProto.DistributedNode.NodeStatus.STARTING,
                "STOPPING": NetworkSecurityEventProto.DistributedNode.NodeStatus.STOPPING,
                "ERROR": NetworkSecurityEventProto.DistributedNode.NodeStatus.ERROR,
                "MAINTENANCE": NetworkSecurityEventProto.DistributedNode.NodeStatus.MAINTENANCE,
                "OVERLOADED": NetworkSecurityEventProto.DistributedNode.NodeStatus.OVERLOADED,
            }
            return status_mapping.get(status_str.upper(), 0)
        except AttributeError:
            return 0


class EvolutionarySnifferZMQOptimized:
    """
    Evolutionary Sniffer con optimizaciones ZMQ avanzadas
    """

    def __init__(self, config_file: str, pipeline_key: Optional[str] = None):
        """Initialize optimized sniffer"""

        # Load config
        self.config = self._load_config_strict(config_file)
        self.config_file = config_file
        self.pipeline_key = pipeline_key

        # Basic setup
        self.node_id = self.config["node_id"]
        self.process_id = os.getpid()
        self.start_time = time.time()
        self.container_id = self._get_container_id()
        self.system_info = self._gather_system_info()

        # Helpers
        self.enum_helper = ProtobufEnumHelper()

        # Setup logging
        self.setup_logging()
        self.logger.info(f"🚀 Evolutionary Sniffer ZMQ OPTIMIZED v3.1 initializing...")
        self.logger.info(f"   🔑 Pipeline key: {'✅' if pipeline_key else '❌'}")
        self.logger.info(f"   📦 Protobuf available: {'✅' if PROTOBUF_AVAILABLE else '❌'}")

        # Verify dependencies
        self._verify_dependencies()

        # Setup ZMQ optimizado
        self.context = zmq.Context()
        self.socket = None
        self.crypto_wrapper = None

        # ZMQ Performance components
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=self.config.get("backpressure", {}).get("circuit_breaker", {}).get("failure_threshold",
                                                                                                 50),
            recovery_timeout=self.config.get("backpressure", {}).get("circuit_breaker", {}).get("recovery_timeout", 30),
            half_open_max_calls=self.config.get("backpressure", {}).get("circuit_breaker", {}).get(
                "half_open_max_calls", 5)
        )

        self.rate_limiter = AdaptiveRateLimiter(
            initial_rate=1000.0,
            min_rate=10.0,
            max_rate=10000.0
        )

        self.event_batcher = EventBatcher(
            max_batch_size=self.config.get("processing", {}).get("batch_size", 10),
            max_wait_time=0.1
        )

        self.setup_socket_optimized()

        # Setup components
        self.features_extractor = NetworkFeaturesExtractor()
        self.time_window_manager = TimeWindowManager(
            self._parse_time_window_configs(),
            self.logger
        )

        # Queues optimizados
        queue_size = self.config["processing"]["internal_queue_size"]
        self.packet_queue = Queue(maxsize=queue_size)

        # Stats avanzadas
        self.stats = {
            'packets_captured': 0,
            'flows_created': 0,
            'windows_completed': 0,
            'events_sent': 0,
            'events_batched': 0,
            'features_extracted': 0,
            'drops': 0,
            'errors': 0,
            'protobuf_errors': 0,
            'zmq_buffer_full': 0,
            'circuit_breaker_open': 0,
            'rate_limited': 0,
            'start_time': time.time(),
            'last_stats_time': time.time(),
            'send_latencies': deque(maxlen=1000),  # Track send performance
        }

        # Control
        self.running = True
        self.handshake_sent = False

        self.logger.info("✅ Evolutionary Sniffer ZMQ Optimized initialized")

    def _load_config_strict(self, config_file: str) -> Dict[str, Any]:
        """Load config with validation"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"❌ Config file not found: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Invalid JSON: {e}")

        required = ["node_id", "network", "capture", "processing", "time_windows", "etcd_crypto"]
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

    def _get_container_id(self) -> Optional[str]:
        """Get container ID if available"""
        try:
            with open('/proc/self/cgroup', 'r') as f:
                content = f.read()
                for line in content.split('\n'):
                    if 'docker' in line:
                        return line.split('/')[-1][:12]
            return None
        except:
            return None

    def _gather_system_info(self) -> Dict[str, Any]:
        """Gather system information"""
        return {
            'hostname': socket.gethostname(),
            'os_name': platform.system(),
            'os_version': platform.release(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': round(psutil.virtual_memory().total / (1024 ** 3), 2)
        }

    def setup_logging(self):
        """Setup logging"""
        log_config = self.config["logging"]
        level = getattr(logging, log_config["level"].upper())

        formatter = logging.Formatter(
            "%(asctime)s - %(name)-20s - %(levelname)-8s - "
            "[node_id:{node_id}] [pid:{pid}] [ZMQ-OPT] - %(message)s".format(
                node_id=self.node_id,
                pid=self.process_id
            )
        )

        self.logger = logging.getLogger(f"sniffer_zmq_opt_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler if configured
        if log_config.get("file"):
            try:
                log_file = log_config["file"]
                os.makedirs(os.path.dirname(log_file), exist_ok=True)

                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

                self.logger.info(f"📝 File logging enabled: {log_file}")
            except Exception as e:
                self.logger.error(f"❌ Error setting up file logging: {e}")

    def setup_socket_optimized(self):
        """Setup ZMQ socket with optimizations"""
        network_config = self.config["network"]
        output_config = network_config["output_socket"]

        # Create socket
        socket_type = getattr(zmq, output_config["socket_type"])
        self.socket = self.context.socket(socket_type)

        # Apply ZMQ optimizations from config
        zmq_config = self.config.get("zmq", {})

        optimizations = {
            zmq.SNDHWM: zmq_config.get("sndhwm", 10000),
            zmq.RCVHWM: zmq_config.get("rcvhwm", 10000),
            zmq.LINGER: zmq_config.get("linger_ms", 0),
            zmq.SNDTIMEO: zmq_config.get("send_timeout_ms", 1),
            zmq.RCVTIMEO: zmq_config.get("recv_timeout_ms", 1),
            zmq.IMMEDIATE: zmq_config.get("immediate", 1),
            zmq.SNDBUF: zmq_config.get("sndbuf", 1048576),
            zmq.RCVBUF: zmq_config.get("rcvbuf", 1048576),
        }

        # Apply TCP-specific optimizations if available
        tcp_opts = {
            zmq.TCP_KEEPALIVE: zmq_config.get("tcp_keepalive", 1),
            zmq.TCP_KEEPALIVE_IDLE: zmq_config.get("tcp_keepalive_idle", 600),
            zmq.TCP_KEEPALIVE_CNT: zmq_config.get("tcp_keepalive_cnt", 3),
            zmq.TCP_KEEPALIVE_INTVL: zmq_config.get("tcp_keepalive_intvl", 60),
        }

        # Apply optimizations
        for opt, value in optimizations.items():
            try:
                self.socket.setsockopt(opt, value)
                self.logger.debug(f"✅ ZMQ option {opt} = {value}")
            except Exception as e:
                self.logger.warning(f"⚠️ Could not set ZMQ option {opt}: {e}")

        for opt, value in tcp_opts.items():
            try:
                self.socket.setsockopt(opt, value)
                self.logger.debug(f"✅ TCP option {opt} = {value}")
            except Exception as e:
                self.logger.debug(f"📝 TCP option {opt} not available: {e}")

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

        self.logger.info(f"🔌 ZMQ optimized socket configured: {connection_info}")
        self.logger.info(f"   📊 SNDHWM: {zmq_config.get('sndhwm', 10000)}")
        self.logger.info(f"   ⏱️ SNDTIMEO: {zmq_config.get('send_timeout_ms', 1)}ms")
        self.logger.info(f"   🔧 Circuit breaker enabled")
        self.logger.info(f"   🎛️ Adaptive rate limiting enabled")
        self.logger.info(f"   📦 Event batching enabled")

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

        self.logger.info(f"⏰ Configured {len(configs)} time windows:")
        for window_type, config in configs.items():
            self.logger.info(f"   📊 {window_type}: {config.window_size_seconds}s window, "
                             f"{len(config.features_required)} features, "
                             f"models: {config.model_types}")

        return configs

    def packet_capture_callback(self, packet):
        """Packet capture callback"""
        try:
            packet_info = self._extract_packet_info(packet)

            if packet_info and self._should_process_packet(packet_info):
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
                        'E': bool(tcp_layer.flags.E),
                        'C': bool(tcp_layer.flags.C),
                    }

                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    info.src_port = udp_layer.sport
                    info.dst_port = udp_layer.dport
                    info.protocol_name = "UDP"
                else:
                    info.protocol_name = "OTHER"

            # Create flow ID
            info.flow_id = f"{info.src_ip}:{info.src_port}-{info.dst_ip}:{info.dst_port}-{info.protocol_name}"

            return info

        except Exception as e:
            self.logger.error(f"❌ Error extracting packet info: {e}")
            return None

    def _should_process_packet(self, packet_info: PacketInfo) -> bool:
        """Determine if packet should be processed"""
        return True

    def start_packet_capture(self):
        """Start packet capture"""
        capture_config = self.config["capture"]

        interface = capture_config["interface"]
        filter_expr = capture_config.get("filter_expression", "")

        self.logger.info(f"🎯 Starting optimized packet capture:")
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
            self.logger.error("💡 Tip: run with sudo for promiscuous capture")
            raise

    def process_packets(self):
        """Process packets from queue"""
        self.logger.info("⚙️ Starting optimized packet processing thread")

        while self.running:
            try:
                packet_info = self.packet_queue.get(timeout=1.0)
                self.time_window_manager.add_packet(packet_info)
                self.packet_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Packet processing error: {e}")
                self.stats['errors'] += 1

    def process_time_windows(self):
        """Process time windows"""
        self.logger.info("⏰ Starting optimized time window processing thread")

        while self.running:
            try:
                completed_windows = self.time_window_manager.get_completed_windows()

                for window_data in completed_windows:
                    self._process_completed_window(window_data)

                # Force flush batched events periodically
                self._flush_batched_events()

                time.sleep(0.1)

            except Exception as e:
                self.logger.error(f"❌ Window processing error: {e}")
                self.stats['errors'] += 1

    def _process_completed_window(self, window_data: Dict[str, Any]):
        """Process completed window"""
        try:
            window_type = window_data['window_type']
            config = window_data['config']
            flows = window_data['flows']

            self.logger.debug(f"📊 Processing window {window_type} with {len(flows)} flows")

            for flow in flows:
                # Extract features
                all_features = self.features_extractor.extract_all_features(flow)
                self.stats['features_extracted'] += 1

                # Create events for each model type
                for model_type in config.model_types:
                    event_data = self._create_network_security_event(
                        flow, all_features, window_data, model_type
                    )

                    if event_data:
                        self._send_event_optimized(event_data)

            self.stats['windows_completed'] += 1

        except Exception as e:
            self.logger.error(f"❌ Window processing error: {e}")
            self.stats['errors'] += 1

    def _create_network_security_event(self, flow: FlowInfo, all_features: Dict[str, float],
                                       window_data: Dict[str, Any], model_type: str) -> Optional[bytes]:
        """Create NetworkSecurityEvent con manejo correcto de enums"""

        if not PROTOBUF_AVAILABLE:
            self.logger.warning("⚠️ Protobuf not available - skipping event creation")
            return None

        try:
            from datetime import datetime, timedelta

            # Create protobuf event
            event = NetworkSecurityEventProto.NetworkSecurityEvent()

            # Basic identification
            event.event_id = str(uuid.uuid4())
            event.event_timestamp.FromDatetime(datetime.fromtimestamp(time.time()))
            event.originating_node_id = self.node_id

            # Network features
            network_features = event.network_features
            network_features.source_ip = flow.src_ip
            network_features.destination_ip = flow.dst_ip
            network_features.source_port = flow.src_port
            network_features.destination_port = flow.dst_port
            network_features.protocol_number = flow.forward_packets[0].protocol_number if flow.forward_packets else 0
            network_features.protocol_name = flow.protocol

            # Timing features
            network_features.flow_start_time.FromDatetime(datetime.fromtimestamp(flow.start_time))
            duration_seconds = flow.last_seen - flow.start_time
            network_features.flow_duration.FromTimedelta(timedelta(seconds=duration_seconds))
            network_features.flow_duration_microseconds = int(duration_seconds * 1_000_000)

            # Basic packet/byte counts
            network_features.total_forward_packets = len(flow.forward_packets)
            network_features.total_backward_packets = len(flow.backward_packets)
            network_features.total_forward_bytes = flow.total_forward_bytes
            network_features.total_backward_bytes = flow.total_backward_bytes

            # Model-specific features
            model_features = self.features_extractor.get_features_for_model(all_features, model_type)

            if model_type == "ddos_83":
                network_features.ddos_features[:] = model_features
            elif model_type == "rf_23":
                network_features.general_attack_features[:] = model_features
            elif model_type == "internal_4":
                network_features.internal_traffic_features[:] = model_features
            else:
                for i, feature_value in enumerate(model_features[:10]):
                    network_features.custom_features[f"feature_{i}"] = feature_value

            # Capturing node info
            capturing_node = event.capturing_node
            capturing_node.node_id = self.node_id
            capturing_node.node_hostname = self.system_info.get('hostname', 'unknown')
            capturing_node.node_role = self.enum_helper.get_node_role_enum("PACKET_SNIFFER")
            capturing_node.node_status = self.enum_helper.get_node_status_enum("ACTIVE")
            capturing_node.agent_version = self.config.get("version", "3.1.0")
            capturing_node.process_id = self.process_id

            # Time window
            time_window = event.time_window
            time_window.window_start.FromDatetime(datetime.fromtimestamp(window_data['start_time']))
            time_window.window_end.FromDatetime(datetime.fromtimestamp(window_data['end_time']))
            time_window.sequence_number = int(time.time())
            time_window.window_type = self.enum_helper.get_window_type_enum("SLIDING")

            # Pipeline tracking
            pipeline_tracking = event.pipeline_tracking
            pipeline_tracking.pipeline_id = str(uuid.uuid4())
            pipeline_tracking.sniffer_process_id = self.process_id
            pipeline_tracking.pipeline_hops_count = 1
            pipeline_tracking.processing_path = f"sniffer[{self.node_id}]"
            pipeline_tracking.retry_attempts = 0
            pipeline_tracking.requires_reprocessing = False

            # Final metadata
            event.overall_threat_score = 0.0
            event.final_classification = "CAPTURED"
            event.threat_category = "UNKNOWN"
            event.correlation_id = flow.flow_id
            event.event_chain_id = f"chain_{flow.flow_id}_{int(time.time())}"
            event.schema_version = 31
            event.protobuf_version = "3.1.0"

            # Serialize
            serialized_data = event.SerializeToString()
            return serialized_data

        except Exception as e:
            self.logger.error(f"❌ Event creation error: {e}")
            self.stats['protobuf_errors'] += 1
            return None

    def _send_event_optimized(self, event_data: bytes):
        """Send event with optimizations (batching, rate limiting, circuit breaker)"""
        try:
            # Check rate limiter
            if not self.rate_limiter.should_allow():
                self.stats['rate_limited'] += 1
                return

            # Add to batch
            batch = self.event_batcher.add_event(event_data)

            if batch:
                self._send_batch(batch)

        except Exception as e:
            self.logger.error(f"❌ Send optimization error: {e}")
            self.stats['errors'] += 1

    def _send_batch(self, batch: List[bytes]):
        """Send batch of events"""
        if not batch:
            return

        try:
            # Use circuit breaker
            send_start = time.time()

            success = self.circuit_breaker.call(self._send_batch_zmq, batch)

            send_latency = time.time() - send_start
            self.stats['send_latencies'].append(send_latency)

            if success:
                self.stats['events_sent'] += len(batch)
                self.stats['events_batched'] += 1
                self.rate_limiter.record_attempt(True)
            else:
                self.stats['drops'] += len(batch)
                self.rate_limiter.record_attempt(False)

        except Exception as e:
            if "Circuit breaker is OPEN" in str(e):
                self.stats['circuit_breaker_open'] += 1
                self.logger.warning("⚠️ Circuit breaker is OPEN - dropping batch")
            else:
                self.logger.error(f"❌ Batch send error: {e}")

            self.stats['drops'] += len(batch)
            self.rate_limiter.record_attempt(False)

    def _send_batch_zmq(self, batch: List[bytes]) -> bool:
        """Send batch via ZMQ"""
        try:
            # For simplicity, send events individually but track as batch
            for event_data in batch:
                self.socket.send(event_data, zmq.NOBLOCK)
            return True

        except zmq.Again:
            self.stats['zmq_buffer_full'] += len(batch)
            raise Exception("ZMQ buffer full")
        except zmq.ZMQError as e:
            raise Exception(f"ZMQ error: {e}")

    def _flush_batched_events(self):
        """Flush any remaining batched events"""
        try:
            remaining_batch = self.event_batcher.force_flush()
            if remaining_batch:
                self._send_batch(remaining_batch)
        except Exception as e:
            self.logger.error(f"❌ Flush error: {e}")

    def send_handshake(self):
        """Send initial handshake"""
        if self.handshake_sent or not PROTOBUF_AVAILABLE:
            return

        try:
            from datetime import datetime

            event = NetworkSecurityEventProto.NetworkSecurityEvent()

            event.event_id = str(uuid.uuid4())
            event.event_timestamp.FromDatetime(datetime.now())
            event.originating_node_id = self.node_id

            capturing_node = event.capturing_node
            capturing_node.node_id = self.node_id
            capturing_node.node_hostname = self.system_info['hostname']
            capturing_node.node_role = self.enum_helper.get_node_role_enum("PACKET_SNIFFER")
            capturing_node.node_status = self.enum_helper.get_node_status_enum("STARTING")
            capturing_node.agent_version = self.config.get("version", "3.1.0")
            capturing_node.process_id = self.process_id

            event.final_classification = "HANDSHAKE"
            event.threat_category = "SYSTEM"
            event.schema_version = 31
            event.protobuf_version = "3.1.0"
            event.custom_metadata["handshake"] = "initial"
            event.custom_metadata["capabilities"] = "packet_capture,feature_extraction,time_windows,zmq_optimized"
            event.event_tags.extend(["handshake", "sniffer_v31", "startup", "zmq_optimized"])

            event_data = event.SerializeToString()

            # Send handshake directly (bypass rate limiting)
            success = self._send_batch_zmq([event_data])

            if success:
                self.handshake_sent = True
                self.logger.info("🤝 Optimized handshake sent successfully")
            else:
                self.logger.warning("⚠️ Error sending handshake")

        except Exception as e:
            self.logger.error(f"❌ Handshake error: {e}")

    def monitor_performance(self):
        """Monitor performance with advanced metrics"""
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            self._log_advanced_performance_stats()

    def _log_advanced_performance_stats(self):
        """Log advanced performance statistics"""
        now = time.time()
        interval = now - self.stats['last_stats_time']

        if interval > 0:
            packet_rate = self.stats['packets_captured'] / interval
            event_rate = self.stats['events_sent'] / interval
            batch_rate = self.stats['events_batched'] / interval
        else:
            packet_rate = event_rate = batch_rate = 0

        # Calculate send latency stats
        latency_stats = {}
        if self.stats['send_latencies']:
            latencies = list(self.stats['send_latencies'])
            latency_stats = {
                'avg_ms': statistics.mean(latencies) * 1000,
                'p95_ms': statistics.quantiles(latencies, n=20)[18] * 1000 if len(latencies) > 5 else 0,
                'max_ms': max(latencies) * 1000,
            }

        # Get rate limiter stats
        rate_limiter_stats = self.rate_limiter.get_stats()

        self.logger.info(f"📊 Advanced Performance Stats v3.1:")
        self.logger.info(f"   📦 Packets: {self.stats['packets_captured']} ({packet_rate:.1f}/s)")
        self.logger.info(f"   📊 Features: {self.stats['features_extracted']}")
        self.logger.info(f"   ⏰ Windows: {self.stats['windows_completed']}")
        self.logger.info(f"   📤 Events: {self.stats['events_sent']} ({event_rate:.1f}/s)")
        self.logger.info(f"   📦 Batches: {self.stats['events_batched']} ({batch_rate:.1f}/s)")
        self.logger.info(f"   🗑️ Drops: {self.stats['drops']}")
        self.logger.info(f"   ❌ Errors: {self.stats['errors']}")
        self.logger.info(f"   🐛 Protobuf errors: {self.stats['protobuf_errors']}")
        self.logger.info(f"   ⚡ ZMQ buffer full: {self.stats['zmq_buffer_full']}")
        self.logger.info(f"   🔴 Circuit breaker open: {self.stats['circuit_breaker_open']}")
        self.logger.info(f"   🎛️ Rate limited: {self.stats['rate_limited']}")
        self.logger.info(f"   📋 Queue: {self.packet_queue.qsize()}")
        self.logger.info(f"   🏃 Flows: {len(self.time_window_manager.active_flows)}")

        if latency_stats:
            self.logger.info(f"   ⏱️ Send latency - Avg: {latency_stats['avg_ms']:.2f}ms, "
                             f"P95: {latency_stats['p95_ms']:.2f}ms, Max: {latency_stats['max_ms']:.2f}ms")

        self.logger.info(f"   🎛️ Rate limiter - Current: {rate_limiter_stats['current_rate']:.1f}/s, "
                         f"Success: {rate_limiter_stats['success_rate'] * 100:.1f}%")

        # Reset stats
        for key in ['packets_captured', 'features_extracted', 'windows_completed',
                    'events_sent', 'events_batched', 'drops', 'errors', 'protobuf_errors',
                    'zmq_buffer_full', 'circuit_breaker_open', 'rate_limited']:
            self.stats[key] = 0

        self.stats['send_latencies'].clear()
        self.stats['last_stats_time'] = now

    def run(self):
        """Run the optimized sniffer"""
        self.logger.info("🚀 Starting Evolutionary Sniffer ZMQ OPTIMIZED")

        try:
            # Send handshake
            self.send_handshake()

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

        # Flush remaining events
        try:
            self._flush_batched_events()
            self.logger.info("📦 Flushed remaining batched events")
        except Exception as e:
            self.logger.error(f"❌ Error flushing events: {e}")

        # Close crypto wrapper
        if self.crypto_wrapper:
            try:
                self.crypto_wrapper.close()
                self.logger.info("🔐 Crypto wrapper closed")
            except Exception as e:
                self.logger.error(f"❌ Error closing crypto wrapper: {e}")

        # Final stats
        runtime = time.time() - self.stats['start_time']
        self.logger.info(f"📊 Final stats - Runtime: {runtime:.1f}s")

        # Wait for threads
        for thread in threads:
            thread.join(timeout=5)

        # Close socket
        if self.socket:
            self.socket.close()
        self.context.term()

        self.logger.info("✅ Optimized sniffer shut down")


# ✅ MAIN ASYNC
async def main():
    """Main async function"""
    if len(sys.argv) != 2:
        print("❌ Usage: python evolutionary_sniffer_zmq_optimized.py <config.json>")
        sys.exit(1)

    config_file = sys.argv[1]

    print("🔍 Starting Evolutionary Sniffer ZMQ OPTIMIZED v3.1...")

    # Check config file exists
    if not os.path.exists(config_file):
        print(f"❌ Config file not found: {config_file}")
        sys.exit(1)

    try:
        # Setup crypto
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
        sniffer = EvolutionarySnifferZMQOptimized(config_file, pipeline_key)
        sniffer.run()

    except Exception as e:
        print(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())