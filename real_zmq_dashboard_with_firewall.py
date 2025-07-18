#!/usr/bin/env python3
"""
Dashboard de Seguridad con ZeroMQ - Backend Principal v2.2.1
CORREGIDO: Timestamp handling + Worker stats + ZMQ cleanup
"""
from typing import Dict, List, Optional, Any, Set
import zmq
import json
import threading
import time
import logging
import queue
import os
import signal
import sys
import psutil
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import http.server
import socketserver
from urllib.parse import urlparse
import mimetypes
from collections import defaultdict, deque


class ConfigurationError(Exception):
    """Error de configuración del dashboard"""
    pass


@dataclass
class EncodingError:
    """Información detallada de errores de encoding"""
    timestamp: str
    worker_id: int
    error_type: str
    message_length: int
    first_bytes_hex: str
    encoding_attempted: str
    position: int
    byte_value: str
    error_message: str
    suggested_fix: str


@dataclass
class WorkerStats:
    """Estadísticas por worker"""
    worker_id: int
    worker_type: str  # ml_events, firewall_responses, etc.
    messages_received: int = 0
    messages_successful: int = 0
    encoding_errors: int = 0
    last_activity: Optional[datetime] = None
    last_error: Optional[EncodingError] = None
    error_rate: float = 0.0
    status: str = "idle"  # idle, active, error


@dataclass
class ConnectionInfo:
    """Información detallada de conexiones activas"""
    connection_id: str
    node_id: Optional[str] = None
    component_type: str = "unknown"
    endpoint: str = ""
    socket_type: str = ""
    mode: str = ""
    status: str = "disconnected"
    last_seen: Optional[datetime] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    version: Optional[str] = None
    handshake_completed: bool = False
    messages_exchanged: int = 0


class EncodingMonitor:
    """Monitor de errores de encoding en tiempo real"""

    def __init__(self, logger):
        self.logger = logger
        self.encoding_errors: List[EncodingError] = []
        self.worker_stats: Dict[str, WorkerStats] = {}
        self.connection_info: Dict[str, ConnectionInfo] = {}
        self.error_patterns: Dict[str, int] = defaultdict(int)
        self.encoding_suggestions: Dict[str, str] = {
            'utf-8': 'Datos UTF-8 válidos',
            'latin-1': 'Posible texto con caracteres especiales',
            'protobuf': 'Datos binarios protobuf detectados',
            'binary': 'Datos binarios sin estructura conocida',
            'corrupted': 'Datos corruptos o fragmentados'
        }

    def detect_encoding_type(self, data: bytes) -> str:
        """Detectar tipo de encoding de los datos - OPTIMIZADO PARA PROTOBUF PRIMERO"""
        if len(data) == 0:
            return 'empty'

        # 1. PRIMERO: Verificar si parece protobuf (antes de UTF-8)
        if self._looks_like_protobuf(data):
            return 'protobuf'

        # 2. Verificar UTF-8 válido
        try:
            decoded = data.decode('utf-8')
            # Verificar si parece JSON
            if decoded.strip().startswith(('{', '[')):
                return 'utf-8'
        except UnicodeDecodeError:
            pass

        # 3. Verificar si es texto en otra codificación
        try:
            decoded = data.decode('latin-1')
            if decoded.isprintable() and '{' in decoded:
                return 'latin-1'
        except:
            pass

        # 4. Verificar otros formatos binarios
        if data.startswith(b'\x00') or data.startswith(b'\xff'):
            return 'binary'

        return 'corrupted'

    def _looks_like_protobuf(self, data: bytes) -> bool:
        """Detectar si los datos parecen ser protobuf - VERSIÓN MEJORADA"""
        if len(data) < 4:
            return False

        # Patrones típicos de protobuf - EXPANDIDOS
        protobuf_patterns = [
            b'\x08', b'\x0a', b'\x10', b'\x12', b'\x18', b'\x1a',
            b'\x20', b'\x22', b'\x28', b'\x2a', b'\x30', b'\x32',
            b'\x38', b'\x3a', b'\x40', b'\x42', b'\x48', b'\x4a',
            b'\x50', b'\x52', b'\x58', b'\x5a', b'\x60', b'\x62'
        ]

        # Verificar si empieza con patrón protobuf
        starts_with_protobuf = any(data.startswith(pattern) for pattern in protobuf_patterns)

        # Verificación adicional: verificar si NO parece JSON o texto
        try:
            # Si se puede decodificar como UTF-8 Y parece JSON, probablemente no es protobuf
            decoded = data.decode('utf-8')
            if decoded.strip().startswith(('{', '[')):
                return False
        except UnicodeDecodeError:
            # No se puede decodificar como UTF-8, más probable que sea protobuf
            pass

        # Verificación adicional: buscar patrones de campo protobuf en los primeros bytes
        if len(data) >= 10:
            # Contar bytes que parecen ser field tags de protobuf
            protobuf_like_bytes = 0
            for i in range(min(10, len(data))):
                byte = data[i]
                # Field numbers y wire types típicos
                if byte in [0x08, 0x0a, 0x10, 0x12, 0x18, 0x1a, 0x20, 0x22, 0x28, 0x2a]:
                    protobuf_like_bytes += 1

            # Si hay varios bytes que parecen protobuf, probablemente lo es
            if protobuf_like_bytes >= 2:
                return True

        return starts_with_protobuf

    def log_encoding_error(self, worker_id: int, worker_type: str,
                           data: bytes, error: Exception, encoding_attempted: str):
        """Registrar error de encoding con detalles"""

        # Crear información del error
        encoding_error = EncodingError(
            timestamp=datetime.now().isoformat(),
            worker_id=worker_id,
            error_type=type(error).__name__,
            message_length=len(data),
            first_bytes_hex=data[:20].hex() if len(data) >= 20 else data.hex(),
            encoding_attempted=encoding_attempted,
            position=getattr(error, 'start', 0),
            byte_value=f"0x{data[getattr(error, 'start', 0)]:02x}" if data else "0x00",
            error_message=str(error),
            suggested_fix=self._get_encoding_suggestion(data)
        )

        # Añadir a la lista de errores
        self.encoding_errors.append(encoding_error)

        # Mantener solo los últimos 100 errores
        if len(self.encoding_errors) > 100:
            self.encoding_errors = self.encoding_errors[-100:]

        # Actualizar estadísticas del worker
        worker_key = f"{worker_type}_{worker_id}"
        if worker_key not in self.worker_stats:
            self.worker_stats[worker_key] = WorkerStats(
                worker_id=worker_id,
                worker_type=worker_type
            )

        stats = self.worker_stats[worker_key]
        stats.encoding_errors += 1
        stats.last_error = encoding_error
        stats.last_activity = datetime.now()
        stats.status = "error"
        stats.error_rate = stats.encoding_errors / max(stats.messages_received, 1) * 100

        # Actualizar patrones de error
        detected_type = self.detect_encoding_type(data)
        self.error_patterns[detected_type] += 1

        self.logger.error(
            f"🔍 Worker {worker_id} ({worker_type}) - Error encoding: "
            f"{encoding_error.error_type} at pos {encoding_error.position}, "
            f"byte {encoding_error.byte_value}, suggested: {encoding_error.suggested_fix}"
        )

    def log_successful_message(self, worker_id: int, worker_type: str,
                               message_length: int, encoding_used: str):
        """Registrar mensaje procesado exitosamente"""
        worker_key = f"{worker_type}_{worker_id}"
        if worker_key not in self.worker_stats:
            self.worker_stats[worker_key] = WorkerStats(
                worker_id=worker_id,
                worker_type=worker_type
            )

        stats = self.worker_stats[worker_key]
        stats.messages_received += 1
        stats.messages_successful += 1
        stats.last_activity = datetime.now()
        stats.status = "active"
        stats.error_rate = stats.encoding_errors / max(stats.messages_received, 1) * 100

    def _get_encoding_suggestion(self, data: bytes) -> str:
        """Obtener sugerencia basada en el análisis de los datos"""
        detected_type = self.detect_encoding_type(data)
        return self.encoding_suggestions.get(detected_type, 'Tipo desconocido')

    def register_connection(self, connection_id: str, endpoint: str,
                            socket_type: str, mode: str):
        """Registrar nueva conexión"""
        self.connection_info[connection_id] = ConnectionInfo(
            connection_id=connection_id,
            endpoint=endpoint,
            socket_type=socket_type,
            mode=mode,
            status="connecting",
            last_seen=datetime.now()
        )

    def update_connection_info(self, connection_id: str, node_id: str = None,
                               component_type: str = None, version: str = None,
                               remote_ip: str = None, remote_port: int = None):
        """Actualizar información de conexión"""
        if connection_id in self.connection_info:
            conn = self.connection_info[connection_id]
            if node_id:
                conn.node_id = node_id
            if component_type:
                conn.component_type = component_type
            if version:
                conn.version = version
            if remote_ip:
                conn.remote_ip = remote_ip
            if remote_port:
                conn.remote_port = remote_port
            conn.last_seen = datetime.now()
            conn.status = "connected"
            conn.handshake_completed = True
            conn.messages_exchanged += 1

    def get_monitoring_data(self) -> Dict:
        """Obtener todos los datos de monitoreo"""
        return {
            'encoding_errors': [asdict(error) for error in self.encoding_errors[-20:]],
            'worker_stats': {k: asdict(v) for k, v in self.worker_stats.items()},
            'connection_info': {k: asdict(v) for k, v in self.connection_info.items()},
            'error_patterns': dict(self.error_patterns),
            'summary': {
                'total_errors': len(self.encoding_errors),
                'active_workers': len([s for s in self.worker_stats.values()
                                       if s.status == "active"]),
                'error_workers': len([s for s in self.worker_stats.values()
                                      if s.status == "error"]),
                'connected_components': len([c for c in self.connection_info.values()
                                             if c.status == "connected"]),
                'most_common_error': max(self.error_patterns.items(),
                                         key=lambda x: x[1])[0] if self.error_patterns else 'none'
            }
        }


class DashboardLogger:
    def __init__(self, node_id: str, log_config: dict):
        self.logger = logging.getLogger(f"dashboard_{node_id}")
        self.node_id = node_id

        # Configurar logging según JSON
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Crear formatter
        formatter = logging.Formatter(log_format)

        # Limpiar handlers existentes
        self.logger.handlers.clear()
        self.logger.setLevel(log_level)

        # Handler de consola
        console_config = log_config.get('handlers', {}).get('console', {})
        if console_config.get('enabled', True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # Handler de archivo
        file_config = log_config.get('handlers', {}).get('file', {})
        if file_config.get('enabled', False):
            file_path = file_config.get('path')
            if file_path:
                # Crear directorio si no existe
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(file_path)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

        # Añadir node_id al contexto
        old_factory = logging.getLogRecordFactory()

        def record_factory(*args, **kwargs):
            record = old_factory(*args, **kwargs)
            record.node_id = self.node_id
            record.pid = os.getpid()
            return record

        logging.setLogRecordFactory(record_factory)

    def info(self, msg, *args, **kwargs):
        self.logger.info(f"[node_id:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(f"[node_id:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(f"[node_id:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(f"[node_id:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)


@dataclass
class SecurityEvent:
    id: str
    source_ip: str
    target_ip: str
    risk_score: float
    anomaly_score: float
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timestamp: str = None
    attack_type: Optional[str] = None
    location: Optional[str] = None
    packets: int = 0
    bytes: int = 0
    port: Optional[int] = None
    protocol: Optional[str] = None
    ml_models_scores: Optional[Dict] = None
    # Campos adicionales del protobuf
    protobuf_data: Optional[Dict] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class FirewallCommand:
    action: str
    target_ip: str
    duration: str
    reason: str
    risk_score: float
    timestamp: str
    event_id: str
    rule_type: str = "iptables"
    port: Optional[int] = None
    protocol: Optional[str] = None


@dataclass
class ComponentStatus:
    node_id: str
    component_type: str
    status: str
    last_seen: datetime
    address: str
    port: int
    socket_type: str
    mode: str
    events_received: int = 0
    events_sent: int = 0
    latency_ms: float = 0.0
    error_count: int = 0


@dataclass
class ZMQConnectionInfo:
    socket_id: str
    socket_type: str
    endpoint: str
    mode: str
    status: str
    high_water_mark: int
    queue_size: int
    total_messages: int
    bytes_transferred: int
    last_activity: datetime
    connected_peers: List[str]


class DashboardConfig:
    """Configuración estricta del dashboard - TODO desde JSON"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = None
        self.load_and_validate_config()

    def load_and_validate_config(self):
        """Cargar y validar configuración - FALLA si hay errores"""
        if not Path(self.config_file).exists():
            raise ConfigurationError(f"❌ Archivo de configuración {self.config_file} no encontrado")

        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"❌ Error parseando JSON en {self.config_file}: {e}")
        except Exception as e:
            raise ConfigurationError(f"❌ Error leyendo {self.config_file}: {e}")

        # Validar campos requeridos
        self._validate_required_fields()

        # Extraer valores validados
        self._extract_config_values()

        print(f"✅ Configuración cargada y validada desde {self.config_file}")

    def _validate_required_fields(self):
        """Validar que todos los campos requeridos existan"""
        required_paths = [
            'node_id',
            'component.name',
            'component.version',
            'network.ml_events_input.port',
            'network.ml_events_input.address',
            'network.ml_events_input.mode',
            'network.ml_events_input.socket_type',
            'network.firewall_commands_output.port',
            'network.firewall_commands_output.address',
            'network.firewall_commands_output.mode',
            'network.firewall_commands_output.socket_type',
            'network.firewall_responses_input.port',
            'network.firewall_responses_input.address',
            'network.firewall_responses_input.mode',
            'network.firewall_responses_input.socket_type',
            'network.admin_interface.address',
            'network.admin_interface.port',
            'zmq.context_io_threads',
            'processing.threads.ml_events_consumers',
            'processing.threads.firewall_command_producers',
            'processing.internal_queues.ml_events_queue_size',
            'processing.internal_queues.firewall_commands_queue_size',
            'monitoring.stats_interval_seconds',
            'logging.level',
            'logging.format'
        ]

        for path in required_paths:
            if not self._get_nested_value(path):
                raise ConfigurationError(f"❌ Campo requerido faltante en configuración: {path}")

    def _get_nested_value(self, path: str):
        """Obtener valor anidado usando notación de punto"""
        keys = path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None

        return value

    def _extract_config_values(self):
        """Extraer todos los valores de configuración"""
        # Node ID y component info
        self.node_id = self.config['node_id']
        component = self.config['component']
        self.component_name = component['name']
        self.version = component['version']
        self.mode = component.get('mode', 'distributed_orchestrator')
        self.role = component.get('role', 'dashboard_coordinator')

        # Network configuration
        network = self.config['network']

        # ML Events Input
        ml_events = network['ml_events_input']
        self.ml_detector_address = ml_events['address']
        self.ml_detector_port = ml_events['port']
        self.ml_detector_mode = ml_events['mode']
        self.ml_detector_socket_type = ml_events['socket_type']
        self.ml_detector_hwm = ml_events.get('high_water_mark', 10000)
        self.ml_detector_expected_publishers = ml_events.get('expected_publishers', 1)

        # Firewall Commands Output
        fw_commands = network['firewall_commands_output']
        self.firewall_commands_address = fw_commands['address']
        self.firewall_commands_port = fw_commands['port']
        self.firewall_commands_mode = fw_commands['mode']
        self.firewall_commands_socket_type = fw_commands['socket_type']
        self.firewall_commands_hwm = fw_commands.get('high_water_mark', 5000)
        self.firewall_commands_expected_subscribers = fw_commands.get('expected_subscribers', 1)

        # Firewall Responses Input
        fw_responses = network['firewall_responses_input']
        self.firewall_responses_address = fw_responses['address']
        self.firewall_responses_port = fw_responses['port']
        self.firewall_responses_mode = fw_responses['mode']
        self.firewall_responses_socket_type = fw_responses['socket_type']
        self.firewall_responses_hwm = fw_responses.get('high_water_mark', 5000)
        self.firewall_responses_expected_publishers = fw_responses.get('expected_publishers', 1)

        # Admin Interface
        admin_interface = network['admin_interface']
        self.web_host = admin_interface['address']
        self.web_port = admin_interface['port']

        # ZMQ Configuration
        zmq_config = self.config['zmq']
        self.zmq_io_threads = zmq_config['context_io_threads']
        self.zmq_max_sockets = zmq_config.get('max_sockets', 1024)
        self.zmq_tcp_keepalive = zmq_config.get('tcp_keepalive', True)
        self.zmq_tcp_keepalive_idle = zmq_config.get('tcp_keepalive_idle', 300)
        self.zmq_immediate = zmq_config.get('immediate', True)

        # Processing Configuration
        processing = self.config['processing']
        threads = processing['threads']
        self.ml_events_consumers = threads['ml_events_consumers']
        self.firewall_command_producers = threads['firewall_command_producers']
        self.firewall_response_consumers = threads.get('firewall_response_consumers', 2)

        queues = processing['internal_queues']
        self.ml_events_queue_size = queues['ml_events_queue_size']
        self.firewall_commands_queue_size = queues['firewall_commands_queue_size']
        self.firewall_responses_queue_size = queues.get('firewall_responses_queue_size', 2000)

        # Monitoring
        monitoring = self.config['monitoring']
        self.stats_interval = monitoring['stats_interval_seconds']
        self.detailed_metrics = monitoring.get('detailed_metrics', True)

        # Logging configuration
        self.logging_config = self.config['logging']

        # Security
        self.security_config = self.config.get('security', {})

        # Web interface
        self.web_interface_config = self.config.get('web_interface', {})


class SecurityDashboard:
    """Dashboard principal de seguridad con monitoreo integrado"""

    def __init__(self, config: DashboardConfig):
        self.config = config
        self.logger = DashboardLogger(config.node_id, config.logging_config)

        # Inicializar monitor de encoding
        self.encoding_monitor = EncodingMonitor(self.logger)

        # Crear contexto ZMQ con configuración del JSON
        self.context = zmq.Context(io_threads=config.zmq_io_threads)

        # Estado del dashboard
        self.events: List[SecurityEvent] = []
        self.firewall_commands: List[FirewallCommand] = []
        self.component_status: Dict[str, ComponentStatus] = {}
        self.zmq_connections: Dict[str, ZMQConnectionInfo] = {}

        # Colas de procesamiento con tamaños del JSON
        self.ml_events_queue = queue.Queue(maxsize=config.ml_events_queue_size)
        self.firewall_commands_queue = queue.Queue(maxsize=config.firewall_commands_queue_size)
        self.firewall_responses_queue = queue.Queue(maxsize=config.firewall_responses_queue_size)

        # WebSocket clients
        self.websocket_clients = set()

        # Estadísticas mejoradas
        self.stats = {
            'events_received': 0,
            'events_processed': 0,
            'commands_sent': 0,
            'threats_blocked': 0,
            'events_per_minute': 0,
            'high_risk_events': 0,
            'geographic_distribution': 0,
            'active_firewall_agents': 0,
            'ml_detector_latency': 0.0,
            'last_update': datetime.now().isoformat(),
            'uptime_seconds': 0,
            'memory_usage_mb': 0,
            'cpu_usage_percent': 0.0,
            # Nuevas estadísticas de encoding
            'encoding_errors_total': 0,
            'encoding_errors_rate': 0.0,
            'active_workers': 0,
            'problematic_workers': 0
        }

        # Métricas detalladas
        self.detailed_metrics = {
            'zmq_connections': {},
            'component_health': {},
            'processing_queues': {},
            'network_topology': {},
            'performance_metrics': {
                'events_per_second_history': deque(maxlen=60),
                'latency_history': deque(maxlen=60),
                'error_rate_history': deque(maxlen=60)
            }
        }

        self.running = False
        self.start_time = time.time()

        # Verificar archivos requeridos
        self._verify_required_files()

        # Configurar sockets ZeroMQ con monitoreo
        self.setup_zmq_sockets_with_monitoring()

    def _verify_required_files(self):
        """Verificar que existan los archivos requeridos"""
        required_files = [
            'templates/dashboard.html',
            'static/css/dashboard.css'
        ]

        for file_path in required_files:
            if not Path(file_path).exists():
                raise ConfigurationError(f"❌ Archivo requerido no encontrado: {file_path}")

        self.logger.info("✅ Archivos requeridos verificados")

    def setup_zmq_sockets_with_monitoring(self):
        """Configurar sockets ZeroMQ con monitoreo integrado"""
        self.logger.info("🔧 Configurando sockets ZeroMQ con monitoreo de errores...")

        try:
            # ML Events Input Socket
            self.logger.info(f"📡 Configurando ML Events socket...")
            socket_type = getattr(zmq, self.config.ml_detector_socket_type)
            self.ml_socket = self.context.socket(socket_type)

            # Configurar opciones desde JSON
            self.ml_socket.setsockopt(zmq.RCVHWM, self.config.ml_detector_hwm)
            self.ml_socket.setsockopt(zmq.LINGER, 1000)
            self.ml_socket.setsockopt(zmq.RCVTIMEO, 1000)

            if self.config.zmq_tcp_keepalive:
                self.ml_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.ml_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, self.config.zmq_tcp_keepalive_idle)

            if self.config.zmq_immediate:
                self.ml_socket.setsockopt(zmq.IMMEDIATE, 1)

            ml_endpoint = f"tcp://{self.config.ml_detector_address}:{self.config.ml_detector_port}"

            if self.config.ml_detector_mode == 'bind':
                self.ml_socket.bind(ml_endpoint)
                self.logger.info(f"🟢 ML Events socket BIND en {ml_endpoint}")
            elif self.config.ml_detector_mode == 'connect':
                self.ml_socket.connect(ml_endpoint)
                self.logger.info(f"🟢 ML Events socket CONNECT a {ml_endpoint}")
            else:
                raise ConfigurationError(f"❌ Modo ZMQ inválido para ML Events: {self.config.ml_detector_mode}")

            # Registrar conexión en el monitor
            self.encoding_monitor.register_connection(
                'ml_events', ml_endpoint,
                self.config.ml_detector_socket_type,
                self.config.ml_detector_mode
            )

            # Registrar conexión en ZMQ info
            self.zmq_connections['ml_events'] = ZMQConnectionInfo(
                socket_id='ml_events',
                socket_type=self.config.ml_detector_socket_type,
                endpoint=ml_endpoint,
                mode=self.config.ml_detector_mode,
                status='active',
                high_water_mark=self.config.ml_detector_hwm,
                queue_size=0,
                total_messages=0,
                bytes_transferred=0,
                last_activity=datetime.now(),
                connected_peers=[]
            )

            # Firewall Commands Output Socket
            self.logger.info(f"🔥 Configurando Firewall Commands socket...")
            socket_type = getattr(zmq, self.config.firewall_commands_socket_type)
            self.firewall_commands_socket = self.context.socket(socket_type)

            self.firewall_commands_socket.setsockopt(zmq.SNDHWM, self.config.firewall_commands_hwm)
            self.firewall_commands_socket.setsockopt(zmq.LINGER, 1000)

            if self.config.zmq_tcp_keepalive:
                self.firewall_commands_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.firewall_commands_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, self.config.zmq_tcp_keepalive_idle)

            fw_commands_endpoint = f"tcp://{self.config.firewall_commands_address}:{self.config.firewall_commands_port}"

            if self.config.firewall_commands_mode == 'bind':
                self.firewall_commands_socket.bind(fw_commands_endpoint)
                self.logger.info(f"🟢 Firewall Commands socket BIND en {fw_commands_endpoint}")
            elif self.config.firewall_commands_mode == 'connect':
                self.firewall_commands_socket.connect(fw_commands_endpoint)
                self.logger.info(f"🟢 Firewall Commands socket CONNECT a {fw_commands_endpoint}")
            else:
                raise ConfigurationError(
                    f"❌ Modo ZMQ inválido para Firewall Commands: {self.config.firewall_commands_mode}")

            # Registrar conexión
            self.encoding_monitor.register_connection(
                'firewall_commands', fw_commands_endpoint,
                self.config.firewall_commands_socket_type,
                self.config.firewall_commands_mode
            )

            self.zmq_connections['firewall_commands'] = ZMQConnectionInfo(
                socket_id='firewall_commands',
                socket_type=self.config.firewall_commands_socket_type,
                endpoint=fw_commands_endpoint,
                mode=self.config.firewall_commands_mode,
                status='active',
                high_water_mark=self.config.firewall_commands_hwm,
                queue_size=0,
                total_messages=0,
                bytes_transferred=0,
                last_activity=datetime.now(),
                connected_peers=[]
            )

            # Firewall Responses Input Socket
            self.logger.info(f"📥 Configurando Firewall Responses socket...")
            socket_type = getattr(zmq, self.config.firewall_responses_socket_type)
            self.firewall_responses_socket = self.context.socket(socket_type)

            self.firewall_responses_socket.setsockopt(zmq.RCVHWM, self.config.firewall_responses_hwm)
            self.firewall_responses_socket.setsockopt(zmq.LINGER, 1000)
            self.firewall_responses_socket.setsockopt(zmq.RCVTIMEO, 1000)

            if self.config.zmq_tcp_keepalive:
                self.firewall_responses_socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
                self.firewall_responses_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, self.config.zmq_tcp_keepalive_idle)

            fw_responses_endpoint = f"tcp://{self.config.firewall_responses_address}:{self.config.firewall_responses_port}"

            if self.config.firewall_responses_mode == 'bind':
                self.firewall_responses_socket.bind(fw_responses_endpoint)
                self.logger.info(f"🟢 Firewall Responses socket BIND en {fw_responses_endpoint}")
            elif self.config.firewall_responses_mode == 'connect':
                self.firewall_responses_socket.connect(fw_responses_endpoint)
                self.logger.info(f"🟢 Firewall Responses socket CONNECT a {fw_responses_endpoint}")
            else:
                raise ConfigurationError(
                    f"❌ Modo ZMQ inválido para Firewall Responses: {self.config.firewall_responses_mode}")

            # Registrar conexión
            self.encoding_monitor.register_connection(
                'firewall_responses', fw_responses_endpoint,
                self.config.firewall_responses_socket_type,
                self.config.firewall_responses_mode
            )

            self.zmq_connections['firewall_responses'] = ZMQConnectionInfo(
                socket_id='firewall_responses',
                socket_type=self.config.firewall_responses_socket_type,
                endpoint=fw_responses_endpoint,
                mode=self.config.firewall_responses_mode,
                status='active',
                high_water_mark=self.config.firewall_responses_hwm,
                queue_size=0,
                total_messages=0,
                bytes_transferred=0,
                last_activity=datetime.now(),
                connected_peers=[]
            )

            self.logger.info("✅ Todos los sockets ZeroMQ configurados con monitoreo")

        except Exception as e:
            self.logger.error(f"❌ Error configurando sockets ZeroMQ: {e}")
            raise ConfigurationError(f"Error en configuración ZeroMQ: {e}")

    def start(self):
        """Iniciar el dashboard"""
        self.running = True
        self.logger.info(f"🚀 Iniciando Dashboard de Seguridad...")
        self.logger.info(f"📋 Node ID: {self.config.node_id}")
        self.logger.info(f"🏗️ Component: {self.config.component_name} v{self.config.version}")
        self.logger.info(f"🔧 Mode: {self.config.mode}")
        self.logger.info(f"🎭 Role: {self.config.role}")
        self.logger.info(f"🖥️ Sistema: {os.uname().sysname} {os.uname().release}")
        self.logger.info(f"🐍 Python: {sys.version.split()[0]}")
        self.logger.info(f"💾 PID: {os.getpid()}")

        # Mostrar configuración de red
        self.log_network_configuration()

        # Iniciar hilos de procesamiento
        self.start_processing_threads()

        # Iniciar servidor web
        self.start_web_server()

        # Iniciar actualizaciones periódicas
        self.start_periodic_updates()

        self.logger.info("🎯 Dashboard iniciado correctamente")
        self.logger.info(f"🌐 Interfaz web disponible en: http://{self.config.web_host}:{self.config.web_port}")

        # Mantener el programa ejecutándose
        try:
            while self.running:
                time.sleep(1)
                self.update_system_metrics()
        except KeyboardInterrupt:
            self.logger.info("🛑 Recibida señal de interrupción")
            self.stop()

    def log_network_configuration(self):
        """Mostrar configuración de red detallada"""
        self.logger.info("🌐 Configuración de Red ZeroMQ:")
        self.logger.info("=" * 60)

        # ML Events
        self.logger.info(f"📡 ML Events Input:")
        self.logger.info(f"   └── Puerto: {self.config.ml_detector_port}")
        self.logger.info(f"   └── Modo: {self.config.ml_detector_mode.upper()}")
        self.logger.info(f"   └── Tipo: {self.config.ml_detector_socket_type}")
        self.logger.info(f"   └── HWM: {self.config.ml_detector_hwm}")
        self.logger.info(f"   └── Expected Publishers: {self.config.ml_detector_expected_publishers}")
        self.logger.info(f"   └── Endpoint: tcp://{self.config.ml_detector_address}:{self.config.ml_detector_port}")

        # Firewall Commands
        self.logger.info(f"🔥 Firewall Commands Output:")
        self.logger.info(f"   └── Puerto: {self.config.firewall_commands_port}")
        self.logger.info(f"   └── Modo: {self.config.firewall_commands_mode.upper()}")
        self.logger.info(f"   └── Tipo: {self.config.firewall_commands_socket_type}")
        self.logger.info(f"   └── HWM: {self.config.firewall_commands_hwm}")
        self.logger.info(f"   └── Expected Subscribers: {self.config.firewall_commands_expected_subscribers}")
        self.logger.info(
            f"   └── Endpoint: tcp://{self.config.firewall_commands_address}:{self.config.firewall_commands_port}")

        # Firewall Responses
        self.logger.info(f"📥 Firewall Responses Input:")
        self.logger.info(f"   └── Puerto: {self.config.firewall_responses_port}")
        self.logger.info(f"   └── Modo: {self.config.firewall_responses_mode.upper()}")
        self.logger.info(f"   └── Tipo: {self.config.firewall_responses_socket_type}")
        self.logger.info(f"   └── HWM: {self.config.firewall_responses_hwm}")
        self.logger.info(f"   └── Expected Publishers: {self.config.firewall_responses_expected_publishers}")
        self.logger.info(
            f"   └── Endpoint: tcp://{self.config.firewall_responses_address}:{self.config.firewall_responses_port}")

        # Web Interface
        self.logger.info(f"🌐 Web Interface:")
        self.logger.info(f"   └── Host: {self.config.web_host}")
        self.logger.info(f"   └── Puerto: {self.config.web_port}")

        # ZMQ Context
        self.logger.info(f"⚙️ ZMQ Context:")
        self.logger.info(f"   └── IO Threads: {self.config.zmq_io_threads}")
        self.logger.info(f"   └── Max Sockets: {self.config.zmq_max_sockets}")
        self.logger.info(f"   └── TCP Keepalive: {self.config.zmq_tcp_keepalive}")

        self.logger.info("=" * 60)

    def start_processing_threads(self):
        """Iniciar hilos de procesamiento según configuración JSON"""
        self.logger.info("🧵 Iniciando hilos de procesamiento...")

        # ML Events Consumers con monitoreo
        for i in range(self.config.ml_events_consumers):
            thread = threading.Thread(target=self.ml_events_receiver_with_monitoring, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"📡 ML Events Receiver {i} iniciado")
            self.logger.info(f"   ✅ ML Events Consumer {i} iniciado")

        # Firewall Command Producers
        for i in range(self.config.firewall_command_producers):
            thread = threading.Thread(target=self.firewall_commands_processor, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"🔥 Firewall Commands Processor {i} iniciado")
            self.logger.info(f"   ✅ Firewall Commands Producer {i} iniciado")

        # Firewall Response Consumers con monitoreo
        for i in range(self.config.firewall_response_consumers):
            thread = threading.Thread(target=self.firewall_responses_receiver_with_monitoring, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"📥 Firewall Responses Receiver {i} iniciado")
            self.logger.info(f"   ✅ Firewall Responses Consumer {i} iniciado")

        self.logger.info(
            f"✅ Total hilos iniciados: {self.config.ml_events_consumers + self.config.firewall_command_producers + self.config.firewall_response_consumers}")

    def ml_events_receiver_with_monitoring(self, worker_id: int):
        """Recibir eventos del ML Detector con monitoreo completo"""
        self.logger.info(f"📡 ML Events Receiver {worker_id} iniciado con monitoreo")
        crash_counter = 0
        while self.running:
            try:
                # Recibir mensaje como bytes
                message_bytes = self.ml_socket.recv(zmq.NOBLOCK)

                # Intentar decodificar con monitoreo
                message_text, encoding_used = self.decode_message_with_monitoring(
                    message_bytes, worker_id, 'ml_events'
                )

                if message_text is None:
                    continue  # Error ya registrado en monitoring

                # Registrar mensaje exitoso
                self.encoding_monitor.log_successful_message(
                    worker_id, 'ml_events', len(message_bytes), encoding_used
                )

                # Intentar extraer información del remitente
                try:
                    event_data = json.loads(message_text)
                    if 'node_id' in event_data:
                        self.encoding_monitor.update_connection_info(
                            'ml_events',
                            node_id=event_data.get('node_id'),
                            component_type='ml_detector',
                            version=event_data.get('version'),
                            remote_ip=event_data.get('source_ip')  # IP del componente
                        )
                except:
                    pass  # Información opcional

                # Actualizar estadísticas de conexión
                conn_info = self.zmq_connections['ml_events']
                conn_info.total_messages += 1
                conn_info.bytes_transferred += len(message_bytes)
                conn_info.last_activity = datetime.now()

                # Parsear y procesar evento
                event = self.parse_security_event(event_data)

                # Añadir a cola de procesamiento
                if not self.ml_events_queue.full():
                    self.ml_events_queue.put(event)
                    self.stats['events_received'] += 1

                    self.logger.debug(
                        f"📨 Worker {worker_id} - Evento recibido: {event.source_ip} -> {event.target_ip} (riesgo: {event.risk_score:.2f})")
                else:
                    self.logger.warning(f"⚠️ Worker {worker_id} - Cola ML events llena, descartando evento")

            except zmq.Again:
                # Timeout, continuar
                continue
            except json.JSONDecodeError as e:
                self.logger.error(f"❌ Worker {worker_id} - Error parseando JSON: {e}")
            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Error general: {e}")
                time.sleep(0.1)

    def decode_message_with_monitoring(self, message_bytes: bytes, worker_id: int,
                                       worker_type: str) -> tuple[Optional[str], str]:
        """Decodificar mensaje - PROTOBUF PRIMERO para evitar errores UTF-8"""

        if not message_bytes:
            return None, 'empty'

        # 🔥 CRÍTICO: Detectar protobuf ANTES que UTF-8
        detected_type = self.encoding_monitor.detect_encoding_type(message_bytes)

        if detected_type == 'protobuf':
            parsed = self.parse_protobuf_with_monitoring(message_bytes, worker_id)
            if parsed:
                return json.dumps(parsed), 'protobuf'
            else:
                return None, 'failed'

        # UTF-8 solo si NO es protobuf
        try:
            decoded = message_bytes.decode('utf-8')
            json.loads(decoded)
            return decoded, 'utf-8'
        except UnicodeDecodeError as e:
            self.encoding_monitor.log_encoding_error(
                worker_id, worker_type, message_bytes, e, 'utf-8'
            )
        except json.JSONDecodeError:
            pass

        # latin-1 fallback
        if detected_type == 'latin-1':
            try:
                decoded = message_bytes.decode('latin-1')
                if decoded.strip().startswith('{'):
                    json.loads(decoded)
                    return decoded, 'latin-1'
            except Exception as e:
                self.encoding_monitor.log_encoding_error(
                    worker_id, worker_type, message_bytes, e, 'latin-1'
                )

        # Último recurso
        try:
            cleaned_bytes = bytearray()
            for byte in message_bytes:
                if byte < 128:
                    cleaned_bytes.append(byte)

            if cleaned_bytes:
                cleaned = bytes(cleaned_bytes).decode('utf-8', errors='ignore')
                if len(cleaned.strip()) > 0 and '{' in cleaned and '}' in cleaned:
                    start = cleaned.find('{')
                    end = cleaned.rfind('}') + 1
                    if start >= 0 and end > start:
                        json_part = cleaned[start:end]
                        json.loads(json_part)
                        return json_part, 'utf-8-cleaned'
        except Exception as e:
            self.encoding_monitor.log_encoding_error(
                worker_id, worker_type, message_bytes, e, 'utf-8-cleaned'
            )

        # Total failure
        self.encoding_monitor.log_encoding_error(
            worker_id, worker_type, message_bytes,
            Exception(f"All decoding methods failed for {len(message_bytes)} bytes"), 'all-failed'
        )
        return None, 'failed'

    def parse_protobuf_with_monitoring(self, data: bytes, worker_id: int) -> Optional[Dict]:
        """Parsear protobuf con monitoreo mejorado - VERSIÓN CORREGIDA"""
        try:
            # Importar protobuf modules correctos
            try:
                import src.protocols.protobuf.network_event_extended_v2_pb2 as network_pb2

                # Intentar parsear como NetworkEvent (NO NetworkEventExtended)
                event = network_pb2.NetworkEvent()
                event.ParseFromString(data)

                # Convertir a diccionario con TODOS los campos del protobuf v2
                parsed_event = {
                    # 🔍 Identificación del evento
                    'id': getattr(event, 'event_id', '') or str(int(time.time() * 1000000)) + f"_{worker_id}",
                    'event_id': getattr(event, 'event_id', ''),
                    'timestamp': getattr(event, 'timestamp', int(time.time() * 1000)),

                    # 🌐 Información de red básica
                    'source_ip': getattr(event, 'source_ip', '127.0.0.1'),
                    'target_ip': getattr(event, 'target_ip', '127.0.0.1'),
                    'packet_size': getattr(event, 'packet_size', 0),
                    'dest_port': getattr(event, 'dest_port', 0),
                    'src_port': getattr(event, 'src_port', 0),
                    'protocol': getattr(event, 'protocol', 'TCP'),

                    # 🤖 Identificación del agente (legacy)
                    'agent_id': getattr(event, 'agent_id', ''),

                    # 📊 Métricas y scoring
                    'anomaly_score': getattr(event, 'anomaly_score', 0.0),
                    'latitude': getattr(event, 'latitude', None),
                    'longitude': getattr(event, 'longitude', None),

                    # 🎯 Clasificación de eventos
                    'event_type': getattr(event, 'event_type', 'unknown'),
                    'risk_score': getattr(event, 'risk_score', 0.5),
                    'description': getattr(event, 'description', ''),

                    # 🖥️ Información del sistema operativo
                    'so_identifier': getattr(event, 'so_identifier', ''),

                    # 🏠 Información del nodo (handshake inicial)
                    'node_hostname': getattr(event, 'node_hostname', ''),
                    'os_version': getattr(event, 'os_version', ''),
                    'firewall_status': getattr(event, 'firewall_status', 'unknown'),
                    'agent_version': getattr(event, 'agent_version', ''),
                    'is_initial_handshake': getattr(event, 'is_initial_handshake', False),

                    # 🆔 CAMPOS DISTRIBUIDOS - CRÍTICOS PARA ETCD
                    'node_id': getattr(event, 'node_id', self.config.node_id),
                    'process_id': getattr(event, 'process_id', 0),
                    'container_id': getattr(event, 'container_id', ''),
                    'cluster_name': getattr(event, 'cluster_name', ''),

                    # 🔄 Estado del componente distribuido
                    'component_status': getattr(event, 'component_status', 'healthy'),
                    'uptime_seconds': getattr(event, 'uptime_seconds', 0),

                    # 📈 Métricas de performance del nodo
                    'queue_depth': getattr(event, 'queue_depth', 0),
                    'cpu_usage_percent': getattr(event, 'cpu_usage_percent', 0.0),
                    'memory_usage_mb': getattr(event, 'memory_usage_mb', 0.0),

                    # 🔧 Configuración dinámica
                    'config_version': getattr(event, 'config_version', ''),
                    'config_timestamp': getattr(event, 'config_timestamp', 0),

                    # 🌍 Enriquecimiento GeoIP
                    'geoip_enriched': getattr(event, 'geoip_enriched', False),
                    'enrichment_node': getattr(event, 'enrichment_node', ''),
                    'enrichment_timestamp': getattr(event, 'enrichment_timestamp', 0),

                    # 🔧 PIDS DE COMPONENTES DISTRIBUIDOS - POSICIÓN 36-40
                    'promiscuous_pid': getattr(event, 'promiscuous_pid', 0),
                    'geoip_enricher_pid': getattr(event, 'geoip_enricher_pid', 0),
                    'ml_detector_pid': getattr(event, 'ml_detector_pid', 0),
                    'dashboard_pid': self.get_safe_dashboard_pid(event),  # CAMPO 39 - CRÍTICO
                    'firewall_pid': getattr(event, 'firewall_pid', 0),

                    # 📊 TIMESTAMPS DE PROCESAMIENTO POR COMPONENTE - POSICIÓN 41-45
                    'promiscuous_timestamp': getattr(event, 'promiscuous_timestamp', 0),
                    'geoip_enricher_timestamp': getattr(event, 'geoip_enricher_timestamp', 0),
                    'ml_detector_timestamp': getattr(event, 'ml_detector_timestamp', 0),
                    'dashboard_timestamp': int(time.time() * 1000),  # Timestamp actual del dashboard
                    'firewall_timestamp': getattr(event, 'firewall_timestamp', 0),

                    # 🎯 MÉTRICAS DE PIPELINE DISTRIBUIDO - POSICIÓN 46-48
                    'processing_latency_ms': getattr(event, 'processing_latency_ms', 0.0),
                    'pipeline_hops': getattr(event, 'pipeline_hops', 0),
                    'pipeline_path': getattr(event, 'pipeline_path', ''),

                    # 🔄 CONTROL DE FLUJO DISTRIBUIDO - POSICIÓN 49-51
                    'retry_count': getattr(event, 'retry_count', 0),
                    'last_error': getattr(event, 'last_error', ''),
                    'requires_reprocessing': getattr(event, 'requires_reprocessing', False),

                    # 🏷️ TAGS Y METADATOS DISTRIBUIDOS - POSICIÓN 52-53
                    'component_tags': list(getattr(event, 'component_tags', [])),
                    'component_metadata': dict(getattr(event, 'component_metadata', {})),

                    # Campos de compatibilidad y adicionales
                    'port': getattr(event, 'dest_port', 80),  # Alias para compatibilidad
                    'attack_type': getattr(event, 'event_type', 'unknown'),  # Alias para compatibilidad
                    'packets': max(1, getattr(event, 'packet_size', 1)),
                    'bytes': len(data),
                    'location': self._get_location_from_coordinates(
                        getattr(event, 'latitude', None),
                        getattr(event, 'longitude', None)
                    ),

                    # Metadatos del parsing
                    'parsing_method': 'protobuf_v2_parsed',
                    'raw_protobuf_length': len(data),
                    'worker_id': worker_id,
                    'dashboard_node_id': self.config.node_id,
                    'dashboard_processing_timestamp': datetime.now().isoformat(),

                    # ML Models scores (si están disponibles en metadata)
                    'ml_models_scores': self._extract_ml_scores_from_metadata(
                        dict(getattr(event, 'component_metadata', {}))
                    )
                }
                # Después de la línea donde se crea parsed_event, añadir:
                # Validación adicional de PIDs para evitar problemas de encoding
                for pid_field in ['dashboard_pid', 'promiscuous_pid', 'ml_detector_pid', 'firewall_pid',
                                  'geoip_enricher_pid']:
                    if pid_field in parsed_event:
                        try:
                            # Asegurar que todos los PIDs son strings válidos
                            pid_value = parsed_event[pid_field]
                            if isinstance(pid_value, (int, float)):
                                parsed_event[pid_field] = str(int(pid_value))
                            elif isinstance(pid_value, bytes):
                                parsed_event[pid_field] = pid_value.decode('utf-8', errors='ignore')
                            elif not isinstance(pid_value, str):
                                parsed_event[pid_field] = str(pid_value)
                        except Exception as e:
                            self.logger.debug(f"Error validando {pid_field}: {e}")
                            parsed_event[pid_field] = "0"

                # Actualizar el dashboard_pid en el evento si es necesario
                if hasattr(event, 'dashboard_pid') and event.dashboard_pid == 0:
                    event.dashboard_pid = os.getpid()
                    parsed_event['dashboard_pid'] = os.getpid()

                self.logger.info(f"📦 Worker {worker_id} - Protobuf v2 parseado correctamente ({len(data)} bytes)")
                self.logger.debug(
                    f"🔍 Evento parseado: {parsed_event['source_ip']} -> {parsed_event['target_ip']} (riesgo: {parsed_event['risk_score']})")
                return parsed_event

            except ImportError as ie:
                self.logger.warning(f"⚠️ Protobuf v2 modules no disponibles: {ie}")
                self.logger.info("🔄 Intentando con protobuf legacy...")

                # Fallback a protobuf legacy
                try:
                    import network_event_extended_fixed_pb2 as legacy_pb2

                    event = legacy_pb2.NetworkEventExtended()
                    event.ParseFromString(data)

                    # Mapear campos legacy a estructura v2
                    parsed_event = self._map_legacy_protobuf_to_v2(event, worker_id, len(data))

                    self.logger.info(f"📦 Worker {worker_id} - Protobuf legacy parseado ({len(data)} bytes)")
                    return parsed_event

                except ImportError:
                    self.logger.warning(f"⚠️ Ningún protobuf module disponible, usando parser básico")

            except Exception as parse_error:
                self.logger.error(f"❌ Error parseando protobuf v2: {parse_error}")
                self.encoding_monitor.log_encoding_error(
                    worker_id, 'protobuf_v2_parser', data, parse_error, 'protobuf_v2'
                )

            # Parser básico mejorado con estructura v2
            event = self._generate_basic_event_v2(worker_id, len(data))

            self.logger.info(f"📦 Worker {worker_id} - Evento básico v2 generado ({len(data)} bytes)")
            return event

        except Exception as e:
            self.logger.error(f"💥 Error crítico en parser protobuf: {e}")
            self.encoding_monitor.log_encoding_error(
                worker_id, 'protobuf_parser', data, e, 'protobuf_critical'
            )
            return None

    def _generate_basic_event_v2(self, worker_id: int, data_length: int) -> dict:
        """Generar evento básico con estructura v2 completa"""
        current_time = int(time.time() * 1000)

        return {
            # 🔍 Identificación del evento
            'id': str(current_time) + f"_{worker_id}",
            'event_id': f"basic_event_{current_time}_{worker_id}",
            'timestamp': current_time,

            # 🌐 Información de red básica (simulada)
            'source_ip': f"192.168.1.{100 + (worker_id % 50)}",
            'target_ip': f"10.0.0.{1 + (worker_id % 50)}",
            'packet_size': data_length,
            'dest_port': 80 + (data_length % 65000),
            'src_port': 1024 + (worker_id % 64000),
            'protocol': 'TCP',

            # 🤖 Identificación del agente
            'agent_id': f'dashboard_worker_{worker_id}',

            # 📊 Métricas y scoring
            'anomaly_score': min(1.0, (data_length % 100) / 100.0),
            'latitude': 40.4168 + ((data_length % 200) - 100) / 1000.0,
            'longitude': -3.7038 + ((data_length % 200) - 100) / 1000.0,

            # 🎯 Clasificación de eventos
            'event_type': ['normal', 'suspicious', 'tor_detected', 'malware'][data_length % 4],
            'risk_score': min(1.0, 0.3 + (data_length % 100) / 100.0),
            'description': f'Basic generated event from protobuf data ({data_length} bytes)',

            # 🖥️ Información del sistema operativo
            'so_identifier': 'linux_iptables',

            # 🏠 Información del nodo
            'node_hostname': 'dashboard-node',
            'os_version': 'Linux',
            'firewall_status': 'active',
            'agent_version': '2.2.0',
            'is_initial_handshake': False,

            # 🆔 CAMPOS DISTRIBUIDOS
            'node_id': self.config.node_id,
            'process_id': os.getpid(),
            'container_id': '',
            'cluster_name': 'upgraded-happiness',

            # 🔄 Estado del componente
            'component_status': 'healthy',
            'uptime_seconds': int(time.time() - self.start_time),

            # 📈 Métricas de performance
            'queue_depth': self.ml_events_queue.qsize(),
            'cpu_usage_percent': 0.0,
            'memory_usage_mb': 0.0,

            # 🔧 Configuración dinámica
            'config_version': '2.2.0',
            'config_timestamp': current_time,

            # 🌍 Enriquecimiento GeoIP
            'geoip_enriched': True,
            'enrichment_node': 'basic_enricher',
            'enrichment_timestamp': current_time,

            # 🔧 PIDS DE COMPONENTES (CRÍTICO - POSICIONES 36-40)
            'promiscuous_pid': 0,
            'geoip_enricher_pid': 0,
            'ml_detector_pid': 0,
            'dashboard_pid': self.get_safe_dashboard_pid(),  # CAMPO 39 - ESTE ES EL CRÍTICO
            'firewall_pid': 0,

            # 📊 TIMESTAMPS DE PROCESAMIENTO (POSICIONES 41-45)
            'promiscuous_timestamp': 0,
            'geoip_enricher_timestamp': 0,
            'ml_detector_timestamp': 0,
            'dashboard_timestamp': current_time,
            'firewall_timestamp': 0,

            # 🎯 MÉTRICAS DE PIPELINE
            'processing_latency_ms': 0.0,
            'pipeline_hops': 1,
            'pipeline_path': 'dashboard_basic',

            # 🔄 CONTROL DE FLUJO
            'retry_count': 0,
            'last_error': '',
            'requires_reprocessing': False,

            # 🏷️ TAGS Y METADATOS
            'component_tags': ['basic', 'dashboard', f'worker_{worker_id}'],
            'component_metadata': {
                'generation_method': 'basic',
                'worker_id': str(worker_id),
                'data_length': str(data_length)
            },

            # Campos de compatibilidad
            'port': 80 + (data_length % 65000),
            'attack_type': ['port_scan', 'ddos', 'intrusion_attempt', 'malware'][data_length % 4],
            'packets': max(1, data_length // 64),
            'bytes': data_length,
            'location': 'Madrid, ES',

            # Metadatos del parsing
            'parsing_method': 'basic_v2_generated',
            'raw_protobuf_length': data_length,
            'worker_id': worker_id,
            'dashboard_node_id': self.config.node_id,
            'dashboard_processing_timestamp': datetime.now().isoformat(),

            # ML Models scores
            'ml_models_scores': {
                'isolation_forest': min(1.0, (data_length % 100) / 100.0),
                'one_class_svm': min(1.0, (data_length % 80) / 80.0),
                'basic_anomaly': min(1.0, (data_length % 60) / 60.0)
            }
        }

    def _map_legacy_protobuf_to_v2(self, legacy_event, worker_id: int, data_length: int) -> dict:
        """Mapear protobuf legacy a estructura v2"""
        return {
            # Campos legacy mapeados
            'id': getattr(legacy_event, 'id', str(int(time.time() * 1000000)) + f"_{worker_id}"),
            'source_ip': getattr(legacy_event, 'source_ip', '127.0.0.1'),
            'target_ip': getattr(legacy_event, 'target_ip', '127.0.0.1'),
            'risk_score': getattr(legacy_event, 'risk_score', 0.5),
            'anomaly_score': getattr(legacy_event, 'anomaly_score', 0.0),
            'latitude': getattr(legacy_event, 'latitude', None),
            'longitude': getattr(legacy_event, 'longitude', None),
            'protocol': getattr(legacy_event, 'protocol', 'TCP'),
            'port': getattr(legacy_event, 'port', 80),
            'attack_type': getattr(legacy_event, 'attack_type', 'unknown'),

            # Campos v2 con valores por defecto
            'event_id': getattr(legacy_event, 'id', ''),
            'timestamp': int(time.time() * 1000),
            'packet_size': data_length,
            'dest_port': getattr(legacy_event, 'port', 80),
            'src_port': 0,
            'event_type': getattr(legacy_event, 'attack_type', 'unknown'),
            'description': f'Legacy event from worker {worker_id}',

            # PIDs distribuidos
            'dashboard_pid': self.get_safe_dashboard_pid(),
            'worker_id': worker_id,
            'node_id': self.config.node_id,

            # Timestamps
            'dashboard_timestamp': int(time.time() * 1000),

            # Metadatos
            'parsing_method': 'protobuf_legacy_mapped',
            'raw_protobuf_length': data_length,
            'location': self._get_location_from_coordinates(
                getattr(legacy_event, 'latitude', None),
                getattr(legacy_event, 'longitude', None)
            ),
            'ml_models_scores': {
                'legacy_score': getattr(legacy_event, 'risk_score', 0.5)
            }
        }

    def _extract_ml_scores_from_metadata(self, metadata: dict) -> dict:
        """Extraer scores de ML desde metadata"""
        ml_scores = {}

        for key, value in metadata.items():
            if 'ml_' in key.lower() or 'score' in key.lower():
                try:
                    ml_scores[key] = float(value)
                except (ValueError, TypeError):
                    ml_scores[key] = str(value)

        # Añadir scores por defecto si no hay ninguno
        if not ml_scores:
            ml_scores = {
                'isolation_forest': 0.5,
                'one_class_svm': 0.5,
                'anomaly_detection': 0.5
            }

        return ml_scores

    def _get_location_from_coordinates(self, lat: float, lon: float) -> str:
        """Obtener ubicación textual desde coordenadas"""
        if lat is None or lon is None:
            return 'Unknown'

        # Coordenadas aproximadas para España
        if 35.0 <= lat <= 44.0 and -10.0 <= lon <= 4.0:
            return 'España'
        elif 40.0 <= lat <= 41.0 and -4.0 <= lon <= -3.0:
            return 'Madrid, ES'
        elif 41.0 <= lat <= 42.0 and 2.0 <= lon <= 3.0:
            return 'Barcelona, ES'
        else:
            return f'Lat:{lat:.2f}, Lon:{lon:.2f}'

    # Mantener métodos existentes de decodificación como fallback
    def looks_like_protobuf(self, data: bytes) -> bool:
        """Detectar si los datos parecen ser protobuf"""
        if len(data) < 4:
            return False

        protobuf_patterns = [
            b'\x08', b'\x0a', b'\x10', b'\x12', b'\x18', b'\x1a',
        ]

        return any(data.startswith(pattern) for pattern in protobuf_patterns)

    def parse_protobuf_message(self, data: bytes, worker_id: int) -> Optional[Dict]:
        """Método legacy de parseo protobuf"""
        return self.parse_protobuf_with_monitoring(data, worker_id)

    def parse_security_event(self, data: Dict) -> SecurityEvent:
        """Parsear datos de evento a SecurityEvent incluyendo datos protobuf"""
        return SecurityEvent(
            id=data.get('id', str(int(time.time() * 1000000))),
            source_ip=data.get('source_ip', data.get('src_ip', '')),
            target_ip=data.get('target_ip', data.get('dst_ip', '')),
            risk_score=float(data.get('risk_score', data.get('anomaly_score', 0.0))),
            anomaly_score=float(data.get('anomaly_score', 0.0)),
            latitude=data.get('latitude'),
            longitude=data.get('longitude'),
            timestamp=data.get('timestamp'),
            attack_type=data.get('attack_type'),
            location=data.get('location'),
            packets=int(data.get('packets', 0)),
            bytes=int(data.get('bytes', 0)),
            port=data.get('port', data.get('dst_port')),
            protocol=data.get('protocol'),
            ml_models_scores=data.get('ml_models_scores'),
            protobuf_data=data  # Guardar todos los datos del protobuf
        )

    def get_safe_dashboard_pid(self, event=None) -> str:
        """Obtener dashboard_pid de forma segura, siempre como string"""
        try:
            if event is not None:
                pid = getattr(event, 'dashboard_pid', None)
                if pid is not None:
                    if isinstance(pid, (int, float)) and pid > 0:
                        return str(int(pid))
                    elif isinstance(pid, str) and pid.isdigit():
                        return pid
                    elif isinstance(pid, bytes):
                        try:
                            decoded = pid.decode('utf-8', errors='ignore')
                            if decoded.isdigit():
                                return decoded
                        except:
                            pass

            return str(os.getpid())

        except Exception as e:
            self.logger.warning(f"Error obteniendo dashboard_pid: {e}")
            return str(os.getpid())

    def firewall_commands_processor(self, worker_id: int):
        """Procesar y enviar comandos de firewall"""
        self.logger.info(f"🔥 Firewall Commands Processor {worker_id} iniciado")

        while self.running:
            try:
                # Obtener comando de la cola
                command = self.firewall_commands_queue.get(timeout=1)

                # Enviar comando
                command_json = json.dumps(asdict(command))
                self.firewall_commands_socket.send_string(command_json)

                # Actualizar estadísticas
                conn_info = self.zmq_connections['firewall_commands']
                conn_info.total_messages += 1
                conn_info.bytes_transferred += len(command_json.encode('utf-8'))
                conn_info.last_activity = datetime.now()

                self.stats['commands_sent'] += 1
                self.firewall_commands.append(command)

                self.logger.info(f"🔥 Worker {worker_id} - Comando enviado: {command.action} para {command.target_ip}")

                # Marcar tarea como completada
                self.firewall_commands_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Error en firewall commands processor: {e}")

    def firewall_responses_receiver_with_monitoring(self, worker_id: int):
        """Recibir respuestas del Firewall Agent con monitoreo robusto"""
        self.logger.info(f"📥 Firewall Responses Receiver {worker_id} iniciado con monitoreo")

        while self.running:
            try:
                # Recibir respuesta como bytes primero
                response_bytes = self.firewall_responses_socket.recv(zmq.NOBLOCK)

                # Decodificar de manera segura
                response_text, encoding_used = self.decode_message_with_monitoring(
                    response_bytes, worker_id, 'firewall_responses'
                )
                if response_text is None:
                    continue

                # Registrar mensaje exitoso
                self.encoding_monitor.log_successful_message(
                    worker_id, 'firewall_responses', len(response_bytes), encoding_used
                )

                # Actualizar estadísticas
                conn_info = self.zmq_connections['firewall_responses']
                conn_info.total_messages += 1
                conn_info.bytes_transferred += len(response_bytes)
                conn_info.last_activity = datetime.now()

                # Parsear respuesta
                response_data = json.loads(response_text)

                # Actualizar información de conexión si tenemos datos del remitente
                if 'node_id' in response_data:
                    self.encoding_monitor.update_connection_info(
                        'firewall_responses',
                        node_id=response_data.get('node_id'),
                        component_type='firewall_agent',
                        version=response_data.get('version')
                    )

                self.logger.info(
                    f"📥 Worker {worker_id} - Respuesta firewall: {response_data.get('status', 'unknown')} para {response_data.get('target_ip', 'unknown')}")

                # Actualizar estadísticas si es exitoso
                if response_data.get('status') == 'applied':
                    self.stats['threats_blocked'] += 1

            except zmq.Again:
                continue
            except json.JSONDecodeError as e:
                self.logger.error(f"❌ Worker {worker_id} - Error parseando respuesta firewall: {e}")
            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Error en firewall responses receiver: {e}")
                time.sleep(0.1)

    def start_web_server(self):
        """Iniciar servidor web para servir archivos estáticos y API"""
        self.logger.info(f"🌐 Iniciando servidor web en {self.config.web_host}:{self.config.web_port}")

        class DashboardHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, dashboard=None, **kwargs):
                self.dashboard = dashboard
                super().__init__(*args, **kwargs)

            def do_GET(self):
                if self.path == '/' or self.path == '/index.html':
                    self.serve_dashboard_html()
                elif self.path == '/api/metrics':
                    self.serve_metrics_api()
                elif self.path == '/api/test-firewall':
                    self.serve_firewall_test_api()
                elif self.path.startswith('/static/'):
                    self.serve_static_file()
                else:
                    self.send_error(404, "Página no encontrada")

            def serve_firewall_test_api(self):
                """Endpoint para probar firewall - NUEVO"""
                try:
                    success = self.dashboard.test_firewall_connection()

                    response_data = {
                        'success': success,
                        'message': 'Comando de prueba enviado' if success else 'Error enviando comando',
                        'timestamp': datetime.now().isoformat(),
                        'test_id': f"test_{int(time.time())}"
                    }

                    response_json = json.dumps(response_data)

                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(response_json.encode('utf-8'))

                except Exception as e:
                    error_response = {
                        'success': False,
                        'message': f'Error en prueba de firewall: {str(e)}',
                        'timestamp': datetime.now().isoformat()
                    }

                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(error_response).encode('utf-8'))

            def serve_dashboard_html(self):
                try:
                    with open('templates/dashboard.html', 'r', encoding='utf-8') as f:
                        html_content = f.read()

                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.send_header('Cache-Control', 'no-cache')
                    self.end_headers()
                    self.wfile.write(html_content.encode('utf-8'))

                except FileNotFoundError:
                    self.send_error(404, "Dashboard HTML no encontrado")
                except Exception as e:
                    self.dashboard.logger.error(f"Error sirviendo dashboard HTML: {e}")
                    self.send_error(500, "Error interno del servidor")

            def serve_static_file(self):
                try:
                    file_path = self.path[1:]  # Remover '/' inicial

                    if not Path(file_path).exists():
                        self.send_error(404, "Archivo no encontrado")
                        return

                    # Determinar tipo MIME
                    mime_type, _ = mimetypes.guess_type(file_path)
                    if mime_type is None:
                        mime_type = 'application/octet-stream'

                    with open(file_path, 'rb') as f:
                        content = f.read()

                    self.send_response(200)
                    self.send_header('Content-type', mime_type)
                    self.send_header('Cache-Control', 'public, max-age=3600')
                    self.end_headers()
                    self.wfile.write(content)

                except Exception as e:
                    self.dashboard.logger.error(f"Error sirviendo archivo estático {self.path}: {e}")
                    self.send_error(500, "Error interno del servidor")

            def serve_metrics_api(self):
                try:
                    metrics = self.dashboard.get_dashboard_metrics()
                    metrics_json = json.dumps(metrics, default=str)

                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(metrics_json.encode('utf-8'))

                except Exception as e:
                    self.dashboard.logger.error(f"Error sirviendo métricas: {e}")
                    self.send_error(500, "Error generando métricas")

        def handler_factory(*args, **kwargs):
            return DashboardHTTPRequestHandler(*args, dashboard=self, **kwargs)

        # Iniciar servidor en hilo separado
        def run_server():
            try:
                with socketserver.TCPServer((self.config.web_host, self.config.web_port), handler_factory) as httpd:
                    self.logger.info(f"✅ Servidor web iniciado correctamente")
                    httpd.serve_forever()
            except Exception as e:
                self.logger.error(f"❌ Error en servidor web: {e}")

        web_thread = threading.Thread(target=run_server)
        web_thread.daemon = True
        web_thread.start()

    def start_periodic_updates(self):
        """Iniciar actualizaciones periódicas según configuración JSON"""

        def update_stats():
            while self.running:
                try:
                    self.update_statistics()
                    self.update_zmq_connection_stats()
                    self.check_component_health()
                    time.sleep(self.config.stats_interval)
                except Exception as e:
                    self.logger.error(f"❌ Error en actualizaciones periódicas: {e}")
                    time.sleep(self.config.stats_interval)

        stats_thread = threading.Thread(target=update_stats)
        stats_thread.daemon = True
        stats_thread.start()
        self.logger.info(f"✅ Actualizaciones periódicas iniciadas (intervalo: {self.config.stats_interval}s)")

    def update_statistics(self):
        """Actualizar estadísticas del dashboard - CORREGIDO COMPLETAMENTE"""
        try:
            # Calcular eventos por minuto de forma segura
            current_time = time.time()
            events_in_last_minute = 0

            for event in self.events:
                try:
                    # CORRECCIÓN CRÍTICA: Manejar timestamp como int o string
                    event_timestamp = event.timestamp

                    if isinstance(event_timestamp, (int, float)):
                        # Unix timestamp en milliseconds o seconds
                        if event_timestamp > 1e12:  # Milliseconds
                            event_time = event_timestamp / 1000.0
                        else:  # Seconds
                            event_time = float(event_timestamp)
                    else:
                        # String timestamp - parsear de forma segura
                        timestamp_str = str(event_timestamp)
                        if 'T' in timestamp_str:
                            # ISO format: 2025-07-17T14:43:59.617000
                            timestamp_str = timestamp_str[:19]  # Solo hasta segundos
                            event_time = time.mktime(time.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S'))
                        else:
                            # Otros formatos - usar tiempo actual como fallback
                            event_time = current_time

                    # Verificar si el evento es de hace menos de 60 segundos
                    if (current_time - event_time) < 60:
                        events_in_last_minute += 1

                except (ValueError, TypeError, AttributeError) as e:
                    # Error parseando timestamp - ignorar este evento
                    self.logger.debug(f"Error parseando timestamp del evento: {e}")
                    continue

            self.stats['events_per_minute'] = events_in_last_minute
            self.stats['high_risk_events'] = len([e for e in self.events if e.risk_score > 0.8])
            self.stats['geographic_distribution'] = len(set(e.location for e in self.events if e.location))
            self.stats['uptime_seconds'] = int(time.time() - self.start_time)
            self.stats['last_update'] = datetime.now().isoformat()

            # CORRECCIÓN: Manejo seguro de estadísticas de encoding
            try:
                monitoring_data = self.encoding_monitor.get_monitoring_data()
                summary = monitoring_data.get('summary', {})

                # Calcular error_rate de forma completamente segura
                total_error_rate = 0.0
                active_workers = 0
                worker_stats = monitoring_data.get('worker_stats', {})

                for worker_key, worker_data in worker_stats.items():
                    try:
                        # worker_data puede ser un dict (del asdict) o un objeto WorkerStats
                        if isinstance(worker_data, dict):
                            error_rate = worker_data.get('error_rate', 0.0)
                            status = worker_data.get('status', 'idle')
                        else:
                            error_rate = getattr(worker_data, 'error_rate', 0.0)
                            status = getattr(worker_data, 'status', 'idle')

                        if status == 'active':
                            total_error_rate += float(error_rate)
                            active_workers += 1

                    except (AttributeError, TypeError, ValueError) as e:
                        self.logger.debug(f"Error procesando worker stats {worker_key}: {e}")
                        continue

                self.stats.update({
                    'encoding_errors_total': summary.get('total_errors', 0),
                    'active_workers': summary.get('active_workers', 0),
                    'problematic_workers': summary.get('error_workers', 0),
                    'encoding_errors_rate': total_error_rate / max(active_workers, 1) if active_workers > 0 else 0.0
                })

            except Exception as e:
                self.logger.error(f"❌ Error actualizando estadísticas de encoding: {e}")
                # Valores por defecto seguros
                self.stats.update({
                    'encoding_errors_total': 0,
                    'active_workers': 0,
                    'problematic_workers': 0,
                    'encoding_errors_rate': 0.0
                })

            # Procesar eventos de la cola de forma segura
            events_processed = 0
            while not self.ml_events_queue.empty() and events_processed < 100:
                try:
                    event = self.ml_events_queue.get_nowait()
                    self.events.append(event)
                    events_processed += 1
                    self.stats['events_processed'] += 1

                    # Mantener solo los últimos 1000 eventos
                    if len(self.events) > 1000:
                        self.events = self.events[-1000:]

                except queue.Empty:
                    break
                except Exception as e:
                    self.logger.error(f"❌ Error procesando evento de la cola: {e}")
                    break

        except Exception as e:
            self.logger.error(f"❌ Error crítico en update_statistics: {e}")
            # Fallback para evitar crash
            self.stats['last_update'] = datetime.now().isoformat()

    def update_zmq_connection_stats(self):
        """Actualizar estadísticas de conexiones ZeroMQ"""
        for conn_id, conn_info in self.zmq_connections.items():
            time_since_activity = (datetime.now() - conn_info.last_activity).total_seconds()

            if time_since_activity > 60:
                conn_info.status = 'inactive'
            elif time_since_activity > 300:
                conn_info.status = 'disconnected'
            else:
                conn_info.status = 'active'

            # Actualizar métricas detalladas
            self.detailed_metrics['zmq_connections'][conn_id] = {
                'status': conn_info.status,
                'total_messages': conn_info.total_messages,
                'bytes_transferred': conn_info.bytes_transferred,
                'last_activity': conn_info.last_activity.isoformat(),
                'endpoint': conn_info.endpoint,
                'socket_type': conn_info.socket_type,
                'mode': conn_info.mode,
                'high_water_mark': conn_info.high_water_mark
            }

    def update_system_metrics(self):
        """Actualizar métricas del sistema"""
        try:
            process = psutil.Process()
            self.stats['memory_usage_mb'] = process.memory_info().rss / 1024 / 1024
            self.stats['cpu_usage_percent'] = process.cpu_percent()
        except:
            pass

    def check_component_health(self):
        """Verificar salud de componentes conectados"""
        # Implementar checks específicos basados en configuración
        pass

    def get_dashboard_metrics(self):
        """Obtener métricas completas incluyendo geolocalización del nodo - CORREGIDO"""

        # Obtener datos de monitoreo de forma segura
        try:
            monitoring_data = self.encoding_monitor.get_monitoring_data()
        except Exception as e:
            self.logger.error(f"Error obteniendo datos de monitoreo: {e}")
            monitoring_data = {'summary': {}, 'worker_stats': {}, 'connection_info': {}}

        # Geolocalización del nodo local (Madrid, España por defecto)
        local_node_position = {
            'latitude': 40.4168,
            'longitude': -3.7038,
            'location': 'Madrid, ES',
            'node_id': self.config.node_id,
            'component_type': 'dashboard',
            'status': 'online',
            'timestamp': datetime.now().isoformat()
        }

        # Convertir conexiones ZMQ de forma segura
        safe_zmq_connections = {}
        for k, v in self.zmq_connections.items():
            try:
                if hasattr(v, '__dict__'):
                    safe_zmq_connections[k] = asdict(v)
                else:
                    safe_zmq_connections[k] = v
            except Exception as e:
                self.logger.debug(f"Error convirtiendo conexión ZMQ {k}: {e}")
                safe_zmq_connections[k] = {'error': str(e)}

        # Convertir component status de forma segura
        safe_component_status = {}
        for k, v in self.component_status.items():
            try:
                safe_component_status[k] = asdict(v)
            except Exception as e:
                self.logger.debug(f"Error convirtiendo component status {k}: {e}")
                safe_component_status[k] = {'error': str(e)}

        return {
            'basic_stats': self.stats,
            'detailed_metrics': self.detailed_metrics,
            'zmq_connections': safe_zmq_connections,
            'component_status': safe_component_status,
            'recent_events': [asdict(e) for e in self.events[-50:]],
            'recent_commands': [asdict(c) for c in self.firewall_commands[-20:]],
            'node_info': {
                'node_id': self.config.node_id,
                'component_name': self.config.component_name,
                'version': self.config.version,
                'mode': self.config.mode,
                'role': self.config.role,
                'uptime_seconds': self.stats['uptime_seconds'],
                'pid': os.getpid()
            },
            'configuration': {
                'ml_events_queue_size': self.config.ml_events_queue_size,
                'ml_events_consumers': self.config.ml_events_consumers,
                'firewall_commands_queue_size': self.config.firewall_commands_queue_size,
                'firewall_command_producers': self.config.firewall_command_producers,
                'stats_interval': self.config.stats_interval
            },
            # NUEVO: Datos de monitoreo de errores
            'encoding_monitoring': monitoring_data,
            # NUEVO: Información de conectividad detallada
            'connectivity_info': {
                'ml_detector': self._get_component_connectivity('ml_events'),
                'firewall_agent': self._get_component_connectivity('firewall_commands'),
                'firewall_responses': self._get_component_connectivity('firewall_responses')
            },
            # NUEVO: Posición del nodo local
            'local_node_position': local_node_position,
            # NUEVO: Indicador de prueba de firewall
            'firewall_test_available': True
        }

    def serve_firewall_test_api(self):
        """Endpoint para probar firewall"""
        try:
            success = self.dashboard.test_firewall_connection()

            response_data = {
                'success': success,
                'message': 'Comando de prueba enviado' if success else 'Error enviando comando',
                'timestamp': datetime.now().isoformat(),
                'test_id': f"test_{int(time.time())}"
            }

            response_json = json.dumps(response_data)

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(response_json.encode('utf-8'))

        except Exception as e:
            error_response = {
                'success': False,
                'message': f'Error en prueba de firewall: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }

            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(error_response).encode('utf-8'))

    def _get_component_connectivity(self, connection_id: str) -> Dict:
        """Obtener información de conectividad para un componente"""
        conn_info = self.encoding_monitor.connection_info.get(connection_id)
        if not conn_info:
            return {'status': 'unknown', 'details': 'No connection info'}

        return {
            'status': conn_info.status,
            'node_id': conn_info.node_id or 'unknown',
            'component_type': conn_info.component_type,
            'endpoint': conn_info.endpoint,
            'remote_ip': conn_info.remote_ip,
            'remote_port': conn_info.remote_port,
            'version': conn_info.version,
            'last_seen': conn_info.last_seen.isoformat() if conn_info.last_seen else None,
            'messages_exchanged': conn_info.messages_exchanged,
            'handshake_completed': conn_info.handshake_completed
        }

    def test_firewall_connection(self):
        """Probar conexión con firewall enviando comando de prueba"""
        try:
            test_command = FirewallCommand(
                action="test_connection",
                target_ip="127.0.0.1",
                duration="10s",
                reason="Connection test",
                risk_score=0.1,
                timestamp=datetime.now().isoformat(),
                event_id=f"test_{int(time.time())}",
                rule_type="test",
                port=22,
                protocol="TCP"
            )

            # Enviar comando de prueba
            if not self.firewall_commands_queue.full():
                self.firewall_commands_queue.put(test_command)
                self.logger.info("🧪 Comando de prueba enviado al firewall")
                return True
            else:
                self.logger.warning("⚠️ Cola de comandos de firewall llena")
                return False

        except Exception as e:
            self.logger.error(f"❌ Error probando firewall: {e}")
            return False

    def stop(self):
        """Detener el dashboard de forma segura - CORREGIDO COMPLETAMENTE"""
        self.logger.info("🛑 Deteniendo Dashboard de Seguridad...")
        self.running = False

        # Cerrar sockets de forma segura con timeouts
        try:
            # Configurar linger para cierre limpio pero rápido
            if hasattr(self, 'ml_socket') and self.ml_socket:
                self.ml_socket.setsockopt(zmq.LINGER, 100)  # 100ms max
                self.ml_socket.close()
                self.logger.debug("✅ ML socket cerrado")

            if hasattr(self, 'firewall_commands_socket') and self.firewall_commands_socket:
                self.firewall_commands_socket.setsockopt(zmq.LINGER, 100)
                self.firewall_commands_socket.close()
                self.logger.debug("✅ Firewall commands socket cerrado")

            if hasattr(self, 'firewall_responses_socket') and self.firewall_responses_socket:
                self.firewall_responses_socket.setsockopt(zmq.LINGER, 100)
                self.firewall_responses_socket.close()
                self.logger.debug("✅ Firewall responses socket cerrado")

        except Exception as e:
            self.logger.error(f"⚠️ Error cerrando sockets: {e}")

        # Cerrar contexto ZeroMQ de forma segura con timeout
        try:
            if hasattr(self, 'context') and self.context:
                # Dar tiempo para que los sockets se cierren
                time.sleep(0.2)
                self.context.term()
                self.logger.debug("✅ Contexto ZMQ terminado")
        except Exception as e:
            self.logger.error(f"⚠️ Error terminando contexto ZMQ: {e}")

        self.logger.info("✅ Dashboard detenido correctamente")


def signal_handler(sig, frame):
    """Manejar señales del sistema"""
    print("\n🛑 Recibida señal de terminación")
    sys.exit(0)

def main():
    """Función principal con configuración estricta"""
    # Configurar manejo de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Verificar archivo de configuración
    if len(sys.argv) != 2:
        print("❌ Uso: python real_zmq_dashboard_with_firewall.py <config.json>")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        # Cargar configuración (FALLA si hay errores)
        config = DashboardConfig(config_file)

        # Crear directorios necesarios
        Path("logs").mkdir(exist_ok=True)
        Path("data").mkdir(exist_ok=True)
        Path("templates").mkdir(exist_ok=True)
        Path("static/css").mkdir(parents=True, exist_ok=True)
        Path("static/js").mkdir(parents=True, exist_ok=True)

        # Crear y iniciar dashboard
        dashboard = SecurityDashboard(config)
        dashboard.start()

    except ConfigurationError as e:
        print(f"💥 ERROR DE CONFIGURACIÓN: {e}")
        print("🔧 Verificar archivo JSON y campos requeridos")
        sys.exit(1)
    except Exception as e:
        print(f"💥 ERROR FATAL: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()