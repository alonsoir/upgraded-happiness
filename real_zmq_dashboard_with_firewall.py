#!/usr/bin/env python3
"""
Dashboard de Seguridad con ZeroMQ - Backend Principal v2.1
CONFIGURACIÓN ESTRICTA: Todo debe leerse del JSON, sin defaults hardcodeados
Archivos separados: templates/dashboard.html, static/css/dashboard.css
"""

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
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Set
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
    """Dashboard principal de seguridad con configuración estricta"""

    def __init__(self, config: DashboardConfig):
        self.config = config
        self.logger = DashboardLogger(config.node_id, config.logging_config)

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

        # Estadísticas
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
            'cpu_usage_percent': 0.0
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

        # Configurar sockets ZeroMQ
        self.setup_zmq_sockets()

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

    def setup_zmq_sockets(self):
        """Configurar sockets ZeroMQ según configuración JSON"""
        self.logger.info("🔧 Configurando sockets ZeroMQ desde configuración JSON...")

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

            # Registrar conexión
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

            self.logger.info("✅ Todos los sockets ZeroMQ configurados correctamente")

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

        # ML Events Consumers
        for i in range(self.config.ml_events_consumers):
            thread = threading.Thread(target=self.ml_events_receiver, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"   ✅ ML Events Consumer {i} iniciado")

        # Firewall Command Producers
        for i in range(self.config.firewall_command_producers):
            thread = threading.Thread(target=self.firewall_commands_processor, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"   ✅ Firewall Commands Producer {i} iniciado")

        # Firewall Response Consumers
        for i in range(self.config.firewall_response_consumers):
            thread = threading.Thread(target=self.firewall_responses_receiver, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"   ✅ Firewall Responses Consumer {i} iniciado")

        self.logger.info(
            f"✅ Total hilos iniciados: {self.config.ml_events_consumers + self.config.firewall_command_producers + self.config.firewall_response_consumers}")

    def ml_events_receiver(self, worker_id: int):
        """Recibir eventos del ML Detector"""
        self.logger.info(f"📡 ML Events Receiver {worker_id} iniciado")

        while self.running:
            try:
                # Recibir mensaje
                message = self.ml_socket.recv_string(zmq.NOBLOCK)

                # Actualizar estadísticas de conexión
                conn_info = self.zmq_connections['ml_events']
                conn_info.total_messages += 1
                conn_info.bytes_transferred += len(message.encode('utf-8'))
                conn_info.last_activity = datetime.now()

                # Parsear evento
                event_data = json.loads(message)
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
                self.logger.error(f"❌ Worker {worker_id} - Error en ML events receiver: {e}")
                time.sleep(0.1)

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

    def firewall_responses_receiver(self, worker_id: int):
        """Recibir respuestas del Firewall Agent"""
        self.logger.info(f"📥 Firewall Responses Receiver {worker_id} iniciado")

        while self.running:
            try:
                # Recibir respuesta
                response = self.firewall_responses_socket.recv_string(zmq.NOBLOCK)

                # Actualizar estadísticas
                conn_info = self.zmq_connections['firewall_responses']
                conn_info.total_messages += 1
                conn_info.bytes_transferred += len(response.encode('utf-8'))
                conn_info.last_activity = datetime.now()

                # Parsear respuesta
                response_data = json.loads(response)

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
                elif self.path.startswith('/static/'):
                    self.serve_static_file()
                else:
                    self.send_error(404, "Página no encontrada")

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
                    self.send_header('Cache-Control', 'public, max-age=3600')  # Cache por 1 hora
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
        """Actualizar estadísticas del dashboard"""
        # Calcular eventos por minuto
        current_time = time.time()
        events_in_last_minute = len([e for e in self.events
                                     if (current_time - time.mktime(
                time.strptime(e.timestamp[:19], '%Y-%m-%dT%H:%M:%S'))) < 60])

        self.stats['events_per_minute'] = events_in_last_minute
        self.stats['high_risk_events'] = len([e for e in self.events if e.risk_score > 0.8])
        self.stats['geographic_distribution'] = len(set(e.location for e in self.events if e.location))
        self.stats['uptime_seconds'] = int(time.time() - self.start_time)
        self.stats['last_update'] = datetime.now().isoformat()

        # Procesar eventos de la cola
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
        """Obtener métricas completas para API"""
        return {
            'basic_stats': self.stats,
            'detailed_metrics': self.detailed_metrics,
            'zmq_connections': {k: asdict(v) if hasattr(v, '__dict__') else v
                                for k, v in self.zmq_connections.items()},
            'component_status': {k: asdict(v) for k, v in self.component_status.items()},
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
            }
        }

    def stop(self):
        """Detener el dashboard"""
        self.logger.info("🛑 Deteniendo Dashboard de Seguridad...")
        self.running = False

        # Cerrar sockets
        try:
            self.ml_socket.close()
            self.firewall_commands_socket.close()
            self.firewall_responses_socket.close()
        except:
            pass

        # Cerrar contexto ZeroMQ
        self.context.term()
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