#!/usr/bin/env python3
"""
Dashboard V3.1 - Backend Principal con Fleet Management y Protobuf V3.1
✅ V3.1: Protobuf exclusivo (TODO O NADA)
✅ V3.1: SUB connection al ML_detector puerto 5580
✅ V3.1: Fleet management múltiples firewall agents
✅ V3.1: Dual communication (dashboard + scheduler channels)
✅ V3.1: NetworkSecurityEvent parsing completo
✅ V3.1: Nuclear broadcast capability
✅ V3.1: Sin cifrado/compresión (desarrollo)
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

# 📦 Protobuf V3.1 - IMPORTACIÓN EXCLUSIVA (TODO O NADA)
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkEventProto = None
FirewallCommandsProto = None


def import_dashboard_protobuf_v31():
    """Importa protobuf V3.1 EXCLUSIVO para dashboard - TODO O NADA"""
    global NetworkEventProto, FirewallCommandsProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    print("🔍 Dashboard: Buscando protobuf V3.1 EXCLUSIVO...")

    # 1. IMPORTAR NETWORK SECURITY CLEAN V3.1
    network_imported = False
    network_strategies = [
        ("network_security_clean_v31_pb2", "Importación directa v3.1"),
        ("protocols.v3.1.network_security_clean_v31_pb2", "Paquete protocols.v3.1"),
    ]

    for import_path, description in network_strategies:
        try:
            NetworkEventProto = __import__(import_path, fromlist=[''])
            network_imported = True
            print(f"✅ NetworkSecurityEvent v3.1 cargado: {description}")
            break
        except ImportError:
            continue

    # 2. IMPORTAR FIREWALL COMMANDS V3.1
    firewall_imported = False
    firewall_strategies = [
        ("firewall_commands_v31_pb2", "Importación directa v3.1"),
        ("protocols.v3.1.firewall_commands_v31_pb2", "Paquete protocols.v3.1"),
    ]

    for import_path, description in firewall_strategies:
        try:
            FirewallCommandsProto = __import__(import_path, fromlist=[''])
            firewall_imported = True
            print(f"✅ FirewallCommands v3.1 cargado: {description}")
            break
        except ImportError:
            continue

    # 3. BÚSQUEDA POR PATHS DINÁMICOS
    if not network_imported or not firewall_imported:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        possible_paths = [
            os.path.join(current_dir, '..', 'protocols', 'v3.1'),
            os.path.join(current_dir, 'protocols', 'v3.1'),
            current_dir,
        ]

        for protocols_path in possible_paths:
            protocols_path = os.path.abspath(protocols_path)

            # Buscar NetworkSecurityEvent V3.1
            if not network_imported:
                network_v31_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')
                if os.path.exists(network_v31_file):
                    try:
                        sys.path.insert(0, protocols_path)
                        import network_security_clean_v31_pb2 as NetworkEventProto
                        network_imported = True
                        print(f"✅ NetworkSecurityEvent v3.1 cargado desde: {protocols_path}")
                    except ImportError:
                        if protocols_path in sys.path:
                            sys.path.remove(protocols_path)

            # Buscar FirewallCommands V3.1
            if not firewall_imported:
                firewall_v31_file = os.path.join(protocols_path, 'firewall_commands_v31_pb2.py')
                if os.path.exists(firewall_v31_file):
                    try:
                        if protocols_path not in sys.path:
                            sys.path.insert(0, protocols_path)
                        import firewall_commands_v31_pb2 as FirewallCommandsProto
                        firewall_imported = True
                        print(f"✅ FirewallCommands v3.1 cargado desde: {protocols_path}")
                    except ImportError:
                        pass

    # 4. VERIFICACIÓN FINAL - TODO O NADA
    if network_imported and firewall_imported:
        PROTOBUF_AVAILABLE = True
        PROTOBUF_VERSION = "v3.1.0"
        print(f"🎯 Dashboard: Protobuf V3.1 COMPLETO cargado exitosamente")

        # Verificar que NetworkSecurityEvent tiene campos V3.1
        try:
            test_event = NetworkEventProto.NetworkSecurityEvent()
            if hasattr(test_event, 'network_features') and hasattr(test_event, 'geo_enrichment'):
                print(f"✅ Verificado: NetworkSecurityEvent V3.1 tiene campos requeridos")
                return True
            else:
                print(f"❌ ERROR: NetworkSecurityEvent no tiene estructura V3.1")
                return False
        except Exception as e:
            print(f"❌ ERROR verificando estructura V3.1: {e}")
            return False
    else:
        print(f"❌ Dashboard: Protobuf V3.1 REQUERIDO pero NO ENCONTRADO")
        print(f"📋 Estado:")
        print(f"   NetworkSecurityEvent V3.1: {'✅' if network_imported else '❌'}")
        print(f"   FirewallCommands V3.1: {'✅' if firewall_imported else '❌'}")
        return False


# Ejecutar importación V3.1 EXCLUSIVA
if not import_dashboard_protobuf_v31():
    print(f"💥 FATAL: Dashboard requiere protobuf V3.1 para funcionar")
    print(f"🛑 PARAR EJECUCIÓN - Sin V3.1 no hay dashboard")
    sys.exit(1)


class ConfigurationError(Exception):
    """Error de configuración del dashboard"""
    pass


class FirewallRulesError(Exception):
    """Error en reglas de firewall"""
    pass


@dataclass
class FirewallRule:
    """Regla de firewall desde JSON"""
    risk_range: List[int]
    action: str
    description: str
    params: Dict[str, Any]
    priority: str = "MEDIUM"
    dry_run: bool = False
    enabled: bool = True


@dataclass
class FirewallAgentInfo:
    """Información de un agente firewall"""
    node_id: str
    dashboard_commands_endpoint: str
    dashboard_responses_endpoint: str
    capabilities: List[str]
    max_rules: int = 1000
    default_rule_duration: int = 600
    status: str = "active"
    active_rules: int = 0


class FirewallFleetManager:
    """Manager de fleet de firewall agents V3.1"""

    def __init__(self, fleet_config: dict, logger, zmq_context):
        self.logger = logger
        self.context = zmq_context
        self.agents: Dict[str, FirewallAgentInfo] = {}
        self.command_sockets: Dict[str, zmq.Socket] = {}
        self.response_sockets: Dict[str, zmq.Socket] = {}
        self.rules: List[FirewallRule] = []
        self.manual_actions: Dict[str, Dict] = {}

        self._load_fleet_config(fleet_config)
        self._setup_fleet_sockets()

    def _load_fleet_config(self, fleet_config: dict):
        """Cargar configuración de la fleet desde JSON"""
        try:
            # Cargar agentes
            agents_config = fleet_config.get('agents', {})
            for agent_id, agent_config in agents_config.items():
                agent_info = FirewallAgentInfo(
                    node_id=agent_id,
                    dashboard_commands_endpoint=f"tcp://{agent_config['dashboard_commands']['address']}:{agent_config['dashboard_commands']['port']}",
                    dashboard_responses_endpoint=f"tcp://{agent_config['dashboard_responses']['address']}:{agent_config['dashboard_responses']['port']}",
                    capabilities=agent_config.get('capabilities', ['LIST_RULES']),
                    max_rules=agent_config.get('max_rules', 10),
                    default_rule_duration=agent_config.get('default_rule_duration', 60)
                )
                self.agents[agent_id] = agent_info

            self.logger.info(f"✅ Fleet cargada: {len(self.agents)} agentes")

        except Exception as e:
            self.logger.error(f"❌ Error cargando fleet config: {e}")
            raise

    def _setup_fleet_sockets(self):
        """Configurar sockets para todos los agents en la fleet"""
        try:
            for agent_id, agent_info in self.agents.items():
                # Socket de comandos (PUB)
                cmd_socket = self.context.socket(zmq.PUB)
                cmd_socket.setsockopt(zmq.SNDHWM, 1000)
                cmd_socket.setsockopt(zmq.LINGER, 0)
                cmd_socket.bind(agent_info.dashboard_commands_endpoint)
                self.command_sockets[agent_id] = cmd_socket

                # Socket de respuestas (SUB)
                resp_socket = self.context.socket(zmq.SUB)
                resp_socket.setsockopt(zmq.RCVHWM, 1000)
                resp_socket.setsockopt(zmq.SUBSCRIBE, b"")  # All topics
                resp_socket.connect(agent_info.dashboard_responses_endpoint)
                self.response_sockets[agent_id] = resp_socket

                self.logger.info(f"✅ Sockets configurados para agent {agent_id}")

        except Exception as e:
            self.logger.error(f"❌ Error configurando sockets fleet: {e}")
            raise

    def send_command_to_agent(self, agent_id: str, command: dict):
        """Enviar comando a un agente específico"""
        try:
            if agent_id not in self.command_sockets:
                raise ValueError(f"Agent {agent_id} no encontrado")

            if not PROTOBUF_AVAILABLE:
                raise ImportError("Protobuf V3.1 no disponible")

            # Crear comando protobuf V3.1
            proto_command = FirewallCommandsProto.FirewallCommand()
            proto_command.command_id = command.get('command_id', f"cmd_{int(time.time())}")
            proto_command.action = self._get_action_enum(command.get('action', 'LIST_RULES'))
            proto_command.target_ip = command.get('target_ip', '127.0.0.1')
            proto_command.target_port = command.get('target_port', 0)
            proto_command.duration_seconds = command.get('duration_seconds', 300)
            proto_command.reason = command.get('reason', 'Dashboard V3.1 command')
            proto_command.node_id = agent_id
            proto_command.timestamp = int(time.time() * 1000)
            proto_command.dry_run = command.get('dry_run', True)

            # Serializar y enviar
            command_bytes = proto_command.SerializeToString()
            self.command_sockets[agent_id].send(command_bytes)

            self.logger.info(f"🔥 Comando enviado a {agent_id}: {command['action']}")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error enviando comando a {agent_id}: {e}")
            return False

    def nuclear_broadcast(self, command: dict):
        """🚨 NUCLEAR BROADCAST: Enviar comando a TODOS los agents"""
        try:
            self.logger.warning(f"🚨 NUCLEAR BROADCAST iniciado: {command['action']}")

            results = {}
            for agent_id in self.agents.keys():
                result = self.send_command_to_agent(agent_id, command)
                results[agent_id] = result

            successful = sum(results.values())
            total = len(results)

            self.logger.warning(f"🚨 NUCLEAR BROADCAST completado: {successful}/{total} exitosos")
            return results

        except Exception as e:
            self.logger.error(f"❌ Error en nuclear broadcast: {e}")
            return {}

    def _get_action_enum(self, action_str: str):
        """Convertir string action a enum protobuf"""
        action_mapping = {
            'BLOCK_IP': FirewallCommandsProto.CommandAction.BLOCK_IP,
            'UNBLOCK_IP': FirewallCommandsProto.CommandAction.UNBLOCK_IP,
            'RATE_LIMIT_IP': FirewallCommandsProto.CommandAction.RATE_LIMIT_IP,
            'ALLOW_IP_TEMP': FirewallCommandsProto.CommandAction.ALLOW_IP_TEMP,
            'LIST_RULES': FirewallCommandsProto.CommandAction.LIST_RULES,
            'FLUSH_RULES': FirewallCommandsProto.CommandAction.FLUSH_RULES,
            'BACKUP_RULES': FirewallCommandsProto.CommandAction.BACKUP_RULES,
            'RESTORE_RULES': FirewallCommandsProto.CommandAction.RESTORE_RULES
        }
        return action_mapping.get(action_str, FirewallCommandsProto.CommandAction.LIST_RULES)

    def get_available_agents(self) -> List[str]:
        """Obtener lista de agents disponibles"""
        return list(self.agents.keys())

    def get_agent_info(self, agent_id: str) -> Optional[FirewallAgentInfo]:
        """Obtener información de un agente específico"""
        return self.agents.get(agent_id)


@dataclass
class SecurityEvent:
    """Evento de seguridad V3.1"""
    id: str
    source_ip: str
    target_ip: str
    risk_score: float
    anomaly_score: float
    source_latitude: Optional[float] = None
    source_longitude: Optional[float] = None
    target_latitude: Optional[float] = None
    target_longitude: Optional[float] = None
    timestamp: str = None
    attack_type: Optional[str] = None
    location: Optional[str] = None
    packets: int = 0
    bytes: int = 0
    port: Optional[int] = None
    protocol: Optional[str] = None
    ml_models_scores: Optional[Dict] = None
    protobuf_data: Optional[Dict] = None
    node_id: Optional[str] = None

    # V3.1 specific fields
    geographic_distance_km: Optional[float] = None
    same_country: Optional[bool] = None
    source_city: Optional[str] = None
    source_country: Optional[str] = None
    target_city: Optional[str] = None
    target_country: Optional[str] = None
    source_ip_enriched: Optional[bool] = None
    target_ip_enriched: Optional[bool] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class DashboardLogger:
    """Logger V3.1"""

    def __init__(self, node_id: str, log_config: dict):
        self.logger = logging.getLogger(f"dashboard_v31_{node_id}")
        self.node_id = node_id

        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        formatter = logging.Formatter(log_format)
        self.logger.handlers.clear()
        self.logger.setLevel(log_level)

        # Console handler
        console_config = log_config.get('handlers', {}).get('console', {})
        if console_config.get('enabled', True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(getattr(logging, console_config.get('level', 'INFO').upper()))
            self.logger.addHandler(console_handler)

        # File handler
        file_config = log_config.get('handlers', {}).get('file', {})
        if file_config.get('enabled', True):
            file_path = file_config.get('path', 'logs/dashboard_v31.log')
            try:
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(file_path, encoding='utf-8')
                file_handler.setFormatter(formatter)
                file_handler.setLevel(getattr(logging, file_config.get('level', 'INFO').upper()))
                self.logger.addHandler(file_handler)
                print(f"✅ Logging V3.1 a archivo: {file_path}")
            except Exception as e:
                print(f"⚠️ Error configurando file logging: {e}")

        # V3.1 events log
        v31_config = log_config.get('handlers', {}).get('v31_events_log', {})
        if v31_config.get('enabled', True):
            v31_path = v31_config.get('path', 'logs/dashboard_v31_events.jsonl')
            try:
                Path(v31_path).parent.mkdir(parents=True, exist_ok=True)
                print(f"✅ V3.1 events log configurado: {v31_path}")
            except Exception as e:
                print(f"⚠️ Error configurando V3.1 events log: {e}")

    def info(self, msg, *args, **kwargs):
        self.logger.info(f"[v31_dashboard:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(f"[v31_dashboard:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(f"[v31_dashboard:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(f"[v31_dashboard:{self.node_id}] [pid:{os.getpid()}] - {msg}", *args, **kwargs)


class DashboardConfigV31:
    """Configuración V3.1 del dashboard"""

    def __init__(self, config_file: str, firewall_rules_file: str):
        self.config_file = config_file
        self.firewall_rules_file = firewall_rules_file
        self.config = None
        self._load_and_validate_config()

    def _load_and_validate_config(self):
        """Cargar y validar configuración V3.1"""
        if not Path(self.config_file).exists():
            raise ConfigurationError(f"❌ Config file {self.config_file} no encontrado")

        if not Path(self.firewall_rules_file).exists():
            raise ConfigurationError(f"❌ Firewall rules file {self.firewall_rules_file} no encontrado")

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)

            with open(self.firewall_rules_file, 'r', encoding='utf-8') as f:
                self.firewall_config = json.load(f)

        except json.JSONDecodeError as e:
            raise ConfigurationError(f"❌ Error parseando JSON: {e}")
        except Exception as e:
            raise ConfigurationError(f"❌ Error cargando config: {e}")

        self._extract_config_values()
        print(f"✅ Configuración V3.1 cargada: {self.config_file}")

    def _extract_config_values(self):
        """Extraer valores de configuración V3.1"""
        # Node info
        self.node_id = self.config['node_id']
        component = self.config['component']
        self.component_name = component['name']
        self.version = component['version']

        # Network V3.1
        network = self.config['network']

        # ML Events (SUB from ML_detector V3.1)
        ml_events = network['ml_events_input']
        self.ml_detector_address = ml_events['address']
        self.ml_detector_port = ml_events['port']
        self.ml_detector_mode = ml_events['mode']
        self.ml_detector_socket_type = ml_events['socket_type']  # SUB

        # Fleet config
        fleet_config = network['firewall_agents_fleet']
        self.fleet_enabled = fleet_config['enabled']
        self.nuclear_broadcast_enabled = fleet_config['nuclear_broadcast_enabled']
        self.fleet_agents = fleet_config['agents']

        # Web interface
        admin = network['admin_interface']
        self.web_host = admin['address']
        self.web_port = admin['port']

        # ZMQ V3.1
        zmq_config = self.config['zmq']
        self.zmq_io_threads = zmq_config['context_io_threads']
        self.zmq_max_sockets = zmq_config['max_sockets']

        # Processing V3.1
        processing = self.config['processing']
        threads = processing['threads']
        self.ml_events_subscribers = threads['ml_events_subscribers']
        self.firewall_fleet_managers = threads['firewall_fleet_managers']
        self.firewall_response_consumers = threads['firewall_response_consumers']

        queues = processing['internal_queues']
        self.ml_events_queue_size = queues['ml_events_queue_size']
        self.firewall_commands_queue_size = queues['firewall_commands_queue_size']

        # Logging
        self.logging_config = self.config['logging']

        # Firewall fleet (from firewall_rules.json)
        self.firewall_fleet_config = self.firewall_config.get('firewall_rules', {}).get('agents_fleet', {})
        self.firewall_rules = self.firewall_config.get('firewall_rules', {}).get('rules', [])
        self.manual_actions = self.firewall_config.get('firewall_rules', {}).get('manual_actions', {})


class SecurityDashboardV31:
    """Dashboard principal V3.1 con Fleet Management"""

    def __init__(self, config: DashboardConfigV31):
        self.config = config
        self.logger = DashboardLogger(config.node_id, config.logging_config)

        # ZMQ Context
        self.context = zmq.Context(io_threads=config.zmq_io_threads)

        # Fleet Manager V3.1
        self.fleet_manager = FirewallFleetManager(
            config.firewall_fleet_config,
            self.logger,
            self.context
        )

        # Estado del dashboard
        self.events: List[SecurityEvent] = []
        self.recent_events: List[Dict] = []  # Para frontend

        # Colas de procesamiento V3.1
        self.ml_events_queue = queue.Queue(maxsize=config.ml_events_queue_size)
        self.firewall_commands_queue = queue.Queue(maxsize=config.firewall_commands_queue_size)

        # Estadísticas V3.1
        self.stats = {
            'events_received': 0,
            'events_processed': 0,
            'commands_sent': 0,
            'threats_blocked': 0,
            'events_per_minute': 0,
            'high_risk_events': 0,
            'total_events': 0,
            'success_rate': 95,
            'failures': 0,
            'confirmations': 0,
            'protobuf_v31_messages': 0,
            'ml_detector_v31_connected': False,
            'fleet_agents_active': len(self.fleet_manager.agents),
            'nuclear_broadcasts_sent': 0,
            'last_update': datetime.now().isoformat(),
            'uptime_seconds': 0
        }

        self.running = False
        self.start_time = time.time()

        # Setup sockets V3.1
        self._setup_zmq_sockets_v31()

    def _setup_zmq_sockets_v31(self):
        """Configurar sockets ZMQ V3.1"""
        self.logger.info("🔧 Configurando sockets ZMQ V3.1...")

        try:
            # ML Events SUB Socket (V3.1)
            self.ml_socket = self.context.socket(zmq.SUB)
            self.ml_socket.setsockopt(zmq.RCVHWM, 2000)
            self.ml_socket.setsockopt(zmq.LINGER, 0)
            self.ml_socket.setsockopt(zmq.RCVTIMEO, 1000)
            self.ml_socket.setsockopt(zmq.SUBSCRIBE, b"")  # Subscribe to all topics

            ml_endpoint = f"tcp://{self.config.ml_detector_address}:{self.config.ml_detector_port}"
            self.ml_socket.connect(ml_endpoint)

            self.logger.info(f"✅ ML Events SUB socket conectado a {ml_endpoint}")

        except Exception as e:
            self.logger.error(f"❌ Error configurando sockets V3.1: {e}")
            raise

    def start(self):
        """Iniciar dashboard V3.1"""
        self.running = True
        self.logger.info(f"🚀 Iniciando Dashboard V3.1...")
        self.logger.info(f"📋 Node ID: {self.config.node_id}")
        self.logger.info(f"🏗️ Component: {self.config.component_name} v{self.config.version}")
        self.logger.info(f"🔥 Fleet Agents: {len(self.fleet_manager.agents)}")
        self.logger.info(f"🚨 Nuclear Broadcast: {self.config.nuclear_broadcast_enabled}")

        # Mostrar configuración de fleet
        for agent_id, agent_info in self.fleet_manager.agents.items():
            self.logger.info(f"   🤖 Agent: {agent_id} -> {agent_info.dashboard_commands_endpoint}")

        # Iniciar hilos V3.1
        self._start_processing_threads_v31()

        # Iniciar servidor web
        self._start_web_server_v31()

        # Iniciar actualizaciones periódicas
        self._start_periodic_updates_v31()

        self.logger.info("✅ Dashboard V3.1 iniciado correctamente")
        self.logger.info(f"🌐 Interfaz web disponible en: http://{self.config.web_host}:{self.config.web_port}")

        try:
            while self.running:
                time.sleep(1)
                self._update_system_metrics()
        except KeyboardInterrupt:
            self.logger.info("🛑 Recibida señal de interrupción")
            self.stop()

    def _start_processing_threads_v31(self):
        """Iniciar hilos de procesamiento V3.1"""
        self.logger.info("🧵 Iniciando hilos de procesamiento V3.1...")

        # ML Events Subscribers (SUB pattern)
        for i in range(self.config.ml_events_subscribers):
            thread = threading.Thread(target=self._ml_events_subscriber_v31, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"📡 ML Events Subscriber V3.1 {i} iniciado")

        # Fleet Command Processors
        for i in range(self.config.firewall_fleet_managers):
            thread = threading.Thread(target=self._fleet_command_processor_v31, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"🔥 Fleet Command Processor V3.1 {i} iniciado")

        # Fleet Response Consumers
        for i in range(self.config.firewall_response_consumers):
            thread = threading.Thread(target=self._fleet_response_consumer_v31, args=(i,))
            thread.daemon = True
            thread.start()
            self.logger.info(f"📥 Fleet Response Consumer V3.1 {i} iniciado")

    def _ml_events_subscriber_v31(self, worker_id: int):
        """Worker para recibir eventos del ML_detector V3.1"""
        self.logger.info(f"📡 ML Events Subscriber V3.1 {worker_id} iniciado")

        while self.running:
            try:
                # Recibir mensaje SUB
                try:
                    message_bytes = self.ml_socket.recv(zmq.NOBLOCK)
                except zmq.Again:
                    continue

                self.logger.debug(f"📨 Worker {worker_id} - Mensaje V3.1 recibido: {len(message_bytes)} bytes")

                # Parse NetworkSecurityEvent V3.1
                try:
                    event_data = self._parse_network_security_event_v31(message_bytes)
                    if not event_data:
                        continue

                    # Crear SecurityEvent
                    event = self._create_security_event_from_v31(event_data)

                    # Añadir a cola
                    if not self.ml_events_queue.full():
                        self.ml_events_queue.put(event)
                        self.stats['events_received'] += 1
                        self.stats['protobuf_v31_messages'] += 1
                        self.stats['ml_detector_v31_connected'] = True

                    self.logger.debug(
                        f"✅ Worker {worker_id} - Evento V3.1 procesado: {event.source_ip} → {event.target_ip}")

                except Exception as e:
                    self.logger.error(f"❌ Worker {worker_id} - Error parseando evento V3.1: {e}")

            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Error general: {e}")
                time.sleep(0.1)

    def _parse_network_security_event_v31(self, data: bytes) -> Optional[Dict]:
        """Parser para NetworkSecurityEvent V3.1"""
        try:
            if not PROTOBUF_AVAILABLE:
                self.logger.error("❌ Protobuf V3.1 no disponible")
                return None

            # Parse NetworkSecurityEvent V3.1
            event = NetworkEventProto.NetworkSecurityEvent()
            event.ParseFromString(data)

            # Extract data completo V3.1
            parsed_event = {
                # Basic identification
                'event_id': event.event_id,
                'timestamp': event.event_timestamp.seconds if event.HasField('event_timestamp') else int(time.time()),
                'node_id': event.capturing_node.node_id if event.HasField('capturing_node') else 'unknown',

                # Network features
                'source_ip': event.network_features.source_ip if event.HasField('network_features') else '127.0.0.1',
                'target_ip': event.network_features.destination_ip if event.HasField(
                    'network_features') else '127.0.0.1',
                'source_port': event.network_features.source_port if event.HasField('network_features') else 0,
                'dest_port': event.network_features.destination_port if event.HasField('network_features') else 0,
                'protocol': event.network_features.protocol_name if event.HasField('network_features') else 'TCP',
                'packets': int(
                    event.network_features.total_forward_packets + event.network_features.total_backward_packets) if event.HasField(
                    'network_features') else 1,
                'bytes': int(
                    event.network_features.total_forward_bytes + event.network_features.total_backward_bytes) if event.HasField(
                    'network_features') else len(data),

                # Dual geolocation V3.1
                'source_latitude': None,
                'source_longitude': None,
                'target_latitude': None,
                'target_longitude': None,
                'source_city': '',
                'source_country': '',
                'target_city': '',
                'target_country': '',
                'source_ip_enriched': False,
                'target_ip_enriched': False,
                'geographic_distance_km': 0.0,
                'same_country': False,

                # ML Analysis V3.1
                'risk_score': 0.5,
                'anomaly_score': 0.5,
                'attack_type': 'network_event',
                'ml_models_scores': {},

                # Legacy compatibility
                'port': 0
            }

            # Extract geo enrichment V3.1
            if event.HasField('geo_enrichment'):
                geo = event.geo_enrichment

                # Source IP geo
                if geo.HasField('source_ip_geo'):
                    parsed_event['source_latitude'] = geo.source_ip_geo.latitude
                    parsed_event['source_longitude'] = geo.source_ip_geo.longitude
                    parsed_event['source_city'] = geo.source_ip_geo.city_name
                    parsed_event['source_country'] = geo.source_ip_geo.country_name
                    parsed_event['source_ip_enriched'] = True

                # Target IP geo
                if geo.HasField('destination_ip_geo'):
                    parsed_event['target_latitude'] = geo.destination_ip_geo.latitude
                    parsed_event['target_longitude'] = geo.destination_ip_geo.longitude
                    parsed_event['target_city'] = geo.destination_ip_geo.city_name
                    parsed_event['target_country'] = geo.destination_ip_geo.country_name
                    parsed_event['target_ip_enriched'] = True

                # Geographic analysis
                parsed_event['geographic_distance_km'] = geo.source_destination_distance_km
                parsed_event['same_country'] = geo.source_destination_same_country

            # Extract ML analysis V3.1
            if event.HasField('ml_analysis'):
                ml = event.ml_analysis
                parsed_event['risk_score'] = ml.ensemble_confidence

                if ml.HasField('level1_general_detection'):
                    parsed_event['anomaly_score'] = ml.level1_general_detection.confidence_score

                if ml.HasField('level3_specialized_predictions'):
                    for pred in ml.level3_specialized_predictions:
                        if pred.model_name:
                            parsed_event['ml_models_scores'][pred.model_name] = pred.confidence_score

                parsed_event['attack_type'] = ml.final_threat_classification or 'network_event'

            # Extract pipeline tracking
            if event.HasField('pipeline_tracking'):
                parsed_event['pipeline_info'] = {
                    'pipeline_id': event.pipeline_tracking.pipeline_id,
                    'processing_latency_ms': event.pipeline_tracking.total_processing_latency.seconds * 1000,
                    'pipeline_hops': event.pipeline_tracking.pipeline_hops_count
                }

            # Port compatibility
            parsed_event['port'] = parsed_event['dest_port'] or 80

            return parsed_event

        except Exception as e:
            self.logger.error(f"❌ Error parsing NetworkSecurityEvent V3.1: {e}")
            return None

    def _create_security_event_from_v31(self, data: Dict) -> SecurityEvent:
        """Crear SecurityEvent desde datos V3.1"""
        return SecurityEvent(
            id=data.get('event_id', str(int(time.time() * 1000000))),
            source_ip=data.get('source_ip', '127.0.0.1'),
            target_ip=data.get('target_ip', '127.0.0.1'),
            risk_score=float(data.get('risk_score', 0.5)),
            anomaly_score=float(data.get('anomaly_score', 0.5)),
            source_latitude=data.get('source_latitude'),
            source_longitude=data.get('source_longitude'),
            target_latitude=data.get('target_latitude'),
            target_longitude=data.get('target_longitude'),
            timestamp=str(data.get('timestamp', int(time.time()))),
            attack_type=data.get('attack_type'),
            location=data.get('location'),
            packets=int(data.get('packets', 0)),
            bytes=int(data.get('bytes', 0)),
            port=data.get('port'),
            protocol=data.get('protocol'),
            ml_models_scores=data.get('ml_models_scores'),
            protobuf_data=data,
            node_id=data.get('node_id'),
            geographic_distance_km=data.get('geographic_distance_km'),
            same_country=data.get('same_country'),
            source_city=data.get('source_city'),
            source_country=data.get('source_country'),
            target_city=data.get('target_city'),
            target_country=data.get('target_country'),
            source_ip_enriched=data.get('source_ip_enriched'),
            target_ip_enriched=data.get('target_ip_enriched')
        )

    def _fleet_command_processor_v31(self, worker_id: int):
        """Procesar comandos de fleet V3.1"""
        self.logger.info(f"🔥 Fleet Command Processor V3.1 {worker_id} iniciado")

        while self.running:
            try:
                command = self.firewall_commands_queue.get(timeout=1)

                # Determinar target
                target = command.get('target', 'single')

                if target == 'nuclear' or command.get('nuclear_broadcast', False):
                    # Nuclear broadcast
                    results = self.fleet_manager.nuclear_broadcast(command)
                    self.stats['nuclear_broadcasts_sent'] += 1
                    self.logger.warning(f"🚨 Nuclear broadcast ejecutado por worker {worker_id}")
                else:
                    # Single agent
                    agent_id = command.get('agent_id', self.fleet_manager.get_available_agents()[0])
                    result = self.fleet_manager.send_command_to_agent(agent_id, command)

                self.stats['commands_sent'] += 1
                self.firewall_commands_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Error procesando comando: {e}")

    def _fleet_response_consumer_v31(self, worker_id: int):
        """Consumir respuestas de fleet V3.1"""
        self.logger.info(f"📥 Fleet Response Consumer V3.1 {worker_id} iniciado")

        while self.running:
            try:
                # Recibir respuestas de todos los agents
                for agent_id, response_socket in self.fleet_manager.response_sockets.items():
                    try:
                        response_bytes = response_socket.recv(zmq.NOBLOCK)
                        self._process_fleet_response(agent_id, response_bytes, worker_id)
                    except zmq.Again:
                        continue

                time.sleep(0.1)  # Small delay to prevent busy waiting

            except Exception as e:
                self.logger.error(f"❌ Worker {worker_id} - Error en fleet response consumer: {e}")
                time.sleep(0.1)

    def _process_fleet_response(self, agent_id: str, response_bytes: bytes, worker_id: int):
        """Procesar respuesta de un agent"""
        try:
            if not PROTOBUF_AVAILABLE:
                return

            # Parse FirewallResponse V3.1
            response = FirewallCommandsProto.FirewallResponse()
            response.ParseFromString(response_bytes)

            self.logger.info(
                f"📥 Worker {worker_id} - Respuesta de {agent_id}: {response.command_id} - Success: {response.success}")

            if response.success:
                self.stats['confirmations'] += 1
            else:
                self.stats['failures'] += 1

        except Exception as e:
            self.logger.error(f"❌ Error procesando respuesta de {agent_id}: {e}")

    def _start_web_server_v31(self):
        """Iniciar servidor web V3.1"""
        self.logger.info(f"🌐 Iniciando servidor web V3.1 en {self.config.web_host}:{self.config.web_port}")

        class DashboardHTTPRequestHandlerV31(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, dashboard=None, **kwargs):
                self.dashboard = dashboard
                super().__init__(*args, **kwargs)

            def do_GET(self):
                if self.path == '/' or self.path == '/index.html':
                    self.serve_dashboard_html()
                elif self.path == '/api/metrics':
                    self.serve_metrics_api_v31()
                elif self.path == '/api/fleet-status':
                    self.serve_fleet_status_api()
                elif self.path.startswith('/static/'):
                    self.serve_static_file()
                else:
                    self.send_error(404, "Página no encontrada")

            def do_POST(self):
                if self.path == '/api/execute-firewall-action':
                    self.serve_execute_firewall_action_v31()
                elif self.path == '/api/nuclear-broadcast':
                    self.serve_nuclear_broadcast_api()
                elif self.path == '/api/firewall-agent-info':
                    self.serve_firewall_agent_info_v31()
                else:
                    self.send_error(404, "Endpoint POST no encontrado")

            def serve_metrics_api_v31(self):
                """API de métricas V3.1"""
                try:
                    # Procesar eventos de la cola para estadísticas
                    self._process_events_for_stats()

                    data = {
                        'success': True,
                        'version': '3.1.0',
                        'basic_stats': self.dashboard.stats,
                        'recent_events': self.dashboard.recent_events,
                        'fleet_info': {
                            'agents_count': len(self.dashboard.fleet_manager.agents),
                            'nuclear_broadcast_enabled': self.dashboard.config.nuclear_broadcast_enabled,
                            'available_agents': self.dashboard.fleet_manager.get_available_agents()
                        },
                        'firewall_rules_info': {
                            'rules_count': len(self.dashboard.config.firewall_rules),
                            'manual_actions': list(self.dashboard.config.manual_actions.keys())
                        },
                        'timestamp': datetime.now().isoformat()
                    }

                    response_json = json.dumps(data, default=str)

                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(response_json.encode('utf-8'))

                except Exception as e:
                    self.dashboard.logger.error(f"❌ Error sirviendo métricas V3.1: {e}")
                    self._send_error_response(str(e))

            def serve_execute_firewall_action_v31(self):
                """Ejecutar acción de firewall V3.1"""
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length)
                    request_data = json.loads(post_data.decode('utf-8'))

                    # Validar datos
                    required_fields = ['action', 'target_ip']
                    for field in required_fields:
                        if field not in request_data:
                            raise ValueError(f"Campo requerido faltante: {field}")

                    # Crear comando
                    command = {
                        'command_id': request_data.get('command_id', f"dashboard_{int(time.time())}"),
                        'action': request_data['action'],
                        'target_ip': request_data['target_ip'],
                        'target_port': request_data.get('target_port', 0),
                        'duration_seconds': request_data.get('duration_seconds', 300),
                        'reason': request_data.get('reason', 'Dashboard V3.1 action'),
                        'dry_run': request_data.get('dry_run', True),
                        'agent_id': request_data.get('firewall_node_id'),
                        'nuclear_broadcast': request_data.get('nuclear_broadcast', False)
                    }

                    # Añadir a cola
                    self.dashboard.firewall_commands_queue.put(command)

                    response_data = {
                        'success': True,
                        'message': f'Comando {command["action"]} encolado exitosamente',
                        'command_id': command['command_id'],
                        'version': '3.1.0'
                    }

                    self._send_json_response(response_data)

                except Exception as e:
                    self.dashboard.logger.error(f"❌ Error en execute-firewall-action V3.1: {e}")
                    self._send_error_response(str(e))

            def serve_nuclear_broadcast_api(self):
                """API para nuclear broadcast V3.1"""
                try:
                    if not self.dashboard.config.nuclear_broadcast_enabled:
                        raise ValueError("Nuclear broadcast deshabilitado")

                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length)
                    request_data = json.loads(post_data.decode('utf-8'))

                    command = {
                        'command_id': f"nuclear_{int(time.time())}",
                        'action': request_data.get('action', 'LIST_RULES'),
                        'target_ip': request_data.get('target_ip', '127.0.0.1'),
                        'duration_seconds': request_data.get('duration_seconds', 300),
                        'reason': 'Nuclear broadcast from Dashboard V3.1',
                        'dry_run': True,
                        'nuclear_broadcast': True,
                        'target': 'nuclear'
                    }

                    self.dashboard.firewall_commands_queue.put(command)

                    response_data = {
                        'success': True,
                        'message': f'🚨 Nuclear broadcast {command["action"]} iniciado',
                        'command_id': command['command_id'],
                        'agents_targeted': len(self.dashboard.fleet_manager.agents)
                    }

                    self._send_json_response(response_data)

                except Exception as e:
                    self.dashboard.logger.error(f"❌ Error en nuclear broadcast: {e}")
                    self._send_error_response(str(e))

            def serve_firewall_agent_info_v31(self):
                """Info de firewall agents V3.1"""
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                    if content_length > 0:
                        post_data = self.rfile.read(content_length)
                        request_data = json.loads(post_data.decode('utf-8'))
                    else:
                        request_data = {}

                    # Obtener agent por defecto o específico
                    available_agents = self.dashboard.fleet_manager.get_available_agents()
                    target_agent_id = available_agents[0] if available_agents else 'unknown'

                    agent_info = self.dashboard.fleet_manager.get_agent_info(target_agent_id)

                    if agent_info:
                        firewall_info = {
                            'node_id': agent_info.node_id,
                            'agent_ip': request_data.get('source_ip', '127.0.0.1'),
                            'status': agent_info.status,
                            'active_rules': agent_info.active_rules,
                            'endpoint': agent_info.dashboard_commands_endpoint,
                            'capabilities': agent_info.capabilities,
                            'max_rules': agent_info.max_rules
                        }
                    else:
                        firewall_info = {
                            'node_id': 'unknown_agent',
                            'agent_ip': '127.0.0.1',
                            'status': 'unknown',
                            'active_rules': 0,
                            'endpoint': 'tcp://localhost:5580',
                            'capabilities': ['LIST_RULES']
                        }

                    response_data = {
                        'success': True,
                        'firewall_info': firewall_info,
                        'version': '3.1.0'
                    }

                    self._send_json_response(response_data)

                except Exception as e:
                    self.dashboard.logger.error(f"❌ Error en firewall-agent-info V3.1: {e}")
                    self._send_error_response(str(e))

            def _process_events_for_stats(self):
                """Procesar eventos de la cola para estadísticas"""
                events_processed = 0
                while not self.dashboard.ml_events_queue.empty() and events_processed < 50:
                    try:
                        event = self.dashboard.ml_events_queue.get_nowait()

                        # Añadir a eventos recientes
                        web_event = {
                            'id': event.id,
                            'timestamp': int(time.time()),
                            'source_ip': event.source_ip,
                            'target_ip': event.target_ip,
                            'risk_score': event.risk_score,
                            'latitude': event.source_latitude or 0.0,
                            'longitude': event.source_longitude or 0.0,
                            'source_latitude': event.source_latitude,
                            'source_longitude': event.source_longitude,
                            'target_latitude': event.target_latitude,
                            'target_longitude': event.target_longitude,
                            'location': event.location,
                            'type': event.attack_type or 'network_event',
                            'protocol': event.protocol or 'TCP',
                            'port': event.port or 80,
                            'packets': event.packets,
                            'bytes': event.bytes,
                            'node_id': event.node_id,
                            'geographic_distance_km': event.geographic_distance_km,
                            'same_country': event.same_country,
                            'source_city': event.source_city,
                            'source_country': event.source_country,
                            'target_city': event.target_city,
                            'target_country': event.target_country,
                            'source_ip_enriched': event.source_ip_enriched,
                            'target_ip_enriched': event.target_ip_enriched,
                            'risk_level': 'high' if event.risk_score > 0.7 else 'medium' if event.risk_score > 0.3 else 'low'
                        }

                        self.dashboard.recent_events.append(web_event)
                        self.dashboard.events.append(event)

                        if event.risk_score > 0.8:
                            self.dashboard.stats['high_risk_events'] += 1

                        events_processed += 1
                        self.dashboard.stats['events_processed'] += 1
                        self.dashboard.stats['total_events'] += 1

                    except queue.Empty:
                        break
                    except Exception as e:
                        self.dashboard.logger.error(f"❌ Error procesando evento para stats: {e}")

            def _send_json_response(self, data):
                """Enviar respuesta JSON"""
                response_json = json.dumps(data, default=str)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(response_json.encode('utf-8'))

            def _send_error_response(self, error_msg):
                """Enviar respuesta de error"""
                error_response = {
                    'success': False,
                    'error': error_msg,
                    'version': '3.1.0',
                    'timestamp': datetime.now().isoformat()
                }
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(error_response).encode('utf-8'))

            def serve_dashboard_html(self):
                """Servir HTML del dashboard"""
                try:
                    html_path = Path('templates/dashboard.html')
                    if html_path.exists():
                        with open(html_path, 'r', encoding='utf-8') as f:
                            html_content = f.read()
                    else:
                        html_content = self._get_basic_html()

                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.send_header('Cache-Control', 'no-cache')
                    self.send_header("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;")
                    self.end_headers()
                    self.wfile.write(html_content.encode('utf-8'))

                except Exception as e:
                    self.dashboard.logger.error(f"Error sirviendo HTML: {e}")
                    self._send_basic_html()

            def _get_basic_html(self):
                """HTML básico si no existe el archivo"""
                return '''<!DOCTYPE html>
<html>
<head>
    <title>Security Dashboard V3.1</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>🚀 Security Dashboard V3.1</h1>
    <p>✅ Dashboard V3.1 funcionando correctamente</p>
    <p>📡 ML Detector V3.1 Compatible (SUB connection)</p>
    <p>🔥 Fleet Management Activo</p>
    <p>🚨 Nuclear Broadcast Disponible</p>
    <p><a href="/api/metrics">Ver métricas JSON V3.1</a></p>
</body>
</html>'''

            def serve_static_file(self):
                """Servir archivos estáticos"""
                try:
                    file_path = self.path[1:]
                    if not Path(file_path).exists():
                        self.send_error(404, "Archivo no encontrado")
                        return

                    mime_type, _ = mimetypes.guess_type(file_path)
                    if mime_type is None:
                        mime_type = 'application/octet-stream'

                    with open(file_path, 'rb') as f:
                        content = f.read()

                    self.send_response(200)
                    self.send_header('Content-type', mime_type)
                    self.end_headers()
                    self.wfile.write(content)

                except Exception as e:
                    self.dashboard.logger.error(f"Error sirviendo archivo estático {self.path}: {e}")
                    self.send_error(500, "Error interno del servidor")

        def handler_factory(*args, **kwargs):
            return DashboardHTTPRequestHandlerV31(*args, dashboard=self, **kwargs)

        def run_server():
            try:
                with socketserver.TCPServer((self.config.web_host, self.config.web_port), handler_factory) as httpd:
                    self.logger.info(f"✅ Servidor web V3.1 iniciado correctamente")
                    httpd.serve_forever()
            except Exception as e:
                self.logger.error(f"❌ Error en servidor web V3.1: {e}")

        web_thread = threading.Thread(target=run_server)
        web_thread.daemon = True
        web_thread.start()

    def _start_periodic_updates_v31(self):
        """Actualizaciones periódicas V3.1"""

        def update_stats():
            while self.running:
                try:
                    self._update_statistics_v31()
                    time.sleep(15)  # Update every 15 seconds
                except Exception as e:
                    self.logger.error(f"❌ Error en actualizaciones periódicas V3.1: {e}")
                    time.sleep(15)

        stats_thread = threading.Thread(target=update_stats)
        stats_thread.daemon = True
        stats_thread.start()
        self.logger.info("✅ Actualizaciones periódicas V3.1 iniciadas")

    def _update_statistics_v31(self):
        """Actualizar estadísticas V3.1"""
        try:
            # Calcular eventos por minuto
            current_time = time.time()
            events_in_last_minute = len([e for e in self.events if (current_time - float(e.timestamp)) < 60])
            self.stats['events_per_minute'] = events_in_last_minute

            # Otras estadísticas
            self.stats['uptime_seconds'] = int(current_time - self.start_time)
            self.stats['last_update'] = datetime.now().isoformat()
            self.stats['fleet_agents_active'] = len(
                [a for a in self.fleet_manager.agents.values() if a.status == 'active'])

            # Success rate
            total_commands = self.stats['commands_sent']
            if total_commands > 0:
                self.stats['success_rate'] = (self.stats['confirmations'] / total_commands) * 100
            else:
                self.stats['success_rate'] = 100

        except Exception as e:
            self.logger.error(f"❌ Error actualizando estadísticas V3.1: {e}")

    def _update_system_metrics(self):
        """Actualizar métricas del sistema"""
        try:
            process = psutil.Process()
            self.stats['memory_usage_mb'] = process.memory_info().rss / 1024 / 1024
            self.stats['cpu_usage_percent'] = process.cpu_percent()
        except:
            pass

    def stop(self):
        """Detener dashboard V3.1"""
        self.logger.info("🛑 Deteniendo Dashboard V3.1...")
        self.running = False

        # Cerrar sockets
        try:
            if hasattr(self, 'ml_socket'):
                self.ml_socket.close()

            # Cerrar sockets de fleet
            for socket in self.fleet_manager.command_sockets.values():
                socket.close()
            for socket in self.fleet_manager.response_sockets.values():
                socket.close()

            self.context.term()
            self.logger.info("✅ Sockets V3.1 cerrados")

        except Exception as e:
            self.logger.error(f"⚠️ Error cerrando sockets V3.1: {e}")

        self.logger.info("✅ Dashboard V3.1 detenido correctamente")


def signal_handler(sig, frame):
    """Manejar señales del sistema"""
    print("\n🛑 Recibida señal de terminación V3.1")
    sys.exit(0)


def main():
    """Función principal V3.1"""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("🚀 Dashboard V3.1 - Inicio")
    print("✅ Protobuf V3.1 exclusivo")
    print("📡 SUB connection al ML_detector puerto 5580")
    print("🔥 Fleet management múltiples firewall agents")
    print("🚨 Nuclear broadcast capability")
    print("❌ Sin cifrado/compresión (desarrollo)")

    if len(sys.argv) != 3:
        print("\n❌ Uso incorrecto:")
        print("python dashboard_v31.py <dashboard_config_v31.json> <firewall_rules.json>")
        print("\n📋 Archivos requeridos:")
        print("   • dashboard_config_v31.json: Configuración V3.1 del dashboard")
        print("   • firewall_rules.json: Configuración de la fleet de firewall agents")
        sys.exit(1)

    config_file = sys.argv[1]
    firewall_rules_file = sys.argv[2]

    # Validar archivos
    if not Path(config_file).exists():
        print(f"\n❌ ERROR: {config_file} no encontrado")
        sys.exit(1)

    if not Path(firewall_rules_file).exists():
        print(f"\n❌ ERROR: {firewall_rules_file} no encontrado")
        sys.exit(1)

    print(f"✅ Archivos de configuración V3.1:")
    print(f"   📋 Dashboard: {config_file}")
    print(f"   🔥 Fleet: {firewall_rules_file}")

    try:
        # Cargar configuración V3.1
        config = DashboardConfigV31(config_file, firewall_rules_file)

        # Crear directorios necesarios
        for directory in ['logs', 'data', 'templates', 'static/css', 'static/js']:
            Path(directory).mkdir(parents=True, exist_ok=True)

        # Iniciar dashboard V3.1
        dashboard = SecurityDashboardV31(config)
        dashboard.start()

    except (ConfigurationError, FirewallRulesError) as e:
        print(f"\n💥 ERROR DE CONFIGURACIÓN V3.1:")
        print(f"❌ {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"\n💥 ERROR DE FORMATO JSON:")
        print(f"❌ {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 ERROR FATAL V3.1:")
        print(f"❌ {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()