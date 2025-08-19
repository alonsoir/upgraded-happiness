#!/usr/bin/env python3
"""
🚀 Dashboard Backend V3.1 - CON CRYPTO + COMPRESIÓN AUTOMÁTICA
✅ Sistema SCADA para monitoreo de seguridad distribuido
✅ Compatible con protobuf V3.1 + ML Detector tricapa
✅ 🔐 CRYPTO TRANSPARENTE - AES-256-GCM + LZ4 automático
✅ 🏆 Fleet Management cifrado - Comunicación segura con agentes
✅ Zero-knowledge crypto para el desarrollador
✅ Mismo patrón que scheduler-firewall.py y simple_firewall_agent_v31.py
"""

import asyncio
import json
import logging
import os
import sys
import time
import zmq
import zmq.asyncio
import threading
import signal
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import queue
import uuid

# 🔐 STEP 1: Importar CryptoZMQV31 (mismo patrón que otros componentes)
crypto_wrapper_class = None
try:
    from crypto.crypto_zmq_v31 import CryptoZMQV31

    crypto_wrapper_class = CryptoZMQV31
    print("✅ CryptoZMQV31 disponible para Dashboard V3.1")
except ImportError as e:
    print(f"⚠️ CryptoZMQV31 NO disponible: {e}")

# 🔍 STEP 2: Add protocols path for protobuf imports (MISMO PATRÓN QUE SCHEDULER)
sys.path.append(os.path.join(os.path.dirname(__file__), 'protocols', 'current'))

# 📦 Protobuf V3.1 - Importación exclusiva (TODO O NADA) - IGUAL QUE SCHEDULER
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkEventProto = None
FirewallCommandsProto = None


def import_dashboard_protobuf_v31():
    """Importa protobuf V3.1 EXCLUSIVO para dashboard - MISMO MECANISMO QUE SCHEDULER"""
    global NetworkEventProto, FirewallCommandsProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    print("🔍 Dashboard: Buscando protobuf V3.1 EXCLUSIVO...")

    # 1. IMPORTAR FIREWALL COMMANDS V3.1
    firewall_imported = False
    firewall_strategies = [
        ("firewall_commands_v31_pb2", "Importación directa"),
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

    # 2. IMPORTAR NETWORK EVENT (ML Detector events)
    network_imported = False
    network_strategies = [
        ("network_security_clean_v31_pb2", "Importación directa v3.1"),
        ("protocols.v3.1.network_security_clean_v31_pb2", "Paquete protocols.v3.1"),
        ("network_event_extended_v3_pb2", "Importación directa v3.0"),
        ("protocols.v3.1.network_event_extended_v3_pb2", "Paquete protocols.v3.1 v3.0"),
    ]

    for import_path, description in network_strategies:
        try:
            NetworkEventProto = __import__(import_path, fromlist=[''])
            network_imported = True
            print(f"✅ NetworkEvent cargado: {description}")
            break
        except ImportError:
            continue

    # 3. ESTRATEGIA DE BÚSQUEDA POR PATHS DINÁMICOS (IGUAL QUE SCHEDULER)
    if not firewall_imported or not network_imported:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        possible_paths = [
            os.path.join(current_dir, '..', 'protocols', 'v3.1'),
            os.path.join(current_dir, 'protocols', 'v3.1'),
            current_dir,
            os.path.join(current_dir, '..'),
        ]

        for protocols_path in possible_paths:
            protocols_path = os.path.abspath(protocols_path)

            # Buscar FirewallCommands V3.1
            if not firewall_imported:
                firewall_pb2_file = os.path.join(protocols_path, 'firewall_commands_v31_pb2.py')
                if os.path.exists(firewall_pb2_file):
                    try:
                        sys.path.insert(0, protocols_path)
                        import firewall_commands_v31_pb2 as FirewallCommandsProto
                        firewall_imported = True
                        print(f"✅ FirewallCommands v3.1 cargado desde: {protocols_path}")
                    except ImportError as e:
                        if protocols_path in sys.path:
                            sys.path.remove(protocols_path)

            # Buscar NetworkEvent
            if not network_imported:
                # Prioridad 1: V3.1 limpio
                network_v31_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')
                network_v3_file = os.path.join(protocols_path, 'network_event_extended_v3_pb2.py')

                if os.path.exists(network_v31_file):
                    try:
                        if protocols_path not in sys.path:
                            sys.path.insert(0, protocols_path)
                        import network_security_clean_v31_pb2 as NetworkEventProto
                        network_imported = True
                        print(f"✅ NetworkEvent v3.1 limpio cargado desde: {protocols_path}")
                    except ImportError:
                        pass

                # Fallback: V3.0 compatible
                elif os.path.exists(network_v3_file):
                    try:
                        if protocols_path not in sys.path:
                            sys.path.insert(0, protocols_path)
                        import network_event_extended_v3_pb2 as NetworkEventProto
                        network_imported = True
                        print(f"✅ NetworkEvent v3.0 cargado desde: {protocols_path}")
                    except ImportError:
                        pass

    # 4. VERIFICACIÓN FINAL - TODO O NADA (IGUAL QUE SCHEDULER)
    if firewall_imported and network_imported:
        PROTOBUF_AVAILABLE = True
        PROTOBUF_VERSION = "v3.1.0"
        print(f"🎯 Dashboard: Protobuf V3.1 COMPLETO cargado exitosamente")

        # Verificar que FirewallCommand tiene los campos nativos V3.1
        try:
            test_command = FirewallCommandsProto.FirewallCommand()
            fields = [field.name for field in test_command.DESCRIPTOR.fields]

            if 'node_id' in fields and 'timestamp' in fields:
                print(f"✅ Verificado: FirewallCommand V3.1 tiene node_id y timestamp nativos")
                print(f"📋 Campos disponibles: {fields}")
                return True
            else:
                print(f"❌ ERROR: FirewallCommand no tiene campos V3.1 requeridos")
                print(f"📋 Campos encontrados: {fields}")
                print(f"📋 Campos requeridos: node_id, timestamp")
                return False

        except Exception as e:
            print(f"❌ ERROR verificando campos V3.1: {e}")
            return False
    else:
        # FALLO TOTAL - Mostrar lo que falta (IGUAL QUE SCHEDULER)
        print(f"❌ Dashboard: Protobuf V3.1 REQUERIDO pero NO ENCONTRADO")
        print(f"📋 Estado:")
        print(f"   FirewallCommands V3.1: {'✅' if firewall_imported else '❌'}")
        print(f"   NetworkEvent: {'✅' if network_imported else '❌'}")
        print(f"📁 Archivos requeridos:")
        print(f"   • firewall_commands_v31_pb2.py")
        print(f"   • network_security_clean_v31_pb2.py (o network_event_extended_v3_pb2.py)")
        print(f"📍 Ubicaciones buscadas:")
        for path in [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'protocols', 'v3.1'),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'protocols', 'v3.1'),
        ]:
            print(f"   • {os.path.abspath(path)}")
        print(f"🔧 SOLUCIÓN: Instalar protobuf V3.1 o compilar .proto files")
        return False


# Ejecutar importación V3.1 EXCLUSIVA (IGUAL QUE SCHEDULER)
if not import_dashboard_protobuf_v31():
    print(f"💥 FATAL: Dashboard requiere protobuf V3.1 para funcionar")
    print(f"🛑 PARAR EJECUCIÓN - Sin V3.1 no hay dashboard")
    sys.exit(1)

# Flask imports
try:
    from flask import Flask, jsonify, request, render_template_string, send_from_directory
    from flask_cors import CORS

    FLASK_AVAILABLE = True
except ImportError as e:
    print(f"❌ Flask no disponible: {e}")
    FLASK_AVAILABLE = False
    sys.exit(1)


@dataclass
class NetworkEventV31:
    """Evento de red V3.1 enriquecido"""
    id: str
    timestamp: float
    source_ip: str
    target_ip: str
    src_port: int
    dest_port: int
    protocol: str
    risk_score: float

    # ✅ NUEVOS CAMPOS V3.1
    ensemble_confidence: float
    pipeline_latency: float
    capturing_node_id: str

    # Coordenadas duales V3.1
    source_latitude: Optional[float] = None
    source_longitude: Optional[float] = None
    target_latitude: Optional[float] = None
    target_longitude: Optional[float] = None

    # Geolocalización enriquecida
    source_city: Optional[str] = None
    source_country: Optional[str] = None
    target_city: Optional[str] = None
    target_country: Optional[str] = None
    geographic_distance_km: Optional[float] = None
    same_country: Optional[bool] = None

    # Enriquecimiento de IPs V3.1
    source_ip_enriched: bool = False
    target_ip_enriched: bool = False

    # ML Analysis V3.1 Tricapa
    tricapa_scores: Optional[Dict[str, float]] = None

    # Información del nodo
    node_id: Optional[str] = None
    agent_id: Optional[str] = None

    # Metadatos adicionales
    event_type: str = "network_event"
    packet_size: int = 0
    bytes_count: int = 0
    packets_count: int = 1

    # Pipeline tracking V3.1
    pipeline_tracking: Optional[Dict] = None


@dataclass
class FirewallEventV31:
    """Evento de firewall V3.1"""
    id: str
    timestamp: float
    type: str  # 'command', 'response', 'error'
    command_id: Optional[str] = None
    action: Optional[str] = None
    target_ip: Optional[str] = None
    agent_id: Optional[str] = None
    success: Optional[bool] = None
    message: Optional[str] = None
    error: Optional[str] = None
    execution_time: Optional[float] = None
    source: str = "Dashboard V3.1"


class DashboardLogger:
    """Logger específico para dashboard"""

    def __init__(self, config: dict):
        self.logger = logging.getLogger("dashboard_v31")
        self._setup_logging(config.get('logging', {}))

    def _setup_logging(self, log_config: dict):
        """Configurar logging del dashboard"""
        level = getattr(logging, log_config.get('level', 'INFO').upper())

        # Clear existing handlers
        self.logger.handlers.clear()
        self.logger.setLevel(level)

        # Console handler
        console_config = log_config.get('handlers', {}).get('console', {})
        if console_config.get('enabled', True):
            console_handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - [dashboard_v31] [crypto_ready] - %(message)s'
            )
            console_handler.setFormatter(formatter)
            console_handler.setLevel(getattr(logging, console_config.get('level', 'INFO').upper()))
            self.logger.addHandler(console_handler)

        # File handler
        file_config = log_config.get('handlers', {}).get('file', {})
        if file_config.get('enabled', True):
            file_path = file_config.get('path', 'logs/dashboard_v31.log')
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(file_path, encoding='utf-8')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(getattr(logging, file_config.get('level', 'INFO').upper()))
            self.logger.addHandler(file_handler)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

    def debug(self, msg):
        self.logger.debug(msg)


class DashboardConfigV31:
    """Configuración del dashboard V3.1"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = self._load_config()
        self._validate_config()

        # Extraer configuraciones principales
        self.node_id = self.config['node_id']
        self.component = self.config['component']
        self.network = self.config['network']
        self.zmq_config = self.config['zmq']
        self.web_server = self.config['web_server']
        self.monitoring = self.config['monitoring']

    def _load_config(self) -> dict:
        """Cargar configuración desde archivo JSON"""
        if not Path(self.config_file).exists():
            raise FileNotFoundError(f"❌ Config file not found: {self.config_file}")

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"❌ Error loading config: {e}")

    def _validate_config(self):
        """Validar configuración requerida"""
        required_keys = ['node_id', 'component', 'network', 'zmq', 'web_server']
        for key in required_keys:
            if key not in self.config:
                raise ValueError(f"❌ Missing required config key: {key}")


class ZMQConnectionManagerV31:
    """Manager de conexiones ZMQ V3.1 CON CRYPTO"""

    def __init__(self, config: DashboardConfigV31, logger: DashboardLogger, crypto_wrapper=None):
        self.config = config
        self.logger = logger
        self.crypto_wrapper = crypto_wrapper  # 🔐 CRYPTO WRAPPER

        self.context = zmq.asyncio.Context()
        self.sockets = {}
        self.connections_status = {}

        # Fleet management sockets
        self.fleet_command_sockets = {}  # Por agent_id
        self.fleet_response_sockets = {}

    async def setup_connections(self):
        """Setup todas las conexiones ZMQ V3.1"""
        try:
            await self._setup_ml_events_connection()
            await self._setup_scheduler_connections()
            await self._setup_fleet_connections()

            self.logger.info("✅ Todas las conexiones ZMQ V3.1 establecidas")

        except Exception as e:
            self.logger.error(f"❌ Error setting up ZMQ connections: {e}")
            raise

    async def _setup_ml_events_connection(self):
        """Setup conexión con ML Detector V3.1"""
        ml_config = self.config.network.get('ml_events_input', {})

        if ml_config.get('enabled', True):
            socket_type = getattr(zmq, ml_config.get('socket_type', 'SUB'))
            socket = self.context.socket(socket_type)

            # Configurar socket
            socket.setsockopt(zmq.RCVHWM, ml_config.get('high_water_mark', 1000))

            if socket_type == zmq.SUB:
                socket.setsockopt(zmq.SUBSCRIBE, b"")  # Suscribirse a todos

            # 🔐 CRYPTO WRAPPING para ML events (DECRYPT)
            if self.crypto_wrapper:
                crypto_channels = self.config.config.get("crypto", {}).get("channels", {})
                if crypto_channels.get("ml_events_input", {}).get("decrypt", False):
                    socket = self.crypto_wrapper.wrap_socket_recv(socket)
                    self.logger.info("🔓 ML Events socket wrapped for AUTOMATIC DECRYPTION")

            # Conectar
            address = ml_config.get('address', 'localhost')
            port = ml_config.get('port', 5580)
            endpoint = f"tcp://{address}:{port}"

            mode = ml_config.get('mode', 'connect')
            if mode == 'connect':
                socket.connect(endpoint)
            else:
                socket.bind(endpoint)

            self.sockets['ml_events'] = socket
            self.connections_status['ml_events'] = {
                'status': 'active',
                'endpoint': endpoint,
                'mode': mode,
                'port': port,
                'crypto_enabled': bool(self.crypto_wrapper)
            }

            self.logger.info(f"📡 ML Events connection: {mode.upper()} {endpoint} (crypto: {bool(self.crypto_wrapper)})")

    async def _setup_scheduler_connections(self):
        """Setup conexiones con Scheduler Firewall"""
        # Por ahora, placeholder para futuras conexiones con scheduler
        self.logger.info("📋 Scheduler connections setup completed")

    async def _setup_fleet_connections(self):
        """Setup conexiones con Fleet de Agentes Firewall V3.1 - CON CRYPTO"""
        fleet_config = self.config.config.get('firewall_fleet', {})

        if not fleet_config.get('enabled', False):
            self.logger.info("🔥 Fleet management deshabilitado")
            return

        agents = fleet_config.get('agents', [])
        self.logger.info(f"🔥 Configurando fleet: {len(agents)} agentes")

        for agent_config in agents:
            agent_id = agent_config.get('node_id', agent_config.get('id', 'unknown'))

            try:
                # Crear socket de comandos para este agente
                command_socket = await self._create_agent_command_socket(agent_id, agent_config)
                self.fleet_command_sockets[agent_id] = command_socket

                self.logger.info(f"🤖 Agent {agent_id}: Command socket configurado")

            except Exception as e:
                self.logger.error(f"❌ Error configurando agent {agent_id}: {e}")

        self.logger.info(f"✅ Fleet management: {len(self.fleet_command_sockets)} agentes activos")

    async def _create_agent_command_socket(self, agent_id: str, agent_config: dict):
        """Crear socket de comandos para un agente específico - CON CRYPTO"""
        # Configuración de red del agente
        network_config = agent_config.get('network_endpoints', {})
        command_config = network_config.get('dashboard_commands', {})

        if not command_config:
            # Fallback a configuración básica
            command_config = {
                'address': 'localhost',
                'port': 5590 + hash(agent_id) % 100,  # Puerto dinámico
                'mode': 'connect',
                'socket_type': 'PUSH'
            }

        # Crear socket
        socket_type = getattr(zmq, command_config.get('socket_type', 'PUSH'))
        socket = self.context.socket(socket_type)

        # Configurar socket
        socket.setsockopt(zmq.SNDHWM, command_config.get('high_water_mark', 500))
        socket.setsockopt(zmq.LINGER, 1000)

        # 🔐 CRYPTO WRAPPING para commands hacia agente (ENCRYPT)
        if self.crypto_wrapper:
            crypto_channels = self.config.config.get("crypto", {}).get("channels", {})
            if crypto_channels.get("firewall_agents_fleet", {}).get("commands_encrypt", False):
                socket = self.crypto_wrapper.wrap_socket_send(socket)
                self.logger.info(f"🔒 Agent {agent_id} command socket wrapped for AUTOMATIC ENCRYPTION")

        # Conectar
        address = command_config.get('address', 'localhost')
        port = command_config.get('port')
        endpoint = f"tcp://{address}:{port}"

        mode = command_config.get('mode', 'connect')
        if mode == 'connect':
            socket.connect(endpoint)
        else:
            socket.bind(endpoint)

        self.connections_status[f'agent_{agent_id}_commands'] = {
            'status': 'active',
            'endpoint': endpoint,
            'mode': mode,
            'port': port,
            'agent_id': agent_id,
            'crypto_enabled': bool(self.crypto_wrapper)
        }

        return socket

    async def send_command_to_agent(self, agent_id: str, command_data: bytes) -> bool:
        """Enviar comando a agente específico - CRYPTO AUTOMÁTICO"""
        if agent_id not in self.fleet_command_sockets:
            self.logger.error(f"❌ Agent {agent_id} not found in fleet")
            return False

        try:
            socket = self.fleet_command_sockets[agent_id]
            # 🔐 El crypto wrapper cifra automáticamente si está configurado
            await socket.send(command_data, zmq.NOBLOCK)

            self.logger.info(f"📤 Command sent to agent {agent_id} (encrypted: {bool(self.crypto_wrapper)})")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error sending command to agent {agent_id}: {e}")
            return False

    def get_connections_status(self) -> dict:
        """Obtener estado de todas las conexiones"""
        return {
            'zmq_connections': self.connections_status,
            'fleet_agents_count': len(self.fleet_command_sockets),
            'ml_events_active': 'ml_events' in self.sockets,
            'crypto_enabled': bool(self.crypto_wrapper)
        }

    async def close_all(self):
        """Cerrar todas las conexiones"""
        try:
            for socket in list(self.sockets.values()):
                socket.close()

            for socket in list(self.fleet_command_sockets.values()):
                socket.close()

            self.context.term()
            self.logger.info("✅ Todas las conexiones ZMQ cerradas")

        except Exception as e:
            self.logger.error(f"❌ Error closing connections: {e}")


class DashboardBackendV31:
    """🚀 Dashboard Backend Principal V3.1 CON CRYPTO AUTOMÁTICO"""

    def __init__(self, config_file: str, firewall_rules_file: str):
        # ✅ Configuración
        self.config = DashboardConfigV31(config_file)
        self.firewall_rules_file = firewall_rules_file

        # ✅ Setup logging
        self.logger = DashboardLogger(self.config.config)

        # 🔐 STEP 3: Inicializar crypto wrapper (mismo patrón que scheduler/agent)
        self.crypto_wrapper = None
        self._init_crypto()

        # ✅ Estado del sistema
        self.running = False
        self.start_time = time.time()

        # ✅ Almacenamiento de eventos
        self.recent_events: deque = deque(maxlen=1000)  # Sin límite estricto
        self.recent_firewall_events: deque = deque(maxlen=1000)
        self.basic_stats = {
            'total_events': 0,
            'events_per_minute': 0,
            'high_risk_events': 0,
            'success_rate': 0,
            'failures': 0,
            'commands_sent': 0,
            'confirmations': 0
        }

        # ✅ Manager de conexiones ZMQ CON CRYPTO
        self.zmq_manager = ZMQConnectionManagerV31(self.config, self.logger, self.crypto_wrapper)

        # ✅ Flask app
        self.app = None
        self._setup_flask_app()

        # ✅ Threads de procesamiento
        self.processing_threads = []

        # ✅ Configuración de firewall desde JSON
        self.firewall_config = self._load_firewall_config()

        self.logger.info(f"🚀 Dashboard Backend V3.1 inicializado: {self.config.node_id}")
        self.logger.info(f"🔐 Crypto enabled: {bool(self.crypto_wrapper)}")

    def _init_crypto(self):
        """🔐 Inicializar crypto wrapper - MISMO PATRÓN que scheduler y agent"""
        crypto_config = self.config.config.get('crypto', {})

        if not crypto_config.get('enabled', False):
            self.logger.info("🔐 Crypto deshabilitado en configuración")
            return

        if not crypto_wrapper_class:
            self.logger.warning("⚠️ CryptoZMQV31 no disponible, ejecutando sin cifrado")
            return

        try:
            crypto_component_id = crypto_config.get('component_crypto_id', self.config.node_id)
            crypto_config_file = crypto_config.get('config_file', 'config/crypto/crypto_config_v31.json')

            self.crypto_wrapper = crypto_wrapper_class(crypto_component_id, crypto_config_file)

            self.logger.info("🔐 Crypto V31 inicializado correctamente")
            self.logger.info(f"   🔑 Component ID: {crypto_component_id}")
            self.logger.info(f"   📋 Config file: {crypto_config_file}")
            self.logger.info("   🔒🗜️ AES-256-GCM + LZ4 compression automático")
            self.logger.info("   🌐 Fleet communication: CIFRADA y COMPRIMIDA")

        except Exception as e:
            self.logger.error(f"❌ Error inicializando crypto: {e}")
            self.crypto_wrapper = None

    def _load_firewall_config(self) -> dict:
        """Cargar configuración de firewall desde JSON"""
        try:
            if Path(self.firewall_rules_file).exists():
                with open(self.firewall_rules_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                    firewall_rules = data.get('firewall_rules', {})

                    # Extraer configuración de agentes
                    agents_fleet = firewall_rules.get('agents_fleet', {})
                    manual_actions = firewall_rules.get('manual_actions', {})

                    return {
                        'agents': [
                            {
                                'node_id': agent_id,
                                'config': agent_config,
                                'network_endpoints': agent_config.get('network_endpoints', {}),
                                'capabilities': agent_config.get('capabilities', {}),
                                'status': agent_config.get('status', 'active')
                            }
                            for agent_id, agent_config in agents_fleet.items()
                            if agent_config.get('status', 'active') == 'active'
                        ],
                        'available_actions': list(manual_actions.keys()),
                        'manual_actions': manual_actions
                    }
            else:
                self.logger.warning(f"⚠️ Firewall rules file not found: {self.firewall_rules_file}")
                return {'agents': [], 'available_actions': [], 'manual_actions': {}}

        except Exception as e:
            self.logger.error(f"❌ Error loading firewall config: {e}")
            return {'agents': [], 'available_actions': [], 'manual_actions': {}}

    def _setup_flask_app(self):
        """Setup Flask application"""
        self.app = Flask(__name__)
        CORS(self.app)

        # Configurar rutas
        self._setup_routes()

        self.logger.info("✅ Flask app configurada")

    def _setup_routes(self):
        """Configurar rutas de la API"""

        @self.app.route('/')
        def dashboard():
            """Página principal del dashboard"""
            try:
                # Cargar template HTML
                template_path = Path(__file__).parent / 'templates' / 'dashboard.html'
                if template_path.exists():
                    with open(template_path, 'r', encoding='utf-8') as f:
                        return f.read()
                else:
                    return self._get_default_dashboard_html()
            except Exception as e:
                self.logger.error(f"❌ Error serving dashboard: {e}")
                return f"❌ Error loading dashboard: {e}", 500

        @self.app.route('/api/metrics')
        def get_metrics():
            """API endpoint para métricas del sistema"""
            try:
                return jsonify({
                    'success': True,
                    'basic_stats': self.basic_stats,
                    'recent_events': [asdict(event) for event in list(self.recent_events)[-50:]],
                    'firewall_events': [asdict(event) for event in list(self.recent_firewall_events)[-50:]],
                    'firewall_config': self.firewall_config,
                    'firewall_rules': {
                        'rules_count': len(self.firewall_config.get('manual_actions', {})),
                        'default_actions': self.firewall_config.get('available_actions', [])
                    },
                    'firewall_stats': {
                        'commands_sent': self.basic_stats['commands_sent'],
                        'responses_ok': self.basic_stats['confirmations'],
                        'errors': self.basic_stats['failures'],
                        'last_agent': 'simple_firewall_agent_v31_001'
                    },
                    'component_status': self._get_component_status(),
                    'zmq_connections': self.zmq_manager.get_connections_status(),
                    'uptime_seconds': time.time() - self.start_time,
                    'crypto_enabled': bool(self.crypto_wrapper)
                })
            except Exception as e:
                self.logger.error(f"❌ Error getting metrics: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/execute-firewall-action', methods=['POST'])
        def execute_firewall_action():
            """🔥 Ejecutar acción de firewall - CON CRYPTO AUTOMÁTICO"""
            try:
                request_data = request.get_json()

                if not request_data:
                    return jsonify({'success': False, 'message': 'No data provided'}), 400

                result = asyncio.run(self._execute_firewall_action_async(request_data))
                return jsonify(result)

            except Exception as e:
                self.logger.error(f"❌ Error executing firewall action: {e}")
                return jsonify({
                    'success': False,
                    'message': f'Execution error: {str(e)}'
                }), 500

        @self.app.route('/api/firewall-agent-info', methods=['POST'])
        def get_firewall_agent_info():
            """Obtener información del agente firewall responsable"""
            try:
                request_data = request.get_json()
                event_id = request_data.get('event_id', 'unknown')

                # Seleccionar agente (por ahora, el primero activo)
                agents = self.firewall_config.get('agents', [])
                if agents:
                    agent = agents[0]
                    return jsonify({
                        'success': True,
                        'firewall_info': {
                            'node_id': agent['node_id'],
                            'agent_ip': agent['config'].get('location', '127.0.0.1'),
                            'status': agent['status'],
                            'active_rules': 0,
                            'endpoint': agent['network_endpoints'].get('dashboard_commands', {}).get('address',
                                                                                                     'localhost'),
                            'capabilities': agent['capabilities'].get('allowed_actions', []),
                            'crypto_enabled': bool(self.crypto_wrapper)
                        }
                    })
                else:
                    return jsonify({
                        'success': True,
                        'firewall_info': {
                            'node_id': 'simple_firewall_agent_v31_001',
                            'agent_ip': '127.0.0.1',
                            'status': 'active',
                            'active_rules': 0,
                            'endpoint': 'localhost',
                            'capabilities': ['MONITOR', 'LIST_RULES'],
                            'crypto_enabled': bool(self.crypto_wrapper)
                        }
                    })
            except Exception as e:
                self.logger.error(f"❌ Error getting firewall agent info: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/static/<path:filename>')
        def static_files(filename):
            """Servir archivos estáticos"""
            return send_from_directory('static', filename)

    async def _execute_firewall_action_async(self, request_data: dict) -> dict:
        """🔥 Ejecutar acción de firewall de forma asíncrona - CRYPTO TRANSPARENTE"""
        try:
            # Extraer parámetros
            action = request_data.get('action', 'LIST_RULES')
            target_ip = request_data.get('target_ip', '127.0.0.1')
            firewall_node_id = request_data.get('firewall_node_id', 'simple_firewall_agent_v31_001')
            command_id = request_data.get('command_id', f"dashboard_{int(time.time())}")

            self.logger.info(f"🔥 Executing action: {action} for IP {target_ip} on agent {firewall_node_id}")
            self.logger.info(f"🔐 Crypto enabled: {bool(self.crypto_wrapper)} (transparent encryption)")

            # Crear comando protobuf V3.1
            if not PROTOBUF_AVAILABLE:
                return {'success': False, 'message': 'Protobuf V3.1 not available'}

            pb_command = FirewallCommandsProto.FirewallCommand()
            pb_command.command_id = command_id

            # Mapear acción a enum
            action_mapping = {
                'BLOCK_IP': FirewallCommandsProto.CommandAction.BLOCK_IP,
                'RATE_LIMIT_IP': FirewallCommandsProto.CommandAction.RATE_LIMIT_IP,
                'LIST_RULES': FirewallCommandsProto.CommandAction.LIST_RULES,
                'MONITOR': FirewallCommandsProto.CommandAction.ALLOW_IP_TEMP
            }

            pb_command.action = action_mapping.get(action, FirewallCommandsProto.CommandAction.LIST_RULES)
            pb_command.target_ip = target_ip
            pb_command.duration_seconds = request_data.get('max_duration', 300)
            pb_command.reason = f"Dashboard V3.1 command: {action}"
            pb_command.dry_run = request_data.get('force_dry_run', True)

            # Campos nativos V3.1
            pb_command.node_id = firewall_node_id
            pb_command.timestamp = int(time.time() * 1000)

            # Metadatos adicionales
            pb_command.extra_params["dashboard_node_id"] = self.config.node_id
            pb_command.extra_params["generated_by"] = "dashboard_v31_backend"
            pb_command.extra_params["crypto_enabled"] = str(bool(self.crypto_wrapper))

            # Serializar comando
            command_bytes = pb_command.SerializeToString()

            # 🔐 Enviar comando (CIFRADO AUTOMÁTICO si crypto habilitado)
            success = await self.zmq_manager.send_command_to_agent(firewall_node_id, command_bytes)

            if success:
                # Registrar evento de firewall
                firewall_event = FirewallEventV31(
                    id=command_id,
                    timestamp=time.time(),
                    type='command',
                    command_id=command_id,
                    action=action,
                    target_ip=target_ip,
                    agent_id=firewall_node_id,
                    source="Dashboard V3.1 Backend (Crypto Enabled)" if self.crypto_wrapper else "Dashboard V3.1 Backend"
                )

                self.recent_firewall_events.append(firewall_event)
                self.basic_stats['commands_sent'] += 1

                return {
                    'success': True,
                    'message': f'{action} command sent successfully (encrypted: {bool(self.crypto_wrapper)})',
                    'command_id': command_id,
                    'node_id': firewall_node_id,
                    'crypto_enabled': bool(self.crypto_wrapper)
                }
            else:
                return {
                    'success': False,
                    'message': f'Failed to send command to agent {firewall_node_id}'
                }

        except Exception as e:
            self.logger.error(f"❌ Error in firewall action execution: {e}")
            return {'success': False, 'message': f'Execution error: {str(e)}'}

    def _get_component_status(self) -> dict:
        """Obtener estado de componentes del sistema"""
        return {
            'promiscuous_agent': {'status': 'active' if len(self.recent_events) > 0 else 'inactive'},
            'geoip_enricher': {'status': 'active'},
            'ml_detector': {'status': 'active' if len(self.recent_events) > 0 else 'inactive'},
            'firewall_agent': {'status': 'active' if len(self.firewall_config.get('agents', [])) > 0 else 'inactive'},
            'crypto_system': {'status': 'active' if self.crypto_wrapper else 'inactive'}
        }

    def _get_default_dashboard_html(self) -> str:
        """Dashboard SCADA V3.1 completo con crypto + todos los componentes"""
        return """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚀 Dashboard SCADA V3.1 - Crypto Enabled</title>

    <!-- External Libraries -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #0a0a0a 100%);
            color: #00ff88;
            overflow-x: hidden;
            line-height: 1.4;
        }

        .dashboard-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            grid-template-rows: auto auto 1fr;
            gap: 15px;
            padding: 15px;
            min-height: 100vh;
        }

        .header {
            grid-column: 1 / -1;
            text-align: center;
            padding: 20px;
            background: rgba(0, 255, 136, 0.1);
            border-radius: 12px;
            border: 2px solid rgba(0, 255, 136, 0.3);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: conic-gradient(from 0deg, transparent, rgba(0, 255, 136, 0.1), transparent);
            animation: rotate 20s linear infinite;
            z-index: -1;
        }

        @keyframes rotate {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
        }

        .crypto-status {
            color: #ffaa00;
            font-weight: bold;
            font-size: 1.2rem;
            text-shadow: 0 0 10px rgba(255, 170, 0, 0.5);
        }

        .system-info {
            grid-column: 1 / -1;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .info-card {
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 8px;
            padding: 15px;
            text-align: center;
            transition: all 0.3s ease;
        }

        .info-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 255, 136, 0.2);
        }

        .info-card h3 {
            color: #00aaff;
            margin-bottom: 10px;
        }

        .info-card .value {
            font-size: 1.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .status-dot {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }

        .status-dot.connected { background: #00ff88; box-shadow: 0 0 10px #00ff88; }
        .status-dot.warning { background: #ffaa00; box-shadow: 0 0 10px #ffaa00; }
        .status-dot.disconnected { background: #ff4444; box-shadow: 0 0 10px #ff4444; }

        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }

        .events-section, .firewall-section {
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 12px;
            padding: 20px;
            max-height: 600px;
            overflow-y: auto;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.3);
        }

        .section-title {
            color: #00ff88;
            font-size: 1.3rem;
            font-weight: bold;
        }

        .btn {
            background: rgba(0, 255, 136, 0.2);
            border: 1px solid #00ff88;
            color: #00ff88;
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-family: inherit;
            font-size: 0.9rem;
        }

        .btn:hover {
            background: rgba(0, 255, 136, 0.3);
            transform: translateY(-2px);
        }

        .btn-danger {
            background: rgba(255, 68, 68, 0.2);
            border-color: #ff4444;
            color: #ff4444;
        }

        .btn-danger:hover {
            background: rgba(255, 68, 68, 0.3);
        }

        .event-item {
            background: rgba(0, 255, 136, 0.05);
            border-left: 4px solid #00ff88;
            margin: 8px 0;
            padding: 12px;
            border-radius: 6px;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .event-item:hover {
            background: rgba(0, 255, 136, 0.1);
            transform: translateX(5px);
        }

        .event-item.risk-high {
            border-left-color: #ff4444;
            background: rgba(255, 68, 68, 0.05);
        }

        .event-item.risk-medium {
            border-left-color: #ffaa00;
            background: rgba(255, 170, 0, 0.05);
        }

        .firewall-event {
            background: rgba(255, 170, 0, 0.05);
            border-left: 4px solid #ffaa00;
            margin: 8px 0;
            padding: 12px;
            border-radius: 6px;
            transition: all 0.3s ease;
        }

        .firewall-event.command {
            border-left-color: #0066CC;
            background: rgba(0, 102, 204, 0.05);
        }

        .firewall-event.response {
            border-left-color: #00ff88;
            background: rgba(0, 255, 136, 0.05);
        }

        .firewall-event.error {
            border-left-color: #ff4444;
            background: rgba(255, 68, 68, 0.05);
        }

        .timestamp {
            color: #888;
            font-size: 0.8rem;
            float: right;
        }

        .risk-score {
            background: rgba(0, 255, 136, 0.2);
            color: #00ff88;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8rem;
            font-weight: bold;
        }

        .risk-score.high {
            background: rgba(255, 68, 68, 0.2);
            color: #ff4444;
        }

        .risk-score.medium {
            background: rgba(255, 170, 0, 0.2);
            color: #ffaa00;
        }

        .no-events {
            text-align: center;
            color: #666;
            padding: 40px;
            font-style: italic;
        }

        .controls {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }

        .controls select {
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid rgba(0, 255, 136, 0.3);
            color: #00ff88;
            padding: 5px 10px;
            border-radius: 4px;
            font-family: inherit;
        }

        .map-container {
            grid-column: 1 / -1;
            height: 400px;
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 12px;
            overflow: hidden;
            position: relative;
        }

        #map {
            height: 100%;
            width: 100%;
        }

        .connection-status {
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(0, 0, 0, 0.9);
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 8px;
            padding: 15px;
            z-index: 1000;
        }

        .status-item {
            display: flex;
            align-items: center;
            margin: 5px 0;
            font-size: 0.9rem;
        }

        .toast {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(0, 255, 136, 0.9);
            color: #000;
            padding: 10px 20px;
            border-radius: 6px;
            z-index: 10000;
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .toast.show {
            opacity: 1;
        }

        .toast.error {
            background: rgba(255, 68, 68, 0.9);
            color: #fff;
        }

        .toast.warning {
            background: rgba(255, 170, 0, 0.9);
            color: #000;
        }

        .scrollbar::-webkit-scrollbar {
            width: 8px;
        }

        .scrollbar::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.3);
        }

        .scrollbar::-webkit-scrollbar-thumb {
            background: rgba(0, 255, 136, 0.3);
            border-radius: 4px;
        }

        .scrollbar::-webkit-scrollbar-thumb:hover {
            background: rgba(0, 255, 136, 0.5);
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        .crypto-indicator {
            background: linear-gradient(45deg, #ffaa00, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: bold;
            animation: pulse 3s infinite;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <div class="header">
            <h1>🚀 Dashboard SCADA V3.1</h1>
            <div class="crypto-status crypto-indicator">🔐 Crypto System: ACTIVE - AES-256-GCM + LZ4</div>
            <div style="margin-top: 10px; font-size: 0.9rem; color: #888;">
                Fleet Management Cifrada | Pipeline Automático | Zero-Knowledge Security
            </div>
        </div>

        <!-- System Info Cards -->
        <div class="system-info">
            <div class="info-card">
                <h3>📊 Eventos</h3>
                <div class="value" id="events-count">0</div>
                <div>En tiempo real</div>
            </div>
            <div class="info-card">
                <h3>🔥 Comandos Firewall</h3>
                <div class="value" id="commands-count">0</div>
                <div>Enviados (cifrados)</div>
            </div>
            <div class="info-card">
                <h3>✅ Confirmaciones</h3>
                <div class="value" id="confirmations-count">0</div>
                <div>Respuestas OK</div>
            </div>
            <div class="info-card">
                <h3>⚡ Success Rate</h3>
                <div class="value" id="success-rate">0%</div>
                <div>Efectividad</div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            <!-- Events Section -->
            <div class="events-section scrollbar">
                <div class="section-header">
                    <h2 class="section-title">📡 Eventos ML V3.1</h2>
                    <div>
                        <button class="btn" onclick="clearEventsList()">🗑️ Limpiar</button>
                        <button class="btn" id="pause-events-btn" onclick="pauseEventsUpdate()">⏸️</button>
                    </div>
                </div>
                <div class="controls">
                    <select id="events-filter" onchange="filterEvents()">
                        <option value="all">Todos los riesgos</option>
                        <option value="high">Alto riesgo</option>
                        <option value="medium">Riesgo medio</option>
                        <option value="low">Bajo riesgo</option>
                    </select>
                </div>
                <div id="events-list">
                    <div class="no-events">
                        <i class="fas fa-satellite-dish" style="font-size: 24px; display: block; margin-bottom: 10px; opacity: 0.5;"></i>
                        <p>Esperando eventos ML V3.1...</p>
                        <small>Puerto 5580 SUB - Descifrado automático</small>
                    </div>
                </div>
            </div>

            <!-- Firewall Section -->
            <div class="firewall-section scrollbar">
                <div class="section-header">
                    <h2 class="section-title">🔥 Comandos Firewall V3.1</h2>
                    <div>
                        <button class="btn" onclick="clearFirewallEventsList()">🗑️ Limpiar</button>
                        <button class="btn btn-danger" onclick="sendTestFirewallCommand()">🧪 Test</button>
                    </div>
                </div>
                <div id="firewall-events-list">
                    <div class="no-events">
                        <i class="fas fa-fire" style="font-size: 24px; display: block; margin-bottom: 10px; opacity: 0.5;"></i>
                        <p>No hay comandos firewall</p>
                        <small>Fleet cifrada lista</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Map Container -->
        <div class="map-container">
            <div id="map"></div>
        </div>
    </div>

    <!-- Connection Status -->
    <div class="connection-status">
        <div style="font-weight: bold; margin-bottom: 10px; color: #00ff88;">🌐 Estado del Sistema</div>
        <div class="status-item">
            <span class="status-dot connected" id="ml-detector-status"></span>
            ML Detector V3.1
        </div>
        <div class="status-item">
            <span class="status-dot connected" id="crypto-status"></span>
            Sistema Crypto
        </div>
        <div class="status-item">
            <span class="status-dot connected" id="fleet-status"></span>
            Fleet Agentes
        </div>
        <div class="status-item">
            <span class="status-dot connected" id="api-status"></span>
            Backend API
        </div>
        <div style="margin-top: 10px; font-size: 0.8rem; color: #888;">
            <div>🔐 AES-256-GCM</div>
            <div>🗜️ LZ4 Compression</div>
            <div>🔑 Pipeline Key</div>
        </div>
    </div>

    <!-- Toast Container -->
    <div id="toast-container"></div>

    <script>
        // Global Variables
        let map = null;
        let markers = [];
        let eventCount = 0;
        let pollingInterval = null;
        let currentEvents = [];
        let currentFirewallEvents = [];
        let eventsPaused = false;

        // Initialize Dashboard
        function initializeDashboard() {
            console.log('🚀 Inicializando Dashboard SCADA V3.1 con Crypto...');

            initializeMap();
            startPolling();
            updateConnectionStatus('crypto-status', 'connected');
            updateConnectionStatus('api-status', 'connected');

            console.log('✅ Dashboard V3.1 inicializado correctamente');
        }

        // Initialize Map
        function initializeMap() {
            try {
                map = L.map('map').setView([40.4168, -3.7038], 6);

                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap contributors'
                }).addTo(map);

                // Add initial markers
                L.marker([40.4168, -3.7038])
                    .bindPopup('<b>🖥️ Dashboard V3.1</b><br>Madrid, España<br>Crypto Enabled')
                    .addTo(map);

                console.log('✅ Mapa inicializado');
            } catch (error) {
                console.error('❌ Error inicializando mapa:', error);
            }
        }

        // Start Polling
        function startPolling() {
            fetchData();
            pollingInterval = setInterval(fetchData, 2000);
            console.log('📡 Polling iniciado cada 2 segundos');
        }

        // Fetch Data from Backend
        async function fetchData() {
            try {
                const response = await fetch('/api/metrics');
                if (!response.ok) throw new Error(`HTTP ${response.status}`);

                const data = await response.json();

                if (data.success) {
                    updateDashboard(data);
                    updateConnectionStatus('api-status', 'connected');
                }
            } catch (error) {
                console.error('❌ Error fetching data:', error);
                updateConnectionStatus('api-status', 'disconnected');
                showToast('Error conectando con backend', 'error');
            }
        }

        // Update Dashboard
        function updateDashboard(data) {
            // Update counters
            if (data.basic_stats) {
                updateElement('events-count', data.basic_stats.total_events || 0);
                updateElement('commands-count', data.basic_stats.commands_sent || 0);
                updateElement('confirmations-count', data.basic_stats.confirmations || 0);
                updateElement('success-rate', (data.basic_stats.success_rate || 0) + '%');

                eventCount = data.basic_stats.total_events || 0;
            }

            // Update connection status
            updateConnectionStatus('ml-detector-status', data.zmq_connections?.ml_events?.status === 'active' ? 'connected' : 'disconnected');
            updateConnectionStatus('fleet-status', data.firewall_config?.agents?.length > 0 ? 'connected' : 'warning');

            // Process new events
            if (data.recent_events && !eventsPaused) {
                processNewEvents(data.recent_events);
            }

            // Process firewall events
            if (data.firewall_events) {
                processFirewallEvents(data.firewall_events);
            }
        }

        // Process New Events
        function processNewEvents(events) {
            const eventsList = document.getElementById('events-list');
            const placeholder = eventsList.querySelector('.no-events');

            if (placeholder && events.length > 0) {
                placeholder.remove();
            }

            events.forEach(event => {
                if (!currentEvents.some(e => e.id === event.id)) {
                    addEventToList(event);
                    addEventToMap(event);
                    currentEvents.push(event);
                }
            });
        }

        // Add Event to List
        function addEventToList(event) {
            const eventsList = document.getElementById('events-list');
            const eventElement = document.createElement('div');

            const riskScore = (event.ensemble_confidence || event.risk_score || 0) * 100;
            const riskLevel = riskScore > 80 ? 'high' : riskScore > 50 ? 'medium' : 'low';

            eventElement.className = `event-item risk-${riskLevel}`;
            eventElement.onclick = () => showEventDetail(event);

            const eventTime = new Date((event.timestamp || Date.now()) * (event.timestamp > 1e10 ? 1 : 1000));

            eventElement.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>${event.source_ip || 'N/A'} → ${event.target_ip || 'N/A'}</strong>
                        <div style="font-size: 0.8rem; color: #888; margin-top: 2px;">
                            ${event.event_type || 'network_event'} | Node: ${event.capturing_node_id || 'N/A'}
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <span class="risk-score ${riskLevel}">${riskScore.toFixed(0)}%</span>
                        <div class="timestamp">${eventTime.toLocaleTimeString()}</div>
                    </div>
                </div>
            `;

            eventsList.insertBefore(eventElement, eventsList.firstChild);
        }

        // Add Event to Map
        function addEventToMap(event) {
            if (!map) return;

            try {
                const lat = event.source_latitude || event.latitude || 40.4168;
                const lng = event.source_longitude || event.longitude || -3.7038;

                if (lat === 0 && lng === 0) return;

                const riskScore = (event.ensemble_confidence || event.risk_score || 0) * 100;
                const color = riskScore > 80 ? '#ff4444' : riskScore > 50 ? '#ffaa00' : '#00ff88';

                const marker = L.circleMarker([lat, lng], {
                    radius: 8,
                    fillColor: color,
                    color: color,
                    weight: 2,
                    opacity: 0.8,
                    fillOpacity: 0.6
                }).bindPopup(`
                    <b>🚨 Evento V3.1</b><br>
                    <strong>IP:</strong> ${event.source_ip}<br>
                    <strong>Target:</strong> ${event.target_ip}<br>
                    <strong>Risk:</strong> ${riskScore.toFixed(0)}%<br>
                    <strong>Node:</strong> ${event.capturing_node_id || 'N/A'}
                `).addTo(map);

                markers.push(marker);

                // Remove old markers
                if (markers.length > 50) {
                    const oldMarker = markers.shift();
                    map.removeLayer(oldMarker);
                }
            } catch (error) {
                console.error('❌ Error adding marker:', error);
            }
        }

        // Process Firewall Events
        function processFirewallEvents(events) {
            const firewallList = document.getElementById('firewall-events-list');
            const placeholder = firewallList.querySelector('.no-events');

            if (placeholder && events.length > 0) {
                placeholder.remove();
            }

            events.forEach(event => {
                if (!currentFirewallEvents.some(e => e.id === event.id)) {
                    addFirewallEventToList(event);
                    currentFirewallEvents.push(event);
                }
            });
        }

        // Add Firewall Event to List
        function addFirewallEventToList(event) {
            const firewallList = document.getElementById('firewall-events-list');
            const eventElement = document.createElement('div');

            const eventType = event.type || 'command';
            eventElement.className = `firewall-event ${eventType}`;

            const eventTime = new Date((event.timestamp || Date.now()) * (event.timestamp > 1e10 ? 1 : 1000));

            eventElement.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>${event.action || 'UNKNOWN'}</strong>
                        <div style="font-size: 0.8rem; color: #888; margin-top: 2px;">
                            ${event.target_ip || 'N/A'} | Agent: ${event.agent_id || 'N/A'}
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <span style="color: ${eventType === 'response' ? '#00ff88' : eventType === 'error' ? '#ff4444' : '#ffaa00'};">
                            ${eventType.toUpperCase()}
                        </span>
                        <div class="timestamp">${eventTime.toLocaleTimeString()}</div>
                    </div>
                </div>
            `;

            firewallList.insertBefore(eventElement, firewallList.firstChild);
        }

        // Utility Functions
        function updateElement(id, value) {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        }

        function updateConnectionStatus(id, status) {
            const element = document.getElementById(id);
            if (element) {
                element.className = `status-dot ${status}`;
            }
        }

        function showToast(message, type = 'info') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.textContent = message;

            container.appendChild(toast);

            setTimeout(() => toast.classList.add('show'), 100);
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => container.removeChild(toast), 300);
            }, 3000);
        }

        // Event Handlers
        function clearEventsList() {
            const eventsList = document.getElementById('events-list');
            eventsList.innerHTML = '<div class="no-events"><p>Lista limpiada</p></div>';
            currentEvents = [];
            showToast('Lista de eventos limpiada', 'info');
        }

        function clearFirewallEventsList() {
            const firewallList = document.getElementById('firewall-events-list');
            firewallList.innerHTML = '<div class="no-events"><p>Lista limpiada</p></div>';
            currentFirewallEvents = [];
            showToast('Lista de comandos firewall limpiada', 'info');
        }

        function pauseEventsUpdate() {
            eventsPaused = !eventsPaused;
            const btn = document.getElementById('pause-events-btn');

            if (eventsPaused) {
                btn.innerHTML = '▶️';
                showToast('Eventos pausados', 'warning');
            } else {
                btn.innerHTML = '⏸️';
                showToast('Eventos reanudados', 'info');
            }
        }

        function filterEvents() {
            const filter = document.getElementById('events-filter').value;
            const events = document.querySelectorAll('.event-item');

            events.forEach(event => {
                const classes = event.className;
                if (filter === 'all' || classes.includes(`risk-${filter}`)) {
                    event.style.display = 'block';
                } else {
                    event.style.display = 'none';
                }
            });
        }

        async function sendTestFirewallCommand() {
            try {
                showToast('Enviando comando de test...', 'info');

                const response = await fetch('/api/execute-firewall-action', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        action: 'LIST_RULES',
                        target_ip: '127.0.0.1',
                        firewall_node_id: 'simple_firewall_agent_001',
                        command_id: `test_${Date.now()}`,
                        force_dry_run: true
                    })
                });

                const result = await response.json();

                if (result.success) {
                    showToast('✅ Comando test enviado correctamente', 'success');
                } else {
                    showToast('❌ Error en comando test: ' + result.message, 'error');
                }
            } catch (error) {
                showToast('❌ Error comunicando con backend', 'error');
            }
        }

        function showEventDetail(event) {
            const riskScore = (event.ensemble_confidence || event.risk_score || 0) * 100;
            showToast(`Evento: ${event.source_ip} → ${event.target_ip} (${riskScore.toFixed(0)}%)`, 'info');
        }

        // Initialize on load
        document.addEventListener('DOMContentLoaded', initializeDashboard);

        // Cleanup on unload
        window.addEventListener('beforeunload', () => {
            if (pollingInterval) clearInterval(pollingInterval);
        });
    </script>
</body>
</html>"""

    async def start_zmq_processing(self):
        """Iniciar procesamiento de mensajes ZMQ"""
        try:
            await self.zmq_manager.setup_connections()

            # Iniciar thread de procesamiento ML events
            if 'ml_events' in self.zmq_manager.sockets:
                ml_thread = threading.Thread(target=self._ml_events_processor, daemon=True)
                ml_thread.start()
                self.processing_threads.append(ml_thread)
                self.logger.info("🔄 ML Events processor started")

            self.logger.info("✅ ZMQ processing iniciado")

        except Exception as e:
            self.logger.error(f"❌ Error starting ZMQ processing: {e}")
            raise

    def _ml_events_processor(self):
        """Procesador de eventos ML en thread separado - DESCIFRADO AUTOMÁTICO"""
        self.logger.info("📡 ML Events processor thread iniciado (crypto ready)")

        # Crear contexto ZMQ síncrono para el thread
        context = zmq.Context()
        socket = context.socket(zmq.SUB)
        socket.setsockopt(zmq.SUBSCRIBE, b"")
        socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 segundo timeout

        # Configurar conexión
        ml_config = self.config.network.get('ml_events_input', {})
        address = ml_config.get('address', 'localhost')
        port = ml_config.get('port', 5580)
        endpoint = f"tcp://{address}:{port}"
        socket.connect(endpoint)

        # 🔐 CRYPTO WRAPPING en thread síncrono
        if self.crypto_wrapper:
            crypto_channels = self.config.config.get("crypto", {}).get("channels", {})
            if crypto_channels.get("ml_events_input", {}).get("decrypt", False):
                socket = self.crypto_wrapper.wrap_socket_recv(socket)
                self.logger.info("🔓 ML Events processor: AUTOMATIC DECRYPTION enabled")

        while self.running:
            try:
                # 🔐 Recibir mensaje (AUTOMÁTICAMENTE DESCIFRADO)
                message_bytes = socket.recv(zmq.NOBLOCK)
                # Antes de procesar el mensaje:
                self.logger.info(f"🔍 Message received: {len(message_bytes)} bytes")
                self.logger.info(f"🔍 First 20 bytes: {message_bytes[:20]}")
                self.logger.info(f"🔐 Crypto wrapper: {bool(self.crypto_wrapper)}")

                # Test UTF-8 validity
                try:
                    test_decode = message_bytes.decode('utf-8')
                    self.logger.info(f"✅ UTF-8 valid")
                except UnicodeDecodeError as e:
                    self.logger.warning(f"❌ UTF-8 invalid: {e}")
                # Procesar evento
                event = self._parse_ml_event_v31(message_bytes)
                if event:
                    self.recent_events.append(event)
                    self._update_basic_stats(event)

                    if self.crypto_wrapper:
                        self.logger.debug(f"📨 ML Event received and decrypted: {event.source_ip} → {event.target_ip}")
                    else:
                        self.logger.debug(f"📨 ML Event received: {event.source_ip} → {event.target_ip}")

            except zmq.Again:
                # No hay mensajes, continuar
                continue
            except Exception as e:
                self.logger.error(f"❌ Error processing ML event: {e}")
                time.sleep(1)

        # Cleanup
        socket.close()
        context.term()
        self.logger.info("📡 ML Events processor thread terminado")

    def _parse_ml_event_v31(self, message_bytes: bytes) -> Optional[NetworkEventV31]:
        """🔥 Parser PROTOBUF ONLY - SIN FALLBACK JSON"""
        try:
            # 🎯 PROTOBUF O NADA - Como todos los otros componentes
            if not PROTOBUF_AVAILABLE or not NetworkEventProto:
                self.logger.error("❌ Protobuf V3.1 no disponible - REQUERIDO")
                return None

            # ✅ SOLO PROTOBUF - NOMBRE DE CLASE CORRECTO
            pb_event = NetworkEventProto.NetworkSecurityEvent()
            pb_event.ParseFromString(message_bytes)

            # Convertir a NetworkEventV31 con todos los campos V3.1
            return NetworkEventV31(
                id=getattr(pb_event, 'event_id', f"event_{int(time.time())}"),
                timestamp=getattr(pb_event, 'timestamp', time.time() * 1000) / 1000,
                source_ip=getattr(pb_event, 'source_ip', '127.0.0.1'),
                target_ip=getattr(pb_event, 'target_ip', '127.0.0.1'),
                src_port=getattr(pb_event, 'src_port', 0),
                dest_port=getattr(pb_event, 'dest_port', 0),
                protocol=getattr(pb_event, 'protocol', 'TCP'),
                risk_score=float(getattr(pb_event, 'risk_score', 0.5)),

                # ✅ CAMPOS V3.1 ESPECÍFICOS
                ensemble_confidence=float(
                    getattr(pb_event, 'ensemble_confidence', getattr(pb_event, 'risk_score', 0.5))),
                pipeline_latency=float(getattr(pb_event, 'pipeline_latency', 0.0)),
                capturing_node_id=getattr(pb_event, 'capturing_node_id', getattr(pb_event, 'node_id', 'unknown')),

                # Coordenadas duales V3.1
                source_latitude=getattr(pb_event, 'source_latitude', None),
                source_longitude=getattr(pb_event, 'source_longitude', None),
                target_latitude=getattr(pb_event, 'target_latitude', None),
                target_longitude=getattr(pb_event, 'target_longitude', None),

                # Geolocalización enriquecida
                source_city=getattr(pb_event, 'source_city', None),
                source_country=getattr(pb_event, 'source_country', None),
                target_city=getattr(pb_event, 'target_city', None),
                target_country=getattr(pb_event, 'target_country', None),
                geographic_distance_km=getattr(pb_event, 'geographic_distance_km', None),
                same_country=getattr(pb_event, 'same_country', None),

                # Enriquecimiento V3.1
                source_ip_enriched=bool(getattr(pb_event, 'source_ip_enriched', False)),
                target_ip_enriched=bool(getattr(pb_event, 'target_ip_enriched', False)),

                # ML Tricapa scores
                tricapa_scores={
                    'isolation_forest': getattr(pb_event, 'isolation_forest_score', 0.5),
                    'one_class_svm': getattr(pb_event, 'one_class_svm_score', 0.5),
                    'local_outlier_factor': getattr(pb_event, 'local_outlier_factor_score', 0.5)
                },

                # Información del nodo
                node_id=getattr(pb_event, 'node_id', 'unknown'),
                agent_id=getattr(pb_event, 'agent_id', ''),

                # Metadatos
                event_type=getattr(pb_event, 'event_type', 'network_event'),
                packet_size=getattr(pb_event, 'packet_size', 0)
            )

        except Exception as e:
            # 🚨 Si falla protobuf = ERROR REAL, no fallback
            self.logger.error(f"❌ PROTOBUF parse failed: {e}")
            self.logger.error(f"   📊 Message size: {len(message_bytes)} bytes")
            self.logger.error(f"   🔍 First 20 bytes: {message_bytes[:20]}")

            # ❌ SIN FALLBACK - Protobuf o nada
            return None

    # ✅ COMENTAR/ELIMINAR COMPLETAMENTE TODO EL CÓDIGO DE FALLBACK JSON:

    """
    # ❌ ELIMINADO: Fallback JSON problemático
    # try:
    #     message_text = message_bytes.decode('utf-8')  # ← Aquí estaba el problema
    #     event_data = json.loads(message_text)
    #     return NetworkEventV31(...) # ← Fallback innecesario
    # except Exception as json_error:
    #     self.logger.warning(f"⚠️ JSON processing failed: {json_error}")

    # ❌ ELIMINADO: Evento básico de fallback
    # return NetworkEventV31(
    #     id=f"fallback_{int(time.time())}",
    #     ...
    # )
    """

    # 🎯 FILOSOFÍA:
    #   - PROTOBUF es la norma
    #   - JSON solo para axiomas y RAG
    #   - SIN fallbacks que nos distraigan
    #   - Falla rápido y limpio
    #   - Consistencia con otros componentes

    def _update_basic_stats(self, event: NetworkEventV31):
        """Actualizar estadísticas básicas"""
        self.basic_stats['total_events'] += 1

        if event.ensemble_confidence > 0.8 or event.risk_score > 0.8:
            self.basic_stats['high_risk_events'] += 1

        # Calcular eventos por minuto (últimos 60 segundos)
        current_time = time.time()
        recent_events_count = len([
            e for e in self.recent_events
            if (current_time - e.timestamp) <= 60
        ])
        self.basic_stats['events_per_minute'] = recent_events_count

        # Calcular success rate basado en eventos de alto riesgo vs total
        if self.basic_stats['total_events'] > 0:
            self.basic_stats['success_rate'] = round(
                100 - (self.basic_stats['high_risk_events'] / self.basic_stats['total_events'] * 100), 1
            )

    async def start(self):
        """Iniciar dashboard backend V3.1"""
        self.running = True

        self.logger.info("🚀 Iniciando Dashboard Backend V3.1...")
        self.logger.info(f"📋 Node ID: {self.config.node_id}")
        self.logger.info(f"🔐 Crypto System: {'ACTIVO' if self.crypto_wrapper else 'INACTIVO'}")
        self.logger.info(f"🏗️ Component: {self.config.component['name']} v{self.config.component['version']}")

        try:
            # Iniciar procesamiento ZMQ
            await self.start_zmq_processing()

            # Configurar Flask
            web_config = self.config.web_server
            host = web_config.get('host', '0.0.0.0')
            port = web_config.get('port', 8080)
            debug = web_config.get('debug', False)

            self.logger.info(f"🌐 Starting web server on {host}:{port}")
            self.logger.info(f"🔗 Dashboard URL: http://{host}:{port}")

            # Ejecutar Flask en thread separado
            flask_thread = threading.Thread(
                target=lambda: self.app.run(host=host, port=port, debug=debug, use_reloader=False),
                daemon=True
            )
            flask_thread.start()
            self.processing_threads.append(flask_thread)

            self.logger.info("✅ Dashboard Backend V3.1 iniciado correctamente")

            # Loop principal
            while self.running:
                await asyncio.sleep(1)
                self._periodic_maintenance()

        except Exception as e:
            self.logger.error(f"❌ Error starting dashboard: {e}")
            raise

    def _periodic_maintenance(self):
        """Mantenimiento periódico"""
        # Limpiar eventos antiguos (mantener últimas 2 horas)
        current_time = time.time()
        cutoff_time = current_time - (2 * 3600)  # 2 horas

        # Filtrar eventos antiguos
        self.recent_events = deque([
            event for event in self.recent_events
            if event.timestamp > cutoff_time
        ], maxlen=1000)

        self.recent_firewall_events = deque([
            event for event in self.recent_firewall_events
            if event.timestamp > cutoff_time
        ], maxlen=1000)

    async def stop(self):
        """Detener dashboard backend"""
        self.logger.info("🛑 Deteniendo Dashboard Backend V3.1...")
        self.running = False

        # 🔐 Crypto cleanup
        if self.crypto_wrapper:
            try:
                self.crypto_wrapper.close()
                self.logger.info("🔐 Crypto wrapper cerrado correctamente")
            except Exception as e:
                self.logger.error(f"❌ Error cerrando crypto wrapper: {e}")

        # Cerrar conexiones ZMQ
        await self.zmq_manager.close_all()

        self.logger.info("✅ Dashboard Backend V3.1 detenido")


def signal_handler(signum, frame):
    """Manejar señales del sistema"""
    print(f"\n📡 Señal {signum} recibida")
    global dashboard
    if 'dashboard' in globals():
        asyncio.create_task(dashboard.stop())
    sys.exit(0)


async def main():
    """Función principal asíncrona"""
    global dashboard

    if len(sys.argv) != 3:
        print("❌ Uso: python dashboard_v31.py <dashboard_config.json> <firewall_rules.json>")
        sys.exit(1)

    config_file = sys.argv[1]
    firewall_rules_file = sys.argv[2]

    # Configurar signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        print("🚀 Dashboard Backend V3.1 - Crypto + Compression Ready")
        print("🔐 AES-256-GCM + LZ4 Automatic Encryption")
        print("🌐 Fleet Management with Transparent Security")

        # Crear dashboard
        dashboard = DashboardBackendV31(config_file, firewall_rules_file)

        # Iniciar dashboard
        await dashboard.start()

    except KeyboardInterrupt:
        print("\n🛑 Shutdown signal received")
        if 'dashboard' in locals():
            await dashboard.stop()
    except Exception as e:
        print(f"💥 Error fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())