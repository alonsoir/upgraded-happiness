#!/usr/bin/env python3
"""
simple_firewall_agent_v31_etcd.py - SIMPLE FIREWALL AGENT V3.1 ETCD + DUAL COMMUNICATION + DEBUG
✅ Dual Communication: Scheduler (PUSH/PULL) + Dashboard (PUB/SUB)
✅ V3.1 PROTOBUF EXCLUSIVO con node_id y timestamp nativos
✅ ETCD crypto obligatorio para todos los canales
✅ Debug completo del pipeline de descompresión
✅ Sin fallbacks - Solo protobuf cifrado y comprimido
"""

import zmq
import json
import threading
import time
import logging
import queue
import os
import sys
import signal
import psutil
import hashlib
import asyncio
import gzip
import zlib
import bz2
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque


# 🔥 NUEVO: Importar cliente ETCD específico para simple firewall agent
try:
    from etcd_crypto_client_simple_firewall_agent_fixed import (
        setup_simple_firewall_agent_crypto,
        get_simple_firewall_agent_pipeline_key,
        get_simple_firewall_agent_crypto_status
    )

    ETCD_CRYPTO_CLIENT_AVAILABLE = True
    print("✅ ETCD Crypto Client for Simple Firewall Agent loaded successfully")
except ImportError as e:
    print(f"❌ CRITICAL: ETCD Crypto Client not available: {e}")
    print("📁 Required: etcd_crypto_client_simple_firewall_agent_fixed.py")
    ETCD_CRYPTO_CLIENT_AVAILABLE = False

# 📦 Protobuf V3.1 - Importación exclusiva (TODO O NADA)
PROTOBUF_AVAILABLE = False
PROTOBUF_VERSION = "unavailable"
NetworkEventProto = None
FirewallCommandsProto = None


def verify_protobuf_files():
    """Verificar que existen los archivos protobuf necesarios"""
    # 🔧 FIX: Import os dentro de la función
    import os

    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    protocols_path = os.path.join(project_root, 'protocols', 'v3_1')

    required_files = [
        'network_security_clean_v31_pb2.py',
        'firewall_commands_v31_pb2.py'
    ]

    missing_files = []
    for file_name in required_files:
        file_path = os.path.join(protocols_path, file_name)
        if not os.path.exists(file_path):
            missing_files.append(file_name)

    if missing_files:
        print(f"❌ CRITICAL: Missing protobuf files:")
        for file_name in missing_files:
            print(f"   📁 {file_name}")
        print(f"🔧 Expected location: {protocols_path}")
        print(f"🛠️ Generate protobuf files with:")
        print(f"   protoc --python_out=protocols/v3_1/ protocols/v3_1/*.proto")
        return False

    print(f"✅ All required protobuf files found in {protocols_path}")
    return True


def import_agent_protobuf_v31():
    """Importa protobuf V3.1 EXCLUSIVO para agent - PATH DIRECTO"""
    global NetworkEventProto, FirewallCommandsProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    # 🔧 FIX: Import os y sys dentro de la función
    import os
    import sys

    print("🔍 Agent ETCD: Buscando protobuf V3.1 EXCLUSIVO...")

    # Agregar path directo al sys.path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)  # Subir un nivel desde core/
    protocols_path = os.path.join(project_root, 'protocols', 'v3_1')

    if protocols_path not in sys.path:
        sys.path.insert(0, protocols_path)

    try:
        # 🔥 IMPORTACIÓN DIRECTA DESDE PATH AGREGADO
        import network_security_clean_v31_pb2
        import firewall_commands_v31_pb2

        # ✅ ASIGNACIÓN CORRECTA - Cada módulo a su variable correspondiente
        NetworkEventProto = network_security_clean_v31_pb2
        FirewallCommandsProto = firewall_commands_v31_pb2  # 🔧 FIX: Era network_security_clean_v31_pb2

        PROTOBUF_AVAILABLE = True
        PROTOBUF_VERSION = "v3.1.0"

        print(f"✅ NetworkEvent v3.1 cargado desde path directo: {protocols_path}")
        print(f"✅ FirewallCommands v3.1 cargado desde path directo: {protocols_path}")
        print(f"🎯 Agent ETCD: Protobuf V3.1 COMPLETO cargado exitosamente")

        # Verificar que FirewallCommand tiene los campos nativos
        try:
            test_command = FirewallCommandsProto.FirewallCommand()
            fields = [field.name for field in test_command.DESCRIPTOR.fields]

            if 'node_id' in fields and 'timestamp' in fields:
                print(f"✅ Verificado: FirewallCommand V3.1 tiene node_id y timestamp nativos")
                print(f"📋 Campos disponibles: {fields}")

                # Verificar también FirewallResponse
                test_response = FirewallCommandsProto.FirewallResponse()
                response_fields = [field.name for field in test_response.DESCRIPTOR.fields]
                print(f"✅ Verificado: FirewallResponse V3.1 campos: {response_fields}")

                return True
            else:
                print(f"❌ ERROR: FirewallCommand no tiene campos V3.1 requeridos")
                print(f"📋 Campos encontrados: {fields}")
                print(f"📋 Campos requeridos: node_id, timestamp")
                return False

        except Exception as e:
            print(f"❌ ERROR verificando campos V3.1: {e}")
            return False

    except ImportError as e:
        print(f"❌ Error importando protobuf v3.1: {e}")
        print(f"🔧 Path intentado: {protocols_path}")
        print("🔧 Verificar que los archivos _pb2.py existen en protocols/v3_1/")

        PROTOBUF_AVAILABLE = False
        PROTOBUF_VERSION = "unavailable"
        NetworkEventProto = None
        FirewallCommandsProto = None
        return False

    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        print(f"🔧 Path usado: {protocols_path}")
        return False


# Ejecutar verificación antes de importar
if not verify_protobuf_files():
    print(f"💥 FATAL: Simple Firewall Agent requires protobuf V3.1 files")
    print(f"🛑 STOPPING EXECUTION - Generate protobuf files first")
    sys.exit(1)

# Ejecutar importación V3.1 EXCLUSIVA
if not import_agent_protobuf_v31():
    print(f"💥 FATAL: Simple Firewall Agent ETCD requires protobuf V3.1 to function")
    print(f"🛑 STOPPING EXECUTION - Without V3.1 there is no agent")
    sys.exit(1)


class AgentConfigurationError(Exception):
    """Error de configuración del agent"""
    pass


class FirewallAgentRulesError(Exception):
    """Error en reglas de firewall del agent"""
    pass


class ETCDCryptoError(Exception):
    """Error específico de ETCD crypto"""
    pass


@dataclass
class FirewallCommand:
    """Comando de firewall procesado"""
    command_id: str
    action: str
    target_ip: str
    target_port: int
    duration_seconds: int
    reason: str
    priority: str
    dry_run: bool
    node_id: str
    timestamp: int
    source: str
    parsing_method: str


@dataclass
class AgentStats:
    """Estadísticas del agent"""
    commands_received: int = 0
    commands_processed: int = 0
    commands_executed: int = 0
    responses_sent: int = 0
    errors: int = 0
    scheduler_commands: int = 0
    dashboard_commands: int = 0
    uptime_start: float = 0
    last_command_time: Optional[datetime] = None
    etcd_crypto_operations: int = 0
    etcd_crypto_errors: int = 0
    compression_debug_operations: int = 0


class CompressionPipelineDebugger:
    """🔧 NUEVA CLASE: Debug completo del pipeline de descompresión"""

    def __init__(self, logger):
        self.logger = logger
        self.compression_stats = {
            'total_messages': 0,
            'gzip_detected': 0,
            'zlib_detected': 0,
            'bzip2_detected': 0,
            'no_compression': 0,
            'manual_decompressions': 0,
            'decompression_failures': 0
        }

    def debug_compression_pipeline(self, command_bytes, source="unknown"):
        """Debug completo del pipeline de descompresión"""
        self.compression_stats['total_messages'] += 1

        self.logger.info(f"🔍 DEBUG COMPRESSION PIPELINE - {source}")
        self.logger.info(f"   📦 Raw bytes received: {len(command_bytes)}")

        # Mostrar primeros bytes para análisis
        if len(command_bytes) >= 16:
            hex_preview = ' '.join([f'{b:02x}' for b in command_bytes[:16]])
            self.logger.info(f"   🔍 First 16 bytes (hex): {hex_preview}")

            # Verificar magic numbers de compresión
            magic_gzip = command_bytes[:2] == b'\x1f\x8b'
            magic_zlib = command_bytes[:2] in [b'\x78\x9c', b'\x78\x01', b'\x78\xda']
            magic_bzip2 = command_bytes[:3] == b'BZh'

            self.logger.info(f"   🔍 Compression signatures:")
            self.logger.info(f"      GZIP: {magic_gzip}")
            self.logger.info(f"      ZLIB: {magic_zlib}")
            self.logger.info(f"      BZIP2: {magic_bzip2}")

            # Actualizar estadísticas
            if magic_gzip:
                self.compression_stats['gzip_detected'] += 1
                self.logger.warning(f"   ⚠️ GZIP signature detected - should be decompressed by ETCD!")
            elif magic_zlib:
                self.compression_stats['zlib_detected'] += 1
                self.logger.warning(f"   ⚠️ ZLIB signature detected - should be decompressed by ETCD!")
            elif magic_bzip2:
                self.compression_stats['bzip2_detected'] += 1
                self.logger.warning(f"   ⚠️ BZIP2 signature detected - should be decompressed by ETCD!")
            else:
                self.compression_stats['no_compression'] += 1
                self.logger.info(f"   ✅ No compression signature - good (ETCD decompressed correctly)")

        # Verificar si parezca protobuf válido
        if len(command_bytes) > 0:
            first_byte = command_bytes[0]
            field_number = (first_byte >> 3) & 0x0F
            wire_type = first_byte & 0x07

            self.logger.info(f"   🔍 Protobuf analysis:")
            self.logger.info(f"      First byte: 0x{first_byte:02x}")
            self.logger.info(f"      Field number: {field_number}")
            self.logger.info(f"      Wire type: {wire_type}")

            # Wire types válidos en protobuf: 0, 1, 2, 3, 4, 5
            if wire_type <= 5:
                self.logger.info(f"   ✅ Looks like valid protobuf wire type")
            else:
                self.logger.warning(f"   ⚠️ Invalid protobuf wire type: {wire_type}")

        return command_bytes

    def attempt_emergency_decompression(self, data, source="unknown"):
        """Decompresión de emergencia si ETCD falló"""
        self.logger.warning(f"🔧 EMERGENCY: Attempting manual decompression for {source}")
        self.compression_stats['manual_decompressions'] += 1

        # Método 1: GZIP
        try:
            if data[:2] == b'\x1f\x8b':
                decompressed = gzip.decompress(data)
                self.logger.warning(f"   🔧 GZIP emergency decompression: {len(data)} → {len(decompressed)} bytes")
                return decompressed, "emergency_gzip"
        except Exception as e:
            self.logger.debug(f"   🔄 GZIP emergency failed: {e}")

        # Método 2: ZLIB
        try:
            if data[:2] in [b'\x78\x9c', b'\x78\x01', b'\x78\xda']:
                decompressed = zlib.decompress(data)
                self.logger.warning(f"   🔧 ZLIB emergency decompression: {len(data)} → {len(decompressed)} bytes")
                return decompressed, "emergency_zlib"
        except Exception as e:
            self.logger.debug(f"   🔄 ZLIB emergency failed: {e}")

        # Método 3: ZLIB sin header
        try:
            decompressed = zlib.decompress(data, -zlib.MAX_WBITS)
            self.logger.warning(
                f"   🔧 ZLIB (no header) emergency decompression: {len(data)} → {len(decompressed)} bytes")
            return decompressed, "emergency_zlib_no_header"
        except Exception as e:
            self.logger.debug(f"   🔄 ZLIB (no header) emergency failed: {e}")

        # Método 4: BZIP2
        try:
            if data[:3] == b'BZh':
                decompressed = bz2.decompress(data)
                self.logger.warning(f"   🔧 BZIP2 emergency decompression: {len(data)} → {len(decompressed)} bytes")
                return decompressed, "emergency_bzip2"
        except Exception as e:
            self.logger.debug(f"   🔄 BZIP2 emergency failed: {e}")

        self.logger.error(f"   ❌ All emergency decompression methods failed for {source}")
        self.compression_stats['decompression_failures'] += 1
        return data, "no_emergency_decompression"

    def get_compression_stats(self):
        """Obtener estadísticas de compresión"""
        return self.compression_stats.copy()

    def log_compression_stats(self):
        """Log estadísticas de compresión"""
        stats = self.compression_stats
        total = stats['total_messages']
        if total > 0:
            self.logger.info(f"📊 COMPRESSION PIPELINE STATS:")
            self.logger.info(f"   📦 Total messages: {total}")
            self.logger.info(
                f"   🗜️ GZIP detected: {stats['gzip_detected']} ({stats['gzip_detected'] / total * 100:.1f}%)")
            self.logger.info(
                f"   🗜️ ZLIB detected: {stats['zlib_detected']} ({stats['zlib_detected'] / total * 100:.1f}%)")
            self.logger.info(
                f"   🗜️ BZIP2 detected: {stats['bzip2_detected']} ({stats['bzip2_detected'] / total * 100:.1f}%)")
            self.logger.info(
                f"   ✅ No compression: {stats['no_compression']} ({stats['no_compression'] / total * 100:.1f}%)")
            self.logger.info(f"   🔧 Manual decompressions: {stats['manual_decompressions']}")
            self.logger.info(f"   ❌ Decompression failures: {stats['decompression_failures']}")


class AgentLogger:
    """Logger específico para agent"""

    def __init__(self, node_id: str, log_config: dict):
        self.logger = logging.getLogger(f"simple_firewall_agent_etcd_{node_id}")
        self.node_id = node_id

        # Configurar logging según JSON
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        log_format = log_config.get('format',
                                    '%(asctime)s - %(name)s - %(levelname)s - [node_id:{node_id}] [pid:{pid}] [SAFE_MODE_V31_ETCD] - %(message)s'
                                    )

        # Reemplazar placeholders
        log_format = log_format.replace('{node_id}', node_id).replace('{pid}', str(os.getpid()))

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
            console_handler.setLevel(getattr(logging, console_config.get('level', 'INFO').upper()))
            self.logger.addHandler(console_handler)

        # Handler de archivo
        file_config = log_config.get('handlers', {}).get('file', {})
        if file_config.get('enabled', True):
            file_path = file_config.get('path', 'logs/simple_firewall_agent_etcd.log')

            try:
                # Crear directorio si no existe
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)

                # Configurar handler de archivo
                file_handler = logging.FileHandler(file_path, encoding='utf-8')
                file_handler.setFormatter(formatter)
                file_handler.setLevel(getattr(logging, file_config.get('level', 'INFO').upper()))
                self.logger.addHandler(file_handler)

            except Exception as e:
                print(f"⚠️ Error configuring file logging: {e}")

    def info(self, msg, *args, **kwargs):
        self.logger.info(f"[node_id:{self.node_id}] [pid:{os.getpid()}] [SAFE_MODE_V31_ETCD] - {msg}", *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(f"[node_id:{self.node_id}] [pid:{os.getpid()}] [SAFE_MODE_V31_ETCD] - {msg}", *args,
                            **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(f"[node_id:{self.node_id}] [pid:{os.getpid()}] [SAFE_MODE_V31_ETCD] - {msg}", *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(f"[node_id:{self.node_id}] [pid:{os.getpid()}] [SAFE_MODE_V31_ETCD] - {msg}", *args, **kwargs)


class AgentConfig:
    """Configuración del agent"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = None
        self.load_and_validate_config()

    def load_and_validate_config(self):
        """Cargar y validar configuración del agent"""
        if not Path(self.config_file).exists():
            raise AgentConfigurationError(f"❌ Config file {self.config_file} not found")

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        except json.JSONDecodeError as e:
            raise AgentConfigurationError(f"❌ JSON parse error in {self.config_file}: {e}")
        except Exception as e:
            raise AgentConfigurationError(f"❌ Error reading {self.config_file}: {e}")

        # Validar sección ETCD crypto OBLIGATORIA
        self._validate_etcd_crypto_section()

        # Validar campos requeridos
        self._validate_required_fields()

        # Extraer valores validados
        self._extract_config_values()

    def _validate_etcd_crypto_section(self):
        """Validar sección ETCD crypto OBLIGATORIA"""
        if 'etcd_crypto' not in self.config:
            raise AgentConfigurationError(
                "❌ CRITICAL: 'etcd_crypto' section REQUIRED in agent config\n"
                "🔧 Add etcd_crypto section with: etcd_host, etcd_port, cluster_name, node_id"
            )

        etcd_crypto = self.config['etcd_crypto']
        required_etcd_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_etcd_fields = [field for field in required_etcd_fields if field not in etcd_crypto]

        if missing_etcd_fields:
            raise AgentConfigurationError(
                f"❌ CRITICAL: Missing required etcd_crypto fields: {missing_etcd_fields}\n"
                f"🔧 Required fields: {required_etcd_fields}"
            )

        # Validar crypto habilitado
        crypto_config = self.config.get('crypto', {})
        if not crypto_config.get('enabled', False):
            raise AgentConfigurationError(
                "❌ CRITICAL: crypto.enabled MUST be true for ETCD agent\n"
                "🔧 Set crypto.enabled=true and crypto.use_etcd_pipeline_key=true"
            )

    def _validate_required_fields(self):
        """Validar campos requeridos"""
        required_paths = [
            'node_id',
            'component.name',
            'component.version',
            'network.scheduler_commands.port',
            'network.scheduler_responses.port',
            'network.dashboard_commands.port',
            'network.dashboard_responses.port'
        ]

        for path in required_paths:
            if not self._get_nested_value(path):
                raise AgentConfigurationError(f"❌ Required field missing: {path}")

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
        """Extraer todos los valores de configuración del agent"""
        # Node ID y component info
        self.node_id = self.config['node_id']
        component = self.config['component']
        self.component_name = component['name']
        self.version = component['version']
        self.mode = component.get('mode', 'distributed_agent')
        self.role = component.get('role', 'simple_firewall_agent')

        # ETCD crypto configuration
        etcd_crypto = self.config['etcd_crypto']
        self.etcd_host = etcd_crypto['etcd_host']
        self.etcd_port = etcd_crypto['etcd_port']
        self.etcd_cluster_name = etcd_crypto['cluster_name']
        self.etcd_node_id = etcd_crypto['node_id']

        # Network configuration DUAL
        network = self.config['network']

        # Scheduler communication
        self.scheduler_commands = network['scheduler_commands']
        self.scheduler_responses = network['scheduler_responses']

        # Dashboard communication
        self.dashboard_commands = network['dashboard_commands']
        self.dashboard_responses = network['dashboard_responses']

        # ZMQ Configuration
        zmq_config = self.config['zmq']
        self.zmq_io_threads = zmq_config['context_io_threads']
        self.zmq_max_sockets = zmq_config.get('max_sockets', 64)
        self.zmq_tcp_keepalive = zmq_config.get('tcp_keepalive', True)
        self.zmq_immediate = zmq_config.get('immediate', True)
        self.zmq_linger_ms = zmq_config.get('linger_ms', 0)
        self.zmq_recv_timeout_ms = zmq_config.get('recv_timeout_ms', 1000)
        self.zmq_send_timeout_ms = zmq_config.get('send_timeout_ms', 1000)

        # Processing Configuration
        processing = self.config['processing']
        self.command_queue_size = processing.get('command_queue_size', 50)
        self.response_queue_size = processing.get('response_queue_size', 25)
        self.max_concurrent_commands = processing.get('max_concurrent_commands', 5)
        self.command_timeout_seconds = processing.get('command_timeout_seconds', 30)

        # Firewall Configuration
        firewall = self.config['firewall']
        self.safety_mode = firewall.get('safety_mode', 'ULTRA_SECURE_V31')
        self.dry_run_by_default = firewall.get('dry_run_by_default', True)
        self.max_rules_per_minute = firewall.get('max_rules_per_minute', 10)
        self.allowed_actions = firewall.get('allowed_actions', ['MONITOR', 'LIST_RULES'])

        # Crypto Configuration
        self.crypto_config = self.config.get('crypto', {})

        # Logging configuration
        self.logging_config = self.config['logging']

        # Debug configuration
        self.debug_config = self.config.get('debug', {})


class SimpleFirewallAgentETCD:
    """Simple Firewall Agent con ETCD crypto y DUAL COMMUNICATION + DEBUG"""

    def __init__(self, config: AgentConfig, firewall_rules_file: str):
        self.config = config
        self.etcd_crypto_ready = False
        self.pipeline_key = None
        self.logger = AgentLogger(config.node_id, config.logging_config)

        # 🔧 NUEVO: Debug de compresión
        self.compression_debugger = CompressionPipelineDebugger(self.logger)

        # Verificar ETCD crypto client disponible
        if not ETCD_CRYPTO_CLIENT_AVAILABLE:
            self.logger.error("❌ CRITICAL: ETCD Crypto Client not available")
            raise ETCDCryptoError("ETCD Crypto Client required for agent operation")

        # Verificar protobuf disponible
        if not PROTOBUF_AVAILABLE:
            self.logger.error("❌ CRITICAL: Protobuf V3.1 modules not available")
            raise RuntimeError("Protobuf V3.1 modules are required for agent")

        # Estadísticas del agent
        self.stats = AgentStats(uptime_start=time.time())

        # Crear contexto ZMQ
        self.context = zmq.Context(io_threads=config.zmq_io_threads)

        # Sockets ZMQ DUAL
        self.scheduler_commands_socket = None
        self.scheduler_responses_socket = None
        self.dashboard_commands_socket = None
        self.dashboard_responses_socket = None

        # Colas de procesamiento
        self.command_queue = queue.Queue(maxsize=config.command_queue_size)
        self.response_queue = queue.Queue(maxsize=config.response_queue_size)

        # Estado del agent
        self.running = False
        self.threads = []

        # Comandos recientes para debugging
        self.recent_commands = deque(maxlen=100)

        self.logger.info(f"🚀 Simple Firewall Agent ETCD initialized: {self.config.node_id}")
        self.logger.info(f"🎯 Mode: {self.config.mode} | Role: {self.config.role}")
        self.logger.info(f"🔐 ETCD Crypto: OBLIGATORIO - DUAL COMMUNICATION")

    async def initialize_etcd_crypto(self, agent_config_path: str, firewall_rules_path: str) -> bool:
        """Inicializar ETCD crypto OBLIGATORIO"""
        try:
            self.logger.info("🔐 Initializing ETCD crypto for Simple Firewall Agent...")

            # Setup ETCD crypto usando el cliente específico
            success = await setup_simple_firewall_agent_crypto(
                agent_config_path, firewall_rules_path)

            if not success:
                self.logger.error("❌ ETCD crypto initialization failed")
                return False

            # Obtener pipeline key
            self.pipeline_key = get_simple_firewall_agent_pipeline_key()
            if not self.pipeline_key:
                self.logger.error("❌ Failed to get pipeline key from ETCD")
                return False

            self.etcd_crypto_ready = True
            self.logger.info("✅ ETCD crypto initialized successfully")
            self.logger.info(f"🔑 Pipeline key obtained: {self.pipeline_key[:16]}...")

            # Log status de ETCD crypto
            etcd_status = get_simple_firewall_agent_crypto_status()
            self.logger.info(f"📊 ETCD Status: ready={etcd_status.get('ready')}, "
                             f"crypto_role={etcd_status.get('crypto_role')}")

            return True

        except Exception as e:
            self.logger.error(f"❌ ETCD crypto initialization error: {e}")
            return False

    def _setup_zmq_sockets(self):
        """Setup ZMQ sockets DUAL según configuración JSON"""
        self.logger.info("🔧 Setting up ZMQ sockets for DUAL COMMUNICATION...")

        try:
            # 1. Scheduler Commands Socket (PULL)
            self.scheduler_commands_socket = self.context.socket(zmq.PULL)
            self.scheduler_commands_socket.setsockopt(zmq.RCVHWM,
                                                      self.config.scheduler_commands.get('high_water_mark', 100))
            self.scheduler_commands_socket.setsockopt(zmq.LINGER, self.config.zmq_linger_ms)
            self.scheduler_commands_socket.setsockopt(zmq.RCVTIMEO, self.config.zmq_recv_timeout_ms)

            if self.config.scheduler_commands['mode'] == 'bind':
                endpoint = f"tcp://*:{self.config.scheduler_commands['port']}"
                self.scheduler_commands_socket.bind(endpoint)
                self.logger.info(f"🔥 Scheduler Commands BIND: {endpoint}")
            else:
                endpoint = f"tcp://{self.config.scheduler_commands['address']}:{self.config.scheduler_commands['port']}"
                self.scheduler_commands_socket.connect(endpoint)
                self.logger.info(f"🔥 Scheduler Commands CONNECT: {endpoint}")

            # 2. Scheduler Responses Socket (PUSH)
            self.scheduler_responses_socket = self.context.socket(zmq.PUSH)
            self.scheduler_responses_socket.setsockopt(zmq.SNDHWM,
                                                       self.config.scheduler_responses.get('high_water_mark', 50))
            self.scheduler_responses_socket.setsockopt(zmq.LINGER, self.config.zmq_linger_ms)
            self.scheduler_responses_socket.setsockopt(zmq.SNDTIMEO, self.config.zmq_send_timeout_ms)

            if self.config.scheduler_responses['mode'] == 'bind':
                endpoint = f"tcp://*:{self.config.scheduler_responses['port']}"
                self.scheduler_responses_socket.bind(endpoint)
                self.logger.info(f"🔄 Scheduler Responses BIND: {endpoint}")
            else:
                endpoint = f"tcp://{self.config.scheduler_responses['address']}:{self.config.scheduler_responses['port']}"
                self.scheduler_responses_socket.connect(endpoint)
                self.logger.info(f"🔄 Scheduler Responses CONNECT: {endpoint}")

            # 3. Dashboard Commands Socket (SUB)
            self.dashboard_commands_socket = self.context.socket(zmq.SUB)
            self.dashboard_commands_socket.setsockopt(zmq.RCVHWM,
                                                      self.config.dashboard_commands.get('high_water_mark', 50))
            self.dashboard_commands_socket.setsockopt(zmq.LINGER, self.config.zmq_linger_ms)
            self.dashboard_commands_socket.setsockopt(zmq.RCVTIMEO, self.config.zmq_recv_timeout_ms)
            self.dashboard_commands_socket.setsockopt(zmq.SUBSCRIBE, b"")  # Subscribe to all

            if self.config.dashboard_commands['mode'] == 'bind':
                endpoint = f"tcp://*:{self.config.dashboard_commands['port']}"
                self.dashboard_commands_socket.bind(endpoint)
                self.logger.info(f"📊 Dashboard Commands BIND: {endpoint}")
            else:
                endpoint = f"tcp://{self.config.dashboard_commands['address']}:{self.config.dashboard_commands['port']}"
                self.dashboard_commands_socket.connect(endpoint)
                self.logger.info(f"📊 Dashboard Commands CONNECT: {endpoint}")

            # 4. Dashboard Responses Socket (PUB)
            self.dashboard_responses_socket = self.context.socket(zmq.PUB)
            self.dashboard_responses_socket.setsockopt(zmq.SNDHWM,
                                                       self.config.dashboard_responses.get('high_water_mark', 50))
            self.dashboard_responses_socket.setsockopt(zmq.LINGER, self.config.zmq_linger_ms)
            self.dashboard_responses_socket.setsockopt(zmq.SNDTIMEO, self.config.zmq_send_timeout_ms)

            if self.config.dashboard_responses['mode'] == 'bind':
                endpoint = f"tcp://*:{self.config.dashboard_responses['port']}"
                self.dashboard_responses_socket.bind(endpoint)
                self.logger.info(f"📈 Dashboard Responses BIND: {endpoint}")
            else:
                endpoint = f"tcp://{self.config.dashboard_responses['address']}:{self.config.dashboard_responses['port']}"
                self.dashboard_responses_socket.connect(endpoint)
                self.logger.info(f"📈 Dashboard Responses CONNECT: {endpoint}")

            self.logger.info("✅ All DUAL ZMQ sockets configured")

        except Exception as e:
            self.logger.error(f"❌ Error setting up DUAL ZMQ sockets: {e}")
            raise AgentConfigurationError(f"ZMQ socket setup error: {e}")

    def _parse_command_with_compression_debug(self, command_bytes, source="unknown"):
        """🔧 NUEVO: Parser con debug completo de compresión"""
        try:
            # PASO 1: Debug del pipeline de compresión
            command_bytes = self.compression_debugger.debug_compression_pipeline(command_bytes, source)
            self.stats.compression_debug_operations += 1

            # PASO 2: Verificar si necesita decompresión de emergencia
            if (command_bytes[:2] == b'\x1f\x8b' or
                    command_bytes[:2] in [b'\x78\x9c', b'\x78\x01', b'\x78\xda'] or
                    command_bytes[:3] == b'BZh'):

                self.logger.error(f"❌ CRITICAL: Received compressed data from {source}!")
                self.logger.error(f"   ETCD should have decompressed but didn't")

                # Intentar decompresión de emergencia
                decompressed, method = self.compression_debugger.attempt_emergency_decompression(command_bytes, source)
                if method.startswith("emergency_"):
                    self.logger.warning(f"🔧 Emergency decompression successful: {method}")
                    command_bytes = decompressed
                else:
                    self.logger.error(f"❌ Emergency decompression failed")
                    return None

            # PASO 3: Intentar parsing protobuf V3.1
            if PROTOBUF_AVAILABLE and FirewallCommandsProto:
                try:
                    pb_command = FirewallCommandsProto.FirewallCommand()
                    pb_command.ParseFromString(command_bytes)

                    if hasattr(pb_command, 'command_id') and pb_command.command_id:
                        self.logger.info(f"✅ Protobuf V3.1 parsed: {pb_command.command_id} from {source}")
                        return self._convert_protobuf_to_dict(pb_command, source)
                    else:
                        self.logger.warning(f"⚠️ Protobuf parsed but missing command_id from {source}")

                except Exception as pb_error:
                    self.logger.error(f"❌ Protobuf parsing failed from {source}: {pb_error}")

                    # Log detalles del error
                    if "utf-8" in str(pb_error).lower():
                        self.logger.error(f"   UTF-8 error detected - data likely still compressed!")
                    elif "truncated" in str(pb_error).lower():
                        self.logger.error(f"   Data appears truncated")

                    return None

            self.logger.error(f"❌ All parsing methods failed for {source}")
            return None

        except Exception as e:
            self.logger.error(f"❌ Critical error in compression debug parsing from {source}: {e}")
            return None

    def _convert_protobuf_to_dict(self, pb_command, source):
        """Convertir protobuf V3.1 a diccionario"""
        try:
            return {
                'command_id': getattr(pb_command, 'command_id', ''),
                'action': getattr(pb_command, 'action', 0),
                'target_ip': getattr(pb_command, 'target_ip', ''),
                'target_port': getattr(pb_command, 'target_port', 0),
                'duration_seconds': getattr(pb_command, 'duration_seconds', 300),
                'reason': getattr(pb_command, 'reason', ''),
                'priority': getattr(pb_command, 'priority', 0),
                'dry_run': getattr(pb_command, 'dry_run', True),
                'node_id': getattr(pb_command, 'node_id', ''),
                'timestamp': getattr(pb_command, 'timestamp', int(time.time() * 1000)),
                'source': source,
                'parsing_method': 'protobuf_v31_with_compression_debug'
            }
        except Exception as e:
            self.logger.error(f"❌ Error converting protobuf to dict: {e}")
            return None

    def _scheduler_commands_receiver(self):
        """Recibir comandos del scheduler"""
        self.logger.info("🔥 Scheduler commands receiver started")

        while self.running:
            try:
                if self.scheduler_commands_socket:
                    try:
                        command_bytes = self.scheduler_commands_socket.recv(zmq.NOBLOCK)
                        self.stats.commands_received += 1
                        self.stats.scheduler_commands += 1
                        self.stats.etcd_crypto_operations += 1

                        self.logger.info(f"🔥 Scheduler comando recibido: {len(command_bytes)} bytes (ETCD decrypted)")

                        # Parse con debug de compresión
                        command_data = self._parse_command_with_compression_debug(command_bytes, "scheduler")

                        if command_data:
                            self.command_queue.put(('scheduler', command_data), timeout=1.0)
                            self.logger.info(f"✅ Comando encolado desde scheduler: {command_data.get('command_id')}")
                        else:
                            self.logger.error(f"❌ Error procesando comando [scheduler]: parsing falló")
                            self.stats.errors += 1

                    except zmq.Again:
                        pass
                    except Exception as e:
                        self.logger.error(f"❌ Error procesando comando [scheduler]: {e}")
                        self.stats.errors += 1
                        self.stats.etcd_crypto_errors += 1

                time.sleep(0.01)

            except Exception as e:
                self.logger.error(f"❌ Scheduler commands receiver error: {e}")
                self.stats.errors += 1
                time.sleep(1)

    def _dashboard_commands_receiver(self):
        """Recibir comandos del dashboard"""
        self.logger.info("📊 Dashboard commands receiver started")

        while self.running:
            try:
                if self.dashboard_commands_socket:
                    try:
                        command_bytes = self.dashboard_commands_socket.recv(zmq.NOBLOCK)
                        self.stats.commands_received += 1
                        self.stats.dashboard_commands += 1
                        self.stats.etcd_crypto_operations += 1

                        self.logger.info(f"📊 Dashboard comando recibido: {len(command_bytes)} bytes (ETCD decrypted)")

                        # Parse con debug de compresión
                        command_data = self._parse_command_with_compression_debug(command_bytes, "dashboard")

                        if command_data:
                            self.command_queue.put(('dashboard', command_data), timeout=1.0)
                            self.logger.info(f"✅ Comando encolado desde dashboard: {command_data.get('command_id')}")
                        else:
                            self.logger.error(f"❌ Error procesando comando [dashboard]: parsing falló")
                            self.stats.errors += 1

                    except zmq.Again:
                        pass
                    except Exception as e:
                        self.logger.error(f"❌ Error procesando comando [dashboard]: {e}")
                        self.stats.errors += 1
                        self.stats.etcd_crypto_errors += 1

                time.sleep(0.01)

            except Exception as e:
                self.logger.error(f"❌ Dashboard commands receiver error: {e}")
                self.stats.errors += 1
                time.sleep(1)

    def _command_processor(self):
        """Procesar comandos de la cola"""
        self.logger.info("🎯 Command processor started")

        while self.running:
            try:
                try:
                    source, command_data = self.command_queue.get(timeout=1)
                    self.stats.commands_processed += 1
                except queue.Empty:
                    continue

                # Procesar comando
                success = self._process_firewall_command(command_data, source)

                if success:
                    self.stats.commands_executed += 1
                    self.logger.info(f"✅ Comando ejecutado exitosamente desde {source}")
                else:
                    self.logger.error(f"❌ Error ejecutando comando desde {source}")
                    self.stats.errors += 1

                # Enviar respuesta
                self._send_response(command_data, source, success)

            except Exception as e:
                self.logger.error(f"❌ Command processor error: {e}")
                self.stats.errors += 1
                time.sleep(1)

    def _process_firewall_command(self, command_data, source):
        """Procesar comando de firewall"""
        try:
            command_id = command_data.get('command_id', 'unknown')
            action = command_data.get('action', 0)
            target_ip = command_data.get('target_ip', '')

            # Convertir action enum a string si es necesario
            action_name = self._get_action_name(action)

            self.logger.info(f"🛡️ Procesando: {command_id} -> {action_name} para {target_ip}")

            # Por ahora, simular ejecución exitosa
            # TODO: Implementar lógica real de firewall
            time.sleep(0.1)  # Simular procesamiento

            return True

        except Exception as e:
            self.logger.error(f"❌ Error processing firewall command: {e}")
            return False

    def _get_action_name(self, action):
        """Convertir action enum a nombre"""
        if isinstance(action, int):
            action_map = {
                0: 'UNKNOWN',
                1: 'BLOCK_IP',
                2: 'RATE_LIMIT_IP',
                3: 'ALLOW_IP_TEMP',
                4: 'LIST_RULES',
                5: 'MONITOR'
            }
            return action_map.get(action, f'ACTION_{action}')
        return str(action)

    def _send_response(self, command_data, source, success):
        """Enviar respuesta apropiada según el source"""
        try:
            response_data = {
                'command_id': command_data.get('command_id', ''),
                'node_id': self.config.node_id,
                'success': success,
                'message': 'Command executed successfully' if success else 'Command execution failed',
                'timestamp': int(time.time() * 1000)
            }

            # Serializar respuesta como protobuf
            if PROTOBUF_AVAILABLE and FirewallCommandsProto:
                pb_response = FirewallCommandsProto.FirewallResponse()
                pb_response.command_id = response_data['command_id']
                pb_response.node_id = response_data['node_id']
                pb_response.success = response_data['success']
                pb_response.message = response_data['message']
                pb_response.timestamp = response_data['timestamp']

                response_bytes = pb_response.SerializeToString()

                if source == 'scheduler':
                    self.scheduler_responses_socket.send(response_bytes, zmq.NOBLOCK)
                    self.logger.info(
                        f"📤 Respuesta enviada a SCHEDULER (ETCD encrypted): {response_data['command_id']} -> Success: {success}")
                elif source == 'dashboard':
                    self.dashboard_responses_socket.send(response_bytes, zmq.NOBLOCK)
                    self.logger.info(
                        f"📤 Respuesta enviada a DASHBOARD (ETCD encrypted): {response_data['command_id']} -> Success: {success}")

                self.stats.responses_sent += 1
                self.stats.etcd_crypto_operations += 1

        except Exception as e:
            self.logger.error(f"❌ Error sending response to {source}: {e}")
            self.stats.errors += 1

    def _start_processing_threads(self):
        """Iniciar threads de procesamiento DUAL"""
        self.logger.info("🧵 Starting DUAL processing threads...")

        # Scheduler commands receiver
        thread = threading.Thread(target=self._scheduler_commands_receiver)
        thread.daemon = True
        thread.start()
        self.threads.append(thread)

        # Dashboard commands receiver
        thread = threading.Thread(target=self._dashboard_commands_receiver)
        thread.daemon = True
        thread.start()
        self.threads.append(thread)

        # Command processor
        thread = threading.Thread(target=self._command_processor)
        thread.daemon = True
        thread.start()
        self.threads.append(thread)

        self.logger.info(f"✅ {len(self.threads)} DUAL processing threads started")

    def _start_periodic_stats(self):
        """Iniciar estadísticas periódicas"""

        def log_stats():
            last_compression_stats_time = time.time()

            while self.running:
                try:
                    # Log estadísticas cada 30 segundos
                    time.sleep(30)

                    uptime = time.time() - self.stats.uptime_start
                    self.logger.info("📊 AGENT ETCD DUAL STATISTICS:")
                    self.logger.info(f"   ⏱️ Uptime: {uptime:.0f}s")
                    self.logger.info(f"   📨 Commands received: {self.stats.commands_received}")
                    self.logger.info(f"   🔄 Commands processed: {self.stats.commands_processed}")
                    self.logger.info(f"   ✅ Commands executed: {self.stats.commands_executed}")
                    self.logger.info(f"   📤 Responses sent: {self.stats.responses_sent}")
                    self.logger.info(f"   🔥 Scheduler commands: {self.stats.scheduler_commands}")
                    self.logger.info(f"   📊 Dashboard commands: {self.stats.dashboard_commands}")
                    self.logger.info(f"   🔐 ETCD crypto operations: {self.stats.etcd_crypto_operations}")
                    self.logger.info(f"   🔧 Compression debug operations: {self.stats.compression_debug_operations}")
                    self.logger.info(f"   ❌ Errors: {self.stats.errors}")

                    # Log estadísticas de compresión cada 5 minutos
                    if time.time() - last_compression_stats_time > 300:
                        self.compression_debugger.log_compression_stats()
                        last_compression_stats_time = time.time()

                except Exception as e:
                    self.logger.error(f"❌ Error in periodic stats: {e}")

        stats_thread = threading.Thread(target=log_stats)
        stats_thread.daemon = True
        stats_thread.start()
        self.threads.append(stats_thread)

    async def start(self, agent_config_path: str, firewall_rules_path: str):
        """Iniciar el agent con ETCD crypto"""
        # PASO 1: Inicializar ETCD crypto ANTES que nada
        if not await self.initialize_etcd_crypto(agent_config_path, firewall_rules_path):
            self.logger.error("❌ Cannot start agent without ETCD crypto")
            raise ETCDCryptoError("ETCD crypto initialization failed")

        # PASO 2: Setup sockets DESPUÉS de ETCD crypto
        self._setup_zmq_sockets()

        self.running = True
        self.logger.info(f"🚀 Starting Simple Firewall Agent ETCD {self.config.version}...")
        self.logger.info(f"📋 Node ID: {self.config.node_id}")
        self.logger.info(f"🏗️ Component: {self.config.component_name}")
        self.logger.info(f"🔧 Mode: {self.config.mode}")
        self.logger.info(f"🎭 Role: {self.config.role}")
        self.logger.info(f"🔐 ETCD Crypto: ✅ ENABLED - DUAL COMMUNICATION")
        self.logger.info(f"🔧 Compression Debug: ✅ ENABLED")

        # Iniciar threads de procesamiento
        self._start_processing_threads()

        # Iniciar estadísticas periódicas
        self._start_periodic_stats()

        self.logger.info("🎯 Simple Firewall Agent ETCD started successfully")

        # Mantener el programa ejecutándose
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Shutdown signal received")
            self.stop()

    def stop(self):
        """Detener el agent con cleanup completo"""
        self.logger.info("🛑 Stopping Simple Firewall Agent ETCD...")
        self.running = False

        # Log estadísticas finales
        uptime = time.time() - self.stats.uptime_start
        self.logger.info(f"📊 FINAL STATS: {uptime:.0f}s uptime, {self.stats.commands_processed} commands processed")
        self.compression_debugger.log_compression_stats()

        # Cerrar sockets ZMQ
        for socket in [self.scheduler_commands_socket, self.scheduler_responses_socket,
                       self.dashboard_commands_socket, self.dashboard_responses_socket]:
            if socket:
                socket.setsockopt(zmq.LINGER, 0)
                socket.close()

        # Terminar contexto ZMQ
        self.context.term()
        self.logger.info("✅ Simple Firewall Agent ETCD stopped successfully")


def signal_handler(sig, frame):
    """Manejar señales del sistema"""
    print("\n🛑 Shutdown signal received")
    sys.exit(0)


async def main_async():
    """Función principal asíncrona del agent ETCD"""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("🚀 Simple Firewall Agent ETCD - DUAL COMMUNICATION + COMPRESSION DEBUG")
    print("✅ Compatible with Scheduler Firewall V3.1 + Dashboard")
    print("🔥 V3.1 PROTOBUF EXCLUSIVO - con node_id y timestamp nativos")
    print("🔐 ETCD CRYPTO OBLIGATORIO - DUAL COMMUNICATION")
    print("🔧 COMPRESSION PIPELINE DEBUG - Diagnosticar problemas UTF-8")

    # Verificar argumentos
    if len(sys.argv) != 3:
        print("\n❌ Usage:")
        print("python simple_firewall_agent_v31_etcd.py <agent_config.json> <firewall_rules.json>")
        sys.exit(1)

    config_file = sys.argv[1]
    firewall_rules_file = sys.argv[2]

    # Validar archivos
    for file_path in [config_file, firewall_rules_file]:
        if not Path(file_path).exists():
            print(f"\n❌ ERROR: File not found: {file_path}")
            sys.exit(1)

    try:
        # Cargar configuración del agent
        config = AgentConfig(config_file)

        # Crear agent ETCD
        agent = SimpleFirewallAgentETCD(config, firewall_rules_file)

        # Iniciar agent (incluye inicialización ETCD)
        await agent.start(config_file, firewall_rules_file)

    except Exception as e:
        print(f"\n💥 FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Función principal del agent - Wrapper para asyncio"""
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n🛑 Keyboard interrupt received")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 Unexpected error in main: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()