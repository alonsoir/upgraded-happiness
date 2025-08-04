#!/usr/bin/env python3
"""
promiscuous_agent_v3.py - Agente distribuido con captura real y protobuf v3.0.0
🆕 ACTUALIZADO: Soporte para NetworkEvent v3.0.0
🔄 COMPATIBLE: Funciona con pipeline v3 y componentes v2
🚀 MEJORADO: Usa nuevos campos v3 para mejor tracking
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
from threading import Event
from typing import Dict, Any, Optional, List
from queue import Queue, Empty

# 📦 Dependencias para captura de paquetes
try:
    from scapy.all import sniff, Ether, IP, TCP, UDP

    SCAPY_AVAILABLE = True
except ImportError:
    print("⚠️ Scapy no disponible - usando modo simulación")
    SCAPY_AVAILABLE = False

# 📦 Protobuf v3.0.0 - ACTUALIZADO
try:
    # 🆕 CAMBIO CRÍTICO: Importar protobuf v3
    import src.protocols.protobuf.network_event_extended_v3_pb2 as NetworkEventProto

    PROTOBUF_AVAILABLE = True
    PROTOBUF_VERSION = "v3.0.0"
except ImportError:
    print("⚠️ Protobuf v3 no disponible - generar con: protoc --python_out=. network_event_extended_v3.proto")
    PROTOBUF_AVAILABLE = False
    PROTOBUF_VERSION = "unavailable"


class DistributedPromiscuousAgent:
    """
    Agente promiscuo distribuido completamente configurable desde JSON v3.0.0
    - Captura real de paquetes de red
    - Serialización protobuf v3.0.0 con nuevos campos
    - node_id y PID para gestión distribuida
    - Backpressure configurable
    - Sin valores hardcodeados
    - 🆕 Soporte completo para nuevos campos v3
    """

    def __init__(self, config_file: str):
        # 📄 Cargar configuración - SIN defaults hardcodeados
        self.config = self._load_config_strict(config_file)
        self.config_file = config_file

        # 🏷️ Identidad distribuida
        self.node_id = self.config["node_id"]
        self.process_id = os.getpid()
        self.container_id = self._get_container_id()
        self.start_time = time.time()

        # 🖥️ Información del sistema
        self.system_info = self._gather_system_info()

        # 📝 Setup logging desde configuración (PRIMERO para usar en otros métodos)
        self.setup_logging()

        # 🔌 Setup ZeroMQ desde configuración
        self.context = zmq.Context()
        self.socket = None
        self.setup_socket()

        # 🔄 Backpressure desde configuración
        self.backpressure_config = self.config["backpressure"]

        # 📦 Queue interno para procesamiento asíncrono
        queue_size = self.config["processing"]["internal_queue_size"]
        self.packet_queue = Queue(maxsize=queue_size)

        # 📊 Métricas actualizadas para v3
        self.stats = {
            'captured': 0,
            'processed': 0,
            'sent': 0,
            'dropped': 0,
            'filtered': 0,
            'buffer_full_errors': 0,
            'backpressure_activations': 0,
            'queue_overflows': 0,
            'protobuf_errors': 0,
            'v3_events_created': 0,  # 🆕 Eventos v3 creados
            'handshakes_sent': 0,  # 🆕 Handshakes enviados
            'pipeline_events': 0,  # 🆕 Eventos normales del pipeline
            'start_time': time.time(),
            'last_stats_time': time.time()
        }

        # 🎛️ Control
        self.stop_event = Event()
        self.running = True
        self.handshake_sent = False

        # ✅ Verificar dependencias críticas
        self._verify_dependencies()

        self.logger.info(f"🚀 Distributed Promiscuous Agent v3.0.0 inicializado")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")
        self.logger.info(f"   🔢 PID: {self.process_id}")
        self.logger.info(f"   📄 Config: {config_file}")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")

    def _load_config_strict(self, config_file: str) -> Dict[str, Any]:
        """Carga configuración SIN proporcionar defaults"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(f"❌ Archivo de configuración no encontrado: {config_file}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"❌ Error parseando JSON: {e}")

        # ✅ Validar campos críticos
        required_fields = [
            "node_id", "zmq", "backpressure", "capture",
            "processing", "protobuf", "logging", "monitoring"
        ]

        for field in required_fields:
            if field not in config:
                raise RuntimeError(f"❌ Campo requerido faltante en config: {field}")

        # ✅ Validar subcampos críticos
        self._validate_config_structure(config)

        return config

    def _validate_config_structure(self, config: Dict[str, Any]):
        """Valida estructura de configuración - actualizada para network"""

        # 🆕 Validar nueva estructura "network" si existe
        if "network" in config:
            network_config = config["network"]
            if "output_socket" in network_config:
                output_socket = network_config["output_socket"]
                required_network_fields = ["address", "port", "mode", "socket_type"]
                for field in required_network_fields:
                    if field not in output_socket:
                        raise RuntimeError(f"❌ Campo network.output_socket faltante: {field}")

                # Validar valores específicos
                valid_modes = ["bind", "connect"]
                if output_socket["mode"].lower() not in valid_modes:
                    raise RuntimeError(f"❌ Modo inválido: {output_socket['mode']}. Válidos: {valid_modes}")

                valid_socket_types = ["PUSH", "PULL", "PUB", "SUB"]
                if output_socket["socket_type"] not in valid_socket_types:
                    raise RuntimeError(
                        f"❌ Tipo de socket inválido: {output_socket['socket_type']}. Válidos: {valid_socket_types}")

        # ✅ Validar campos ZMQ (mantener para opciones técnicas)
        if "zmq" in config:
            zmq_required = ["sndhwm", "linger_ms", "send_timeout_ms"]
            # Si no hay network config, también requerir output_port
            if "network" not in config or "output_socket" not in config.get("network", {}):
                zmq_required.append("output_port")

            for field in zmq_required:
                if field not in config["zmq"]:
                    raise RuntimeError(f"❌ Campo ZMQ faltante: zmq.{field}")

        # Resto de validaciones...
        proc_required = ["internal_queue_size", "processing_threads", "queue_timeout_seconds"]
        for field in proc_required:
            if field not in config["processing"]:
                raise RuntimeError(f"❌ Campo processing faltante: processing.{field}")

        cap_required = ["interface", "filter_expression", "buffer_size", "promiscuous_mode"]
        for field in cap_required:
            if field not in config["capture"]:
                raise RuntimeError(f"❌ Campo capture faltante: capture.{field}")

    def _get_container_id(self) -> Optional[str]:
        """Obtiene ID del contenedor si está ejecutándose en uno"""
        try:
            # Intentar leer cgroup para Docker
            with open('/proc/self/cgroup', 'r') as f:
                content = f.read()
                for line in content.split('\n'):
                    if 'docker' in line:
                        return line.split('/')[-1][:12]  # Primeros 12 chars del container ID
            return None
        except:
            return None

    def _gather_system_info(self) -> Dict[str, Any]:
        """Recolecta información del sistema"""
        return {
            'hostname': socket.gethostname(),
            'os_name': platform.system(),
            'os_version': platform.release(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': round(psutil.virtual_memory().total / (1024 ** 3), 2)
        }

    def _verify_dependencies(self):
        """Verifica que las dependencias críticas estén disponibles"""
        issues = []

        if not SCAPY_AVAILABLE:
            if self.config["capture"]["mode"] == "real":
                issues.append("❌ Scapy requerido para captura real - pip install scapy")

        if not PROTOBUF_AVAILABLE:
            issues.append("❌ Protobuf v3 no generado - ejecutar: protoc --python_out=. network_event_extended_v3.proto")

        if issues:
            for issue in issues:
                print(issue)
            raise RuntimeError("❌ Dependencias críticas faltantes")

    def setup_socket(self):
        """Configuración ZMQ desde archivo usando nueva estructura network"""
        # 🆕 Leer desde la nueva sección "network"
        network_config = self.config.get("network", {})
        output_socket_config = network_config.get("output_socket", {})

        # 🔄 Fallback a configuración legacy "zmq" si no existe "network"
        if not output_socket_config:
            self.logger.warning("⚠️ Usando configuración legacy 'zmq' - considera migrar a 'network'")
            zmq_config = self.config["zmq"]

            self.socket = self.context.socket(zmq.PUSH)

            # Configuración legacy
            self.socket.setsockopt(zmq.SNDHWM, zmq_config["sndhwm"])
            self.socket.setsockopt(zmq.LINGER, zmq_config["linger_ms"])
            self.socket.setsockopt(zmq.SNDTIMEO, zmq_config["send_timeout_ms"])

            port = zmq_config["output_port"]
            bind_address = f"tcp://*:{port}"
            self.socket.bind(bind_address)

            self.logger.info(f"🔌 Socket ZMQ configurado (legacy):")
            self.logger.info(f"   📡 Bind: {bind_address}")
            self.logger.info(f"   🌊 SNDHWM: {zmq_config['sndhwm']}")
            return

        # 🆕 Nueva configuración desde "network"
        zmq_config = self.config["zmq"]  # Mantenemos zmq para opciones técnicas

        try:
            # 🔧 Determinar tipo de socket desde configuración
            socket_type_str = output_socket_config.get("socket_type", "PUSH")
            socket_type = getattr(zmq, socket_type_str)
            self.socket = self.context.socket(socket_type)

            # 🔧 Configurar opciones ZMQ (desde sección zmq)
            self.socket.setsockopt(zmq.SNDHWM, zmq_config["sndhwm"])
            self.socket.setsockopt(zmq.LINGER, zmq_config["linger_ms"])
            self.socket.setsockopt(zmq.SNDTIMEO, zmq_config["send_timeout_ms"])

            # 🔌 Configurar dirección desde "network"
            address = output_socket_config["address"]
            port = output_socket_config["port"]
            mode = output_socket_config["mode"].lower()

            if mode == "bind":
                # BIND para actuar como servidor
                bind_address = f"tcp://*:{port}"
                self.socket.bind(bind_address)
                connection_info = f"BIND on {bind_address}"
            elif mode == "connect":
                # CONNECT para actuar como cliente
                connect_address = f"tcp://{address}:{port}"
                self.socket.connect(connect_address)
                connection_info = f"CONNECT to {connect_address}"
            else:
                raise ValueError(f"❌ Modo de socket desconocido: {mode}. Use 'bind' o 'connect'")

            self.logger.info(f"🔌 Socket ZMQ configurado:")
            self.logger.info(f"   📡 {connection_info}")
            self.logger.info(f"   🔌 Tipo: {socket_type_str}")
            self.logger.info(f"   🌊 SNDHWM: {zmq_config['sndhwm']}")
            self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
            self.logger.info(f"   📝 Descripción: {output_socket_config.get('description', 'N/A')}")

        except Exception as e:
            raise RuntimeError(f"❌ Error configurando socket ZMQ: {e}")

    def setup_logging(self):
        """Setup logging desde configuración con node_id - CORREGIDO: disco + pantalla"""
        log_config = self.config["logging"]

        # 📝 Configurar nivel
        level = getattr(logging, log_config["level"].upper())

        # 🏷️ Formato de UNA LÍNEA con node_id y PID
        log_format = (
            "%(asctime)s - %(name)-20s - %(levelname)-8s - "
            "[node_id:{node_id}] [pid:{pid}] [v3.0.0] - %(message)s"
        ).format(
            node_id=self.node_id,
            pid=self.process_id
        )
        formatter = logging.Formatter(log_format)

        # 📋 Setup logger
        self.logger = logging.getLogger(f"promiscuous_agent_{self.node_id}")
        self.logger.setLevel(level)
        self.logger.handlers.clear()  # Limpiar handlers existentes
        self.logger.propagate = False

        # 🔧 HANDLER 1: SIEMPRE añadir StreamHandler (pantalla)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # 🔧 HANDLER 2: Si especifica file, también añadir FileHandler (disco)
        if log_config.get("file"):
            try:
                # Crear directorio si no existe
                log_file = log_config["file"]
                os.makedirs(os.path.dirname(log_file), exist_ok=True)

                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

                # Log inicial para confirmar file logging
                self.logger.info(f"📝 File logging habilitado: {log_file}")
            except Exception as e:
                # Si falla file logging, solo usar console
                self.logger.error(f"❌ Error configurando file logging: {e}")

        self.logger.info(f"📋 Logging configurado: nivel={log_config['level']}, "
                         f"handlers={len(self.logger.handlers)}")

    def create_network_event(self, packet_data: Dict[str, Any], is_handshake: bool = False) -> bytes:
        """
        Crea evento protobuf v3.0.0 desde datos de paquete
        🆕 ACTUALIZADO: Usa nuevos campos v3 para mejor tracking
        """
        if not PROTOBUF_AVAILABLE:
            raise RuntimeError("❌ Protobuf v3 no disponible")

        try:
            # 📦 Crear evento protobuf v3.0.0
            event = NetworkEventProto.NetworkEvent()

            # 🆔 Identificación única
            event.event_id = str(uuid.uuid4())
            event.timestamp = int(time.time() * 1000)  # Milliseconds

            # 🌐 Datos de red
            event.source_ip = packet_data.get('src_ip', 'unknown')
            event.target_ip = packet_data.get('dst_ip', 'unknown')
            event.packet_size = packet_data.get('size', 0)
            event.dest_port = packet_data.get('dst_port', 0)
            event.src_port = packet_data.get('src_port', 0)
            event.protocol = packet_data.get('protocol', 'unknown')

            # 🤖 Identificación del agente (legacy)
            event.agent_id = f"agent_{self.node_id}"

            # 🆔 CAMPOS DISTRIBUIDOS CRÍTICOS
            event.node_id = self.node_id
            event.process_id = self.process_id
            if self.container_id:
                event.container_id = self.container_id

            # 🔄 Estado del componente
            event.component_status = "healthy"  # TODO: calcular basado en métricas
            event.uptime_seconds = int(time.time() - self.start_time)

            # 📈 Métricas de performance
            event.queue_depth = self.packet_queue.qsize()
            try:
                process = psutil.Process(self.process_id)
                event.cpu_usage_percent = process.cpu_percent()
                event.memory_usage_mb = process.memory_info().rss / (1024 * 1024)
            except:
                pass  # Ignorar errores de psutil

            # 🔧 Configuración
            event.config_version = self.config.get("version", "unknown")
            event.config_timestamp = int(time.time())

            # 🏠 Información del nodo (solo en handshake)
            if is_handshake:
                event.is_initial_handshake = True
                event.node_hostname = self.system_info['hostname']
                event.os_version = f"{self.system_info['os_name']} {self.system_info['os_version']}"
                event.agent_version = self.config.get("agent_version", "1.0.0")
                event.so_identifier = self._get_so_identifier()
                event.firewall_status = "unknown"  # TODO: detectar estado del firewall

                # 📊 Descripción de handshake
                event.description = f"Initial handshake from {self.node_id}"
                event.event_type = "handshake"

                # 📊 Contabilizar handshake
                self.stats['handshakes_sent'] += 1
            else:
                event.is_initial_handshake = False
                event.description = f"Packet captured from {event.source_ip} to {event.target_ip}"
                event.event_type = "network_traffic"

                # 📊 Contabilizar evento normal
                self.stats['pipeline_events'] += 1

            # 🔧 CAMPOS DE PIPELINE DISTRIBUIDO (POSICIONES 36-45) - CORREGIDOS

            # PIDS de componentes (36-40)
            event.promiscuous_pid = self.process_id  # CRÍTICO: Nuestro PID
            event.geoip_enricher_pid = 0  # No tenemos geoip enricher aquí
            event.ml_detector_pid = 0  # No tenemos ml detector aquí
            event.dashboard_pid = 0  # Será llenado por el dashboard
            event.firewall_pid = 0  # No tenemos firewall aquí

            # TIMESTAMPS de procesamiento (41-45) - CORREGIDOS
            current_time_ms = int(time.time() * 1000)

            # CORRECCIÓN CRÍTICA: Llenar promiscuous_timestamp (campo 41)
            if 'timestamp' in packet_data:
                # Usar timestamp del paquete si está disponible
                event.promiscuous_timestamp = int(packet_data['timestamp'] * 1000)
            else:
                # Usar timestamp actual
                event.promiscuous_timestamp = current_time_ms

            event.geoip_enricher_timestamp = 0  # No procesado por geoip aún
            event.ml_detector_timestamp = 0  # No procesado por ML aún
            event.dashboard_timestamp = 0  # Será llenado por dashboard
            event.firewall_timestamp = 0  # No procesado por firewall aún

            # MÉTRICAS de pipeline (46-48)
            event.processing_latency_ms = 0.0  # Calcular en componentes posteriores
            event.pipeline_hops = 1  # Somos el primer componente
            event.pipeline_path = f"promiscuous[{self.node_id}]"

            # CONTROL de flujo (49-51)
            event.retry_count = 0
            event.last_error = ""
            event.requires_reprocessing = False

            # TAGS y metadatos (52-53)
            event.component_tags.extend([
                "promiscuous",
                "packet_capture",
                f"node_{self.node_id}",
                f"pid_{self.process_id}",
                "protobuf_v3"  # 🆕 Indicar que usa v3
            ])

            # Metadatos del componente
            metadata = event.component_metadata
            metadata["capture_interface"] = self.config["capture"]["interface"]
            metadata["agent_version"] = self.config.get("agent_version", "1.0.0")
            metadata["config_file"] = self.config_file
            metadata["queue_size"] = str(self.packet_queue.qsize())
            metadata["processing_thread"] = str(threading.current_thread().name)
            metadata["protobuf_version"] = PROTOBUF_VERSION  # 🆕 Versión del protobuf

            # ============================================================
            # 🆕 CAMPOS NUEVOS v3.0.0 - APROVECHAR DONDE SEA APROPIADO
            # ============================================================

            # 🔄 VERSIONADO Y COMPATIBILIDAD (campos 93-95)
            event.protobuf_schema_version = "v3.0.0"
            event.legacy_compatibility_mode = False  # Usando v3 nativo
            # deprecated_fields se deja vacío por ahora

            # 📊 MÉTRICAS DE RENDIMIENTO (campos 96-99) - Solo campos disponibles
            # geoip_lookup_latency_ms = 0 (no aplicable aquí)
            # cache_hits_count = 0 (no aplicable aquí)
            # cache_misses_count = 0 (no aplicable aquí)
            # enrichment_success_rate = 0 (no aplicable aquí)

            # 🔄 Serializar a bytes
            serialized_data = event.SerializeToString()

            # 📊 Contabilizar evento v3 creado
            self.stats['v3_events_created'] += 1

            # 📊 Log de debugging para verificar campos críticos
            self.logger.debug(f"📦 Protobuf v3 creado - Tamaño: {len(serialized_data)} bytes")
            self.logger.debug(f"   🔢 promiscuous_pid: {event.promiscuous_pid}")
            self.logger.debug(f"   ⏰ promiscuous_timestamp: {event.promiscuous_timestamp}")
            self.logger.debug(f"   🛤️ pipeline_path: {event.pipeline_path}")
            self.logger.debug(f"   📦 schema_version: {event.protobuf_schema_version}")
            self.logger.debug(f"   🏷️ event_type: {event.event_type}")

            return serialized_data

        except Exception as e:
            self.stats['protobuf_errors'] += 1
            self.logger.error(f"❌ Error creando evento protobuf v3: {e}")
            raise

    def _get_so_identifier(self) -> str:
        """Identifica el sistema operativo y su firewall"""
        os_name = self.system_info['os_name'].lower()

        if 'linux' in os_name:
            # TODO: detectar si usa ufw, iptables, etc.
            return "linux_iptables"
        elif 'darwin' in os_name:
            return "darwin_pf"
        elif 'windows' in os_name:
            return "windows_firewall"
        else:
            return "unknown"

    def packet_capture_callback(self, packet):
        """Callback para captura de paquetes con Scapy - MEJORADO con timestamp"""
        try:
            # 📊 Extraer información del paquete con timestamp de captura
            packet_data = self._extract_packet_info(packet)

            if packet_data and self._should_process_packet(packet_data):
                # 📋 Añadir a queue para procesamiento asíncrono
                try:
                    queue_timeout = self.config["processing"]["queue_timeout_seconds"]
                    self.packet_queue.put(packet_data, timeout=queue_timeout)
                    self.stats['captured'] += 1
                except:
                    self.stats['queue_overflows'] += 1

        except Exception as e:
            self.logger.error(f"❌ Error en callback de captura: {e}")

    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """Extrae información relevante del paquete - MEJORADO con timestamp preciso"""
        try:
            info = {}

            # 📦 Información básica con timestamp de captura preciso
            info['size'] = len(packet)
            info['timestamp'] = time.time()  # CRÍTICO: Timestamp cuando se capturó

            # 🌐 Capa IP
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info['src_ip'] = ip_layer.src
                info['dst_ip'] = ip_layer.dst
                info['protocol'] = ip_layer.proto

                # 🚪 Puertos para TCP/UDP
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    info['src_port'] = tcp_layer.sport
                    info['dst_port'] = tcp_layer.dport
                    info['protocol'] = 'tcp'
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    info['src_port'] = udp_layer.sport
                    info['dst_port'] = udp_layer.dport
                    info['protocol'] = 'udp'
                else:
                    info['src_port'] = 0
                    info['dst_port'] = 0
                    info['protocol'] = 'other'
            else:
                # Sin capa IP
                info['src_ip'] = 'unknown'
                info['dst_ip'] = 'unknown'
                info['src_port'] = 0
                info['dst_port'] = 0
                info['protocol'] = 'non-ip'

            return info

        except Exception as e:
            self.logger.error(f"❌ Error extrayendo info de paquete: {e}")
            return None

    def _should_process_packet(self, packet_data: Dict[str, Any]) -> bool:
        """Determina si el paquete debe ser procesado según filtros"""
        capture_config = self.config["capture"]

        # 📏 Filtro por tamaño mínimo
        if packet_data['size'] < capture_config.get("min_packet_size", 0):
            self.stats['filtered'] += 1
            return False

        # 🚪 Filtro por puertos excluidos
        excluded_ports = capture_config.get("excluded_ports", [])
        if (packet_data.get('src_port') in excluded_ports or
                packet_data.get('dst_port') in excluded_ports):
            self.stats['filtered'] += 1
            return False

        # 📝 Filtro por protocolos incluidos
        included_protocols = capture_config.get("included_protocols", [])
        if included_protocols and packet_data.get('protocol') not in included_protocols:
            self.stats['filtered'] += 1
            return False

        return True

    def start_packet_capture(self):
        """Inicia captura de paquetes"""
        capture_config = self.config["capture"]

        if not SCAPY_AVAILABLE:
            self.logger.error("❌ Scapy no disponible - no se puede capturar paquetes")
            return

        interface = capture_config["interface"]
        filter_expr = capture_config.get("filter_expression", "")

        self.logger.info(f"🎯 Iniciando captura de paquetes v3.0.0:")
        self.logger.info(f"   📡 Interface: {interface}")
        self.logger.info(f"   🔍 Filtro: {filter_expr or 'sin filtro'}")
        self.logger.info(f"   🎭 Promiscuo: {capture_config['promiscuous_mode']}")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")

        try:
            # 🎣 Iniciar captura con Scapy
            sniff(
                iface=interface if interface != "any" else None,
                filter=filter_expr,
                prn=self.packet_capture_callback,
                store=0,  # No almacenar paquetes en memoria
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.logger.error(f"❌ Error en captura de paquetes: {e}")
            self.logger.error("💡 Tip: ejecutar con sudo para captura promiscua")

    def process_packets(self):
        """Thread para procesar paquetes de la cola"""
        queue_timeout = self.config["processing"]["queue_timeout_seconds"]

        self.logger.info("⚙️ Iniciando thread de procesamiento de paquetes v3.0.0")

        while self.running:
            try:
                # 📋 Obtener paquete de la cola
                packet_data = self.packet_queue.get(timeout=queue_timeout)

                # 📦 Crear evento protobuf v3.0.0
                protobuf_data = self.create_network_event(packet_data)

                # 📤 Enviar con backpressure
                success = self.send_event_with_backpressure(protobuf_data)

                if success:
                    self.stats['processed'] += 1

                self.packet_queue.task_done()

            except Empty:
                # Timeout normal - continuar
                continue
            except Exception as e:
                self.logger.error(f"❌ Error procesando paquete: {e}")

    def send_handshake(self):
        """Envía handshake inicial del nodo v3.0.0"""
        if self.handshake_sent:
            return

        try:
            # 📦 Crear evento handshake con timestamp preciso
            handshake_data = {
                'src_ip': 'handshake',
                'dst_ip': 'handshake',
                'size': 0,
                'src_port': 0,
                'dst_port': 0,
                'protocol': 'handshake',
                'timestamp': time.time()  # CRÍTICO: Timestamp del handshake
            }

            protobuf_data = self.create_network_event(handshake_data, is_handshake=True)

            # 📤 Enviar handshake
            success = self.send_event_with_backpressure(protobuf_data)

            if success:
                self.handshake_sent = True
                self.logger.info(f"🤝 Handshake v3.0.0 enviado exitosamente")
            else:
                self.logger.warning(f"⚠️ Error enviando handshake")

        except Exception as e:
            self.logger.error(f"❌ Error creando handshake: {e}")

    def send_event_with_backpressure(self, event_data: bytes) -> bool:
        """Envío con backpressure configurable"""
        bp_config = self.backpressure_config
        max_retries = bp_config["max_retries"]

        for attempt in range(max_retries + 1):
            try:
                # 🚀 Intento de envío
                self.socket.send(event_data, zmq.NOBLOCK)
                self.stats['sent'] += 1
                return True

            except zmq.Again:
                # 🔴 Buffer lleno
                self.stats['buffer_full_errors'] += 1

                if attempt == max_retries:
                    # 🗑️ Último intento fallido
                    self.stats['dropped'] += 1
                    return False

                # 🔄 Aplicar backpressure
                if not self._apply_backpressure(attempt):
                    return False

                continue

            except zmq.ZMQError as e:
                self.logger.error(f"❌ Error ZMQ: {e}")
                self.stats['dropped'] += 1
                return False

        return False

    def _apply_backpressure(self, attempt: int) -> bool:
        """Aplica backpressure según configuración"""
        bp_config = self.backpressure_config

        if not bp_config["enabled"]:
            return False

        if attempt >= bp_config["max_retries"]:
            self.stats['dropped'] += 1
            return False

        # 🔄 Aplicar delay configurado
        delays = bp_config["retry_delays_ms"]
        delay_ms = delays[attempt] if attempt < len(delays) else delays[-1]

        time.sleep(delay_ms / 1000.0)
        self.stats['backpressure_activations'] += 1
        return True

    def monitor_performance(self):
        """Thread de monitoreo de performance v3.0.0"""
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            self._log_performance_stats_v3()
            self._check_performance_alerts()

    def _log_performance_stats_v3(self):
        """Log de estadísticas de performance v3.0.0"""
        now = time.time()
        interval = now - self.stats['last_stats_time']

        # 📊 Calcular rates
        capture_rate = self.stats['captured'] / interval if interval > 0 else 0
        process_rate = self.stats['processed'] / interval if interval > 0 else 0
        send_rate = self.stats['sent'] / interval if interval > 0 else 0

        self.logger.info(f"📊 Performance Stats v3.0.0:")
        self.logger.info(f"   📡 Capturados: {self.stats['captured']} ({capture_rate:.1f}/s)")
        self.logger.info(f"   ⚙️ Procesados: {self.stats['processed']} ({process_rate:.1f}/s)")
        self.logger.info(f"   📤 Enviados: {self.stats['sent']} ({send_rate:.1f}/s)")
        self.logger.info(f"   🗑️ Descartados: {self.stats['dropped']}")
        self.logger.info(f"   📋 Cola: {self.packet_queue.qsize()}")
        self.logger.info(f"   🔄 Backpressure: {self.stats['backpressure_activations']}")
        self.logger.info(f"   📦 Eventos v3 creados: {self.stats['v3_events_created']}")
        self.logger.info(f"   🤝 Handshakes: {self.stats['handshakes_sent']}")
        self.logger.info(f"   🛤️ Pipeline events: {self.stats['pipeline_events']}")

        # 🔄 Reset stats para próximo intervalo
        for key in ['captured', 'processed', 'sent', 'dropped', 'backpressure_activations',
                    'v3_events_created', 'handshakes_sent', 'pipeline_events']:
            self.stats[key] = 0

        self.stats['last_stats_time'] = now

    def _check_performance_alerts(self):
        """Verifica alertas de performance"""
        monitoring_config = self.config["monitoring"]
        alerts = monitoring_config.get("alerts", {})

        # 🚨 Alert de cola llena
        queue_usage = self.packet_queue.qsize() / self.config["processing"]["internal_queue_size"]
        max_queue_usage = alerts.get("max_queue_usage_percent", 100) / 100.0

        if queue_usage > max_queue_usage:
            self.logger.warning(f"🚨 ALERTA: Cola interna llena ({queue_usage * 100:.1f}%)")

    def run(self):
        """Ejecutar el agente distribuido v3.0.0"""
        self.logger.info("🚀 Iniciando Distributed Promiscuous Agent v3.0.0...")

        # 🤝 Enviar handshake inicial
        self.send_handshake()

        # 🧵 Iniciar threads
        threads = []

        # Thread de monitoreo
        monitor_thread = threading.Thread(target=self.monitor_performance, name="Monitor")
        monitor_thread.start()
        threads.append(monitor_thread)

        # Threads de procesamiento
        num_processing_threads = self.config["processing"]["processing_threads"]
        for i in range(num_processing_threads):
            proc_thread = threading.Thread(target=self.process_packets, name=f"Processor-{i}")
            proc_thread.start()
            threads.append(proc_thread)

        # Thread de captura (debe ser último para bloquear)
        capture_thread = threading.Thread(target=self.start_packet_capture, name="Capture")
        capture_thread.start()
        threads.append(capture_thread)

        self.logger.info(f"✅ Agent v3.0.0 iniciado con {len(threads)} threads")
        self.logger.info(f"   📦 Protobuf: {PROTOBUF_VERSION}")
        self.logger.info(f"   🏷️ Node ID: {self.node_id}")

        try:
            # 🔄 Mantener vivo el proceso principal
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Deteniendo Agent v3.0.0...")

        # 🛑 Cierre graceful
        self.shutdown(threads)

    def shutdown(self, threads):
        """Cierre graceful del agente v3.0.0"""
        self.running = False
        self.stop_event.set()

        # 📊 Stats finales
        runtime = time.time() - self.stats['start_time']
        total_v3_events = self.stats.get('v3_events_created', 0)

        self.logger.info(f"📊 Stats finales v3.0.0 - Runtime: {runtime:.1f}s")
        self.logger.info(f"   📦 Total eventos v3 creados: {total_v3_events}")

        # 🧵 Esperar threads
        for thread in threads:
            thread.join(timeout=5)

        # 🔌 Cerrar socket
        if self.socket:
            self.socket.close()
        self.context.term()

        self.logger.info("✅ Distributed Promiscuous Agent v3.0.0 cerrado correctamente")


# 🚀 Main
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python promiscuous_agent_v3.py <config.json>")
        print("💡 Ejemplo: python promiscuous_agent_v3.py enhanced_agent_config.json")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        agent = DistributedPromiscuousAgent(config_file)
        agent.run()
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)