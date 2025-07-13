#!/usr/bin/env python3
"""
Enhanced Promiscuous Agent para Upgraded-Happiness (LIMPIO)
REFACTORIZADO: Lee TODA la configuración desde JSON
RESPONSABILIDAD ÚNICA: Captura de paquetes + envío ZeroMQ
ELIMINADO: GPS detection + geolocalización (ahora en geoip_enricher.py)
CORREGIDO: PUB → PUSH socket para compatibilidad con pipeline PUSH/PULL
"""

import json
import time
import logging
import os
import sys
import socket
import uuid
import argparse
import threading
import signal
from typing import Dict, List, Optional, Tuple, Any
from collections import deque

# Messaging and serialization
import zmq

# Network and packet capture
from scapy.all import *

# System detection
import platform
import subprocess
import shutil

# Configurar logging básico (se reconfigurará desde JSON)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Importar protobuf
try:
    from src.protocols.protobuf import network_event_extended_fixed_pb2

    EXTENDED_PROTOBUF = True
    logger.info("✅ Protobuf extendido importado desde src.protocols.protobuf")
except ImportError:
    try:
        import network_event_extended_fixed_pb2

        EXTENDED_PROTOBUF = True
        logger.info("✅ Protobuf extendido importado desde directorio local")
    except ImportError:
        EXTENDED_PROTOBUF = False
        logger.error("❌ Protobuf extendido no disponible")


class SimpleSystemDetector:
    """Detector ligero de SO y firewall configurado desde JSON"""

    def __init__(self, system_config: Dict = None):
        """Inicializar detector con configuración"""
        self.config = system_config or {}
        self._so_identifier = None
        self._node_info = None
        self._is_first_event = True
        self._detect_firewall = self.config.get('detect_firewall', True)
        self._detect_os = self.config.get('detect_os', True)
        self._include_hardware_info = self.config.get('include_hardware_info', False)

    def get_so_identifier(self) -> str:
        """Retorna identificador único del SO y firewall"""
        if self._so_identifier is None:
            self._so_identifier = self._detect_so_identifier()
        return self._so_identifier

    def _detect_so_identifier(self) -> str:
        """Detecta SO y firewall, retorna identificador compacto"""
        if not self._detect_os:
            return "unknown_unknown"

        os_name = platform.system().lower()

        if os_name == "linux":
            firewall = self._detect_linux_firewall() if self._detect_firewall else "unknown"
            return f"linux_{firewall}"
        elif os_name == "windows":
            return "windows_firewall" if self._detect_firewall else "windows_unknown"
        elif os_name == "darwin":
            return "darwin_pf" if self._detect_firewall else "darwin_unknown"
        else:
            return "unknown_unknown"

    def _detect_linux_firewall(self) -> str:
        """Detecta tipo de firewall en Linux"""
        # Orden de prioridad: ufw -> firewalld -> iptables
        if shutil.which('ufw'):
            try:
                result = subprocess.run(['ufw', 'status'],
                                        capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    return 'ufw'
            except:
                pass

        if shutil.which('firewall-cmd'):
            try:
                result = subprocess.run(['systemctl', 'is-active', 'firewalld'],
                                        capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    return 'firewalld'
            except:
                pass

        if shutil.which('iptables'):
            return 'iptables'

        return 'unknown'

    def get_node_info_for_handshake(self) -> dict:
        """Retorna información completa del nodo para el primer evento"""
        if self._node_info is None:
            try:
                # Detectar estado del firewall
                firewall_status = "unknown"
                os_name = platform.system().lower()

                if self._detect_firewall:
                    if os_name == "linux":
                        firewall_status = self._get_linux_firewall_status()
                    elif os_name == "windows":
                        firewall_status = self._get_windows_firewall_status()
                    elif os_name == "darwin":
                        firewall_status = self._get_macos_firewall_status()

                node_info = {
                    'node_hostname': socket.gethostname(),
                    'os_version': f"{platform.system()} {platform.release()}",
                    'firewall_status': firewall_status,
                    'agent_version': '1.0.0'
                }

                # Información adicional de hardware si está configurado
                if self._include_hardware_info:
                    try:
                        node_info['architecture'] = platform.machine()
                        node_info['processor'] = platform.processor()
                        node_info['python_version'] = platform.python_version()
                    except:
                        pass

                self._node_info = node_info

            except Exception as e:
                logger.warning(f"Error detectando información del sistema: {e}")
                self._node_info = {
                    'node_hostname': 'unknown',
                    'os_version': 'unknown',
                    'firewall_status': 'unknown',
                    'agent_version': '1.0.0'
                }

        return self._node_info

    def _get_linux_firewall_status(self) -> str:
        """Obtiene estado del firewall en Linux"""
        try:
            if shutil.which('ufw'):
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=3)
                if 'Status: active' in result.stdout:
                    return 'active'
                else:
                    return 'inactive'
        except:
            pass
        return 'unknown'

    def _get_windows_firewall_status(self) -> str:
        """Obtiene estado del firewall en Windows"""
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                                    capture_output=True, text=True, timeout=5)
            if 'State                                 ON' in result.stdout:
                return 'active'
            else:
                return 'inactive'
        except:
            pass
        return 'unknown'

    def _get_macos_firewall_status(self) -> str:
        """Obtiene estado del firewall en macOS"""
        try:
            result = subprocess.run(['pfctl', '-s', 'info'],
                                    capture_output=True, text=True, timeout=3)
            if 'Status: Enabled' in result.stdout:
                return 'active'
            else:
                return 'inactive'
        except:
            pass
        return 'unknown'

    def is_first_event(self) -> bool:
        """Retorna True solo para el primer evento (handshake)"""
        if self._is_first_event:
            self._is_first_event = False
            return True
        return False

    def get_system_summary(self) -> dict:
        """Retorna resumen del sistema"""
        return {
            'node_id': socket.gethostname(),
            'so_identifier': self.get_so_identifier(),
            'os_name': platform.system(),
            'os_version': platform.release(),
            'firewall_type': self.get_so_identifier().split('_')[-1] if '_' in self.get_so_identifier() else 'unknown',
            'firewall_status': self.get_node_info_for_handshake()['firewall_status']
        }


class EnhancedPromiscuousAgent:
    """
    Agente promiscuo configurado completamente desde JSON
    RESPONSABILIDAD ÚNICA: Captura de paquetes + envío ZeroMQ
    SIN GeoIP/GPS - esa responsabilidad es del geoip_enricher.py
    CORREGIDO: Usa PUSH socket para compatibilidad con pipeline PUSH/PULL
    """

    def __init__(self, config_file: Optional[str] = None):
        """Inicializar agente con configuración JSON completa"""
        self.config = self._load_config(config_file)
        self.config_file = config_file

        # Configurar logging desde JSON PRIMERO
        self._setup_logging()

        # Configuración básica desde JSON
        self.agent_id = f"agent_{socket.gethostname()}_{int(time.time())}"
        self.hostname = socket.gethostname()

        # Configuración de red desde JSON
        self.zmq_port = self.config['zmq']['output_port']
        self.interface = self.config['capture']['interface']
        self.promiscuous_mode = self.config['capture']['promiscuous_mode']
        self.buffer_size = self.config['capture']['buffer_size']
        self.timeout = self.config['capture']['timeout']
        self.max_packets_per_second = self.config['capture']['max_packets_per_second']

        # Configuración de filtrado desde JSON
        self.filtering_config = self.config.get('filtering', {})
        self.protocols = self.filtering_config.get('protocols', ['tcp', 'udp', 'icmp'])
        self.exclude_ports = set(self.filtering_config.get('exclude_ports', []))
        self.include_ports = set(self.filtering_config.get('include_ports', []))
        self.max_packet_size = self.filtering_config.get('max_packet_size', 65535)

        # Configuración de handshake desde JSON
        self.handshake_config = self.config.get('handshake', {})
        self.send_handshake = self.handshake_config.get('enabled', True)
        self.send_initial = self.handshake_config.get('send_initial', True)
        self.handshake_interval = self.handshake_config.get('interval', 30)

        # Configuración de performance desde JSON
        self.performance_config = self.config.get('performance', {})
        self.max_memory_mb = self.performance_config.get('max_memory_mb', 512)
        self.stats_interval = self.performance_config.get('stats_interval', 60)

        # Inicializar componentes
        self.zmq_context = None
        self.zmq_socket = None
        self.running = False

        # Sistema detector configurado desde JSON
        self.system_detector = SimpleSystemDetector(self.config.get('system_detection', {}))

        # Estadísticas
        self.stats = {
            'packets_captured': 0,
            'packets_sent': 0,
            'packets_filtered': 0,
            'handshakes_sent': 0,
            'errors': 0,
            'start_time': time.time(),
            'last_handshake': 0
        }

        # Rate limiting
        self.packet_times = deque(maxlen=100)

        # Inicializar servicios
        self._init_zmq()

        self.so_identifier = self.system_detector.get_so_identifier()

        logger.info(f"🚀 Enhanced Promiscuous Agent inicializado (LIMPIO)")
        logger.info(f"Config file: {config_file or 'default config'}")
        logger.info(f"Agent ID: {self.agent_id}")
        logger.info(f"🖥️  SO detectado: {self.so_identifier}")
        logger.info(f"📡 ZMQ output: localhost:{self.zmq_port}")
        logger.info(f"🔍 Interface: {self.interface}")
        logger.info(f"🤝 Handshake: {self.send_handshake}")
        logger.info(f"📦 Protobuf: {'✅' if EXTENDED_PROTOBUF else '❌'}")

    def _load_config(self, config_file):
        """Cargar configuración desde archivo JSON (SIN secciones GeoIP/GPS)"""
        default_config = {
            "agent_info": {
                "name": "enhanced_promiscuous_agent",
                "version": "1.0.0",
                "description": "Agente promiscuo para captura de paquetes (sin GeoIP)"
            },
            "capture": {
                "interface": "any",
                "promiscuous_mode": True,
                "buffer_size": 512,
                "timeout": 1,
                "max_packets_per_second": 1000
            },
            "zmq": {
                "output_port": 5559,
                "context_threads": 1,
                "high_water_mark": 1000,
                "linger": 0
            },
            "filtering": {
                "protocols": ["tcp", "udp", "icmp"],
                "exclude_ports": [],
                "include_ports": [],
                "max_packet_size": 65535
            },
            "handshake": {
                "enabled": True,
                "send_initial": True,
                "interval": 30,
                "system_info": True
            },
            "system_detection": {
                "detect_firewall": True,
                "detect_os": True,
                "include_hardware_info": False
            },
            "performance": {
                "max_memory_mb": 512,
                "stats_interval": 60,
                "batch_processing": False
            },
            "logging": {
                "level": "INFO",
                "file": "logs/promiscuous_agent.log",
                "max_size": "10MB",
                "backup_count": 5,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "console_output": True
            },
            "protobuf": {
                "enabled": True,
                "extended_format": True,
                "timestamp_correction": True,
                "compression": False
            }
        }

        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)

                # Merge recursivo de configuraciones
                self._merge_config(default_config, user_config)
                logger.info(f"📄 Configuración promiscuous agent cargada desde {config_file}")

            except Exception as e:
                logger.error(f"❌ Error cargando configuración promiscuous agent: {e}")
                logger.info("⚠️ Usando configuración por defecto")
        else:
            if config_file:
                logger.warning(f"⚠️ Archivo de configuración promiscuous agent no encontrado: {config_file}")
            logger.info("⚠️ Usando configuración promiscuous agent por defecto")

        return default_config

    def _merge_config(self, base, update):
        """Merge recursivo de configuraciones"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def _setup_logging(self):
        """Configurar logging desde configuración JSON"""
        log_config = self.config.get('logging', {})

        # Configurar nivel
        level = getattr(logging, log_config.get('level', 'INFO').upper())
        logger.setLevel(level)

        # Limpiar handlers existentes
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        # Formatter desde configuración
        formatter = logging.Formatter(
            log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )

        # Console handler si está habilitado
        if log_config.get('console_output', True):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # File handler si se especifica archivo
        if log_config.get('file'):
            # Crear directorio si no existe
            log_file = log_config['file']
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=self._parse_size(log_config.get('max_size', '10MB')),
                backupCount=log_config.get('backup_count', 5)
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    def _parse_size(self, size_str: str) -> int:
        """Parse size string (e.g., '10MB') to bytes"""
        if isinstance(size_str, int):
            return size_str

        size_str = size_str.upper()
        if size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        else:
            return int(size_str)

    def _init_zmq(self):
        """Inicializar conexión ZeroMQ usando configuración"""
        try:
            zmq_config = self.config['zmq']
            self.zmq_context = zmq.Context(zmq_config.get('context_threads', 1))
            # 🔧 CORREGIDO: PUB → PUSH para compatibilidad con pipeline PUSH/PULL
            self.zmq_socket = self.zmq_context.socket(zmq.PUSH)

            # Configurar opciones de socket
            self.zmq_socket.setsockopt(zmq.SNDHWM, zmq_config.get('high_water_mark', 1000))
            self.zmq_socket.setsockopt(zmq.LINGER, zmq_config.get('linger', 0))

            zmq_address = f"tcp://*:{self.zmq_port}"
            self.zmq_socket.bind(zmq_address)

            # Dar tiempo para que ZMQ se establezca
            time.sleep(0.1)

            logger.info(f"🔌 ZeroMQ PUSH socket vinculado a {zmq_address}")

        except Exception as e:
            logger.error(f"❌ Error inicializando ZeroMQ: {e}")
            raise

    def _should_filter_packet(self, packet) -> bool:
        """Determina si un paquete debe ser filtrado basado en configuración"""

        # Filtro por tamaño
        packet_size = len(packet)
        if packet_size > self.max_packet_size:
            return True

        # Filtro de puertos
        if TCP in packet or UDP in packet:
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport

            # Excluir puertos específicos
            if src_port in self.exclude_ports or dst_port in self.exclude_ports:
                return True

            # Incluir solo puertos específicos (si está configurado)
            if self.include_ports and src_port not in self.include_ports and dst_port not in self.include_ports:
                return True

        # Filtro de protocolo
        protocol = None
        if TCP in packet:
            protocol = 'tcp'
        elif UDP in packet:
            protocol = 'udp'
        elif ICMP in packet:
            protocol = 'icmp'

        if protocol and protocol not in self.protocols:
            return True

        return False

    def _check_rate_limit(self) -> bool:
        """Verificar rate limiting de paquetes"""
        now = time.time()
        self.packet_times.append(now)

        # Limpiar tiempos antiguos (más de 1 segundo)
        while self.packet_times and now - self.packet_times[0] > 1.0:
            self.packet_times.popleft()

        # Verificar si excedemos el límite por segundo
        if len(self.packet_times) > self.max_packets_per_second:
            return False

        return True

    def create_network_event(self, packet) -> 'NetworkEvent':
        """
        Crear evento usando el protobuf configurado
        SIN COORDENADAS - esa responsabilidad es del geoip_enricher.py
        """

        if not EXTENDED_PROTOBUF:
            logger.warning("Protobuf extendido no disponible")
            return None

        # Crear evento
        event = network_event_extended_fixed_pb2.NetworkEvent()

        # Campos básicos
        event.event_id = str(uuid.uuid4())
        event.timestamp = int(time.time())  # Timestamp corregido: segundos Unix
        event.agent_id = self.agent_id

        # Información de red básica
        if IP in packet:
            event.source_ip = packet[IP].src
            event.target_ip = packet[IP].dst
        else:
            event.source_ip = "unknown"
            event.target_ip = "unknown"

        # Puertos
        if TCP in packet:
            event.src_port = packet[TCP].sport
            event.dest_port = packet[TCP].dport
        elif UDP in packet:
            event.src_port = packet[UDP].sport
            event.dest_port = packet[UDP].dport
        else:
            event.src_port = 0
            event.dest_port = 0

        # Campos adicionales básicos
        event.packet_size = len(packet)
        event.event_type = "network_capture"
        event.anomaly_score = 0.0
        event.risk_score = 0.0
        event.description = f"Packet captured from {event.source_ip} to {event.target_ip}"

        # SIN COORDENADAS - se añadirán en geoip_enricher.py
        event.latitude = 0.0
        event.longitude = 0.0

        # Información del sistema
        event.so_identifier = self.system_detector.get_so_identifier()

        # Solo en el primer evento, añadir información completa
        if self.send_handshake and self.system_detector.is_first_event():
            node_info = self.system_detector.get_node_info_for_handshake()
            event.is_initial_handshake = True
            event.node_hostname = node_info['node_hostname']
            event.os_version = node_info['os_version']
            event.firewall_status = node_info['firewall_status']
            event.agent_version = node_info['agent_version']

            self.stats['handshakes_sent'] += 1
            self.stats['last_handshake'] = time.time()

            logger.info(f"📤 Enviando handshake inicial con SO: {event.so_identifier}")
        else:
            event.is_initial_handshake = False
            event.node_hostname = ""
            event.os_version = ""
            event.firewall_status = ""
            event.agent_version = ""

        self.stats['packets_captured'] += 1
        return event

    def send_event(self, event):
        """Enviar evento via ZeroMQ usando PUSH socket para garantizar delivery"""
        try:
            # Enviar como protobuf binario usando PUSH socket
            data = event.SerializeToString()

            # PUSH socket garantiza delivery a PULL socket
            self.zmq_socket.send(data, zmq.NOBLOCK)
            self.stats['packets_sent'] += 1

        except zmq.Again:
            logger.warning("⚠️ ZMQ buffer lleno - evento descartado")
        except Exception as e:
            logger.error(f"❌ Error enviando evento: {e}")
            self.stats['errors'] += 1

    def send_periodic_handshake(self):
        """Envía handshake periódico según configuración"""
        if not self.send_handshake:
            return

        now = time.time()
        if now - self.stats['last_handshake'] >= self.handshake_interval:
            # Crear evento de handshake
            if EXTENDED_PROTOBUF:
                event = network_event_extended_fixed_pb2.NetworkEvent()

                event.event_id = str(uuid.uuid4())
                event.timestamp = int(now)
                event.agent_id = self.agent_id
                event.source_ip = "127.0.0.1"
                event.target_ip = "127.0.0.1"
                event.packet_size = 0
                event.src_port = 0
                event.dest_port = 0
                event.event_type = "periodic_handshake"
                event.anomaly_score = 0.0
                event.risk_score = 0.0
                event.description = "Periodic agent handshake"

                # SIN COORDENADAS
                event.latitude = 0.0
                event.longitude = 0.0

                # Información del sistema
                event.so_identifier = self.system_detector.get_so_identifier()
                node_info = self.system_detector.get_node_info_for_handshake()
                event.is_initial_handshake = False
                event.node_hostname = node_info['node_hostname']
                event.os_version = node_info['os_version']
                event.firewall_status = node_info['firewall_status']
                event.agent_version = node_info['agent_version']

                self.send_event(event)
                self.stats['last_handshake'] = now
                self.stats['handshakes_sent'] += 1

                logger.debug(f"📤 Handshake periódico enviado")

    def packet_handler(self, packet):
        """Handler principal para procesar paquetes capturados"""
        try:
            # Verificar rate limiting
            if not self._check_rate_limit():
                return

            # Aplicar filtros configurados
            if self._should_filter_packet(packet):
                self.stats['packets_filtered'] += 1
                return

            # Crear evento de red básico (SIN coordenadas)
            event = self.create_network_event(packet)
            if not event:
                return

            # Enviar via ZeroMQ usando PUSH socket
            self.send_event(event)

            # Log periódico de estadísticas
            if self.stats['packets_captured'] % 100 == 0:
                self._log_stats()

            # Enviar handshake periódico
            self.send_periodic_handshake()

        except Exception as e:
            logger.error(f"❌ Error procesando paquete: {e}")
            self.stats['errors'] += 1

    def _log_stats(self):
        """Log de estadísticas del agente"""
        stats = self.stats
        filter_rate = (stats['packets_filtered'] / max(stats['packets_captured'] + stats['packets_filtered'], 1)) * 100

        logger.info(
            f"📊 Stats: {stats['packets_captured']} capturados, "
            f"{stats['packets_sent']} enviados, "
            f"{stats['packets_filtered']} filtrados ({filter_rate:.1f}%), "
            f"{stats['handshakes_sent']} handshakes, "
            f"{stats['errors']} errores"
        )

    def start(self):
        """Iniciar captura de paquetes usando configuración completa"""
        if not self.zmq_socket:
            raise RuntimeError("ZeroMQ no inicializado")

        # Verificar permisos
        if os.geteuid() != 0:
            logger.error("❌ Se requieren privilegios de root para captura promiscua")
            logger.info("💡 Ejecutar con: sudo python promiscuous_agent.py")
            raise PermissionError("Root privileges required")

        self.running = True

        print(f"\n🎯 Enhanced Promiscuous Agent Started (LIMPIO)")
        print(f"📄 Config: {self.config_file or 'default'}")
        print(f"🔌 ZMQ Output: localhost:{self.zmq_port}")
        print(f"📡 Interface: {self.interface}")
        print(f"🔒 Promiscuous: {'✅ Enabled' if self.promiscuous_mode else '❌ Disabled'}")
        print(f"🤝 Handshake: {'✅ Enabled' if self.send_handshake else '❌ Disabled'}")
        print(f"⚡ Performance: max {self.max_packets_per_second} pps, {self.max_memory_mb}MB")
        print(f"🎯 Filtering: {len(self.protocols)} protocols, exclude {len(self.exclude_ports)} ports")
        print(f"📦 Protobuf: {'✅ Available' if EXTENDED_PROTOBUF else '❌ Not available'}")
        print(f"🧹 LIMPIO: Sin GeoIP/GPS - solo captura + envío")
        print(f"📡 Destino: geoip_enricher.py (puerto {self.zmq_port})")
        print(f"🔧 CORREGIDO: PUSH socket para compatibilidad PUSH/PULL pipeline")
        print("=" * 70)

        try:
            # Configurar parámetros de captura desde JSON
            capture_kwargs = {
                'iface': self.interface if self.interface != 'any' else None,
                'prn': self.packet_handler,
                'store': 0,
                'stop_filter': lambda x: not self.running
            }

            # Configuración adicional de captura
            if hasattr(conf, 'bufsize'):
                conf.bufsize = self.buffer_size

            logger.info(f"🎯 Iniciando captura en interfaz: {self.interface}")
            logger.info(f"📡 Enviando eventos a puerto {self.zmq_port} (geoip_enricher.py)")
            logger.info(f"🧹 LIMPIO: Solo captura - SIN procesamiento GeoIP/GPS")

            # Captura en modo configurado
            sniff(**capture_kwargs)

        except PermissionError:
            logger.error("❌ Error: Se requieren privilegios de root para captura promiscua")
            logger.info("💡 Ejecutar con: sudo python promiscuous_agent.py enhanced_agent_config.json")
            raise
        except Exception as e:
            logger.error(f"❌ Error en captura: {e}")
            raise

    def stop(self):
        """Detener agente limpiamente"""
        logger.info("🛑 Deteniendo agente promiscuo...")
        self.running = False

        # Cerrar conexiones
        if self.zmq_socket:
            self.zmq_socket.close()
        if self.zmq_context:
            self.zmq_context.term()

        # Log final de estadísticas
        self._log_stats()
        logger.info(f"✅ Agente {self.agent_id} detenido correctamente")

    def get_statistics(self) -> Dict:
        """Retorna estadísticas completas"""
        uptime = time.time() - self.stats['start_time']

        return {
            'uptime_seconds': uptime,
            'packets_captured': self.stats['packets_captured'],
            'packets_sent': self.stats['packets_sent'],
            'packets_filtered': self.stats['packets_filtered'],
            'handshakes_sent': self.stats['handshakes_sent'],
            'errors': self.stats['errors'],
            'agent_id': self.agent_id,
            'so_identifier': self.so_identifier,
            'config_file': self.config_file,
            'configuration': {
                'zmq_port': self.zmq_port,
                'interface': self.interface,
                'handshake_enabled': self.send_handshake,
                'promiscuous_mode': self.promiscuous_mode,
                'max_pps': self.max_packets_per_second,
                'filtering_enabled': len(self.exclude_ports) > 0 or len(self.include_ports) > 0,
                'socket_type': 'PUSH'  # Información del tipo de socket
            }
        }


def main():
    """Función principal con configuración JSON completa"""
    parser = argparse.ArgumentParser(description='Enhanced Promiscuous Agent (LIMPIO - Sin GeoIP, PUSH socket)')
    parser.add_argument('config_file', nargs='?',
                        default='enhanced_agent_config.json',
                        help='Archivo de configuración JSON')
    parser.add_argument('--test-config', action='store_true',
                        help='Validar configuración y salir')
    parser.add_argument('--stats', action='store_true',
                        help='Mostrar estadísticas cada 10 segundos')

    args = parser.parse_args()

    # Configurar manejo de señales para parada limpia
    agent = None

    def signal_handler(signum, frame):
        logger.info(f"📡 Señal {signum} recibida")
        if agent:
            agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Crear agente
        agent = EnhancedPromiscuousAgent(config_file=args.config_file)

        if args.test_config:
            print("✅ Configuración JSON válida para promiscuous agent (LIMPIO, PUSH)")
            stats = agent.get_statistics()
            print(f"📡 ZMQ Port: {stats['configuration']['zmq_port']}")
            print(f"🔍 Interface: {stats['configuration']['interface']}")
            print(f"🤝 Handshake: {'✅' if stats['configuration']['handshake_enabled'] else '❌'}")
            print(f"🔌 Socket Type: {stats['configuration']['socket_type']}")
            print(f"🧹 GeoIP/GPS: ❌ Eliminado (responsabilidad del geoip_enricher.py)")
            print(f"🔧 Pipeline: PUSH → PULL (Corregido)")
            return 0

        logger.info("🚀 Iniciando Enhanced Promiscuous Agent (LIMPIO)...")
        logger.info("📡 Solo captura + envío ZeroMQ - SIN procesamiento GeoIP/GPS")
        logger.info("🎯 Destino: geoip_enricher.py para enriquecimiento geográfico")
        logger.info("⚡ Presiona Ctrl+C para detener")

        # Thread de estadísticas si está solicitado
        if args.stats:
            def stats_thread():
                while agent.running:
                    time.sleep(10)
                    agent._log_stats()

            threading.Thread(target=stats_thread, daemon=True).start()

        agent.start()

    except KeyboardInterrupt:
        logger.info("🛑 Interrupción por teclado")
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        return 1
    finally:
        if agent:
            # Mostrar estadísticas finales
            stats = agent.get_statistics()
            print(f"\n📊 Estadísticas Finales (LIMPIO, PUSH):")
            print(f"   ⏱️  Uptime: {stats['uptime_seconds']:.1f}s")
            print(f"   📦 Packets captured: {stats['packets_captured']}")
            print(f"   📤 Packets sent: {stats['packets_sent']}")
            print(f"   🔍 Packets filtered: {stats['packets_filtered']}")
            print(f"   🤝 Handshakes sent: {stats['handshakes_sent']}")
            print(f"   ❌ Errors: {stats['errors']}")
            print(f"   📄 Config: {stats['config_file'] or 'default'}")
            print(f"   🔌 Socket: {stats['configuration']['socket_type']}")
            print(f"   🧹 GeoIP/GPS: ❌ Eliminado - solo captura")

            agent.stop()

    return 0


if __name__ == "__main__":
    # Verificar que se ejecuta con privilegios suficientes
    if os.geteuid() != 0:
        print("⚠️  ADVERTENCIA: Se requieren privilegios de root para captura promiscua")
        print("💡 Ejecutar: sudo python promiscuous_agent.py enhanced_agent_config.json")

    sys.exit(main())