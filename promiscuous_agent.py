#!/usr/bin/env python3
"""
Enhanced Promiscuous Agent para Upgraded-Happiness
REFACTORIZADO: Lee TODA la configuración desde JSON
Usa enhanced_agent_config.json para TODA la configuración
TIMESTAMP CORREGIDO - GPS detection + geolocalización + handshake inicial
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
import re
import struct
from typing import Dict, List, Optional, Tuple, Any

# Messaging and serialization
import zmq

# Network and packet capture
from scapy.all import *

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

# Geolocalización
try:
    import geoip2.database
    import geoip2.errors

    GEOIP_AVAILABLE = True
    logger.info("✅ GeoIP2 disponible")
except ImportError:
    GEOIP_AVAILABLE = False
    logger.warning("⚠️  GeoIP2 no disponible. Instalar con: pip install geoip2")

# System detection
import platform
import subprocess
import shutil


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


class GeoDetector:
    """Detector configurado de coordenadas GPS en paquetes"""

    def __init__(self, gps_config: Dict = None):
        """Inicializar detector con configuración GPS"""
        self.config = gps_config or {}

        # Configuración desde JSON
        self.enabled = self.config.get('enabled', True)
        self.binary_detection = self.config.get('binary_detection', True)
        self.json_detection = self.config.get('json_detection', True)
        self.min_precision = self.config.get('min_coordinate_precision', 0.001)

        # Patrones de coordenadas desde configuración
        self.lat_lon_patterns = self.config.get('coordinate_patterns', [
            r'lat[itude]*["\s]*[:=]\s*([+-]?\d+\.?\d*)',
            r'lon[gitude]*["\s]*[:=]\s*([+-]?\d+\.?\d*)',
            r'latitude["\s]*[:=]\s*([+-]?\d+\.?\d*)',
            r'longitude["\s]*[:=]\s*([+-]?\d+\.?\d*)',
            r'GPS["\s]*[:=]\s*([+-]?\d+\.?\d*)[,\s]+([+-]?\d+\.?\d*)',
            r'coordinates["\s]*[:=]\s*\[?\s*([+-]?\d+\.?\d*)[,\s]+([+-]?\d+\.?\d*)',
        ])

    def extract_coordinates_from_payload(self, payload):
        """Extrae coordenadas de texto plano en el payload"""
        if not self.enabled:
            return None

        try:
            payload_str = payload.decode('utf-8', errors='ignore')

            coordinates = {}

            # Buscar patrones de coordenadas
            for pattern in self.lat_lon_patterns:
                matches = re.findall(pattern, payload_str, re.IGNORECASE)
                if matches:
                    if len(matches[0]) == 2:  # GPS pattern with lat,lon
                        coordinates['latitude'] = float(matches[0][0])
                        coordinates['longitude'] = float(matches[0][1])
                    else:
                        # Determine if it's lat or lon based on pattern
                        if 'lat' in pattern.lower():
                            coordinates['latitude'] = float(matches[0])
                        elif 'lon' in pattern.lower():
                            coordinates['longitude'] = float(matches[0])

            if len(coordinates) >= 2:
                # Verificar precisión mínima
                if (abs(coordinates['latitude']) >= self.min_precision and
                        abs(coordinates['longitude']) >= self.min_precision):
                    return coordinates

            return None

        except Exception:
            return None

    def check_json_coordinates(self, payload):
        """Busca coordenadas en JSON"""
        if not self.enabled or not self.json_detection:
            return None

        try:
            payload_str = payload.decode('utf-8', errors='ignore')

            # Try to parse as JSON
            try:
                data = json.loads(payload_str)
                coords = self.extract_json_coords(data)
                if coords:
                    return coords
            except json.JSONDecodeError:
                pass

            # Try partial JSON patterns
            json_patterns = [
                r'"lat":\s*([+-]?\d+\.?\d*)',
                r'"lng":\s*([+-]?\d+\.?\d*)',
                r'"latitude":\s*([+-]?\d+\.?\d*)',
                r'"longitude":\s*([+-]?\d+\.?\d*)',
            ]

            coords = {}
            for pattern in json_patterns:
                matches = re.findall(pattern, payload_str, re.IGNORECASE)
                if matches:
                    value = float(matches[0])
                    if 'lat' in pattern:
                        coords['latitude'] = value
                    elif 'lng' in pattern or 'lon' in pattern:
                        coords['longitude'] = value

            if len(coords) >= 2:
                # Verificar precisión mínima
                if (abs(coords['latitude']) >= self.min_precision and
                        abs(coords['longitude']) >= self.min_precision):
                    return coords

        except Exception:
            pass
        return None

    def extract_json_coords(self, data):
        """Extrae coordenadas recursivamente de estructuras JSON"""
        if isinstance(data, dict):
            # Check common coordinate keys
            lat_keys = ['lat', 'latitude', 'Lat', 'Latitude']
            lon_keys = ['lng', 'lon', 'longitude', 'Lng', 'Lon', 'Longitude']

            lat, lon = None, None

            for key in lat_keys:
                if key in data and isinstance(data[key], (int, float)):
                    lat = data[key]
                    break

            for key in lon_keys:
                if key in data and isinstance(data[key], (int, float)):
                    lon = data[key]
                    break

            if lat is not None and lon is not None:
                # Verificar precisión mínima
                if abs(lat) >= self.min_precision and abs(lon) >= self.min_precision:
                    return {'latitude': lat, 'longitude': lon}

            # Recursive search
            for key, value in data.items():
                result = self.extract_json_coords(value)
                if result:
                    return result

        elif isinstance(data, list):
            for item in data:
                result = self.extract_json_coords(item)
                if result:
                    return result

        return None

    def check_binary_coordinates(self, payload):
        """Busca coordenadas en formatos binarios"""
        if not self.enabled or not self.binary_detection:
            return None

        try:
            # IEEE 754 double precision (8 bytes)
            if len(payload) >= 16:
                for i in range(len(payload) - 15):
                    try:
                        lat = struct.unpack('d', payload[i:i + 8])[0]
                        lon = struct.unpack('d', payload[i + 8:i + 16])[0]

                        # Validate coordinate ranges
                        if (-90 <= lat <= 90) and (-180 <= lon <= 180):
                            if abs(lat) >= self.min_precision and abs(lon) >= self.min_precision:
                                return {'latitude': lat, 'longitude': lon}
                    except struct.error:
                        continue

        except Exception:
            pass
        return None

    def analyze_packet(self, packet):
        """Analiza un paquete buscando coordenadas GPS"""
        if not self.enabled:
            return None

        # Extract payload
        payload = None
        if Raw in packet:
            payload = packet[Raw].load
        elif TCP in packet and packet[TCP].payload:
            payload = bytes(packet[TCP].payload)
        elif UDP in packet and packet[UDP].payload:
            payload = bytes(packet[UDP].payload)

        if not payload:
            return None

        # Check different coordinate extraction methods
        methods = [
            self.check_json_coordinates,
            self.extract_coordinates_from_payload,
            self.check_binary_coordinates,
        ]

        for method_func in methods:
            coords = method_func(payload)
            if coords:
                return coords

        return None


class GeoIPEnricher:
    """Enriquecedor geográfico configurado desde JSON"""

    def __init__(self, geo_config: Dict = None):
        """Inicializar enricher con configuración"""
        self.config = geo_config or {}

        # Configuración desde JSON
        self.geoip_db_path = self.config.get('geoip_db_path')
        self.cache_ttl = self.config.get('geo_cache_ttl', 3600)
        self.cache_max_size = self.config.get('cache_max_size', 10000)

        # Coordenadas fallback desde configuración
        fallback = self.config.get('fallback_coordinates', {})
        self.fallback_lat = fallback.get('latitude', 0.0)
        self.fallback_lon = fallback.get('longitude', 0.0)

        self.reader = None
        self.enabled = False
        self.geo_cache = {}

        # Inicializar GeoIP si está disponible y configurado
        if GEOIP_AVAILABLE and self.geoip_db_path and os.path.exists(self.geoip_db_path):
            try:
                self.reader = geoip2.database.Reader(self.geoip_db_path)
                self.enabled = True
                logger.info(f"🌍 Base de datos GeoIP cargada: {self.geoip_db_path}")
            except Exception as e:
                logger.warning(f"⚠️  Error cargando GeoIP: {e}")
        else:
            if self.geoip_db_path:
                logger.warning(f"⚠️  Base de datos GeoIP no encontrada: {self.geoip_db_path}")
            else:
                logger.warning("⚠️  GeoIP no configurado")

    def get_geolocation(self, packet, ip_address: str) -> Tuple[float, float, str]:
        """
        Obtener geolocalización híbrida: GPS en paquete + fallback GeoIP
        Retorna: (latitude, longitude, source)
        """

        # Verificar caché primero
        if ip_address in self.geo_cache:
            cache_entry = self.geo_cache[ip_address]
            if time.time() - cache_entry['timestamp'] < self.cache_ttl:
                return cache_entry['lat'], cache_entry['lon'], cache_entry['source']

        # Usar GPS detector integrado si está disponible
        if hasattr(self, 'gps_detector') and self.gps_detector:
            coords = self.gps_detector.analyze_packet(packet)
            if coords:
                lat = coords['latitude']
                lon = coords['longitude']
                source = "packet-gps"

                # Guardar en caché
                self._cache_geolocation(ip_address, lat, lon, source)
                return lat, lon, source

        # Fallback a base de datos GeoIP
        if self.enabled and ip_address not in ['127.0.0.1', '::1']:
            try:
                response = self.reader.city(ip_address)

                lat = float(response.location.latitude or self.fallback_lat)
                lon = float(response.location.longitude or self.fallback_lon)
                source = "geoip-database"

                # Guardar en caché
                self._cache_geolocation(ip_address, lat, lon, source)
                return lat, lon, source

            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"🌍 IP no encontrada en GeoIP: {ip_address}")
            except Exception as e:
                logger.debug(f"🌍 Error en lookup GeoIP para {ip_address}: {e}")

        # Fallback a coordenadas configuradas
        return self.fallback_lat, self.fallback_lon, "fallback"

    def _cache_geolocation(self, ip_address: str, lat: float, lon: float, source: str):
        """Guardar geolocalización en caché"""
        # Limpiar caché si está lleno
        if len(self.geo_cache) >= self.cache_max_size:
            oldest_entries = sorted(
                self.geo_cache.items(),
                key=lambda x: x[1]['timestamp']
            )[:self.cache_max_size // 2]

            for ip, _ in oldest_entries:
                del self.geo_cache[ip]

        self.geo_cache[ip_address] = {
            'lat': lat,
            'lon': lon,
            'source': source,
            'timestamp': time.time()
        }

    def close(self):
        """Cerrar recursos"""
        if self.reader:
            self.reader.close()


class EnhancedPromiscuousAgent:
    """
    Agente promiscuo configurado completamente desde JSON
    TIMESTAMP CORREGIDO - Eliminará todos los errores de parsing
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
        self.zmq_port = self.config['network']['zmq_port']
        self.zmq_host = self.config['network']['zmq_host']
        self.interface = self.config['network']['interface']
        self.promiscuous_mode = self.config['network']['promiscuous_mode']
        self.packet_filter = self.config['network']['packet_filter']
        self.max_packet_size = self.config['network']['max_packet_size']
        self.batch_size = self.config['network']['batch_size']
        self.send_timeout = self.config['network']['send_timeout']

        # Configuración de captura desde JSON
        self.capture_config = self.config.get('capture_settings', {})
        self.buffer_size = self.capture_config.get('buffer_size', 1000000)
        self.exclude_loopback = self.capture_config.get('exclude_loopback', False)

        # Configuración de filtrado desde JSON
        self.filtering_config = self.config.get('filtering', {})
        self.exclude_local = self.filtering_config.get('exclude_local_traffic', False)
        self.min_packet_size = self.filtering_config.get('min_packet_size', 0)
        self.max_packet_size_filter = self.filtering_config.get('max_packet_size', 65535)
        self.allowed_protocols = self.filtering_config.get('protocols', ['TCP', 'UDP', 'ICMP'])
        self.exclude_ports = set(self.filtering_config.get('exclude_ports', []))
        self.include_ports = set(self.filtering_config.get('include_ports', []))

        # Configuración de performance desde JSON
        self.performance_config = self.config.get('performance', {})
        self.max_packets_per_second = self.performance_config.get('max_packets_per_second', 1000)
        self.max_memory_usage = self.performance_config.get('max_memory_usage_mb', 512)

        # Inicializar componentes
        self.zmq_context = None
        self.zmq_socket = None
        self.running = False

        # Componentes de detección configurados desde JSON
        self.system_detector = SimpleSystemDetector(self.config.get('system_detection', {}))
        self.geo_detector = GeoDetector(self.config.get('gps_detection', {}))
        self.geoip_enricher = GeoIPEnricher(self.config.get('geolocation', {}))

        # Conectar GPS detector al GeoIP enricher
        self.geoip_enricher.gps_detector = self.geo_detector

        # Configuración de handshake desde JSON
        self.handshake_config = self.config.get('system_detection', {})
        self.send_handshake = self.handshake_config.get('send_handshake', True)
        self.handshake_interval = self.handshake_config.get('handshake_interval', 300)

        # Estadísticas
        self.stats = {
            'packets_captured': 0,
            'packets_with_gps': 0,
            'packets_with_geoip': 0,
            'packets_sent': 0,
            'packets_filtered': 0,
            'handshakes_sent': 0,
            'errors': 0,
            'start_time': time.time(),
            'last_handshake': 0
        }

        # Rate limiting
        self.packet_times = deque(maxlen=100)

        # Caché de geolocalización
        self.geo_cache = {}

        # Inicializar servicios
        self._init_zmq()

        self.so_identifier = self.system_detector.get_so_identifier()

        logger.info(f"🚀 Enhanced Promiscuous Agent inicializado desde JSON config")
        logger.info(f"Config file: {config_file or 'default config'}")
        logger.info(f"Agent ID: {self.agent_id}")
        logger.info(f"🖥️  SO detectado: {self.so_identifier}")
        logger.info(f"📡 ZMQ: {self.zmq_host}:{self.zmq_port}")
        logger.info(f"🔍 Interface: {self.interface}")
        logger.info(f"🎯 GPS detection: {self.geo_detector.enabled}")
        logger.info(f"🌍 GeoIP: {self.geoip_enricher.enabled}")
        logger.info(f"🤝 Handshake: {self.send_handshake}")

    def _load_config(self, config_file):
        """Cargar configuración desde archivo JSON"""
        default_config = {
            "agent_info": {
                "name": "enhanced_promiscuous_agent",
                "version": "1.0.0",
                "description": "Agente promiscuo con detección GPS y geolocalización"
            },
            "network": {
                "zmq_port": 5559,
                "zmq_host": "localhost",
                "interface": "any",
                "promiscuous_mode": True,
                "packet_filter": "",
                "max_packet_size": 65535,
                "batch_size": 100,
                "send_timeout": 1000
            },
            "capture_settings": {
                "buffer_size": 1000000,
                "enable_packet_reassembly": False,
                "capture_all_interfaces": True,
                "exclude_loopback": False,
                "capture_wireless": True
            },
            "gps_detection": {
                "enabled": True,
                "coordinate_patterns": [
                    "lat[itude]*[\"\\s]*[:=]\\s*([+-]?\\d+\\.?\\d*)",
                    "lon[gitude]*[\"\\s]*[:=]\\s*([+-]?\\d+\\.?\\d*)",
                    "GPS[\"\\s]*[:=]\\s*([+-]?\\d+\\.?\\d*)[,\\s]+([+-]?\\d+\\.?\\d*)",
                    "coordinates[\"\\s]*[:=]\\s*\\[?\\s*([+-]?\\d+\\.?\\d*)[,\\s]+([+-]?\\d+\\.?\\d*)"
                ],
                "binary_detection": True,
                "json_detection": True,
                "min_coordinate_precision": 0.001
            },
            "geolocation": {
                "geoip_db_path": "GeoLite2-City.mmdb",
                "geo_cache_ttl": 3600,
                "cache_max_size": 10000,
                "fallback_coordinates": {
                    "latitude": 0.0,
                    "longitude": 0.0
                }
            },
            "system_detection": {
                "detect_firewall": True,
                "detect_os": True,
                "send_handshake": True,
                "handshake_interval": 300,
                "include_hardware_info": False
            },
            "filtering": {
                "exclude_local_traffic": False,
                "exclude_broadcast": False,
                "min_packet_size": 0,
                "max_packet_size": 65535,
                "protocols": ["TCP", "UDP", "ICMP"],
                "exclude_ports": [],
                "include_ports": []
            },
            "performance": {
                "max_packets_per_second": 1000,
                "max_memory_usage_mb": 512,
                "processing_threads": 1,
                "enable_async_processing": False
            },
            "logging": {
                "level": "INFO",
                "file": "logs/promiscuous_agent.log",
                "max_size_mb": 100,
                "backup_count": 5,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "console_output": True,
                "log_packets": False,
                "log_gps_detections": True
            },
            "security": {
                "require_root": True,
                "validate_permissions": True,
                "secure_mode": True
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
                maxBytes=log_config.get('max_size_mb', 100) * 1024 * 1024,
                backupCount=log_config.get('backup_count', 5)
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    def _init_zmq(self):
        """Inicializar conexión ZeroMQ usando configuración"""
        try:
            self.zmq_context = zmq.Context()
            self.zmq_socket = self.zmq_context.socket(zmq.PUB)

            zmq_address = f"tcp://*:{self.zmq_port}"
            self.zmq_socket.bind(zmq_address)
            self.zmq_socket.setsockopt(zmq.SNDTIMEO, self.send_timeout)

            # Dar tiempo para que ZMQ se establezca
            time.sleep(0.1)

            logger.info(f"🔌 ZeroMQ Publisher vinculado a {zmq_address}")

        except Exception as e:
            logger.error(f"❌ Error inicializando ZeroMQ: {e}")
            raise

    def _should_filter_packet(self, packet) -> bool:
        """Determina si un paquete debe ser filtrado basado en configuración"""

        # Filtro por tamaño
        packet_size = len(packet)
        if packet_size < self.min_packet_size or packet_size > self.max_packet_size_filter:
            return True

        # Filtro por protocolo
        if IP in packet:
            # Filtro de tráfico local
            if self.exclude_local:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if (src_ip.startswith('127.') or dst_ip.startswith('127.') or
                        src_ip.startswith('192.168.') or dst_ip.startswith('192.168.') or
                        src_ip.startswith('10.') or dst_ip.startswith('10.')):
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
                protocol = 'TCP'
            elif UDP in packet:
                protocol = 'UDP'
            elif ICMP in packet:
                protocol = 'ICMP'

            if protocol and protocol not in self.allowed_protocols:
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

    def create_enhanced_network_event(self, packet) -> 'NetworkEvent':
        """
        Crear evento usando el protobuf configurado
        TIMESTAMP CORREGIDO: usa segundos Unix estándar
        """

        if not EXTENDED_PROTOBUF:
            logger.warning("Protobuf extendido no disponible")
            return None

        # Crear evento
        event = network_event_extended_fixed_pb2.NetworkEvent()

        # Campos básicos
        event.event_id = str(uuid.uuid4())
        event.timestamp = int(time.time())  # TIMESTAMP CORREGIDO: segundos Unix
        event.agent_id = self.agent_id

        # Información de red
        if IP in packet:
            event.source_ip = packet[IP].src
            event.target_ip = packet[IP].dst

            # Geolocalización usando configuración
            src_lat, src_lon, src_source = self.geoip_enricher.get_geolocation(packet, packet[IP].src)
            event.latitude = src_lat
            event.longitude = src_lon

            # Actualizar estadísticas según fuente
            if src_source == "packet-gps":
                self.stats['packets_with_gps'] += 1
                if self.config['logging'].get('log_gps_detections', True):
                    logger.debug(f"🎯 GPS detectado: {packet[IP].src} -> {src_lat}, {src_lon}")
            elif src_source == "geoip-database":
                self.stats['packets_with_geoip'] += 1

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

        # Campos adicionales
        event.packet_size = len(packet)
        event.event_type = "network_capture"
        event.anomaly_score = 0.0
        event.risk_score = 0.0
        event.description = f"Packet captured from {event.source_ip} to {event.target_ip}"

        # CAMPOS EXTENDIDOS - información del sistema
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
        """Enviar evento via ZeroMQ usando protobuf configurado"""
        try:
            # Enviar como protobuf binario
            data = event.SerializeToString()

            # Envío simple - sin topic para compatibilidad
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

            # Crear evento de red con geolocalización e información para handshake
            event = self.create_enhanced_network_event(packet)
            if not event:
                return

            # Enviar via ZeroMQ
            self.send_event(event)

            # Log periódico de estadísticas si está configurado
            if (self.stats['packets_captured'] % 100 == 0 and
                    self.config['logging'].get('log_packets', False)):
                self._log_stats()

            # Enviar handshake periódico
            self.send_periodic_handshake()

        except Exception as e:
            logger.error(f"❌ Error procesando paquete: {e}")
            self.stats['errors'] += 1

    def _log_stats(self):
        """Log de estadísticas del agente"""
        stats = self.stats
        gps_rate = (stats['packets_with_gps'] / max(stats['packets_captured'], 1)) * 100
        geoip_rate = (stats['packets_with_geoip'] / max(stats['packets_captured'], 1)) * 100
        filter_rate = (stats['packets_filtered'] / max(stats['packets_captured'] + stats['packets_filtered'], 1)) * 100

        logger.info(
            f"📊 Stats: {stats['packets_captured']} capturados, "
            f"{stats['packets_sent']} enviados, "
            f"{stats['packets_filtered']} filtrados ({filter_rate:.1f}%), "
            f"{gps_rate:.1f}% con GPS, "
            f"{geoip_rate:.1f}% con GeoIP, "
            f"{stats['handshakes_sent']} handshakes, "
            f"{stats['errors']} errores"
        )

    def start(self):
        """Iniciar captura de paquetes usando configuración completa"""
        if not self.zmq_socket:
            raise RuntimeError("ZeroMQ no inicializado")

        # Verificar permisos si está configurado
        if self.config['security']['require_root'] and os.geteuid() != 0:
            logger.error("❌ Se requieren privilegios de root para captura promiscua")
            logger.info("💡 Ejecutar con: sudo python promiscuous_agent.py")
            raise PermissionError("Root privileges required")

        self.running = True

        print(f"\n🎯 Enhanced Promiscuous Agent Started (JSON CONFIG)")
        print(f"📄 Config: {self.config_file or 'default'}")
        print(f"🔌 ZMQ: {self.zmq_host}:{self.zmq_port}")
        print(f"📡 Interface: {self.interface}")
        print(f"🔍 Filter: {self.packet_filter or 'None'}")
        print(f"📍 GPS detection: {'✅ Enabled' if self.geo_detector.enabled else '❌ Disabled'}")
        print(f"🌍 GeoIP: {'✅ Enabled' if self.geoip_enricher.enabled else '❌ Disabled'}")
        print(f"🤝 Handshake: {'✅ Enabled' if self.send_handshake else '❌ Disabled'}")
        print(f"🔒 Promiscuous: {'✅ Enabled' if self.promiscuous_mode else '❌ Disabled'}")
        print(f"⚡ Performance: max {self.max_packets_per_second} pps, {self.max_memory_usage}MB")
        print(f"🎯 Filtering: {len(self.allowed_protocols)} protocols, exclude {len(self.exclude_ports)} ports")
        print(f"📦 Protobuf: {'✅ Available' if EXTENDED_PROTOBUF else '❌ Not available'}")
        print(f"🔧 Timestamp: ✅ CORREGIDO (eliminará errores de parsing en ML detector)")
        print("=" * 70)

        try:
            # Configurar parámetros de captura desde JSON
            capture_kwargs = {
                'iface': self.interface if self.interface != 'any' else None,
                'prn': self.packet_handler,
                'store': 0,
                'stop_filter': lambda x: not self.running
            }

            # Filtro BPF si está configurado
            if self.packet_filter:
                capture_kwargs['filter'] = self.packet_filter
                logger.info(f"🔍 Filtro BPF aplicado: {self.packet_filter}")

            # Configuración adicional de captura
            if hasattr(conf, 'bufsize'):
                conf.bufsize = self.buffer_size

            logger.info(f"🎯 Iniciando captura en interfaz: {self.interface}")
            logger.info(f"📍 Geolocalización: GPS en paquetes + GeoIP fallback")
            logger.info(f"🔧 TIMESTAMP CORREGIDO: Eliminará errores de parsing en ML detector")

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
        if self.geoip_enricher:
            self.geoip_enricher.close()

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
            'packets_with_gps': self.stats['packets_with_gps'],
            'packets_with_geoip': self.stats['packets_with_geoip'],
            'handshakes_sent': self.stats['handshakes_sent'],
            'errors': self.stats['errors'],
            'agent_id': self.agent_id,
            'so_identifier': self.so_identifier,
            'config_file': self.config_file,
            'configuration': {
                'zmq_port': self.zmq_port,
                'interface': self.interface,
                'gps_detection': self.geo_detector.enabled,
                'geoip_enabled': self.geoip_enricher.enabled,
                'handshake_enabled': self.send_handshake,
                'promiscuous_mode': self.promiscuous_mode,
                'max_pps': self.max_packets_per_second,
                'filtering_enabled': len(self.exclude_ports) > 0 or len(self.include_ports) > 0
            }
        }


def main():
    """Función principal con configuración JSON completa"""
    import signal

    parser = argparse.ArgumentParser(description='Enhanced Promiscuous Agent (JSON Config)')
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
            print("✅ Configuración JSON válida para promiscuous agent")
            stats = agent.get_statistics()
            print(f"📡 ZMQ Port: {stats['configuration']['zmq_port']}")
            print(f"🔍 Interface: {stats['configuration']['interface']}")
            print(f"🎯 GPS Detection: {'✅' if stats['configuration']['gps_detection'] else '❌'}")
            print(f"🌍 GeoIP: {'✅' if stats['configuration']['geoip_enabled'] else '❌'}")
            print(f"🤝 Handshake: {'✅' if stats['configuration']['handshake_enabled'] else '❌'}")
            return 0

        logger.info("🚀 Iniciando Enhanced Promiscuous Agent (JSON CONFIG)...")
        logger.info("📍 Usando protobuf extendido: network_event_extended_fixed_pb2")
        logger.info("🎯 Detectando GPS en paquetes + fallback GeoIP configurado")
        logger.info("🔧 TIMESTAMP CORREGIDO - Eliminará errores de parsing")
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
            print(f"\n📊 Estadísticas Finales (JSON CONFIG):")
            print(f"   ⏱️  Uptime: {stats['uptime_seconds']:.1f}s")
            print(f"   📦 Packets captured: {stats['packets_captured']}")
            print(f"   📤 Packets sent: {stats['packets_sent']}")
            print(f"   🔍 Packets filtered: {stats['packets_filtered']}")
            print(f"   🎯 GPS detections: {stats['packets_with_gps']}")
            print(f"   🌍 GeoIP lookups: {stats['packets_with_geoip']}")
            print(f"   🤝 Handshakes sent: {stats['handshakes_sent']}")
            print(f"   ❌ Errors: {stats['errors']}")
            print(f"   📄 Config: {stats['config_file'] or 'default'}")

            agent.stop()

    return 0


if __name__ == "__main__":
    # Verificar que se ejecuta con privilegios suficientes
    if os.geteuid() != 0:
        print("⚠️  ADVERTENCIA: Se recomienda ejecutar como root para captura promiscua")
        print("💡 Ejecutar: sudo python promiscuous_agent.py enhanced_agent_config.json")

    sys.exit(main())