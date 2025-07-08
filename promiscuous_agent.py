#!/usr/bin/env python3
"""
Enhanced Promiscuous Agent - TIMESTAMP CORREGIDO
Corregido el problema de timestamp que causaba errores de parsing
"""

import json

# Messaging and serialization
import zmq
# Network and packet capture
from scapy.all import *

try:
    from src.protocols.protobuf import network_event_extended_fixed_pb2 as network_event_extended_pb2
    EXTENDED_PROTOBUF = True
except ImportError:
    from src.protocols.protobuf import network_event_pb2
    EXTENDED_PROTOBUF = False
# Geolocation
try:
    import geoip2.database
    import geoip2.errors

    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("⚠️  GeoIP2 no disponible. Instalar con: pip install geoip2")


# Detector de coordenadas GPS (implementación simplificada integrada)
import re
import struct

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('promiscuous_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

import platform
import subprocess
import shutil
import socket
import uuid


# ====== AÑADIR ESTA CLASE A TU ARCHIVO ======
class SystemDetector:
    """Detector ligero de SO y firewall para integrar en tu agente existente"""

    def __init__(self):
        self._so_identifier = None
        self._node_info = None
        self._is_first_event = True

    def get_so_identifier(self) -> str:
        """Retorna identificador único del SO y firewall"""
        if self._so_identifier is None:
            self._so_identifier = self._detect_so_identifier()
        return self._so_identifier

    def _detect_so_identifier(self) -> str:
        """Detecta SO y firewall, retorna identificador compacto"""
        os_name = platform.system().lower()

        if os_name == "linux":
            firewall = self._detect_linux_firewall()
            return f"linux_{firewall}"
        elif os_name == "windows":
            return "windows_firewall"
        elif os_name == "darwin":
            return "darwin_pf"
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

                if os_name == "linux":
                    firewall_status = self._get_linux_firewall_status()
                elif os_name == "windows":
                    firewall_status = self._get_windows_firewall_status()
                elif os_name == "darwin":
                    firewall_status = self._get_macos_firewall_status()

                self._node_info = {
                    'node_hostname': socket.gethostname(),
                    'os_version': f"{platform.system()} {platform.release()}",
                    'firewall_status': firewall_status,
                    'agent_version': '1.0.0'  # Tu versión actual
                }
            except Exception as e:
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

class GeoDetector:
    """Detector simplificado de coordenadas GPS en paquetes"""

    def __init__(self):
        # Patrones de coordenadas en texto plano
        self.lat_lon_patterns = [
            r'lat[itude]*["\s]*[:=]\s*([+-]?\d+\.?\d*)',
            r'lon[gitude]*["\s]*[:=]\s*([+-]?\d+\.?\d*)',
            r'latitude["\s]*[:=]\s*([+-]?\d+\.?\d*)',
            r'longitude["\s]*[:=]\s*([+-]?\d+\.?\d*)',
            r'GPS["\s]*[:=]\s*([+-]?\d+\.?\d*)[,\s]+([+-]?\d+\.?\d*)',
            r'coordinates["\s]*[:=]\s*\[?\s*([+-]?\d+\.?\d*)[,\s]+([+-]?\d+\.?\d*)',
        ]

    def extract_coordinates_from_payload(self, payload):
        """Extrae coordenadas de texto plano en el payload"""
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

            return coordinates if len(coordinates) >= 2 else None

        except Exception:
            return None

    def check_json_coordinates(self, payload):
        """Busca coordenadas en JSON"""
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
        try:
            # IEEE 754 double precision (8 bytes)
            if len(payload) >= 16:
                for i in range(len(payload) - 15):
                    try:
                        lat = struct.unpack('d', payload[i:i + 8])[0]
                        lon = struct.unpack('d', payload[i + 8:i + 16])[0]

                        # Validate coordinate ranges
                        if (-90 <= lat <= 90) and (-180 <= lon <= 180):
                            if abs(lat) > 0.001 or abs(lon) > 0.001:
                                return {'latitude': lat, 'longitude': lon}
                    except struct.error:
                        continue

        except Exception:
            pass
        return None

    def analyze_packet(self, packet):
        """Analiza un paquete buscando coordenadas GPS"""
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


class EnhancedPromiscuousAgent:
    """
    Agente promiscuo adaptado para usar el protobuf existente de upgraded-happiness
    TIMESTAMP CORREGIDO - Eliminará todos los errores de parsing
    """

    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.agent_id = f"agent_{socket.gethostname()}_{int(time.time())}"
        self.hostname = socket.gethostname()

        # Inicializar componentes
        self.zmq_context = None
        self.zmq_socket = None
        self.geo_detector = GeoDetector()
        self.geoip_reader = None
        self.running = False
        self.stats = {
            'packets_captured': 0,
            'packets_with_gps': 0,
            'packets_with_geoip': 0,
            'packets_sent': 0,
            'errors': 0
        }

        # Caché de geolocalización
        self.geo_cache = {}
        self.cache_max_size = 10000

        # Inicializar servicios
        self._init_zmq()
        self._init_geoip()

        self.system_detector = SystemDetector()
        self.so_identifier = self.system_detector.get_so_identifier()
        print(f"🖥️  SO detectado: {self.so_identifier}")

        logger.info(f"🚀 Enhanced Promiscuous Agent iniciado - ID: {self.agent_id}")

    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Cargar configuración del agente"""
        default_config = {
            'zmq_port': 5559,
            'zmq_host': 'localhost',
            'interface': 'any',
            'promiscuous_mode': True,
            'packet_filter': '',
            'geoip_db_path': 'GeoLite2-City.mmdb',
            'max_packet_size': 65535,
            'geo_cache_ttl': 3600,
            'batch_size': 100,
        }

        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
                logger.info(f"📄 Configuración cargada desde {config_file}")
            except Exception as e:
                logger.warning(f"⚠️  Error cargando configuración: {e}")

        return default_config

    def _init_zmq(self):
        """Inicializar conexión ZeroMQ"""
        try:
            self.zmq_context = zmq.Context()
            self.zmq_socket = self.zmq_context.socket(zmq.PUB)
            zmq_address = f"tcp://*:{self.config['zmq_port']}"
            self.zmq_socket.bind(zmq_address)

            # Dar tiempo para que ZMQ se establezca
            time.sleep(0.1)

            logger.info(f"🔌 ZeroMQ Publisher vinculado a {zmq_address}")

        except Exception as e:
            logger.error(f"❌ Error inicializando ZeroMQ: {e}")
            raise

    def _init_geoip(self):
        """Inicializar base de datos GeoIP"""
        if not GEOIP_AVAILABLE:
            logger.warning("⚠️  GeoIP no disponible - solo detección en paquetes")
            return

        geoip_path = self.config['geoip_db_path']

        if os.path.exists(geoip_path):
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_path)
                logger.info(f"🌍 Base de datos GeoIP cargada: {geoip_path}")
            except Exception as e:
                logger.warning(f"⚠️  Error cargando GeoIP: {e}")
        else:
            logger.warning(f"⚠️  Base de datos GeoIP no encontrada: {geoip_path}")

    def get_geolocation(self, packet, ip_address: str) -> Tuple[float, float, str]:
        """
        Obtener geolocalización híbrida: GPS en paquete + fallback GeoIP
        Retorna: (latitude, longitude, source)
        """

        # Verificar caché primero
        if ip_address in self.geo_cache:
            cache_entry = self.geo_cache[ip_address]
            if time.time() - cache_entry['timestamp'] < self.config['geo_cache_ttl']:
                return cache_entry['lat'], cache_entry['lon'], cache_entry['source']

        # 🎯 PASO 1: Detectar coordenadas GPS en el paquete
        try:
            coords = self.geo_detector.analyze_packet(packet)

            if coords:
                lat = coords['latitude']
                lon = coords['longitude']
                source = "packet-gps"

                self.stats['packets_with_gps'] += 1
                logger.debug(f"🎯 GPS detectado en paquete de {ip_address}: {lat}, {lon}")

                # Guardar en caché
                self._cache_geolocation(ip_address, lat, lon, source)
                return lat, lon, source

        except Exception as e:
            logger.debug(f"🔍 No se detectó GPS en paquete de {ip_address}: {e}")

        # 🔄 PASO 2: Fallback a base de datos GeoIP
        if self.geoip_reader and ip_address not in ['127.0.0.1', '::1']:
            try:
                response = self.geoip_reader.city(ip_address)

                lat = float(response.location.latitude or 0.0)
                lon = float(response.location.longitude or 0.0)
                source = "geoip-database"

                self.stats['packets_with_geoip'] += 1

                # Guardar en caché
                self._cache_geolocation(ip_address, lat, lon, source)
                return lat, lon, source

            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"🌍 IP no encontrada en GeoIP: {ip_address}")
            except Exception as e:
                logger.debug(f"🌍 Error en lookup GeoIP para {ip_address}: {e}")

        # 🚫 PASO 3: Fallback vacío
        return 0.0, 0.0, "unknown"

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

    def create_enhanced_network_event(self, packet) -> 'NetworkEvent':
        """
        Crear evento usando el protobuf disponible (extendido o original)
        """

        if EXTENDED_PROTOBUF:
            # Usar protobuf extendido
            event = network_event_extended_pb2.NetworkEvent()

            # Campos básicos
            event.event_id = str(uuid.uuid4())
            event.timestamp = int(time.time())  # Timestamp en segundos
            event.agent_id = self.agent_id

            # Información de red
            if IP in packet:
                event.source_ip = packet[IP].src
                event.target_ip = packet[IP].dst

                # Geolocalización
                src_lat, src_lon, src_source = self.get_geolocation(packet, packet[IP].src)
                event.latitude = src_lat
                event.longitude = src_lon

            # Puertos
            if TCP in packet:
                event.src_port = packet[TCP].sport
                event.dest_port = packet[TCP].dport
            elif UDP in packet:
                event.src_port = packet[UDP].sport
                event.dest_port = packet[UDP].dport

            # Campos adicionales
            event.packet_size = len(packet)
            event.event_type = "network_capture"
            event.anomaly_score = 0.0
            event.risk_score = 0.0
            event.description = f"Packet captured from {event.source_ip} to {event.target_ip}"

            # CAMPOS EXTENDIDOS - NUEVA FUNCIONALIDAD
            event.so_identifier = self.system_detector.get_so_identifier()

            # Solo en el primer evento, añadir información completa
            if self.system_detector.is_first_event():
                node_info = self.system_detector.get_node_info_for_handshake()
                event.is_initial_handshake = True
                event.node_hostname = node_info['node_hostname']
                event.os_version = node_info['os_version']
                event.firewall_status = node_info['firewall_status']
                event.agent_version = node_info['agent_version']

                print(f"📤 Enviando handshake inicial con SO: {event.so_identifier}")
            else:
                event.is_initial_handshake = False
                event.node_hostname = ""
                event.os_version = ""
                event.firewall_status = ""
                event.agent_version = ""

        else:
            # Fallback al protobuf original
            event = network_event_pb2.NetworkEvent()

            # Solo campos básicos disponibles
            event.event_id = str(uuid.uuid4())
            event.timestamp = int(time.time())
            event.agent_id = self.agent_id

            if IP in packet:
                event.source_ip = packet[IP].src
                event.target_ip = packet[IP].dst

                src_lat, src_lon, src_source = self.get_geolocation(packet, packet[IP].src)
                event.latitude = src_lat
                event.longitude = src_lon

            if TCP in packet:
                event.src_port = packet[TCP].sport
                event.dest_port = packet[TCP].dport
            elif UDP in packet:
                event.src_port = packet[UDP].sport
                event.dest_port = packet[UDP].dport

            event.packet_size = len(packet)
            event.event_type = "network_capture"
            event.anomaly_score = 0.0
            event.risk_score = 0.0
            event.description = f"Packet captured from {event.source_ip} to {event.target_ip}"

            print("⚠️  Usando protobuf network_event_extended_fixed.")

        self.stats['packets_captured'] += 1
        return event

    def send_event(self, event):
        """Enviar evento via ZeroMQ usando protobuf"""
        try:
            # Enviar como protobuf binario
            data = event.SerializeToString()

            # Envío simple - sin topic para compatibilidad
            self.zmq_socket.send(data)
            self.stats['packets_sent'] += 1

        except Exception as e:
            logger.error(f"❌ Error enviando evento: {e}")
            self.stats['errors'] += 1

    def packet_handler(self, packet):
        """Handler principal para procesar paquetes capturados"""
        try:
            # Crear evento de red con geolocalización e informacion para hacer un handshake
            event = self.create_enhanced_network_event(packet)
            # Enviar via ZeroMQ
            self.send_event(event)

            # Log periódico de estadísticas
            if self.stats['packets_captured'] % 100 == 0:
                self._log_stats()

        except Exception as e:
            logger.error(f"❌ Error procesando paquete: {e}")
            self.stats['errors'] += 1

    def _log_stats(self):
        """Log de estadísticas del agente"""
        stats = self.stats
        gps_rate = (stats['packets_with_gps'] / max(stats['packets_captured'], 1)) * 100
        geoip_rate = (stats['packets_with_geoip'] / max(stats['packets_captured'], 1)) * 100

        logger.info(
            f"📊 Stats: {stats['packets_captured']} capturados, "
            f"{stats['packets_sent']} enviados, "
            f"{gps_rate:.1f}% con GPS, "
            f"{geoip_rate:.1f}% con GeoIP, "
            f"{stats['errors']} errores"
        )

    def start(self):
        """Iniciar captura de paquetes"""
        if not self.zmq_socket:
            raise RuntimeError("ZeroMQ no inicializado")

        self.running = True
        interface = self.config['interface']
        packet_filter = self.config['packet_filter']

        logger.info(f"🎯 Iniciando captura promiscua en interfaz: {interface}")
        logger.info(f"🔌 Enviando eventos a ZeroMQ puerto: {self.config['zmq_port']}")
        logger.info(f"📍 Geolocalización: GPS en paquetes + GeoIP fallback")
        logger.info(f"🔧 TIMESTAMP CORREGIDO: Eliminará errores de parsing en ML detector")

        if packet_filter:
            logger.info(f"🔍 Filtro BPF aplicado: {packet_filter}")

        try:
            # Captura en modo promiscuo
            sniff(
                iface=interface if interface != 'any' else None,
                prn=self.packet_handler,
                filter=packet_filter if packet_filter else None,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            logger.error("❌ Error: Se requieren privilegios de root para captura promiscua")
            logger.info("💡 Ejecutar con: sudo python promiscuous_agent.py")
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
        if self.geoip_reader:
            self.geoip_reader.close()

        # Log final de estadísticas
        self._log_stats()
        logger.info(f"✅ Agente {self.agent_id} detenido correctamente")


def main():
    """Función principal"""
    import signal

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
        # Crear y iniciar agente
        config_file = sys.argv[1] if len(sys.argv) > 1 else None
        agent = EnhancedPromiscuousAgent(config_file)

        logger.info("🚀 Iniciando Enhanced Promiscuous Agent...")
        logger.info("📍 Usando protobuf existente: network_event_pb2.NetworkEvent")
        logger.info("🎯 Detectando GPS en paquetes + fallback GeoIP local")
        logger.info("🔧 TIMESTAMP CORREGIDO - Eliminará errores de parsing")
        logger.info("⚡ Presiona Ctrl+C para detener")

        agent.start()

    except KeyboardInterrupt:
        logger.info("🛑 Interrupción por teclado")
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        return 1
    finally:
        if agent:
            agent.stop()

    return 0


if __name__ == "__main__":
    # Verificar que se ejecuta con privilegios suficientes
    if os.geteuid() != 0:
        print("⚠️  ADVERTENCIA: Se recomienda ejecutar como root para captura promiscua")
        print("💡 Ejecutar: sudo python promiscuous_agent.py")

    sys.exit(main())