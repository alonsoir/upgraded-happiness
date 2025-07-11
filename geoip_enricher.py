#!/usr/bin/env python3
"""
GeoIP Enricher para Upgraded-Happiness
Componente dedicado EXCLUSIVAMENTE al enriquecimiento geográfico de eventos
Arquitectura: promiscuous_agent → geoip_enricher → ml_detector → dashboard

RESPONSABILIDAD ÚNICA: Enriquecer eventos con coordenadas geográficas
- Recibe eventos desde promiscuous_agent (puerto 5559)
- Enriquece con coordenadas (redes privadas + GeoIP)
- Envía eventos enriquecidos a ml_detector (puerto 5560)
"""

import zmq
import time
import json
import os
import sys
import logging
import threading
import ipaddress
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Configurar logging básico (se reconfigurará desde JSON)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Importar protobuf
try:
    from src.protocols.protobuf import network_event_extended_fixed_pb2

    PROTOBUF_AVAILABLE = True
    logger.info("✅ Protobuf network_event_extended_fixed_pb2 importado desde src.protocols.protobuf")
except ImportError:
    try:
        import network_event_extended_fixed_pb2

        PROTOBUF_AVAILABLE = True
        logger.info("✅ Protobuf network_event_extended_fixed_pb2 importado desde directorio local")
    except ImportError:
        PROTOBUF_AVAILABLE = False
        logger.error("❌ Protobuf no disponible")

# Importar GeoIP
try:
    import geoip2.database
    import geoip2.errors

    GEOIP_AVAILABLE = True
    logger.info("✅ GeoIP2 disponible")
except ImportError:
    GEOIP_AVAILABLE = False
    logger.warning("⚠️  GeoIP2 no disponible")


class PrivateNetworkMapper:
    """Mapea redes privadas a coordenadas específicas según configuración"""

    def __init__(self, private_mapping: Dict):
        """Inicializar mapper de redes privadas"""
        self.networks = {}

        # Convertir configuración a objetos de red
        for network_str, location in private_mapping.items():
            try:
                network = ipaddress.ip_network(network_str, strict=False)
                self.networks[network] = {
                    'lat': location['lat'],
                    'lon': location['lon'],
                    'city': location.get('city', 'Unknown'),
                    'country': location.get('country', 'XX'),
                    'region': location.get('region', 'Unknown')
                }
                logger.info(f"🏠 Red privada mapeada: {network_str} → {location.get('city', 'Unknown')}")
            except Exception as e:
                logger.error(f"❌ Error mapeando red {network_str}: {e}")

    def lookup_ip(self, ip_str: str) -> Optional[Dict]:
        """Busca IP en redes privadas configuradas"""
        try:
            ip = ipaddress.ip_address(ip_str)

            for network, location in self.networks.items():
                if ip in network:
                    logger.debug(f"🎯 IP {ip_str} encontrada en red privada {network}")
                    return location

            return None
        except Exception as e:
            logger.debug(f"Error en lookup privado para {ip_str}: {e}")
            return None


class GeoIPEnricher:
    """Enriquecedor GeoIP con cache y mapeo de redes privadas"""

    def __init__(self, config: Dict):
        """Inicializar GeoIP enricher desde configuración"""
        self.config = config
        self.reader = None
        self.enabled = config.get('enabled', True)

        # Cache configurado
        self.cache = {}
        self.cache_max_size = config.get('cache_size', 10000)
        self.cache_ttl = config.get('cache_ttl_seconds', 3600)

        # Mapper de redes privadas
        private_mapping = config.get('private_network_mapping', {})
        self.private_mapper = PrivateNetworkMapper(private_mapping)

        # Estadísticas
        self.stats = {
            'private_network_hits': 0,
            'geoip_hits': 0,
            'cache_hits': 0,
            'lookup_failures': 0
        }

        # Inicializar base de datos GeoIP
        if GEOIP_AVAILABLE and self.enabled:
            db_path = config.get('database_path')
            if db_path and os.path.exists(db_path):
                try:
                    self.reader = geoip2.database.Reader(db_path)
                    logger.info(f"🌍 GeoIP database cargada: {db_path}")
                except Exception as e:
                    logger.warning(f"⚠️  Error cargando GeoIP database: {e}")
                    self.enabled = False
            else:
                logger.warning(f"⚠️  GeoIP database no encontrada: {db_path}")
                self.enabled = False
        else:
            logger.warning("⚠️  GeoIP no disponible")
            self.enabled = False

    def enrich_ip(self, ip: str) -> Tuple[Optional[float], Optional[float], Optional[str]]:
        """
        Enriquece IP con coordenadas geográficas
        Returns: (latitude, longitude, city)
        Priority: Cache → Private Networks → GeoIP → None
        """
        if not ip or ip == 'unknown':
            return None, None, None

        # 1. Verificar cache
        cache_key = ip
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            if time.time() - cache_entry['timestamp'] < self.cache_ttl:
                self.stats['cache_hits'] += 1
                return cache_entry['lat'], cache_entry['lon'], cache_entry['city']

        # 2. Buscar en redes privadas (PRIORIDAD)
        private_result = self.private_mapper.lookup_ip(ip)
        if private_result:
            self.stats['private_network_hits'] += 1
            lat, lon, city = private_result['lat'], private_result['lon'], private_result['city']
            self._cache_result(ip, lat, lon, city)
            return lat, lon, city

        # 3. Buscar en GeoIP (fallback)
        if self.enabled and self.reader:
            try:
                response = self.reader.city(ip)
                latitude = float(response.location.latitude) if response.location.latitude else None
                longitude = float(response.location.longitude) if response.location.longitude else None
                city = str(response.city.name) if response.city.name else "Unknown"

                if latitude is not None and longitude is not None:
                    self.stats['geoip_hits'] += 1
                    self._cache_result(ip, latitude, longitude, city)
                    return latitude, longitude, city

            except geoip2.errors.AddressNotFoundError:
                pass  # IP no encontrada en GeoIP
            except Exception as e:
                logger.debug(f"Error GeoIP para {ip}: {e}")

        # 4. No encontrada
        self.stats['lookup_failures'] += 1
        self._cache_result(ip, None, None, None)
        return None, None, None

    def _cache_result(self, ip: str, lat: Optional[float], lon: Optional[float], city: Optional[str]):
        """Guarda resultado en cache con TTL"""
        # Limpiar cache si está lleno
        if len(self.cache) >= self.cache_max_size:
            # Eliminar entradas más antiguas
            oldest_entries = sorted(
                self.cache.items(),
                key=lambda x: x[1]['timestamp']
            )[:self.cache_max_size // 2]

            for old_ip, _ in oldest_entries:
                del self.cache[old_ip]

        self.cache[ip] = {
            'lat': lat,
            'lon': lon,
            'city': city,
            'timestamp': time.time()
        }

    def get_stats(self) -> Dict:
        """Retorna estadísticas del enricher"""
        return {
            'private_network_hits': self.stats['private_network_hits'],
            'geoip_hits': self.stats['geoip_hits'],
            'cache_hits': self.stats['cache_hits'],
            'lookup_failures': self.stats['lookup_failures'],
            'cache_size': len(self.cache),
            'cache_max_size': self.cache_max_size,
            'enabled': self.enabled
        }

    def close(self):
        """Cierra recursos"""
        if self.reader:
            self.reader.close()


class HealthCheckHandler(BaseHTTPRequestHandler):
    """Handler para health checks"""

    def __init__(self, enricher_service, *args, **kwargs):
        self.enricher_service = enricher_service
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Maneja peticiones GET para health check y métricas"""
        path = urlparse(self.path).path

        if path == '/health':
            self._handle_health()
        elif path == '/metrics':
            self._handle_metrics()
        else:
            self.send_error(404, "Not Found")

    def _handle_health(self):
        """Health check endpoint"""
        try:
            health_data = {
                'status': 'healthy',
                'timestamp': time.time(),
                'uptime_seconds': time.time() - self.enricher_service.stats['start_time'],
                'protobuf_available': PROTOBUF_AVAILABLE,
                'geoip_available': GEOIP_AVAILABLE
            }

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(health_data).encode())

        except Exception as e:
            self.send_error(500, f"Health check failed: {e}")

    def _handle_metrics(self):
        """Metrics endpoint (Prometheus compatible)"""
        try:
            stats = self.enricher_service.get_statistics()

            metrics = []
            for key, value in stats.items():
                if isinstance(value, (int, float)):
                    metrics.append(f'geoip_enricher_{key} {value}')

            response = '\n'.join(metrics) + '\n'

            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(response.encode())

        except Exception as e:
            self.send_error(500, f"Metrics collection failed: {e}")

    def log_message(self, format, *args):
        """Silenciar logs del servidor HTTP"""
        pass


class GeoIPEnricherService:
    """Servicio principal de enriquecimiento geográfico"""

    def __init__(self, config_file: str = None):
        """Inicializar servicio desde configuración JSON"""
        self.config = self._load_config(config_file)
        self.config_file = config_file

        # Configurar logging desde JSON
        self._setup_logging()

        # Configuración de red
        self.input_port = self.config['network']['input_port']
        self.output_port = self.config['network']['output_port']
        self.bind_address = self.config['network']['bind_address']
        self.socket_timeout = self.config['network']['socket_timeout']

        # Estado del servicio
        self.running = False

        # ZeroMQ setup
        zmq_threads = self.config['network']['zmq_context_threads']
        self.context = zmq.Context(zmq_threads)
        self.input_socket = None
        self.output_socket = None

        # GeoIP Enricher
        self.geoip_enricher = GeoIPEnricher(self.config.get('geoip', {}))

        # Estadísticas
        self.stats = {
            'events_processed': 0,
            'events_enriched': 0,
            'coordinates_preserved': 0,
            'coordinates_added': 0,
            'processing_errors': 0,
            'start_time': time.time()
        }

        # Health check server
        self.health_server = None
        if self.config.get('health_check', {}).get('enabled', True):
            self._setup_health_server()

        logger.info("🌍 GeoIP Enricher Service initialized")
        logger.info(f"📄 Config: {config_file or 'default'}")
        logger.info(f"📡 Input port: {self.input_port}")
        logger.info(f"📤 Output port: {self.output_port}")
        logger.info(f"🌍 GeoIP enabled: {self.geoip_enricher.enabled}")
        logger.info(f"📦 Protobuf available: {PROTOBUF_AVAILABLE}")

    def _load_config(self, config_file: str) -> Dict:
        """Cargar configuración desde archivo JSON con defaults"""
        default_config = {
            "agent_info": {
                "name": "geoip_enricher",
                "version": "1.0.0"
            },
            "network": {
                "input_port": 5559,
                "output_port": 5560,
                "bind_address": "*",
                "zmq_context_threads": 1,
                "socket_timeout": 3000,
                "high_water_mark": 1000,
                "linger": 0
            },
            "geoip": {
                "enabled": True,
                "database_path": "GeoLite2-City.mmdb",
                "cache_size": 10000,
                "cache_ttl_seconds": 3600,
                "private_network_mapping": {}
            },
            "processing": {
                "stats_interval_seconds": 60
            },
            "health_check": {
                "enabled": True,
                "port": 8080
            },
            "logging": {
                "level": "INFO",
                "console_output": True
            }
        }

        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                self._merge_config(default_config, user_config)
                logger.info(f"📄 Configuración cargada desde {config_file}")
            except Exception as e:
                logger.error(f"❌ Error cargando configuración: {e}")
                logger.info("⚠️  Usando configuración por defecto")
        else:
            if config_file:
                logger.warning(f"⚠️  Archivo de configuración no encontrado: {config_file}")
            logger.info("⚠️  Usando configuración por defecto")

        return default_config

    def _merge_config(self, base: Dict, update: Dict):
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

        # Formatter
        formatter = logging.Formatter(
            log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )

        # Console handler
        if log_config.get('console_output', True):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # File handler si se especifica
        if log_config.get('file'):
            log_file = log_config['file']
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=log_config.get('max_size_mb', 10) * 1024 * 1024,
                backupCount=log_config.get('backup_count', 5)
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    def _setup_health_server(self):
        """Configurar servidor de health checks"""
        try:
            health_config = self.config.get('health_check', {})
            port = health_config.get('port', 8080)

            def handler_factory(*args, **kwargs):
                return HealthCheckHandler(self, *args, **kwargs)

            self.health_server = HTTPServer(('', port), handler_factory)
            logger.info(f"🏥 Health check server configurado en puerto {port}")
        except Exception as e:
            logger.warning(f"⚠️  No se pudo configurar health check server: {e}")

    def start(self):
        """Iniciar el servicio de enriquecimiento"""
        try:
            # Configurar sockets ZeroMQ
            self.input_socket = self.context.socket(zmq.SUB)
            input_addr = f"tcp://localhost:{self.input_port}"
            self.input_socket.connect(input_addr)
            self.input_socket.setsockopt(zmq.SUBSCRIBE, b"")
            self.input_socket.setsockopt(zmq.RCVTIMEO, self.socket_timeout)

            self.output_socket = self.context.socket(zmq.PUB)
            output_addr = f"tcp://{self.bind_address}:{self.output_port}"
            self.output_socket.bind(output_addr)

            self.running = True

            print(f"\n🌍 GeoIP Enricher Service Started")
            print(f"📄 Config: {self.config_file or 'default'}")
            print(f"📡 Input: {input_addr} (from promiscuous_agent)")
            print(f"📤 Output: {output_addr} (to ml_detector)")
            print(f"🌍 GeoIP: {'✅ Enabled' if self.geoip_enricher.enabled else '❌ Disabled'}")
            print(f"📦 Protobuf: {'✅ Available' if PROTOBUF_AVAILABLE else '❌ Not available'}")
            print(f"🏥 Health check: {'✅ Enabled' if self.health_server else '❌ Disabled'}")
            print("=" * 70)

            # Thread de procesamiento principal
            processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
            processing_thread.start()

            # Thread de estadísticas
            stats_interval = self.config['processing']['stats_interval_seconds']
            stats_thread = threading.Thread(target=self._stats_loop, args=(stats_interval,), daemon=True)
            stats_thread.start()

            # Thread de health check server
            if self.health_server:
                health_thread = threading.Thread(target=self.health_server.serve_forever, daemon=True)
                health_thread.start()

            # Mantener servicio vivo
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 Stopping GeoIP Enricher...")
                self.running = False

        except Exception as e:
            logger.error(f"Error starting service: {e}")
            raise
        finally:
            self.cleanup()

    def _processing_loop(self):
        """Loop principal de procesamiento de eventos"""
        logger.info("🔄 Iniciando loop de procesamiento...")

        while self.running:
            try:
                # Recibir evento con timeout
                message = self.input_socket.recv(zmq.NOBLOCK)
                self.stats['events_processed'] += 1

                # Procesar evento
                enriched_event = self._process_event(message)

                if enriched_event:
                    # Enviar evento enriquecido
                    self.output_socket.send(enriched_event)
                    self.stats['events_enriched'] += 1

            except zmq.Again:
                continue  # Timeout - continuar
            except Exception as e:
                logger.error(f"Error en processing loop: {e}")
                self.stats['processing_errors'] += 1
                time.sleep(0.1)

    def _process_event(self, message: bytes) -> Optional[bytes]:
        """Procesa un evento individual - SOLO enriquecimiento geográfico"""

        if not PROTOBUF_AVAILABLE:
            logger.warning("Protobuf no disponible - no se puede procesar evento")
            return None

        try:
            # Parsear evento protobuf entrante
            event = network_event_extended_fixed_pb2.NetworkEvent()
            event.ParseFromString(message)

            # Crear evento enriquecido copiando TODA la información original
            enriched_event = network_event_extended_fixed_pb2.NetworkEvent()
            enriched_event.CopyFrom(event)

            # VERIFICAR si ya tiene coordenadas (no sobrescribir)
            has_coordinates = (
                    hasattr(event, 'latitude') and hasattr(event, 'longitude') and
                    event.latitude != 0 and event.longitude != 0
            )

            if has_coordinates:
                # Ya tiene coordenadas - preservar
                self.stats['coordinates_preserved'] += 1
                logger.debug(
                    f"🎯 Coordenadas preservadas para {event.source_ip}: {event.latitude:.4f}, {event.longitude:.4f}")
            else:
                # No tiene coordenadas - enriquecer
                if event.source_ip and event.source_ip != 'unknown':
                    latitude, longitude, city = self.geoip_enricher.enrich_ip(event.source_ip)

                    if latitude is not None and longitude is not None:
                        enriched_event.latitude = latitude
                        enriched_event.longitude = longitude
                        self.stats['coordinates_added'] += 1
                        logger.debug(
                            f"🌍 Coordenadas añadidas para {event.source_ip}: {latitude:.4f}, {longitude:.4f} ({city})")

            return enriched_event.SerializeToString()

        except Exception as e:
            logger.error(f"Error procesando evento: {e}")
            self.stats['processing_errors'] += 1
            return None

    def _stats_loop(self, interval: int):
        """Loop de estadísticas"""
        while self.running:
            try:
                time.sleep(interval)
                self._print_stats()
            except Exception as e:
                logger.error(f"Error en stats loop: {e}")

    def _print_stats(self):
        """Imprime estadísticas del servicio"""
        uptime = time.time() - self.stats['start_time']
        geoip_stats = self.geoip_enricher.get_stats()

        print(f"\n🌍 GeoIP Enricher Stats - Uptime: {uptime:.0f}s")
        print(f"📥 Events Processed: {self.stats['events_processed']}")
        print(f"📤 Events Enriched: {self.stats['events_enriched']}")
        print(f"🎯 Coordinates Preserved: {self.stats['coordinates_preserved']}")
        print(f"🌍 Coordinates Added: {self.stats['coordinates_added']}")
        print(f"🏠 Private Network Hits: {geoip_stats['private_network_hits']}")
        print(f"🌐 GeoIP Hits: {geoip_stats['geoip_hits']}")
        print(f"💾 Cache Hits: {geoip_stats['cache_hits']}")
        print(f"❌ Processing Errors: {self.stats['processing_errors']}")
        print(f"📄 Config: {self.config_file or 'default'}")
        print("-" * 50)

    def get_statistics(self) -> Dict:
        """Retorna estadísticas completas para health checks y métricas"""
        uptime = time.time() - self.stats['start_time']
        geoip_stats = self.geoip_enricher.get_stats()

        return {
            'uptime_seconds': uptime,
            'events_processed': self.stats['events_processed'],
            'events_enriched': self.stats['events_enriched'],
            'coordinates_preserved': self.stats['coordinates_preserved'],
            'coordinates_added': self.stats['coordinates_added'],
            'processing_errors': self.stats['processing_errors'],
            'private_network_hits': geoip_stats['private_network_hits'],
            'geoip_hits': geoip_stats['geoip_hits'],
            'cache_hits': geoip_stats['cache_hits'],
            'lookup_failures': geoip_stats['lookup_failures'],
            'cache_size': geoip_stats['cache_size'],
            'protobuf_available': PROTOBUF_AVAILABLE,
            'geoip_available': GEOIP_AVAILABLE,
            'geoip_enabled': geoip_stats['enabled'],
            'config_file': self.config_file,
            'configuration': {
                'input_port': self.input_port,
                'output_port': self.output_port
            }
        }

    def cleanup(self):
        """Limpia recursos del servicio"""
        logger.info("🧹 Cleaning up resources...")

        if self.health_server:
            self.health_server.shutdown()

        if self.input_socket:
            self.input_socket.close()
        if self.output_socket:
            self.output_socket.close()
        if self.context:
            self.context.term()
        if self.geoip_enricher:
            self.geoip_enricher.close()


def main():
    """Función principal"""
    import argparse

    parser = argparse.ArgumentParser(description='GeoIP Enricher Service')
    parser.add_argument('config_file', nargs='?',
                        default='geoip_enricher_config.json',
                        help='Archivo de configuración JSON')
    parser.add_argument('--test-config', action='store_true',
                        help='Validar configuración y salir')

    args = parser.parse_args()

    if args.test_config:
        try:
            service = GeoIPEnricherService(config_file=args.config_file)
            print("✅ Configuración válida")
            stats = service.get_statistics()
            print(f"📡 Input port: {stats['configuration']['input_port']}")
            print(f"📤 Output port: {stats['configuration']['output_port']}")
            print(f"🌍 GeoIP enabled: {stats['geoip_enabled']}")
            return 0
        except Exception as e:
            print(f"❌ Error en configuración: {e}")
            return 1

    if not PROTOBUF_AVAILABLE:
        print("❌ Error: Protobuf no disponible")
        print("📦 Instalar con: pip install protobuf")
        return 1

    try:
        service = GeoIPEnricherService(config_file=args.config_file)

        print(f"\n🌍 GeoIP Enricher Service iniciado:")
        stats = service.get_statistics()
        print(f"   📡 Input port: {stats['configuration']['input_port']}")
        print(f"   📤 Output port: {stats['configuration']['output_port']}")
        print(f"   🌍 GeoIP: {'✅' if stats['geoip_enabled'] else '❌'}")

        service.start()

    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        logger.error(f"Error fatal: {e}")
        return 1
    finally:
        if 'service' in locals():
            service._print_stats()

    return 0


if __name__ == "__main__":
    sys.exit(main())