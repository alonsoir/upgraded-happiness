#!/usr/bin/env python3
"""
GeoIP Enricher para Upgraded-Happiness (DISTRIBUIDO)
RESPONSABILIDAD ÚNICA: Enriquecimiento geográfico de eventos
INPUT:  PULL BIND :5559 ← promiscuous_agents (PUSH CONNECT)
OUTPUT: PUSH CONNECT → ml_detectors:5560 (PULL BIND)
"""

import json
import time
import logging
import os
import sys
import socket
import argparse
import threading
import signal
from typing import Dict, List, Optional, Tuple
from collections import deque
import ipaddress

# Messaging and serialization
import zmq

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

# Importar NetworkManager (reutilizar el mismo)
try:
    from networkManagerPromiscuousAgent import DistributedNetworkManager

    NETWORK_MANAGER_AVAILABLE = True
    logger.info("✅ NetworkManager importado correctamente")
except ImportError as e:
    NETWORK_MANAGER_AVAILABLE = False
    logger.warning(f"⚠️ NetworkManager no disponible: {e}")
    logger.info("💡 Funcionará solo en modo local")

# GeoIP libraries (opcional)
GEOIP_AVAILABLE = False
try:
    import geoip2.database
    import geoip2.errors

    GEOIP_AVAILABLE = True
    logger.info("✅ GeoIP2 disponible")
except ImportError:
    logger.info("ℹ️ GeoIP2 no disponible - usando coordenadas de fallback")


class SimpleGeoIPProvider:
    """Proveedor GeoIP simple con fallbacks y mappings básicos"""

    def __init__(self, geoip_config: Dict):
        self.config = geoip_config
        self.enabled = geoip_config.get('enabled', True)
        self.database_path = geoip_config.get('database_path')
        self.cache_enabled = geoip_config.get('cache_enabled', True)
        self.cache_size = geoip_config.get('cache_size', 10000)
        self.fallback = geoip_config.get('fallback_coordinates', {
            'latitude': 0.0, 'longitude': 0.0, 'country': 'Unknown', 'city': 'Unknown'
        })

        # Cache simple
        self.cache = {} if self.cache_enabled else None
        self.database = None

        # Mappings para IPs privadas
        self.private_mappings = geoip_config.get('private_ip_handling', {}).get('custom_mapping', {})

        # Inicializar database si está disponible
        if GEOIP_AVAILABLE and self.database_path and os.path.exists(self.database_path):
            try:
                self.database = geoip2.database.Reader(self.database_path)
                logger.info(f"✅ GeoIP database cargada: {self.database_path}")
            except Exception as e:
                logger.warning(f"⚠️ Error cargando GeoIP database: {e}")

        logger.info(f"🌍 GeoIP Provider inicializado (enabled: {self.enabled})")

    def lookup(self, ip_address: str) -> Dict:
        """Lookup de coordenadas geográficas para una IP"""
        if not self.enabled:
            return self.fallback.copy()

        # Check cache
        if self.cache_enabled and ip_address in self.cache:
            return self.cache[ip_address]

        result = self._perform_lookup(ip_address)

        # Cache result
        if self.cache_enabled and len(self.cache) < self.cache_size:
            self.cache[ip_address] = result

        return result

    def _perform_lookup(self, ip_address: str) -> Dict:
        """Realizar lookup real de GeoIP"""
        try:
            # Validar IP
            ip_obj = ipaddress.ip_address(ip_address)

            # IPs privadas - usar mappings custom
            if ip_obj.is_private:
                return self._lookup_private_ip(ip_address, ip_obj)

            # IPs loopback o especiales
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
                return self.fallback.copy()

            # Lookup con database real
            if self.database:
                return self._lookup_with_database(ip_address)

            # Fallback con coordenadas simuladas para testing
            return self._generate_test_coordinates(ip_address)

        except Exception as e:
            logger.debug(f"❌ Error en lookup de {ip_address}: {e}")
            return self.fallback.copy()

    def _lookup_private_ip(self, ip_address: str, ip_obj) -> Dict:
        """Lookup para IPs privadas usando mappings custom"""
        # Buscar en mappings configurados
        for network_str, coords in self.private_mappings.items():
            try:
                network = ipaddress.ip_network(network_str, strict=False)
                if ip_obj in network:
                    logger.debug(f"🏠 IP privada {ip_address} mapeada a {coords}")
                    return coords.copy()
            except:
                continue

        # Fallback para IPs privadas
        fallback = self.fallback.copy()
        fallback['country'] = 'Private'
        fallback['city'] = 'Local Network'
        return fallback

    def _lookup_with_database(self, ip_address: str) -> Dict:
        """Lookup usando database GeoIP2"""
        try:
            response = self.database.city(ip_address)
            return {
                'latitude': float(response.location.latitude or 0.0),
                'longitude': float(response.location.longitude or 0.0),
                'country': response.country.name or 'Unknown',
                'city': response.city.name or 'Unknown'
            }
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"🔍 IP {ip_address} no encontrada en database")
            return self.fallback.copy()
        except Exception as e:
            logger.debug(f"❌ Error en database lookup: {e}")
            return self.fallback.copy()

    def _generate_test_coordinates(self, ip_address: str) -> Dict:
        """Generar coordenadas de test basadas en la IP (para desarrollo)"""
        # Usar hash de IP para generar coordenadas consistentes pero variadas
        ip_hash = hash(ip_address) % 10000

        # Generar coordenadas en Europa para testing
        base_lat = 40.0 + (ip_hash % 1000) / 100.0  # 40.0 - 50.0
        base_lon = -5.0 + (ip_hash % 2000) / 100.0  # -5.0 - 15.0

        return {
            'latitude': round(base_lat, 4),
            'longitude': round(base_lon, 4),
            'country': f'TestCountry{ip_hash % 5}',
            'city': f'TestCity{ip_hash % 10}'
        }

    def get_statistics(self) -> Dict:
        """Estadísticas del proveedor GeoIP"""
        return {
            'enabled': self.enabled,
            'database_available': self.database is not None,
            'cache_enabled': self.cache_enabled,
            'cache_size': len(self.cache) if self.cache else 0,
            'private_mappings': len(self.private_mappings)
        }


class GeoIPEnricher:
    """
    Enriquecedor GeoIP configurado completamente desde JSON
    RESPONSABILIDAD ÚNICA: Añadir coordenadas geográficas a eventos
    """

    def __init__(self, config_file: Optional[str] = None):
        """Inicializar enricher desde configuración JSON"""
        self.config = self._load_config(config_file)
        self.config_file = config_file

        # Configurar logging desde JSON PRIMERO
        self._setup_logging()

        # Configuración básica desde JSON
        self.enricher_id = f"geoip_{socket.gethostname()}_{int(time.time())}"

        # Configuración de red desde JSON
        self.input_config = self.config['network']['input']
        self.output_config = self.config['network']['output']

        # Configuración de procesamiento desde JSON
        self.processing_config = self.config.get('processing', {})
        self.batch_processing = self.processing_config.get('batch_processing', False)
        self.max_events_per_second = self.processing_config.get('max_events_per_second', 1000)
        self.stats_interval = self.processing_config.get('stats_interval', 60)

        # Estado interno
        self.running = False
        self.zmq_context = None
        self.input_socket = None
        self.network_manager = None

        # Proveedor GeoIP
        self.geoip_provider = SimpleGeoIPProvider(self.config.get('geoip', {}))

        # Estadísticas
        self.stats = {
            'events_received': 0,
            'events_enriched': 0,
            'events_sent': 0,
            'geoip_lookups': 0,
            'geoip_cache_hits': 0,
            'errors': 0,
            'network_errors': 0,
            'start_time': time.time(),
            'handshakes_processed': 0
        }

        # Rate limiting
        self.event_times = deque(maxlen=100)

        # Inicializar red
        self._init_network()

        logger.info(f"🌍 GeoIP Enricher inicializado")
        logger.info(f"Config file: {config_file or 'default config'}")
        logger.info(f"Enricher ID: {self.enricher_id}")
        logger.info(f"📡 Input: PULL BIND :{self.input_config['port']}")
        logger.info(f"📤 Output: configurado desde JSON")
        logger.info(f"🌍 GeoIP: {'✅' if self.geoip_provider.enabled else '❌'}")

    def _load_config(self, config_file):
        """Cargar configuración desde archivo JSON"""
        default_config = {
            "agent_info": {
                "name": "geoip_enricher",
                "version": "2.0.0",
                "description": "Enriquecedor geográfico para eventos de red",
                "mode": "local",
                "node_id": f"geoip_node_{socket.gethostname()}"
            },
            "network": {
                "input": {
                    "socket_type": "PULL",
                    "connection_mode": "bind",
                    "port": 5559,
                    "bind_address": "*",
                    "high_water_mark": 1000,
                    "timeout_ms": 5000
                },
                "output": {
                    "mode": "local",
                    "socket_type": "PUSH",
                    "connection_mode": "bind",
                    "targets": {
                        "ml_detectors": [
                            {
                                "id": "ml_detector_local",
                                "address": "localhost",
                                "port": 5560,
                                "weight": 100,
                                "enabled": True
                            }
                        ]
                    },
                    "backward_compatibility": {
                        "local_mode": {
                            "enabled": True,
                            "output_port": 5560,
                            "bind_address": "*"
                        }
                    }
                }
            },
            "geoip": {
                "enabled": True,
                "provider": "simple",
                "cache_enabled": True,
                "cache_size": 1000,
                "fallback_coordinates": {
                    "latitude": 40.4168,
                    "longitude": -3.7038,
                    "country": "Spain",
                    "city": "Madrid"
                }
            },
            "processing": {
                "batch_processing": False,
                "max_events_per_second": 1000,
                "stats_interval": 60
            },
            "logging": {
                "level": "INFO",
                "file": "logs/geoip_enricher.log",
                "console_output": True,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            },
            "protobuf": {
                "enabled": True,
                "extended_format": True
            }
        }

        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                self._merge_config(default_config, user_config)
                logger.info(f"📄 Configuración GeoIP enricher cargada desde {config_file}")
            except Exception as e:
                logger.error(f"❌ Error cargando configuración: {e}")
                logger.info("⚠️ Usando configuración por defecto")
        else:
            if config_file:
                logger.warning(f"⚠️ Archivo de configuración no encontrado: {config_file}")
            logger.info("⚠️ Usando configuración por defecto")

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

        level = getattr(logging, log_config.get('level', 'INFO').upper())
        logger.setLevel(level)

        # Limpiar handlers existentes
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        formatter = logging.Formatter(
            log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )

        # Console handler
        if log_config.get('console_output', True):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # File handler
        if log_config.get('file'):
            log_file = log_config['file']
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    def _init_network(self):
        """Inicializar red con input y output sockets"""
        try:
            # Configurar ZMQ context
            self.zmq_context = zmq.Context(1)

            # INPUT: PULL BIND socket
            self._init_input_socket()

            # OUTPUT: NetworkManager distribuido o socket local
            self._init_output_network()

        except Exception as e:
            logger.error(f"❌ Error inicializando red: {e}")
            raise

    def _init_input_socket(self):
        """Inicializar socket de entrada PULL BIND"""
        input_config = self.input_config

        self.input_socket = self.zmq_context.socket(zmq.PULL)
        self.input_socket.setsockopt(zmq.RCVHWM, input_config.get('high_water_mark', 1000))
        self.input_socket.setsockopt(zmq.RCVTIMEO, input_config.get('timeout_ms', 5000))

        bind_address = f"tcp://{input_config.get('bind_address', '*')}:{input_config['port']}"
        self.input_socket.bind(bind_address)

        logger.info(f"📡 Input socket: PULL BIND {bind_address}")

    def _init_output_network(self):
        """Inicializar NetworkManager para output o socket local"""
        output_config = self.output_config

        # Intentar usar NetworkManager distribuido
        if NETWORK_MANAGER_AVAILABLE and output_config.get('mode') == 'distributed':
            logger.info("🌐 Inicializando NetworkManager distribuido para output")
            self.network_manager = DistributedNetworkManager(output_config, self.zmq_context)
        else:
            # Fallback a socket local
            logger.info("🏠 Inicializando output socket local")
            self._init_output_local(output_config)

    def _init_output_local(self, output_config):
        """Inicializar socket de salida local"""
        legacy_config = output_config.get('backward_compatibility', {}).get('local_mode', {})
        port = legacy_config.get('output_port', 5560)
        address = legacy_config.get('bind_address', '*')

        self.output_socket = self.zmq_context.socket(zmq.PUSH)
        self.output_socket.setsockopt(zmq.SNDHWM, 1000)
        self.output_socket.setsockopt(zmq.LINGER, 1000)

        bind_address = f"tcp://{address}:{port}"
        self.output_socket.bind(bind_address)

        logger.info(f"📤 Output socket: PUSH BIND {bind_address}")

    def _check_rate_limit(self) -> bool:
        """Verificar rate limiting"""
        now = time.time()
        self.event_times.append(now)

        # Limpiar tiempos antiguos
        while self.event_times and now - self.event_times[0] > 1.0:
            self.event_times.popleft()

        return len(self.event_times) <= self.max_events_per_second

    def _enrich_event_with_geoip(self, event) -> Optional['NetworkEvent']:
        """Enriquecer evento con información geográfica"""
        try:
            # Crear evento enriquecido (copia del original)
            enriched_event = network_event_extended_fixed_pb2.NetworkEvent()
            enriched_event.CopyFrom(event)

            # Extraer IP de origen para lookup
            source_ip = event.source_ip

            if source_ip and source_ip != 'unknown':
                # Realizar lookup GeoIP
                geo_data = self.geoip_provider.lookup(source_ip)
                self.stats['geoip_lookups'] += 1

                # Enriquecer con coordenadas
                enriched_event.latitude = geo_data['latitude']
                enriched_event.longitude = geo_data['longitude']

                # Opcionalmente añadir info adicional en descripción
                if geo_data['city'] != 'Unknown':
                    geo_info = f"Geo: {geo_data['city']}, {geo_data['country']}"
                    if enriched_event.description:
                        enriched_event.description = f"{geo_info} | {enriched_event.description}"
                    else:
                        enriched_event.description = geo_info

                logger.debug(f"🌍 IP {source_ip} → {geo_data['latitude']:.4f}, {geo_data['longitude']:.4f}")

            else:
                # Sin IP válida, usar coordenadas de fallback
                fallback = self.geoip_provider.fallback
                enriched_event.latitude = fallback['latitude']
                enriched_event.longitude = fallback['longitude']
                logger.debug(f"🔍 Sin IP válida, usando fallback: {fallback['latitude']}, {fallback['longitude']}")

            self.stats['events_enriched'] += 1
            return enriched_event

        except Exception as e:
            logger.error(f"❌ Error enriqueciendo evento: {e}")
            self.stats['errors'] += 1
            return None

    def _send_event(self, event):
        """Enviar evento enriquecido"""
        try:
            data = event.SerializeToString()

            # Usar NetworkManager si está disponible
            if self.network_manager:
                success = self.network_manager.send_event(data)
                if success:
                    self.stats['events_sent'] += 1
                else:
                    self.stats['network_errors'] += 1
            # Usar socket local
            elif hasattr(self, 'output_socket'):
                self.output_socket.send(data, zmq.NOBLOCK)
                self.stats['events_sent'] += 1
            else:
                logger.error("❌ No hay método de envío disponible")
                self.stats['errors'] += 1

        except zmq.Again:
            logger.warning("⚠️ Output buffer lleno - evento descartado")
            self.stats['errors'] += 1
        except Exception as e:
            logger.error(f"❌ Error enviando evento: {e}")
            self.stats['errors'] += 1

    def _processing_loop(self):
        """Loop principal de procesamiento"""
        logger.info("🔄 Iniciando loop de procesamiento GeoIP...")

        while self.running:
            try:
                # Recibir evento desde promiscuous_agent
                message = self.input_socket.recv()
                self.stats['events_received'] += 1

                # Verificar rate limiting
                if not self._check_rate_limit():
                    continue

                # Parsear evento protobuf
                if EXTENDED_PROTOBUF:
                    event = network_event_extended_fixed_pb2.NetworkEvent()
                    event.ParseFromString(message)

                    # Procesar handshakes sin enriquecimiento
                    if event.is_initial_handshake:
                        self.stats['handshakes_processed'] += 1
                        logger.info(f"🤝 Handshake de {event.agent_id}")
                        # Pasar handshake sin modificar
                        self._send_event(event)
                        continue

                    # Enriquecer evento normal con GeoIP
                    enriched_event = self._enrich_event_with_geoip(event)
                    if enriched_event:
                        self._send_event(enriched_event)

                # Log de estadísticas cada 100 eventos
                if self.stats['events_received'] % 100 == 0:
                    self._log_stats()

            except zmq.Again:
                continue  # Timeout - continuar
            except Exception as e:
                logger.error(f"❌ Error en processing loop: {e}")
                self.stats['errors'] += 1
                time.sleep(0.1)

    def _log_stats(self):
        """Log de estadísticas"""
        stats = self.stats
        enrichment_rate = (stats['events_enriched'] / max(stats['events_received'], 1)) * 100

        network_info = ""
        if self.network_manager:
            net_stats = self.network_manager.get_statistics()
            network_info = f" | Net: {net_stats['mode']} ({net_stats['healthy_targets']}/{net_stats['total_targets']})"

        logger.info(
            f"📊 GeoIP Stats: {stats['events_received']} recibidos, "
            f"{stats['events_enriched']} enriquecidos ({enrichment_rate:.1f}%), "
            f"{stats['events_sent']} enviados, "
            f"{stats['geoip_lookups']} lookups, "
            f"{stats['errors']} errores{network_info}"
        )

    def start(self):
        """Iniciar el enricher"""
        if not self.input_socket:
            raise RuntimeError("Input socket no inicializado")

        if not self.network_manager and not hasattr(self, 'output_socket'):
            raise RuntimeError("Output no configurado")

        self.running = True

        print(f"\n🌍 GeoIP Enricher Started")
        print(f"📄 Config: {self.config_file or 'default'}")
        print(f"📡 Input: PULL BIND :{self.input_config['port']} (desde promiscuous_agents)")

        if self.network_manager:
            net_stats = self.network_manager.get_statistics()
            print(f"📤 Output: {net_stats['mode']} ({net_stats['total_targets']} targets)")
        else:
            print(f"📤 Output: Local PUSH BIND :5560")

        print(f"🌍 GeoIP: {'✅ Enabled' if self.geoip_provider.enabled else '❌ Disabled'}")
        print(f"📦 Protobuf: {'✅ Available' if EXTENDED_PROTOBUF else '❌ Not available'}")
        print(f"🌐 NetworkManager: {'✅ Available' if NETWORK_MANAGER_AVAILABLE else '❌ Local only'}")
        print("=" * 70)

        try:
            # Thread de procesamiento
            processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
            processing_thread.start()

            # Thread de estadísticas
            stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
            stats_thread.start()

            # Mantener vivo
            while self.running:
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n🛑 Stopping GeoIP enricher...")
            self.running = False
        finally:
            self.cleanup()

    def _stats_loop(self):
        """Loop de estadísticas"""
        while self.running:
            try:
                time.sleep(self.stats_interval)
                self._log_stats()
            except Exception as e:
                logger.error(f"❌ Error en stats loop: {e}")

    def cleanup(self):
        """Limpiar recursos"""
        logger.info("🧹 Limpiando GeoIP enricher...")

        if self.network_manager:
            self.network_manager.cleanup()

        if hasattr(self, 'output_socket'):
            self.output_socket.close()

        if self.input_socket:
            self.input_socket.close()

        if self.zmq_context:
            self.zmq_context.term()

        # Log final
        self._log_stats()
        logger.info(f"✅ GeoIP Enricher {self.enricher_id} detenido")

    def get_statistics(self) -> Dict:
        """Estadísticas completas"""
        uptime = time.time() - self.stats['start_time']

        base_stats = {
            'uptime_seconds': uptime,
            'events_received': self.stats['events_received'],
            'events_enriched': self.stats['events_enriched'],
            'events_sent': self.stats['events_sent'],
            'geoip_lookups': self.stats['geoip_lookups'],
            'handshakes_processed': self.stats['handshakes_processed'],
            'errors': self.stats['errors'],
            'network_errors': self.stats['network_errors'],
            'enricher_id': self.enricher_id,
            'config_file': self.config_file,
            'geoip_provider': self.geoip_provider.get_statistics()
        }

        if self.network_manager:
            base_stats['network'] = self.network_manager.get_statistics()

        return base_stats


def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='GeoIP Enricher (DISTRIBUIDO)')
    parser.add_argument('config_file', nargs='?',
                        default='geoip_enricher_config.json',
                        help='Archivo de configuración JSON')
    parser.add_argument('--test-config', action='store_true',
                        help='Validar configuración y salir')

    args = parser.parse_args()

    # Configurar manejo de señales
    enricher = None

    def signal_handler(signum, frame):
        logger.info(f"📡 Señal {signum} recibida")
        if enricher:
            enricher.running = False
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        enricher = GeoIPEnricher(config_file=args.config_file)

        if args.test_config:
            print("✅ Configuración JSON válida para GeoIP enricher")
            stats = enricher.get_statistics()
            print(f"📡 Input: PULL BIND :{enricher.input_config['port']}")
            print(f"📤 Output: configurado")
            print(f"🌍 GeoIP: {'✅' if stats['geoip_provider']['enabled'] else '❌'}")
            return 0

        logger.info("🚀 Iniciando GeoIP Enricher...")
        enricher.start()

    except KeyboardInterrupt:
        logger.info("🛑 Interrupción por teclado")
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        return 1
    finally:
        if enricher:
            stats = enricher.get_statistics()
            print(f"\n📊 Estadísticas Finales:")
            print(f"   ⏱️ Uptime: {stats['uptime_seconds']:.1f}s")
            print(f"   📥 Eventos recibidos: {stats['events_received']}")
            print(f"   🌍 Eventos enriquecidos: {stats['events_enriched']}")
            print(f"   📤 Eventos enviados: {stats['events_sent']}")
            print(f"   🔍 Lookups GeoIP: {stats['geoip_lookups']}")
            print(f"   ❌ Errores: {stats['errors']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())