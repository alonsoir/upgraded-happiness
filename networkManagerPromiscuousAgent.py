#!/usr/bin/env python3
"""
NetworkManager para Enhanced Promiscuous Agent
Maneja conexiones distribuidas, load balancing y health checking
CORREGIDO: etcd3 es opcional - funciona sin él
"""

import zmq
import time
import threading
import logging
import socket
from typing import Dict, List, Optional, Tuple
from collections import deque

logger = logging.getLogger(__name__)

# etcd3 es opcional
ETCD_AVAILABLE = False
try:
    import etcd3

    ETCD_AVAILABLE = True
    logger.info("✅ etcd3 disponible para service discovery")
except ImportError:
    logger.info("ℹ️ etcd3 no disponible - service discovery deshabilitado")


class NetworkTarget:
    """Representa un target geoip_enricher"""

    def __init__(self, config: Dict):
        self.id = config['id']
        self.address = config['address']
        self.port = config['port']
        self.weight = config.get('weight', 100)
        self.priority = config.get('priority', 1)
        self.enabled = config.get('enabled', True)

        # Estado de salud
        self.is_healthy = True
        self.failure_count = 0
        self.last_health_check = 0
        self.response_times = deque(maxlen=10)

    def __str__(self):
        return f"{self.id}@{self.address}:{self.port}"

    @property
    def endpoint(self):
        return f"tcp://{self.address}:{self.port}"

    def mark_healthy(self, response_time: float = 0):
        """Marcar target como saludable"""
        self.is_healthy = True
        self.failure_count = 0
        self.last_health_check = time.time()
        if response_time > 0:
            self.response_times.append(response_time)

    def mark_unhealthy(self):
        """Marcar target como no saludable"""
        self.failure_count += 1
        self.last_health_check = time.time()

    def should_check_health(self, interval: int) -> bool:
        """Determinar si necesita health check"""
        return time.time() - self.last_health_check >= interval


class ServiceDiscovery:
    """Maneja service discovery via etcd (OPCIONAL)"""

    def __init__(self, config: Dict):
        self.config = config
        self.etcd_client = None
        self.enabled = config.get('enabled', False) and ETCD_AVAILABLE

        if self.enabled:
            try:
                endpoints = config.get('etcd', {}).get('endpoints', [])
                if endpoints:
                    # Parsear endpoint
                    host, port = endpoints[0].split(':')
                    self.etcd_client = etcd3.client(host=host, port=int(port))
                    logger.info(f"✅ Service discovery conectado a etcd: {endpoints[0]}")
            except Exception as e:
                logger.warning(f"⚠️ No se pudo conectar a etcd: {e}")
                self.enabled = False
        elif config.get('enabled', False) and not ETCD_AVAILABLE:
            logger.warning("⚠️ Service discovery habilitado pero etcd3 no disponible")

    def discover_geoip_enrichers(self) -> List[Dict]:
        """Descubrir geoip_enrichers desde etcd"""
        if not self.enabled or not self.etcd_client:
            return []

        try:
            key_prefix = self.config.get('etcd', {}).get('key_prefix', '/services/geoip_enrichers/')

            # Obtener servicios desde etcd
            services = []
            for value, metadata in self.etcd_client.get_prefix(key_prefix):
                try:
                    import json
                    service_info = json.loads(value.decode('utf-8'))
                    services.append(service_info)
                except Exception as e:
                    logger.warning(f"⚠️ Error parseando servicio desde etcd: {e}")

            logger.debug(f"🔍 Descubiertos {len(services)} geoip_enrichers desde etcd")
            return services

        except Exception as e:
            logger.error(f"❌ Error en service discovery: {e}")
            return []


class LoadBalancer:
    """Maneja load balancing entre targets"""

    def __init__(self, targets: List[NetworkTarget], strategy: str = "round_robin"):
        self.targets = targets
        self.strategy = strategy
        self.current_index = 0

    def get_next_target(self) -> Optional[NetworkTarget]:
        """Obtener siguiente target según estrategia"""
        healthy_targets = [t for t in self.targets if t.enabled and t.is_healthy]

        if not healthy_targets:
            logger.warning("⚠️ No hay targets saludables disponibles")
            return None

        if self.strategy == "round_robin":
            target = healthy_targets[self.current_index % len(healthy_targets)]
            self.current_index += 1
            return target

        elif self.strategy == "weighted":
            # Implementar weighted round robin
            total_weight = sum(t.weight for t in healthy_targets)
            if total_weight == 0:
                return healthy_targets[0]

            # Selección basada en peso (simplificado)
            import random
            weights = [t.weight for t in healthy_targets]
            return random.choices(healthy_targets, weights=weights)[0]

        elif self.strategy == "least_connections":
            # Para PUSH/PULL, usar el que tiene mejor response time
            return min(healthy_targets,
                       key=lambda t: sum(t.response_times) / max(len(t.response_times), 1))

        else:  # single_target o default
            return healthy_targets[0]


class DistributedNetworkManager:
    """Manager de red distribuida para promiscuous agent"""

    def __init__(self, config: Dict, zmq_context: zmq.Context):
        self.config = config
        self.context = zmq_context
        self.mode = config.get('mode', 'local')
        self.socket_type = config.get('socket_type', 'PUSH')
        self.connection_mode = config.get('connection_mode', 'connect')

        # Inicializar componentes
        self.targets = []
        self.sockets = {}
        self.load_balancer = None
        self.service_discovery = None
        self.health_checker = None

        # Configuración
        self.connection_config = config.get('connection_management', {})
        self.health_config = config.get('health_check', {})
        self.lb_config = config.get('load_balancing', {})

        if self.mode == 'distributed':
            self._init_distributed_mode()
        else:
            self._init_local_mode()

    def _init_distributed_mode(self):
        """Inicializar modo distribuido"""
        logger.info("🌐 Inicializando modo distribuido")

        # Service discovery (OPCIONAL)
        discovery_config = self.config.get('service_discovery', {})
        self.service_discovery = ServiceDiscovery(discovery_config)

        # Cargar targets estáticos
        static_targets = self.config.get('targets', {}).get('geoip_enrichers', [])
        for target_config in static_targets:
            target = NetworkTarget(target_config)
            self.targets.append(target)
            logger.info(f"📡 Target configurado: {target}")

        # Descubrir targets dinámicos (SOLO SI ETCD DISPONIBLE)
        if self.service_discovery.enabled:
            discovered = self.service_discovery.discover_geoip_enrichers()
            for service in discovered:
                target = NetworkTarget(service)
                if target.id not in [t.id for t in self.targets]:
                    self.targets.append(target)
                    logger.info(f"🔍 Target descubierto: {target}")
        else:
            logger.info("ℹ️ Service discovery deshabilitado - usando solo targets estáticos")

        # Verificar que tenemos targets
        if not self.targets:
            logger.warning("⚠️ No hay targets configurados - el agente no funcionará")
            return

        # Load balancer
        strategy = self.lb_config.get('strategy', 'round_robin')
        self.load_balancer = LoadBalancer(self.targets, strategy)

        # Health checker
        if self.health_config.get('enabled', True):
            self._start_health_checker()

        # Crear sockets para cada target
        self._create_target_sockets()

    def _init_local_mode(self):
        """Inicializar modo local (backward compatibility)"""
        logger.info("🏠 Inicializando modo local")

        # Usar configuración legacy o backward compatibility
        legacy_config = self.config.get('backward_compatibility', {}).get('local_mode', {})
        port = legacy_config.get('output_port', 5559)
        address = legacy_config.get('bind_address', '*')
        socket_type = legacy_config.get('socket_type', 'PUSH')
        connection_mode = legacy_config.get('connection_mode', 'bind')

        # Crear socket según configuración explícita
        if socket_type == 'PUSH':
            socket = self.context.socket(zmq.PUSH)
        else:
            raise ValueError(f"Socket type no soportado en local mode: {socket_type}")

        socket.setsockopt(zmq.SNDHWM, self.connection_config.get('high_water_mark', 1000))
        socket.setsockopt(zmq.LINGER, self.connection_config.get('linger_ms', 1000))

        if connection_mode == 'bind':
            bind_address = f"tcp://{address}:{port}"
            socket.bind(bind_address)
            logger.info(f"🔌 Socket local {socket_type} BIND en {bind_address}")
        else:
            connect_address = f"tcp://{address}:{port}"
            socket.connect(connect_address)
            logger.info(f"🔌 Socket local {socket_type} CONNECT a {connect_address}")

        self.sockets['local'] = socket

    def _create_target_sockets(self):
        """Crear sockets para targets distribuidos"""
        for target in self.targets:
            if not target.enabled:
                continue

            try:
                # Usar socket_type explícito del config
                if self.socket_type == 'PUSH':
                    socket = self.context.socket(zmq.PUSH)
                else:
                    raise ValueError(f"Socket type no soportado: {self.socket_type}")

                socket.setsockopt(zmq.SNDHWM, self.connection_config.get('high_water_mark', 1000))
                socket.setsockopt(zmq.LINGER, self.connection_config.get('linger_ms', 1000))
                socket.setsockopt(zmq.SNDTIMEO, self.connection_config.get('send_timeout_ms', 5000))

                # En modo distribuido, promiscuous_agent siempre hace CONNECT
                if self.connection_mode == 'connect':
                    socket.connect(target.endpoint)
                    logger.info(f"🔌 Socket {self.socket_type} CONNECT a {target}")
                elif self.connection_mode == 'bind':
                    # Caso especial - no debería pasar en distribuido normal
                    socket.bind(target.endpoint)
                    logger.info(f"🔌 Socket {self.socket_type} BIND en {target}")
                else:
                    raise ValueError(f"Connection mode no válido: {self.connection_mode}")

                self.sockets[target.id] = socket

            except Exception as e:
                logger.error(f"❌ Error conectando a {target}: {e}")
                target.mark_unhealthy()

    def _start_health_checker(self):
        """Iniciar health checker en thread separado"""

        def health_check_loop():
            interval = self.health_config.get('interval_seconds', 30)

            while True:
                try:
                    self._perform_health_checks()
                    time.sleep(interval)
                except Exception as e:
                    logger.error(f"❌ Error en health check: {e}")
                    time.sleep(interval)

        thread = threading.Thread(target=health_check_loop, daemon=True)
        thread.start()
        logger.info("💓 Health checker iniciado")

    def _perform_health_checks(self):
        """Realizar health checks en todos los targets"""
        interval = self.health_config.get('interval_seconds', 30)
        timeout = self.health_config.get('timeout_ms', 5000) / 1000.0
        failure_threshold = self.health_config.get('failure_threshold', 3)

        for target in self.targets:
            if not target.should_check_health(interval):
                continue

            try:
                # Health check simple: intentar conectar TCP
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)

                result = sock.connect_ex((target.address, target.port))
                sock.close()

                response_time = time.time() - start_time

                if result == 0:
                    target.mark_healthy(response_time)
                    if target.failure_count > 0:
                        logger.info(f"💚 Target recuperado: {target}")
                else:
                    target.mark_unhealthy()

                    if target.failure_count >= failure_threshold and target.is_healthy:
                        target.is_healthy = False
                        logger.warning(f"💔 Target marcado como no saludable: {target}")

            except Exception as e:
                target.mark_unhealthy()
                logger.debug(f"❌ Health check fallido para {target}: {e}")

    def send_event(self, event_data: bytes) -> bool:
        """Enviar evento usando load balancing"""
        if self.mode == 'local':
            return self._send_local(event_data)
        else:
            return self._send_distributed(event_data)

    def _send_local(self, event_data: bytes) -> bool:
        """Enviar en modo local"""
        try:
            socket = self.sockets.get('local')
            if socket:
                socket.send(event_data, zmq.NOBLOCK)
                return True
        except zmq.Again:
            logger.warning("⚠️ Buffer ZMQ lleno - evento descartado")
        except Exception as e:
            logger.error(f"❌ Error enviando evento local: {e}")
        return False

    def _send_distributed(self, event_data: bytes) -> bool:
        """Enviar en modo distribuido con load balancing"""
        retry_attempts = self.lb_config.get('retry_attempts', 3)
        retry_delay = self.lb_config.get('retry_delay_ms', 1000) / 1000.0

        for attempt in range(retry_attempts):
            target = self.load_balancer.get_next_target()
            if not target:
                logger.warning("⚠️ No hay targets disponibles")
                return False

            socket = self.sockets.get(target.id)
            if not socket:
                logger.warning(f"⚠️ Socket no disponible para {target}")
                continue

            try:
                socket.send(event_data, zmq.NOBLOCK)
                return True

            except zmq.Again:
                logger.debug(f"🔄 Buffer lleno en {target}, reintentando...")
                target.mark_unhealthy()

            except Exception as e:
                logger.warning(f"❌ Error enviando a {target}: {e}")
                target.mark_unhealthy()

            if attempt < retry_attempts - 1:
                time.sleep(retry_delay)

        logger.error("❌ Falló envío después de todos los reintentos")
        return False

    def get_statistics(self) -> Dict:
        """Obtener estadísticas de red"""
        stats = {
            'mode': self.mode,
            'socket_type': self.socket_type,
            'connection_mode': self.connection_mode,
            'total_targets': len(self.targets),
            'healthy_targets': len([t for t in self.targets if t.is_healthy]),
            'enabled_targets': len([t for t in self.targets if t.enabled]),
            'active_sockets': len(self.sockets),
            'etcd_available': ETCD_AVAILABLE,
            'service_discovery_enabled': getattr(self.service_discovery, 'enabled', False)
        }

        if self.mode == 'distributed':
            stats['targets'] = [
                {
                    'id': t.id,
                    'endpoint': t.endpoint,
                    'healthy': t.is_healthy,
                    'failures': t.failure_count,
                    'avg_response_time': sum(t.response_times) / max(len(t.response_times), 1)
                }
                for t in self.targets
            ]

        return stats

    def cleanup(self):
        """Limpiar recursos"""
        for socket in self.sockets.values():
            socket.close()
        self.sockets.clear()
        logger.info("🧹 Network manager limpiado")