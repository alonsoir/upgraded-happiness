#!/usr/bin/env python3
"""
🛡️ Dashboard SCADA REAL - ZeroMQ 5560 + Mapa Interactivo + Comandos Firewall
Conectado a eventos enriquecidos por ML del puerto 5560 (PROTOBUF)
Envía comandos de firewall por puerto 5561 (PROTOBUF)
ACTUALIZADO: Usa estructuras protobuf reales con enums y campos correctos
"""

import json
import logging
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import uuid

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Importar protobuf y zmq
try:
    import zmq

    ZMQ_AVAILABLE = True
    logger.info("✅ ZMQ disponible")
except ImportError:
    ZMQ_AVAILABLE = False
    logger.error("❌ ZMQ no disponible")

# Importar protobuf - USAR ESTRUCTURAS REALES
try:
    from src.protocols.protobuf import network_event_extended_fixed_pb2
    from src.protocols.protobuf import firewall_commands_pb2

    PROTOBUF_AVAILABLE = True
    logger.info("✅ Protobuf importado desde src.protocols.protobuf")
except ImportError:
    try:
        import network_event_extended_fixed_pb2
        import firewall_commands_pb2

        PROTOBUF_AVAILABLE = True
        logger.info("✅ Protobuf importado desde directorio local")
    except ImportError:
        PROTOBUF_AVAILABLE = False
        logger.error("❌ Protobuf no disponible")


class FirewallCommandGenerator:
    """Generador de comandos de firewall usando estructuras protobuf reales"""

    def __init__(self):
        # Cache de información de nodos
        self.known_nodes = {}

        # Mapeo de acciones a enums
        self.action_mapping = {
            'block_ip': firewall_commands_pb2.BLOCK_IP,
            'unblock_ip': firewall_commands_pb2.UNBLOCK_IP,
            'block_port': firewall_commands_pb2.BLOCK_PORT,
            'unblock_port': firewall_commands_pb2.UNBLOCK_PORT,
            'rate_limit': firewall_commands_pb2.RATE_LIMIT_IP,
            'allow_temp': firewall_commands_pb2.ALLOW_IP_TEMP
        }

        # Mapeo de prioridades a enums
        self.priority_mapping = {
            'low': firewall_commands_pb2.LOW,
            'medium': firewall_commands_pb2.MEDIUM,
            'high': firewall_commands_pb2.HIGH,
            'critical': firewall_commands_pb2.CRITICAL
        }

        # Reglas básicas por tipo de amenaza
        self.threat_rules = {
            'port_scan': {
                'action': 'block_ip',
                'duration': 3600,
                'priority': 'high'
            },
            'anomaly_high': {
                'action': 'block_ip',
                'duration': 1800,
                'priority': 'medium'
            },
            'rate_limit_exceeded': {
                'action': 'rate_limit',
                'duration': 900,
                'priority': 'medium',
                'rate_limit_rule': '10/min'
            },
            'suspicious_port': {
                'action': 'block_ip',
                'duration': 3600,
                'priority': 'high'
            }
        }

    def register_node(self, event_data):
        """Registra un nodo cuando recibe su handshake inicial"""
        if event_data.get('is_initial_handshake'):
            node_id = event_data.get('agent_id', 'unknown')

            self.known_nodes[node_id] = {
                'so_identifier': event_data.get('so_identifier', 'unknown'),
                'hostname': event_data.get('node_hostname', 'unknown'),
                'os_version': event_data.get('os_version', 'unknown'),
                'firewall_status': event_data.get('firewall_status', 'unknown'),
                'agent_version': event_data.get('agent_version', 'unknown'),
                'last_seen': time.time()
            }

            logger.info(f"🖥️  Nodo registrado: {node_id} ({event_data.get('so_identifier')})")

    def analyze_threat_and_generate_commands(self, event_data) -> list:
        """Analiza un evento y genera comandos de firewall si es necesario"""
        commands = []

        # Análisis básico de amenazas
        threat_type = self.detect_threat_type(event_data)

        if threat_type:
            # Generar comando basado en el tipo de amenaza
            command = self.create_firewall_command_protobuf(event_data, threat_type)
            if command:
                commands.append(command)

        return commands

    def detect_threat_type(self, event_data) -> str:
        """Detecta el tipo de amenaza basado en el evento"""

        # Anomalía alta
        anomaly_score = event_data.get('anomaly_score', 0)
        if anomaly_score > 0.8:
            return 'anomaly_high'

        # Puerto sospechoso (puertos SCADA)
        dest_port = event_data.get('dest_port', 0)
        suspicious_ports = [22, 23, 502, 1911, 4840, 20000]  # SSH, Telnet, Modbus, etc.
        if dest_port in suspicious_ports:
            return 'suspicious_port'

        # Rate limiting
        event_type = event_data.get('event_type', '')
        if 'flood' in event_type.lower() or 'brute' in event_type.lower():
            return 'rate_limit_exceeded'

        # Port scanning
        if 'scan' in event_type.lower():
            return 'port_scan'

        return None

    def create_firewall_command_protobuf(self, event_data, threat_type):
        """Crea un comando de firewall usando protobuf real"""
        if not PROTOBUF_AVAILABLE:
            return None

        if threat_type not in self.threat_rules:
            return None

        rule = self.threat_rules[threat_type]
        source_ip = event_data.get('source_ip')
        dest_port = event_data.get('dest_port', 0)

        if not source_ip:
            return None

        # Crear comando protobuf usando estructura real
        command = firewall_commands_pb2.FirewallCommand()
        command.command_id = str(uuid.uuid4())
        command.action = self.action_mapping[rule['action']]
        command.target_ip = source_ip

        if rule['action'] in ['block_port', 'unblock_port']:
            command.target_port = dest_port
        else:
            command.target_port = 0

        command.duration_seconds = rule['duration']
        command.reason = f"Detected {threat_type} from {source_ip}"
        command.priority = self.priority_mapping[rule['priority']]
        command.dry_run = True  # Siempre dry_run por seguridad

        # Agregar rate limiting si aplica
        if 'rate_limit_rule' in rule:
            command.rate_limit_rule = rule['rate_limit_rule']

        # Agregar parámetros extra específicos del SO
        if 'extra_params' in rule:
            for key, value in rule['extra_params'].items():
                command.extra_params[key] = value

        return command

    def create_command_batch(self, target_node_id, commands, description="Dashboard generated commands"):
        """Crea un lote de comandos para enviar al firewall agent"""
        if not PROTOBUF_AVAILABLE:
            return None

        if target_node_id not in self.known_nodes:
            logger.warning(f"⚠️  Nodo desconocido: {target_node_id}")
            return None

        node_info = self.known_nodes[target_node_id]

        # Crear lote usando estructura protobuf real
        batch = firewall_commands_pb2.FirewallCommandBatch()
        batch.batch_id = str(uuid.uuid4())
        batch.target_node_id = target_node_id
        batch.so_identifier = node_info['so_identifier']
        batch.timestamp = int(time.time() * 1000)
        batch.generated_by = 'dashboard'
        batch.dry_run_all = True  # Siempre seguro
        batch.description = description
        batch.confidence_score = 0.8
        batch.expected_execution_time = len(commands) * 2

        # Agregar comandos al lote
        for command in commands:
            batch.commands.append(command)

        return batch


class FirewallCommandSender:
    """Cliente ZeroMQ para enviar comandos de firewall al puerto 5561 usando PROTOBUF"""

    def __init__(self):
        if not ZMQ_AVAILABLE:
            logger.error("ZMQ no disponible para FirewallCommandSender")
            self.socket = None
            self.context = None
            return

        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUSH)

        try:
            self.socket.connect("tcp://localhost:5561")
            self.command_log = deque(maxlen=100)
            logger.info("🔥 Firewall command sender conectado al puerto 5561 (PROTOBUF)")
        except Exception as e:
            logger.error(f"Error conectando al puerto 5561: {e}")
            self.socket = None

    def send_firewall_command_batch(self, batch):
        """Enviar lote de comandos usando protobuf"""
        if not self.socket or not PROTOBUF_AVAILABLE:
            logger.error("Socket o protobuf no disponible para enviar comando")
            return False

        try:
            # Enviar como protobuf serializado
            message = batch.SerializeToString()
            self.socket.send(message)

            # Log local
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': 'firewall_batch_sent',
                'batch_id': batch.batch_id,
                'target_node': batch.target_node_id,
                'command_count': len(batch.commands),
                'generated_by': batch.generated_by
            }
            self.command_log.append(log_entry)

            logger.info(f"🔥 Lote protobuf enviado: {batch.batch_id} ({len(batch.commands)} comandos)")
            return True

        except Exception as e:
            logger.error(f"❌ Error enviando lote firewall protobuf: {e}")
            return False

    def send_firewall_command_json(self, command_data):
        """Enviar comando individual usando JSON (convertir a protobuf)"""
        if not self.socket or not PROTOBUF_AVAILABLE:
            logger.error("Socket o protobuf no disponible para enviar comando")
            return False

        try:
            # Convertir JSON a protobuf
            command = firewall_commands_pb2.FirewallCommand()
            command.command_id = command_data.get('command_id', str(uuid.uuid4()))

            # Mapear acción string a enum
            action_str = command_data.get('action', 'BLOCK_IP').lower()
            if action_str == 'block_ip':
                command.action = firewall_commands_pb2.BLOCK_IP
            elif action_str == 'rate_limit':
                command.action = firewall_commands_pb2.RATE_LIMIT_IP
            elif action_str == 'allow':
                command.action = firewall_commands_pb2.ALLOW_IP_TEMP
            else:
                command.action = firewall_commands_pb2.BLOCK_IP

            command.target_ip = command_data.get('target_ip', '')
            command.target_port = command_data.get('target_port', 0)
            command.duration_seconds = command_data.get('duration_seconds', 3600)
            command.reason = command_data.get('reason', 'Dashboard command')

            # Mapear prioridad string a enum
            priority_str = command_data.get('priority', 'MEDIUM').lower()
            if priority_str == 'low':
                command.priority = firewall_commands_pb2.LOW
            elif priority_str == 'high':
                command.priority = firewall_commands_pb2.HIGH
            elif priority_str == 'critical':
                command.priority = firewall_commands_pb2.CRITICAL
            else:
                command.priority = firewall_commands_pb2.MEDIUM

            command.dry_run = command_data.get('dry_run', True)

            # Crear lote con un solo comando
            batch = firewall_commands_pb2.FirewallCommandBatch()
            batch.batch_id = str(uuid.uuid4())
            batch.target_node_id = command_data.get('source_agent', 'unknown')
            batch.so_identifier = 'unknown'
            batch.timestamp = int(time.time() * 1000)
            batch.generated_by = 'dashboard_web'
            batch.dry_run_all = True
            batch.description = 'Single command from web interface'
            batch.confidence_score = 0.8
            batch.expected_execution_time = 2

            # Agregar comando al lote
            batch.commands.append(command)

            # Enviar lote
            return self.send_firewall_command_batch(batch)

        except Exception as e:
            logger.error(f"❌ Error convirtiendo JSON a protobuf: {e}")
            return False

    def get_command_log(self):
        """Obtener log de comandos enviados"""
        return list(self.command_log)

    def close(self):
        """Cerrar conexión"""
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()


class ZeroMQListener:
    """Listener de ZeroMQ puerto 5560 (eventos enriquecidos por ML) usando PROTOBUF"""

    def __init__(self, dashboard_handler):
        self.dashboard_handler = dashboard_handler
        self.running = False
        self.context = None
        self.socket = None

        # Estadísticas del broker
        self.broker_stats = {
            'connection_time': None,
            'total_messages': 0,
            'bytes_received': 0,
            'last_message_time': None,
            'broker_health': 'unknown'
        }

        # Estadísticas de eventos
        self.stats = {
            'total_events': 0,
            'events_with_gps': 0,
            'events_per_minute': deque(maxlen=60),
            'unique_ips': set(),
            'unique_agents': set(),
            'anomaly_events': 0,
            'high_risk_events': 0,
            'start_time': datetime.now(),
            'last_event_time': None,
            'ml_models_detected': set(),
            'event_types': defaultdict(int),
            'ports_seen': defaultdict(int),
            'handshakes_received': 0,
            'nodes_registered': 0
        }

    def start(self):
        """Iniciar conexión a ZeroMQ 5560"""
        if not ZMQ_AVAILABLE:
            logger.error("ZMQ no disponible para listener")
            return

        self.running = True

        try:
            self.context = zmq.Context()
            self.socket = self.context.socket(zmq.SUB)
            self.socket.connect("tcp://localhost:5560")
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")
            self.socket.setsockopt(zmq.RCVTIMEO, 5000)

            self.broker_stats['connection_time'] = datetime.now()

            logger.info("🔌 Conectado a ZeroMQ puerto 5560 (eventos enriquecidos por ML - PROTOBUF)")

            # Thread de escucha
            thread = threading.Thread(target=self._listen_events, daemon=True)
            thread.start()

            logger.info("🎯 Dashboard iniciado - Esperando eventos enriquecidos protobuf...")

        except Exception as e:
            logger.error(f"❌ Error conectando a ZeroMQ: {e}")

    def _listen_events(self):
        """Escuchar eventos del puerto 5560 (PROTOBUF)"""
        while self.running:
            try:
                message = self.socket.recv(zmq.NOBLOCK)

                # Estadísticas del broker
                self.broker_stats['total_messages'] += 1
                self.broker_stats['bytes_received'] += len(message)
                self.broker_stats['last_message_time'] = datetime.now()
                self.broker_stats['broker_health'] = 'healthy'

                # Intentar parsear como protobuf
                if PROTOBUF_AVAILABLE:
                    try:
                        event = network_event_extended_fixed_pb2.NetworkEvent()
                        event.ParseFromString(message)
                        self._process_event_protobuf(event)
                        continue
                    except Exception as e:
                        logger.debug(f"Error parsing protobuf: {e}")

                # Fallback a JSON (no debería ocurrir)
                try:
                    event_data = json.loads(message.decode('utf-8'))
                    self._process_json_event(event_data)
                    logger.warning("Recibido evento en JSON - se esperaba protobuf")
                except Exception as e:
                    logger.error(f"Error parsing mensaje: {e}")

            except zmq.Again:
                time.sleep(0.1)
                if self.broker_stats['last_message_time']:
                    time_since = (datetime.now() - self.broker_stats['last_message_time']).total_seconds()
                    if time_since > 60:
                        self.broker_stats['broker_health'] = 'stale'
            except Exception as e:
                logger.error(f"❌ Error en listener: {e}")
                time.sleep(1)

    def _process_event_protobuf(self, event):
        """Procesar evento protobuf usando todos los campos disponibles"""
        try:
            event_dict = {
                'event_id': event.event_id or f"evt_{int(time.time() * 1000)}",
                'timestamp': datetime.now().isoformat(),
                'source_ip': event.source_ip or 'unknown',
                'target_ip': event.target_ip or 'unknown',
                'packet_size': max(0, event.packet_size),
                'dest_port': max(0, min(65535, event.dest_port)),
                'src_port': max(0, min(65535, event.src_port)),
                'agent_id': event.agent_id or 'unknown',
                'anomaly_score': max(0.0, min(1.0, event.anomaly_score)),
                'latitude': event.latitude if abs(event.latitude) <= 90 and event.latitude != 0 else None,
                'longitude': event.longitude if abs(event.longitude) <= 180 and event.longitude != 0 else None,
                'event_type': event.event_type or 'network',
                'risk_score': max(0.0, min(1.0, event.risk_score)),
                'description': event.description or '',
                'has_gps': (abs(event.latitude) <= 90 and abs(event.longitude) <= 180 and
                            event.latitude != 0 and event.longitude != 0),
                'ml_enhanced': event.anomaly_score > 0 or event.risk_score > 0,
                'risk_level': self._get_risk_level(event.risk_score),
                'source': 'protobuf',

                # Campos adicionales del protobuf real
                'so_identifier': event.so_identifier or 'unknown',
                'node_hostname': event.node_hostname or 'unknown',
                'os_version': event.os_version or 'unknown',
                'firewall_status': event.firewall_status or 'unknown',
                'agent_version': event.agent_version or 'unknown',
                'is_initial_handshake': event.is_initial_handshake
            }

            # Procesar handshake inicial
            if event.is_initial_handshake:
                self.stats['handshakes_received'] += 1
                self.stats['nodes_registered'] += 1
                logger.info(f"🤝 Handshake recibido de {event.agent_id} ({event.so_identifier})")

            self._update_stats(event_dict)
            self._add_to_dashboard(event_dict)

            if event_dict['ml_enhanced']:
                logger.info(f"📡 Evento ML protobuf: {event_dict['source_ip']} → {event_dict['target_ip']} "
                            f"(R: {event_dict['risk_score']:.2f}, A: {event_dict['anomaly_score']:.2f})")

        except Exception as e:
            logger.error(f"❌ Error procesando evento protobuf: {e}")

    def _process_json_event(self, event_data):
        """Procesar evento JSON (FALLBACK SOLAMENTE)"""
        try:
            event_dict = {
                'event_id': event_data.get('event_id', f"evt_{int(time.time() * 1000)}"),
                'timestamp': datetime.now().isoformat(),
                'source_ip': event_data.get('source_ip', 'unknown'),
                'target_ip': event_data.get('target_ip', 'unknown'),
                'packet_size': event_data.get('packet_size', 0),
                'dest_port': event_data.get('dest_port', 0),
                'src_port': event_data.get('src_port', 0),
                'agent_id': event_data.get('agent_id', 'unknown'),
                'anomaly_score': event_data.get('anomaly_score', 0.0),
                'latitude': event_data.get('latitude'),
                'longitude': event_data.get('longitude'),
                'event_type': event_data.get('event_type', 'network'),
                'risk_score': event_data.get('risk_score', 0.0),
                'description': event_data.get('description', ''),
                'has_gps': event_data.get('latitude') is not None and event_data.get('longitude') is not None,
                'ml_enhanced': event_data.get('anomaly_score', 0) > 0 or event_data.get('risk_score', 0) > 0,
                'risk_level': self._get_risk_level(event_data.get('risk_score', 0.0)),
                'source': 'json_fallback',

                # Campos adicionales con fallback
                'so_identifier': event_data.get('so_identifier', 'unknown'),
                'node_hostname': event_data.get('node_hostname', 'unknown'),
                'os_version': event_data.get('os_version', 'unknown'),
                'firewall_status': event_data.get('firewall_status', 'unknown'),
                'agent_version': event_data.get('agent_version', 'unknown'),
                'is_initial_handshake': event_data.get('is_initial_handshake', False)
            }

            self._update_stats(event_dict)
            self._add_to_dashboard(event_dict)

        except Exception as e:
            logger.error(f"❌ Error procesando JSON fallback: {e}")

    def _get_risk_level(self, risk_score):
        """Calcular nivel de riesgo"""
        if risk_score >= 0.8:
            return 'high'
        elif risk_score >= 0.5:
            return 'medium'
        elif risk_score > 0:
            return 'low'
        else:
            return 'none'

    def _update_stats(self, event):
        """Actualizar estadísticas"""
        self.stats['total_events'] += 1
        self.stats['last_event_time'] = datetime.now()

        if event['has_gps']:
            self.stats['events_with_gps'] += 1

        self.stats['unique_ips'].add(event['source_ip'])
        self.stats['unique_ips'].add(event['target_ip'])
        self.stats['unique_agents'].add(event['agent_id'])

        if event['anomaly_score'] > 0.7:
            self.stats['anomaly_events'] += 1

        if event['risk_score'] > 0.8:
            self.stats['high_risk_events'] += 1

        self.stats['event_types'][event['event_type']] += 1

        if event['dest_port']:
            self.stats['ports_seen'][event['dest_port']] += 1

        self.stats['events_per_minute'].append(datetime.now())

        if event['anomaly_score'] > 0:
            self.stats['ml_models_detected'].add('Anomaly Detection')
        if event['risk_score'] > 0:
            self.stats['ml_models_detected'].add('Risk Assessment')

    def _add_to_dashboard(self, event):
        """Añadir evento al dashboard"""
        if hasattr(self.dashboard_handler, 'shared_data'):
            self.dashboard_handler.shared_data['events'].append(event)

            # Procesar evento con la integración de firewall
            if hasattr(self.dashboard_handler, 'firewall_integration'):
                self.dashboard_handler.firewall_integration.process_received_event(event)

            if len(self.dashboard_handler.shared_data['events']) > 300:
                self.dashboard_handler.shared_data['events'] = \
                    self.dashboard_handler.shared_data['events'][-300:]

    def get_stats(self):
        """Obtener estadísticas completas"""
        now = datetime.now()
        recent_events = [t for t in self.stats['events_per_minute']
                         if (now - t).total_seconds() < 60]
        events_per_minute = len(recent_events)

        last_event_delta = None
        if self.stats['last_event_time']:
            last_event_delta = (now - self.stats['last_event_time']).total_seconds()

        return {
            'total_events': self.stats['total_events'],
            'events_with_gps': self.stats['events_with_gps'],
            'events_per_minute': events_per_minute,
            'unique_ips': len(self.stats['unique_ips']),
            'unique_agents': len(self.stats['unique_agents']),
            'anomaly_events': self.stats['anomaly_events'],
            'high_risk_events': self.stats['high_risk_events'],
            'uptime_seconds': (now - self.stats['start_time']).total_seconds(),
            'last_event_seconds_ago': last_event_delta,
            'ml_models_active': list(self.stats['ml_models_detected']),
            'event_types': dict(self.stats['event_types']),
            'top_ports': dict(sorted(self.stats['ports_seen'].items(),
                                     key=lambda x: x[1], reverse=True)[:10]),
            'gps_percentage': (self.stats['events_with_gps'] / max(1, self.stats['total_events'])) * 100,
            'broker_stats': self.broker_stats,
            'handshakes_received': self.stats['handshakes_received'],
            'nodes_registered': self.stats['nodes_registered']
        }

    def stop(self):
        """Detener listener"""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()


class DashboardFirewallIntegration:
    """Integración de firewall para el dashboard usando protobuf real"""

    def __init__(self, dashboard_instance):
        self.dashboard = dashboard_instance
        self.command_generator = FirewallCommandGenerator()

        # Estado de la UI
        self.selected_events = []
        self.pending_commands = {}

    def process_received_event(self, event_data):
        """Procesa un evento recibido y genera comandos protobuf"""

        # Registrar nodo si es handshake inicial
        self.command_generator.register_node(event_data)

        # Analizar amenazas automáticamente (retorna objetos protobuf)
        suggested_commands = self.command_generator.analyze_threat_and_generate_commands(event_data)

        if suggested_commands:
            logger.info(
                f"💡 {len(suggested_commands)} comando(s) protobuf sugerido(s) para evento {event_data.get('event_id', 'unknown')}")

            # Guardar comandos sugeridos para aprobación manual
            event_id = event_data.get('event_id')
            self.pending_commands[event_id] = {
                'event': event_data,
                'commands_protobuf': suggested_commands,  # Objetos protobuf
                'timestamp': time.time()
            }

    def get_pending_commands_summary(self):
        """Retorna resumen de comandos pendientes"""
        summary = {
            'total_events_with_commands': len(self.pending_commands),
            'total_commands': sum(len(p['commands_protobuf']) for p in self.pending_commands.values()),
            'oldest_pending': None
        }

        if self.pending_commands:
            oldest = min(self.pending_commands.values(), key=lambda x: x['timestamp'])
            summary['oldest_pending'] = time.time() - oldest['timestamp']

        return summary


class DashboardHandler(BaseHTTPRequestHandler):
    """Handler del dashboard con capacidades de firewall usando protobuf real"""

    # Datos compartidos entre instancias del handler
    shared_data = {
        'events': [],
        'zmq_listener': None,
        'firewall_sender': None,
        'firewall_integration': None
    }

    def __init__(self, *args, **kwargs):
        # Inicializar integración de firewall si no existe
        if not self.shared_data['firewall_integration']:
            self.shared_data['firewall_integration'] = DashboardFirewallIntegration(self)

        super().__init__(*args, **kwargs)

    @property
    def firewall_integration(self):
        return self.shared_data['firewall_integration']

    def do_GET(self):
        """Manejar peticiones GET"""
        try:
            if self.path == '/':
                self.serve_dashboard()
            elif self.path == '/api/stats':
                self.serve_stats()
            elif self.path == '/api/events':
                self.serve_events()
            elif self.path == '/api/events/gps':
                self.serve_gps_events()
            elif self.path == '/api/firewall/log':
                self.serve_firewall_log()
            elif self.path == '/api/firewall/pending':
                self.serve_pending_commands()
            elif self.path == '/health':
                self.serve_health()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logger.error(f"❌ Error en GET {self.path}: {e}")
            self.send_error(500, f"Internal Error: {e}")

    def do_POST(self):
        """Manejar peticiones POST"""
        try:
            if self.path == '/api/firewall/block':
                self.handle_firewall_block()
            elif self.path == '/api/firewall/generate':
                self.handle_generate_firewall_command()
            elif self.path == '/api/firewall/approve':
                self.handle_approve_command()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logger.error(f"❌ Error en POST {self.path}: {e}")
            self.send_error(500, f"Internal Error: {e}")

    def handle_firewall_block(self):
        """Manejar solicitud de bloqueo de firewall - convertir JSON web a protobuf"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))

            event_id = request_data.get('event_id')
            target_ip = request_data.get('target_ip')
            source_agent = request_data.get('source_agent')

            if not target_ip or not source_agent:
                self.send_json({'error': 'Missing required fields'}, status=400)
                return

            # Enviar usando el método JSON que convierte a protobuf internamente
            if self.shared_data['firewall_sender']:
                success = self.shared_data['firewall_sender'].send_firewall_command_json(request_data)
                if success:
                    self.send_json({
                        'success': True,
                        'message': f'Firewall command sent for {target_ip} (converted to protobuf batch)',
                        'command_id': request_data.get('command_id', 'auto-generated')
                    })
                else:
                    self.send_json({'error': 'Failed to send firewall command'}, status=500)
            else:
                self.send_json({'error': 'Firewall sender not available'}, status=500)

        except Exception as e:
            logger.error(f"❌ Error en firewall block: {e}")
            self.send_json({'error': str(e)}, status=500)

    def handle_approve_command(self):
        """Aprobar y ejecutar comando pendiente (protobuf nativo)"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))

            event_id = request_data.get('event_id')

            if not event_id:
                self.send_json({'error': 'Missing event_id'}, status=400)
                return

            # Verificar si hay comandos pendientes (protobuf)
            if event_id in self.firewall_integration.pending_commands:
                pending = self.firewall_integration.pending_commands[event_id]
                commands_protobuf = pending['commands_protobuf']
                event_data = pending['event']

                # Crear lote de comandos
                batch = self.firewall_integration.command_generator.create_command_batch(
                    target_node_id=event_data.get('agent_id'),
                    commands=commands_protobuf,
                    description=f"Approved commands for event {event_id}"
                )

                if batch:
                    # Enviar lote protobuf
                    if self.shared_data['firewall_sender']:
                        success = self.shared_data['firewall_sender'].send_firewall_command_batch(batch)
                        if success:
                            # Limpiar comandos pendientes
                            del self.firewall_integration.pending_commands[event_id]

                            self.send_json({
                                'success': True,
                                'message': f'Batch {batch.batch_id} sent successfully',
                                'batch_id': batch.batch_id,
                                'commands_sent': len(batch.commands)
                            })
                        else:
                            self.send_json({'error': 'Failed to send command batch'}, status=500)
                    else:
                        self.send_json({'error': 'Firewall sender not available'}, status=500)
                else:
                    self.send_json({'error': 'Could not create command batch'}, status=500)
            else:
                self.send_json({'error': 'No pending commands for this event'}, status=404)

        except Exception as e:
            logger.error(f"❌ Error aprobando comando: {e}")
            self.send_json({'error': str(e)}, status=500)

    def handle_generate_firewall_command(self):
        """Generar comando de firewall"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))

            # Información del evento
            event_info = request_data.get('event', {})

            # Generar comando inteligente
            suggested_command = self._generate_intelligent_firewall_command(event_info)

            self.send_json({
                'success': True,
                'suggested_command': suggested_command
            })

        except Exception as e:
            logger.error(f"❌ Error generando comando: {e}")
            self.send_json({'error': str(e)}, status=500)

    def _generate_intelligent_firewall_command(self, event_info):
        """Generar comando de firewall inteligente basado en el evento"""
        target_ip = event_info.get('target_ip', 'unknown')
        source_ip = event_info.get('source_ip', 'unknown')
        risk_score = event_info.get('risk_score', 0)
        dest_port = event_info.get('dest_port', 0)
        protocol = event_info.get('protocol', 'TCP')

        # Determinar tipo de regla basado en el riesgo
        if risk_score >= 0.9:
            action = 'BLOCK_IP'
            duration = 86400  # 24h
            priority = 'CRITICAL'
        elif risk_score >= 0.8:
            action = 'BLOCK_IP'
            duration = 3600  # 1h
            priority = 'HIGH'
        else:
            action = 'RATE_LIMIT_IP'
            duration = 900  # 15min
            priority = 'MEDIUM'

        # Generar comando específico del protocolo
        if dest_port in [22, 3389]:  # SSH, RDP
            command = f"iptables -A INPUT -s {source_ip} -p {protocol.lower()} --dport {dest_port} -j DROP"
        elif dest_port in [80, 443]:  # HTTP, HTTPS
            command = f"iptables -A INPUT -s {source_ip} -p {protocol.lower()} --dport {dest_port} -m limit --limit 10/min -j ACCEPT"
        else:
            command = f"iptables -A INPUT -s {source_ip} -j DROP"

        return {
            'action': action,
            'target_ip': source_ip,  # Bloqueamos la IP de origen
            'target_port': dest_port,
            'duration_seconds': duration,
            'priority': priority,
            'firewall_rule': {
                'rule_type': 'iptables',
                'command': command,
                'duration': f"{duration}s",
                'priority': priority
            },
            'reason': f"Automated response to risk score {risk_score:.2f}",
            'analysis': {
                'threat_type': self._analyze_threat_type(event_info),
                'recommended_action': action,
                'confidence': min(risk_score * 100, 95)
            }
        }

    def _analyze_threat_type(self, event_info):
        """Analizar tipo de amenaza basado en el evento"""
        dest_port = event_info.get('dest_port', 0)
        packet_size = event_info.get('packet_size', 0)

        if dest_port == 22:
            return 'SSH_BRUTE_FORCE'
        elif dest_port == 3389:
            return 'RDP_ATTACK'
        elif dest_port in [80, 443]:
            return 'WEB_ATTACK'
        elif packet_size > 1400:
            return 'POTENTIAL_DDoS'
        else:
            return 'SUSPICIOUS_TRAFFIC'

    def serve_firewall_log(self):
        """Servir log de comandos de firewall"""
        if self.shared_data['firewall_sender']:
            log_data = self.shared_data['firewall_sender'].get_command_log()
            self.send_json({
                'commands': log_data,
                'count': len(log_data)
            })
        else:
            self.send_json({'commands': [], 'count': 0})

    def serve_pending_commands(self):
        """Servir comandos pendientes (convertir protobuf a JSON para web)"""
        if self.firewall_integration:
            summary = self.firewall_integration.get_pending_commands_summary()
            pending = {}

            # Convertir comandos protobuf a JSON para la web
            for event_id, data in self.firewall_integration.pending_commands.items():
                commands_json = []
                for cmd_protobuf in data['commands_protobuf']:
                    commands_json.append({
                        'command_id': cmd_protobuf.command_id,
                        'action': firewall_commands_pb2.CommandAction.Name(cmd_protobuf.action),
                        'target_ip': cmd_protobuf.target_ip,
                        'target_port': cmd_protobuf.target_port,
                        'duration_seconds': cmd_protobuf.duration_seconds,
                        'reason': cmd_protobuf.reason,
                        'priority': firewall_commands_pb2.CommandPriority.Name(cmd_protobuf.priority),
                        'dry_run': cmd_protobuf.dry_run,
                        'rate_limit_rule': cmd_protobuf.rate_limit_rule
                    })

                pending[event_id] = {
                    'event': data['event'],
                    'commands': commands_json,
                    'timestamp': data['timestamp']
                }

            self.send_json({
                'summary': summary,
                'pending_commands': pending
            })
        else:
            self.send_json({'summary': {}, 'pending_commands': {}})

    def serve_stats(self):
        """Estadísticas del sistema"""
        if self.shared_data['zmq_listener']:
            stats = self.shared_data['zmq_listener'].get_stats()
        else:
            stats = {'error': 'ZeroMQ listener not initialized'}

        # Agregar estadísticas de firewall
        if self.firewall_integration:
            stats['firewall_stats'] = self.firewall_integration.get_pending_commands_summary()

        self.send_json(stats)

    def serve_events(self):
        """Eventos recientes"""
        events = self.shared_data['events'][-50:]
        self.send_json({
            'events': events,
            'count': len(events),
            'source': 'zeromq_5560_ml_enriched_protobuf',
            'protobuf_available': PROTOBUF_AVAILABLE,
            'zmq_available': ZMQ_AVAILABLE
        })

    def serve_gps_events(self):
        """Solo eventos con GPS"""
        all_events = self.shared_data['events']
        gps_events = [e for e in all_events if e.get('has_gps')]

        self.send_json({
            'events': gps_events[-30:],
            'count': len(gps_events),
            'total_events': len(all_events)
        })

    def serve_health(self):
        """Health check"""
        stats = {}
        if self.shared_data['zmq_listener']:
            stats = self.shared_data['zmq_listener'].get_stats()

        health_data = {
            'status': 'healthy' if stats.get('total_events', 0) > 0 else 'waiting_for_events',
            'timestamp': datetime.now().isoformat(),
            'zeromq_port': 5560,
            'firewall_port': 5561,
            'protobuf_enabled': PROTOBUF_AVAILABLE,
            'zmq_enabled': ZMQ_AVAILABLE,
            'total_events': stats.get('total_events', 0),
            'events_with_gps': stats.get('events_with_gps', 0),
            'firewall_enabled': self.shared_data['firewall_sender'] is not None,
            'communication_protocol': 'protobuf' if PROTOBUF_AVAILABLE else 'json_fallback',
            'handshakes_received': stats.get('handshakes_received', 0),
            'nodes_registered': stats.get('nodes_registered', 0)
        }
        self.send_json(health_data)

    def send_json(self, data, status=200):
        """Enviar respuesta JSON"""
        json_data = json.dumps(data, indent=2, default=str)
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-length', str(len(json_data.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(json_data.encode('utf-8'))

    def serve_dashboard(self):
        """Dashboard HTML interactivo"""
        html = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SCADA Real - ML Enhanced + Firewall (PROTOBUF)</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css" />
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3a 100%);
            color: #fff; overflow: hidden;
        }
        .header { 
            background: rgba(0, 0, 0, 0.9); padding: 0.8rem;
            border-bottom: 2px solid #00ff88;
            display: flex; justify-content: space-between; align-items: center;
        }
        .header h1 { color: #00ff88; font-size: 1.3rem; }
        .status { display: flex; gap: 15px; align-items: center; font-size: 0.85rem; }
        .status-item { 
            background: rgba(255, 255, 255, 0.1);
            padding: 4px 8px; border-radius: 12px;
        }
        .status-dot { 
            width: 8px; height: 8px; border-radius: 50%;
            display: inline-block; margin-right: 5px;
            animation: pulse 2s infinite;
        }
        .online { background: #00ff88; }
        .warning { background: #ffaa00; }
        .error { background: #ff4444; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }

        .main-container { 
            display: grid; grid-template-columns: 1fr 380px;
            height: calc(100vh - 70px); gap: 1rem; padding: 1rem;
        }
        .map-container { position: relative; border-radius: 10px; overflow: hidden; }
        #map { height: 100%; width: 100%; }

        .sidebar { 
            background: rgba(0, 0, 0, 0.8); border-radius: 10px;
            padding: 1rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem;
        }

        .stats-grid {
            display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 10px;
            text-align: center; border-left: 3px solid #00ff88;
        }
        .stat-value { font-size: 1.4rem; font-weight: bold; color: #00ff88; }
        .stat-label { font-size: 0.8rem; color: #ccc; margin-top: 3px; }

        .events-section { flex: 1; }
        .events-header { color: #00ff88; font-size: 1.1rem; margin-bottom: 0.5rem; }
        .event-item { 
            background: rgba(255, 255, 255, 0.1);
            border-left: 3px solid #00ff88; padding: 8px;
            margin-bottom: 8px; border-radius: 5px; font-size: 0.85rem;
            animation: slideIn 0.5s ease; cursor: pointer;
            transition: all 0.3s ease;
        }
        .event-item:hover { 
            background: rgba(255, 255, 255, 0.2);
            border-left-color: #ff8800;
            transform: translateX(5px);
        }
        .event-item.high-risk {
            border-left-color: #ff4444;
            background: rgba(255, 68, 68, 0.1);
        }
        .event-item.high-risk:hover {
            background: rgba(255, 68, 68, 0.2);
            box-shadow: 0 0 10px rgba(255, 68, 68, 0.3);
        }
        .event-time { font-size: 0.75rem; color: #aaa; }
        .event-ip { font-weight: bold; color: #00ff88; font-family: monospace; }
        .event-details { font-size: 0.75rem; color: #ccc; margin-top: 3px; }
        .gps-badge { 
            background: #00ff88; color: #000; padding: 1px 4px; 
            border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }
        .ml-badge {
            background: #ff8800; color: #fff; padding: 1px 4px;
            border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }
        .protobuf-badge {
            background: #8800ff; color: #fff; padding: 1px 4px;
            border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }
        .handshake-badge {
            background: #00ffff; color: #000; padding: 1px 4px;
            border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }
        .risk-badge {
            padding: 1px 4px; border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }
        .risk-low { background: #4CAF50; color: white; }
        .risk-medium { background: #FF9800; color: white; }
        .risk-high { background: #F44336; color: white; }

        .block-button {
            background: #ff4444; color: white; border: none;
            padding: 4px 8px; border-radius: 3px; font-size: 0.7rem;
            cursor: pointer; margin-left: 5px; opacity: 0.8;
            transition: opacity 0.3s ease;
        }
        .block-button:hover {
            opacity: 1;
            background: #ff2222;
        }

        .ml-models {
            background: rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 10px;
        }
        .ml-model { 
            background: rgba(0, 255, 136, 0.2); color: #00ff88;
            padding: 3px 8px; border-radius: 15px; font-size: 0.75rem;
            display: inline-block; margin: 2px;
        }

        .btn { 
            background: #00ff88; color: #0f0f23; padding: 6px 12px;
            border: none; border-radius: 5px; cursor: pointer;
            margin: 3px; font-weight: bold; font-size: 0.8rem;
        }
        .btn:hover { background: #00cc66; }

        /* Modal styles */
        .modal {
            display: none; position: fixed; z-index: 10000;
            left: 0; top: 0; width: 100%; height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
        }
        .modal-content {
            background: linear-gradient(135deg, #1a1a3a 0%, #2a2a4a 100%);
            margin: 5% auto; padding: 20px; border-radius: 10px;
            width: 80%; max-width: 600px; color: #fff;
            border: 2px solid #ff4444;
        }
        .modal-header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 20px; color: #ff4444;
        }
        .close {
            color: #aaa; font-size: 28px; font-weight: bold;
            cursor: pointer; line-height: 1;
        }
        .close:hover { color: #fff; }
        .command-preview {
            background: rgba(0, 0, 0, 0.5); padding: 15px;
            border-radius: 5px; font-family: monospace;
            margin: 15px 0; color: #00ff88;
            border-left: 3px solid #ff4444;
        }
        .modal-buttons {
            display: flex; gap: 10px; margin-top: 20px;
        }
        .btn-danger { background: #ff4444; color: white; }
        .btn-danger:hover { background: #ff2222; }
        .btn-cancel { background: #666; color: white; }
        .btn-cancel:hover { background: #555; }

        @keyframes slideIn { from { opacity: 0; transform: translateX(-20px); } to { opacity: 1; transform: translateX(0); } }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SCADA Real - ML Enhanced + Firewall (PROTOBUF REAL)</h1>
        <div class="status">
            <div class="status-item">
                <span class="status-dot online" id="zmq-status"></span>
                <span>ZeroMQ</span>
            </div>
            <div class="status-item">
                <span class="status-dot" id="ml-status"></span>
                <span>ML Active</span>
            </div>
            <div class="status-item">
                <span class="status-dot" id="firewall-status"></span>
                <span>Firewall</span>
            </div>
            <div class="status-item">
                <span class="status-dot" id="protobuf-status"></span>
                <span>Protobuf</span>
            </div>
            <div class="status-item">
                Eventos: <span id="total-events">0</span>
            </div>
            <div class="status-item">
                Nodos: <span id="nodes-registered">0</span>
            </div>
            <div class="status-item">
                ML: <span id="ml-events">0</span>
            </div>
        </div>
    </div>

    <div class="main-container">
        <div class="map-container">
            <div id="map"></div>
        </div>

        <div class="sidebar">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" id="events-per-minute">0</div>
                    <div class="stat-label">Eventos/min</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="anomaly-events">0</div>
                    <div class="stat-label">Anomalías</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="high-risk-events">0</div>
                    <div class="stat-label">Alto Riesgo</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="gps-percentage">0%</div>
                    <div class="stat-label">Con GPS</div>
                </div>
            </div>

            <div class="ml-models">
                <h4 style="color: #00ff88; margin-bottom: 8px; font-size: 0.9rem;">🤖 Modelos ML Activos</h4>
                <div id="ml-models-list">
                    <div class="ml-model">Cargando...</div>
                </div>
            </div>

            <div class="events-section">
                <div class="events-header">🚨 Eventos ML Enriquecidos (Protobuf Real)</div>
                <div id="events-list">
                    <div class="event-item">
                        <div class="event-time">Conectando a ZeroMQ 5560...</div>
                        <div class="event-ip">Esperando eventos protobuf enriquecidos por ML</div>
                    </div>
                </div>
            </div>

            <div style="margin-top: auto;">
                <button class="btn" onclick="refreshData()">🔄 Actualizar</button>
                <button class="btn" onclick="clearMap()">🗺️ Limpiar Mapa</button>
                <button class="btn" onclick="showFirewallLog()">🔥 Log Firewall</button>
                <button class="btn" onclick="showPendingCommands()">📋 Pendientes</button>
            </div>
        </div>
    </div>

    <!-- Modal de confirmación de firewall -->
    <div id="firewallModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>🔥 Bloquear Evento de Alto Riesgo (→ Protobuf Real)</h2>
                <span class="close" onclick="closeFirewallModal()">&times;</span>
            </div>
            <div id="modal-event-info"></div>
            <div class="command-preview" id="command-preview">
                Generando comando de firewall protobuf...
            </div>
            <div class="modal-buttons">
                <button class="btn btn-danger" onclick="executeFirewallCommand()">🛡️ Bloquear IP (Protobuf Batch)</button>
                <button class="btn btn-cancel" onclick="closeFirewallModal()">❌ Cancelar</button>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
    <script>
        class MLFirewallDashboard {
            constructor() {
                this.map = null;
                this.markers = new Map();
                this.lastEventCount = 0;
                this.allEvents = [];
                this.selectedEvent = null;

                this.initMap();
                this.startPeriodicUpdates();
                this.log('🛡️ Dashboard ML + Firewall (PROTOBUF REAL) inicializado');
            }

            initMap() {
                this.map = L.map('map').setView([40.0, 0.0], 2);
                L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                    attribution: '©OpenStreetMap, ©CartoDB'
                }).addTo(this.map);
            }

            log(message) {
                const now = new Date().toLocaleTimeString();
                console.log(`[${now}] ${message}`);
            }

            async refreshData() {
                try {
                    const [statsResponse, eventsResponse, gpsResponse, healthResponse] = await Promise.all([
                        fetch('/api/stats'),
                        fetch('/api/events'),
                        fetch('/api/events/gps'),
                        fetch('/health')
                    ]);

                    const stats = await statsResponse.json();
                    const eventsData = await eventsResponse.json();
                    const gpsData = await gpsResponse.json();
                    const healthData = await healthResponse.json();

                    this.updateStats(stats);
                    this.updateEvents(eventsData.events);
                    this.updateMap(gpsData.events);
                    this.updateStatusIndicators(stats, eventsData, healthData);

                } catch (e) {
                    this.log('❌ Error actualizando datos: ' + e.message);
                }
            }

            updateStatusIndicators(stats, eventsData, healthData) {
                const zmqStatus = document.getElementById('zmq-status');
                const mlStatus = document.getElementById('ml-status');
                const firewallStatus = document.getElementById('firewall-status');
                const protobufStatus = document.getElementById('protobuf-status');

                // Estado ZMQ
                if (stats.total_events > this.lastEventCount) {
                    zmqStatus.className = 'status-dot online';

                    // Estado ML
                    const hasMLScores = eventsData.events && eventsData.events.some(e => 
                        (e.anomaly_score && e.anomaly_score > 0) || (e.risk_score && e.risk_score > 0)
                    );
                    mlStatus.className = hasMLScores ? 'status-dot online' : 'status-dot warning';
                } else {
                    zmqStatus.className = 'status-dot warning';
                    mlStatus.className = 'status-dot warning';
                }

                // Estado del firewall
                firewallStatus.className = healthData.firewall_enabled ? 'status-dot online' : 'status-dot error';

                // Estado protobuf
                if (healthData.communication_protocol === 'protobuf') {
                    protobufStatus.className = 'status-dot online';
                } else {
                    protobufStatus.className = 'status-dot warning';
                }

                this.lastEventCount = stats.total_events || 0;
            }

            updateStats(stats) {
                document.getElementById('total-events').textContent = stats.total_events || 0;
                document.getElementById('nodes-registered').textContent = stats.nodes_registered || 0;
                document.getElementById('events-per-minute').textContent = stats.events_per_minute || 0;
                document.getElementById('anomaly-events').textContent = stats.anomaly_events || 0;
                document.getElementById('high-risk-events').textContent = stats.high_risk_events || 0;
                document.getElementById('gps-percentage').textContent = 
                    (stats.gps_percentage || 0).toFixed(1) + '%';

                const mlEvents = this.allEvents.filter(e => e.ml_enhanced).length;
                document.getElementById('ml-events').textContent = mlEvents;

                const mlContainer = document.getElementById('ml-models-list');
                if (stats.ml_models_active && stats.ml_models_active.length > 0) {
                    mlContainer.innerHTML = stats.ml_models_active
                        .map(model => `<div class="ml-model">${model}</div>`)
                        .join('');
                } else {
                    mlContainer.innerHTML = '<div class="ml-model">Esperando ML...</div>';
                }
            }

            updateEvents(events) {
                if (!events || events.length === 0) {
                    document.getElementById('events-list').innerHTML = `
                        <div class="event-item">
                            <div class="event-time">Sin eventos recientes</div>
                            <div class="event-ip">Verifica que el ML Detector esté enviando protobuf al puerto 5560</div>
                        </div>
                    `;
                    return;
                }

                this.allEvents = events;
                const eventsList = document.getElementById('events-list');
                eventsList.innerHTML = '';

                events.slice(-20).reverse().forEach((event) => {
                    const eventDiv = document.createElement('div');
                    eventDiv.className = 'event-item';
                    if (event.risk_level === 'high') {
                        eventDiv.className += ' high-risk';
                    }

                    const time = new Date(event.timestamp).toLocaleTimeString();
                    const gpsBadge = event.has_gps ? '<span class="gps-badge">GPS</span>' : '';
                    const mlBadge = event.ml_enhanced ? '<span class="ml-badge">ML</span>' : '';
                    const protobufBadge = event.source === 'protobuf' ? '<span class="protobuf-badge">PB</span>' : '';
                    const handshakeBadge = event.is_initial_handshake ? '<span class="handshake-badge">HS</span>' : '';

                    let riskBadge = '';
                    if (event.risk_level === 'high') {
                        riskBadge = '<span class="risk-badge risk-high">ALTO</span>';
                    } else if (event.risk_level === 'medium') {
                        riskBadge = '<span class="risk-badge risk-medium">MEDIO</span>';
                    } else if (event.risk_level === 'low') {
                        riskBadge = '<span class="risk-badge risk-low">BAJO</span>';
                    }

                    // Botón de bloqueo para eventos de alto riesgo
                    const blockButton = (event.risk_level === 'high' || event.risk_score > 0.7) ? 
                        '<button class="block-button" data-event-id="' + event.event_id + '">🛡️ BLOQUEAR</button>' : '';

                    eventDiv.innerHTML = `
                        <div class="event-time">${time} | ${event.agent_id}</div>
                        <div class="event-ip">${event.source_ip} → ${event.target_ip}:${event.dest_port}${gpsBadge}${mlBadge}${protobufBadge}${handshakeBadge}${riskBadge}${blockButton}</div>
                        <div class="event-details">
                            A: ${(event.anomaly_score * 100).toFixed(1)}% | 
                            R: ${(event.risk_score * 100).toFixed(1)}% | 
                            ${event.packet_size}B
                            ${event.description ? ` | ${event.description}` : ''}
                            ${event.so_identifier ? ` | ${event.so_identifier}` : ''}
                        </div>
                    `;

                    // Agregar event listener para click en el evento
                    eventDiv.addEventListener('click', (e) => {
                        if (!e.target.classList.contains('block-button')) {
                            this.showEventDetails(event);
                        }
                    });

                    // Event listener para el botón de bloqueo
                    const blockBtn = eventDiv.querySelector('.block-button');
                    if (blockBtn) {
                        blockBtn.addEventListener('click', (e) => {
                            e.stopPropagation();
                            this.showFirewallModal(event);
                        });
                    }

                    eventsList.appendChild(eventDiv);
                });
            }

            updateMap(gpsEvents) {
                if (!gpsEvents || gpsEvents.length === 0) return;

                gpsEvents.forEach(event => {
                    if (event.latitude && event.longitude) {
                        const markerId = `${event.event_id}_${event.latitude}_${event.longitude}`;

                        if (!this.markers.has(markerId)) {
                            let markerColor = '#00ff88';
                            let markerSize = 8;

                            if (event.risk_level === 'high') {
                                markerColor = '#ff4444';
                                markerSize = 12;
                            } else if (event.risk_level === 'medium') {
                                markerColor = '#ffaa00';
                                markerSize = 10;
                            }

                            const marker = L.circleMarker([event.latitude, event.longitude], {
                                color: markerColor,
                                fillColor: markerColor,
                                fillOpacity: 0.8,
                                radius: markerSize,
                                weight: 2
                            }).addTo(this.map);

                            const protocolBadge = event.source === 'protobuf' ? ' [PROTOBUF]' : '';
                            const handshakeBadge = event.is_initial_handshake ? ' [HANDSHAKE]' : '';

                            const popupContent = `
                                <div style="color: #000;">
                                    <strong>🌐 Evento ML${protocolBadge}${handshakeBadge}</strong><br>
                                    <strong>Origen:</strong> ${event.source_ip}<br>
                                    <strong>Destino:</strong> ${event.target_ip}:${event.dest_port}<br>
                                    <strong>Riesgo:</strong> ${(event.risk_score * 100).toFixed(1)}%<br>
                                    <strong>Anomalía:</strong> ${(event.anomaly_score * 100).toFixed(1)}%<br>
                                    <strong>Agente:</strong> ${event.agent_id}<br>
                                    <strong>SO:</strong> ${event.so_identifier || 'unknown'}<br>
                                    <strong>Hostname:</strong> ${event.node_hostname || 'unknown'}<br>
                                    ${event.description ? `<strong>Desc:</strong> ${event.description}<br>` : ''}
                                    <strong>Tiempo:</strong> ${new Date(event.timestamp).toLocaleString()}<br>
                                    ${(event.risk_level === 'high' || event.risk_score > 0.7) ? 
                                        '<button onclick="dashboard.showFirewallModal(' + JSON.stringify(event).replace(/"/g, '&quot;') + ')" style="background: #ff4444; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; margin-top: 5px;">🛡️ Bloquear IP (Protobuf)</button>' : ''}
                                </div>
                            `;

                            marker.bindPopup(popupContent, { maxWidth: 300 });
                            this.markers.set(markerId, marker);

                            // Event listener para click en marcador
                            marker.on('click', () => {
                                this.showEventDetails(event);
                            });
                        }
                    }
                });
            }

            showEventDetails(event) {
                this.log(`📋 Detalles del evento: ${event.source_ip} → ${event.target_ip} [${event.source || 'unknown'}]`);
                this.log(`🖥️  Nodo: ${event.node_hostname} (${event.so_identifier})`);
            }

            showFirewallModal(event) {
                this.selectedEvent = event;
                const modal = document.getElementById('firewallModal');
                const eventInfo = document.getElementById('modal-event-info');
                const commandPreview = document.getElementById('command-preview');

                eventInfo.innerHTML = `
                    <h3>Evento Detectado (${event.source || 'unknown'}):</h3>
                    <p><strong>IP Origen:</strong> ${event.source_ip}</p>
                    <p><strong>IP Destino:</strong> ${event.target_ip}:${event.dest_port}</p>
                    <p><strong>Riesgo:</strong> ${(event.risk_score * 100).toFixed(1)}%</p>
                    <p><strong>Anomalía:</strong> ${(event.anomaly_score * 100).toFixed(1)}%</p>
                    <p><strong>Agente:</strong> ${event.agent_id}</p>
                    <p><strong>SO:</strong> ${event.so_identifier || 'unknown'}</p>
                    <p><strong>Hostname:</strong> ${event.node_hostname || 'unknown'}</p>
                    <p><strong>Fuente:</strong> ${event.source === 'protobuf' ? 'Protobuf ✅' : 'JSON (fallback)'}</p>
                `;

                commandPreview.innerHTML = 'Generando comando de firewall protobuf batch inteligente...';

                modal.style.display = 'block';

                // Generar comando de firewall
                this.generateFirewallCommand(event);
            }

            async generateFirewallCommand(event) {
                try {
                    const response = await fetch('/api/firewall/generate', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({event: event})
                    });

                    const result = await response.json();
                    const commandPreview = document.getElementById('command-preview');

                    if (result.success) {
                        const cmd = result.suggested_command;
                        commandPreview.innerHTML = `
                            <strong>Comando sugerido (será convertido a FirewallCommandBatch):</strong><br>
                            ${cmd.firewall_rule.command}<br><br>
                            <strong>Acción:</strong> ${cmd.action}<br>
                            <strong>Duración:</strong> ${cmd.firewall_rule.duration}<br>
                            <strong>Prioridad:</strong> ${cmd.firewall_rule.priority}<br>
                            <strong>Análisis:</strong> ${cmd.analysis.threat_type}<br>
                            <strong>Confianza:</strong> ${cmd.analysis.confidence.toFixed(1)}%<br>
                            <em>📦 Este comando se enviará como FirewallCommandBatch protobuf al puerto 5561</em>
                        `;
                        this.suggestedCommand = cmd;
                    } else {
                        commandPreview.textContent = 'Error generando comando: ' + result.error;
                    }
                } catch (e) {
                    const commandPreview = document.getElementById('command-preview');
                    commandPreview.textContent = 'Error de conexión: ' + e.message;
                }
            }

            async executeFirewallCommand() {
                if (!this.selectedEvent || !this.suggestedCommand) return;

                try {
                    const response = await fetch('/api/firewall/block', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            event_id: this.selectedEvent.event_id,
                            target_ip: this.selectedEvent.source_ip,
                            source_agent: this.selectedEvent.agent_id,
                            action: this.suggestedCommand.action,
                            target_port: this.selectedEvent.dest_port,
                            duration_seconds: this.suggestedCommand.duration_seconds,
                            reason: `High risk event: ${(this.selectedEvent.risk_score * 100).toFixed(1)}% risk score`,
                            priority: this.suggestedCommand.priority,
                            dry_run: true,
                            ml_scores: {
                                anomaly_score: this.selectedEvent.anomaly_score,
                                risk_score: this.selectedEvent.risk_score
                            },
                            packet_info: `Packet from ${this.selectedEvent.source_ip} to ${this.selectedEvent.target_ip}:${this.selectedEvent.dest_port}`
                        })
                    });

                    const result = await response.json();

                    if (result.success) {
                        this.log(`🛡️ Comando protobuf batch enviado: ${result.command_id}`);
                        alert(`✅ Comando de firewall enviado exitosamente como PROTOBUF BATCH\\nComando ID: ${result.command_id}`);
                    } else {
                        alert(`❌ Error: ${result.error}`);
                    }

                    this.closeFirewallModal();

                } catch (e) {
                    alert(`❌ Error de conexión: ${e.message}`);
                }
            }

            closeFirewallModal() {
                document.getElementById('firewallModal').style.display = 'none';
                this.selectedEvent = null;
                this.suggestedCommand = null;
            }

            async showFirewallLog() {
                try {
                    const response = await fetch('/api/firewall/log');
                    const result = await response.json();

                    let logText = 'LOG DE COMANDOS DE FIREWALL (PROTOBUF BATCH):\\n\\n';
                    result.commands.forEach(cmd => {
                        logText += `${cmd.timestamp} - ${cmd.action} - ${cmd.target_node} (${cmd.command_count} cmd)\\n`;
                    });

                    alert(logText || 'No hay comandos en el log');
                } catch (e) {
                    alert('Error obteniendo log: ' + e.message);
                }
            }

            async showPendingCommands() {
                try {
                    const response = await fetch('/api/firewall/pending');
                    const result = await response.json();

                    const summary = result.summary;
                    let text = `COMANDOS PENDIENTES (PROTOBUF BATCH):\\n\\n`;
                    text += `Eventos con comandos: ${summary.total_events_with_commands || 0}\\n`;
                    text += `Total comandos: ${summary.total_commands || 0}\\n`;

                    if (summary.oldest_pending) {
                        text += `Más antiguo: ${summary.oldest_pending.toFixed(1)}s\\n`;
                    }

                    text += '\\nEstos comandos serán enviados como FirewallCommandBatch protobuf al simple_firewall_agent.py';

                    alert(text);
                } catch (e) {
                    alert('Error obteniendo comandos pendientes: ' + e.message);
                }
            }

            clearMap() {
                this.markers.forEach(marker => {
                    this.map.removeLayer(marker);
                });
                this.markers.clear();
                this.log('🗺️ Mapa limpiado');
            }

            startPeriodicUpdates() {
                setInterval(() => this.refreshData(), 3000);
                setTimeout(() => this.refreshData(), 1000);
            }
        }

        let dashboard;

        function refreshData() { dashboard.refreshData(); }
        function clearMap() { dashboard.clearMap(); }
        function showFirewallLog() { dashboard.showFirewallLog(); }
        function showPendingCommands() { dashboard.showPendingCommands(); }
        function closeFirewallModal() { dashboard.closeFirewallModal(); }
        function executeFirewallCommand() { dashboard.executeFirewallCommand(); }

        document.addEventListener('DOMContentLoaded', function() {
            dashboard = new MLFirewallDashboard();
            console.log('🛡️ Dashboard ML Enhanced + Firewall - ZeroMQ 5560/5561 (PROTOBUF REAL)');
            console.log('🤖 Mostrando eventos protobuf con ML scores en tiempo real');
            console.log('🔥 Comandos de firewall protobuf batch por puerto 5561');
            console.log('📦 Usando estructuras protobuf reales con enums');
        });

        // Cerrar modal con ESC
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeFirewallModal();
            }
        });

        // Cerrar modal clickeando fuera
        window.addEventListener('click', function(e) {
            const modal = document.getElementById('firewallModal');
            if (e.target === modal) {
                closeFirewallModal();
            }
        });
    </script>
</body>
</html>"""

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-length', str(len(html.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def log_message(self, format, *args):
        pass


def main():
    """Función principal del dashboard"""
    print("🛡️ DASHBOARD SCADA REAL - ZeroMQ 5560 + Firewall 5561 (PROTOBUF REAL)")
    print("=" * 75)
    print("🎯 Conectándose a:")
    print("   📡 ZeroMQ 5560 (eventos enriquecidos por ML - PROTOBUF)")
    print("   🔥 ZeroMQ 5561 (comandos de firewall - PROTOBUF)")
    print("   🤖 Eventos con anomaly_score y risk_score")
    print("   🗺️ Coordenadas GPS cuando disponibles")
    print("   🛡️ Respuesta automática a amenazas")
    print("   📦 Comunicación usando network_event_extended_fixed_pb2")
    print("   🔥 Comandos usando firewall_commands_pb2 con enums")
    print("   📋 Soporte para FirewallCommandBatch")
    print("")

    # Verificar puerto disponible
    host = '127.0.0.1'
    port = 8000

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            print(f"⚠️ Puerto {port} ocupado, usando 8001...")
            port = 8001

        # Crear servidor
        server = HTTPServer((host, port), DashboardHandler)

        # Inicializar firewall sender
        if ZMQ_AVAILABLE:
            firewall_sender = FirewallCommandSender()
            DashboardHandler.shared_data['firewall_sender'] = firewall_sender
        else:
            logger.warning("ZMQ no disponible - Firewall sender deshabilitado")

        # Inicializar listener ZeroMQ
        if ZMQ_AVAILABLE:
            zmq_listener = ZeroMQListener(DashboardHandler)
            DashboardHandler.shared_data['zmq_listener'] = zmq_listener
            zmq_listener.start()
        else:
            logger.warning("ZMQ no disponible - Listener deshabilitado")

        print(f"🚀 Dashboard iniciado en http://{host}:{port}")
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"📡 API Stats: http://{host}:{port}/api/stats")
        print(f"🗺️ Eventos GPS: http://{host}:{port}/api/events/gps")
        print(f"🔥 Firewall Log: http://{host}:{port}/api/firewall/log")
        print(f"📋 Comandos Pendientes: http://{host}:{port}/api/firewall/pending")
        print("")
        print("✅ CONFIGURACIÓN:")
        print(f"   🔌 ZeroMQ disponible: {ZMQ_AVAILABLE}")
        print(f"   📦 Protobuf disponible: {PROTOBUF_AVAILABLE}")
        if ZMQ_AVAILABLE:
            print("   🔌 ZeroMQ puerto 5560 (entrada - PROTOBUF)")
            print("   🔥 ZeroMQ puerto 5561 (salida firewall - PROTOBUF)")
        if PROTOBUF_AVAILABLE:
            print("   📦 network_event_extended_fixed_pb2 ✅")
            print("   📦 firewall_commands_pb2 ✅")
            print("   🔥 FirewallCommandBatch ✅")
            print("   📋 CommandAction & CommandPriority enums ✅")
        print("")
        print("🎯 FUNCIONALIDADES:")
        print("   ✅ Recepción de eventos protobuf desde ML detector")
        print("   ✅ Procesamiento de handshakes iniciales")
        print("   ✅ Generación automática de comandos firewall")
        print("   ✅ Envío de FirewallCommandBatch protobuf")
        print("   ✅ Modal de confirmación para bloqueos")
        print("   ✅ Gestión de comandos pendientes")
        print("   ✅ Indicador de nodos registrados")
        print("   ✅ Soporte para todos los campos del protobuf")
        print("")
        print("🛑 Presiona Ctrl+C para detener")

        server.serve_forever()

    except KeyboardInterrupt:
        print("\n🛑 Dashboard detenido por usuario")
        if DashboardHandler.shared_data.get('zmq_listener'):
            DashboardHandler.shared_data['zmq_listener'].stop()
        if DashboardHandler.shared_data.get('firewall_sender'):
            DashboardHandler.shared_data['firewall_sender'].close()
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()