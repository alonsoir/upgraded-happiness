#!/usr/bin/env python3
"""
🛡️ Dashboard SCADA REAL - ZeroMQ + Mapa Interactivo + Comandos Firewall
REFACTORIZADO: Lee TODA la configuración desde JSON
Usa dashboard_config.json para TODA la configuración
Conectado a eventos enriquecidos por ML (puerto configurable)
Envía comandos de firewall (puerto configurable)
"""

import json
import logging
import socket
import threading
import time
import os
import sys
import argparse
from collections import defaultdict, deque
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import uuid
from typing import Dict

# Configurar logging básico (se reconfigurará desde JSON)
logging.basicConfig(level=logging.INFO)
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
    """Generador de comandos de firewall configurado desde JSON"""

    def __init__(self, firewall_config: Dict):
        """Inicializar generador con configuración JSON"""
        self.config = firewall_config

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

        # Reglas de amenazas desde configuración JSON
        self.threat_rules = self.config.get('threat_rules', {})

        # Configuración de detección automática
        self.auto_threat_detection = self.config.get('auto_threat_detection', True)
        self.require_manual_approval = self.config.get('require_manual_approval', True)
        self.max_pending_commands = self.config.get('max_pending_commands', 100)

        # Umbrales desde configuración
        self.threat_thresholds = self.config.get('threat_thresholds', {})
        self.high_risk_score = self.threat_thresholds.get('high_risk_score', 0.8)
        self.critical_risk_score = self.threat_thresholds.get('critical_risk_score', 0.9)
        self.anomaly_threshold = self.threat_thresholds.get('anomaly_threshold', 0.7)

        logger.info("🔥 FirewallCommandGenerator initialized from JSON config")
        logger.info(f"Auto detection: {self.auto_threat_detection}")
        logger.info(f"Manual approval: {self.require_manual_approval}")
        logger.info(f"Threat rules: {len(self.threat_rules)}")

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
        """Analiza un evento y genera comandos de firewall usando configuración"""
        if not self.auto_threat_detection:
            return []

        commands = []

        # Análisis de amenazas usando configuración
        threat_type = self.detect_threat_type(event_data)

        if threat_type and threat_type in self.threat_rules:
            # Verificar si debe aplicarse automáticamente
            rule = self.threat_rules[threat_type]
            if not self.require_manual_approval and rule.get('auto_apply', False):
                # Generar comando basado en el tipo de amenaza
                command = self.create_firewall_command_protobuf(event_data, threat_type)
                if command:
                    commands.append(command)

        return commands

    def detect_threat_type(self, event_data) -> str:
        """Detecta el tipo de amenaza basado en configuración"""

        # Anomalía alta usando umbral configurado
        anomaly_score = event_data.get('anomaly_score', 0)
        if anomaly_score > self.anomaly_threshold:
            return 'anomaly_high'

        # Riesgo crítico usando umbral configurado
        risk_score = event_data.get('risk_score', 0)
        if risk_score > self.critical_risk_score:
            return 'brute_force'
        elif risk_score > self.high_risk_score:
            return 'suspicious_port'

        # Puerto sospechoso usando configuración del dashboard
        dest_port = event_data.get('dest_port', 0)
        suspicious_ports = self.config.get('suspicious_ports', [22, 23, 135, 139, 445])
        if dest_port in suspicious_ports:
            return 'suspicious_port'

        # Patrones de eventos según configuración
        event_type = event_data.get('event_type', '')
        description = event_data.get('description', '').lower()

        if 'flood' in description or 'brute' in description:
            return 'rate_limit_exceeded'
        elif 'scan' in description:
            return 'port_scan'

        return None

    def create_firewall_command_protobuf(self, event_data, threat_type):
        """Crea un comando de firewall usando protobuf real y configuración"""
        if not PROTOBUF_AVAILABLE:
            return None

        if threat_type not in self.threat_rules:
            return None

        rule = self.threat_rules[threat_type]
        source_ip = event_data.get('source_ip')
        dest_port = event_data.get('dest_port', 0)

        if not source_ip:
            return None

        # Crear comando protobuf usando configuración
        command = firewall_commands_pb2.FirewallCommand()
        command.command_id = str(uuid.uuid4())
        command.action = self.action_mapping[rule['action']]
        command.target_ip = source_ip

        if rule['action'] in ['block_port', 'unblock_port']:
            command.target_port = dest_port
        else:
            command.target_port = 0

        command.duration_seconds = rule['duration_seconds']
        command.reason = f"Detected {threat_type} from {source_ip}"
        command.priority = self.priority_mapping[rule['priority']]

        # Dry run basado en configuración
        command.dry_run = rule.get('dry_run', True)

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
        batch.dry_run_all = True  # Seguro por defecto
        batch.description = description
        batch.confidence_score = 0.8
        batch.expected_execution_time = len(commands) * 2

        # Agregar comandos al lote
        for command in commands:
            batch.commands.append(command)

        return batch

    def get_pending_commands_summary(self):
        """Retorna resumen de comandos pendientes"""
        # Implementación básica - se extenderá en la integración
        return {
            'total_events_with_commands': 0,
            'total_commands': 0,
            'oldest_pending': None
        }


class FirewallCommandSender:
    """Cliente ZeroMQ para enviar comandos configurado desde JSON"""

    def __init__(self, network_config: Dict):
        """Inicializar sender con configuración de red"""
        self.config = network_config

        if not ZMQ_AVAILABLE:
            logger.error("ZMQ no disponible para FirewallCommandSender")
            self.socket = None
            self.context = None
            return

        # Configuración desde JSON
        self.output_port = self.config['zmq_output_port']
        self.max_message_size = self.config.get('max_message_size', 1048576)

        self.context = zmq.Context(self.config.get('zmq_context_threads', 1))
        self.socket = self.context.socket(zmq.PUSH)

        try:
            output_addr = f"tcp://localhost:{self.output_port}"
            self.socket.connect(output_addr)
            self.command_log = deque(maxlen=100)
            logger.info(f"🔥 Firewall command sender conectado a {output_addr} (PROTOBUF)")
        except Exception as e:
            logger.error(f"Error conectando al puerto {self.output_port}: {e}")
            self.socket = None

    def send_firewall_command_batch(self, batch):
        """Enviar lote de comandos usando protobuf"""
        if not self.socket or not PROTOBUF_AVAILABLE:
            logger.error("Socket o protobuf no disponible para enviar comando")
            return False

        try:
            # Enviar como protobuf serializado
            message = batch.SerializeToString()

            # Verificar tamaño del mensaje
            if len(message) > self.max_message_size:
                logger.warning(f"Mensaje muy grande: {len(message)} bytes (límite: {self.max_message_size})")
                return False

            self.socket.send(message)

            # Log local
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': 'firewall_batch_sent',
                'batch_id': batch.batch_id,
                'target_node': batch.target_node_id,
                'command_count': len(batch.commands),
                'generated_by': batch.generated_by,
                'message_size': len(message)
            }
            self.command_log.append(log_entry)

            logger.info(
                f"🔥 Lote protobuf enviado: {batch.batch_id} ({len(batch.commands)} comandos, {len(message)} bytes)")
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
    """Listener de ZeroMQ configurado desde JSON"""

    def __init__(self, dashboard_handler, network_config: Dict):
        """Inicializar listener con configuración JSON"""
        self.dashboard_handler = dashboard_handler
        self.config = network_config

        # Configuración de red desde JSON
        self.input_port = self.config['zmq_input_port']
        self.socket_timeout = self.config.get('zmq_socket_timeout', 5000)

        self.running = False
        self.context = None
        self.socket = None

        # Estadísticas del broker configuradas
        self.broker_stats = {
            'connection_time': None,
            'total_messages': 0,
            'bytes_received': 0,
            'last_message_time': None,
            'broker_health': 'unknown',
            'max_message_size': self.config.get('max_message_size', 1048576)
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
            'nodes_registered': 0,
            'protobuf_events': 0,
            'json_events': 0,
            'parsing_errors': 0
        }

    def start(self):
        """Iniciar conexión a ZeroMQ usando configuración"""
        if not ZMQ_AVAILABLE:
            logger.error("ZMQ no disponible para listener")
            return

        self.running = True

        try:
            self.context = zmq.Context(self.config.get('zmq_context_threads', 1))
            self.socket = self.context.socket(zmq.SUB)

            input_addr = f"tcp://localhost:{self.input_port}"
            self.socket.connect(input_addr)
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")
            self.socket.setsockopt(zmq.RCVTIMEO, self.socket_timeout)

            self.broker_stats['connection_time'] = datetime.now()

            logger.info(f"🔌 Conectado a ZeroMQ {input_addr} (eventos enriquecidos por ML - PROTOBUF)")

            # Thread de escucha
            thread = threading.Thread(target=self._listen_events, daemon=True)
            thread.start()

            logger.info("🎯 Dashboard iniciado - Esperando eventos enriquecidos protobuf...")

        except Exception as e:
            logger.error(f"❌ Error conectando a ZeroMQ: {e}")

    def _listen_events(self):
        """Escuchar eventos del puerto configurado (PROTOBUF)"""
        while self.running:
            try:
                message = self.socket.recv(zmq.NOBLOCK)

                # Estadísticas del broker
                self.broker_stats['total_messages'] += 1
                self.broker_stats['bytes_received'] += len(message)
                self.broker_stats['last_message_time'] = datetime.now()
                self.broker_stats['broker_health'] = 'healthy'

                # Verificar tamaño del mensaje
                if len(message) > self.broker_stats['max_message_size']:
                    logger.warning(f"Mensaje muy grande recibido: {len(message)} bytes")

                # Intentar parsear como protobuf
                if PROTOBUF_AVAILABLE:
                    try:
                        event = network_event_extended_fixed_pb2.NetworkEvent()
                        event.ParseFromString(message)
                        self._process_event_protobuf(event)
                        self.stats['protobuf_events'] += 1
                        continue
                    except Exception as e:
                        logger.debug(f"Error parsing protobuf: {e}")
                        self.stats['parsing_errors'] += 1

                # Fallback a JSON (no debería ocurrir)
                try:
                    event_data = json.loads(message.decode('utf-8'))
                    self._process_json_event(event_data)
                    self.stats['json_events'] += 1
                    logger.warning("Recibido evento en JSON - se esperaba protobuf")
                except Exception as e:
                    logger.error(f"Error parsing mensaje: {e}")
                    self.stats['parsing_errors'] += 1

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
            # Usar configuración para límite de eventos
            max_events = self.dashboard_handler.shared_data.get('max_events_buffer', 300)

            self.dashboard_handler.shared_data['events'].append(event)

            # Procesar evento con la integración de firewall
            if hasattr(self.dashboard_handler, 'firewall_integration'):
                self.dashboard_handler.firewall_integration.process_received_event(event)

            if len(self.dashboard_handler.shared_data['events']) > max_events:
                self.dashboard_handler.shared_data['events'] = \
                    self.dashboard_handler.shared_data['events'][-max_events:]

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
            'nodes_registered': self.stats['nodes_registered'],
            'protobuf_events': self.stats['protobuf_events'],
            'json_events': self.stats['json_events'],
            'parsing_errors': self.stats['parsing_errors']
        }

    def stop(self):
        """Detener listener"""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()


class DashboardFirewallIntegration:
    """Integración de firewall para el dashboard configurada desde JSON"""

    def __init__(self, dashboard_instance, firewall_config: Dict):
        """Inicializar integración con configuración JSON"""
        self.dashboard = dashboard_instance
        self.config = firewall_config
        self.command_generator = FirewallCommandGenerator(firewall_config)

        # Estado de la UI
        self.selected_events = []
        self.pending_commands = {}

        # Configuración desde JSON
        self.max_pending = self.config.get('max_pending_commands', 100)
        self.command_timeout = self.config.get('command_timeout_seconds', 300)

        logger.info("🔥 DashboardFirewallIntegration initialized from JSON config")

    def process_received_event(self, event_data):
        """Procesa un evento recibido y genera comandos protobuf"""

        # Registrar nodo si es handshake inicial
        self.command_generator.register_node(event_data)

        # Analizar amenazas automáticamente usando configuración
        if self.config.get('auto_threat_detection', True):
            suggested_commands = self.command_generator.analyze_threat_and_generate_commands(event_data)

            if suggested_commands:
                logger.info(
                    f"💡 {len(suggested_commands)} comando(s) protobuf sugerido(s) para evento {event_data.get('event_id', 'unknown')}")

                # Guardar comandos sugeridos para aprobación manual
                event_id = event_data.get('event_id')

                # Limpiar comandos antiguos
                self._cleanup_old_commands()

                # Verificar límite de comandos pendientes
                if len(self.pending_commands) < self.max_pending:
                    self.pending_commands[event_id] = {
                        'event': event_data,
                        'commands_protobuf': suggested_commands,  # Objetos protobuf
                        'timestamp': time.time()
                    }

    def _cleanup_old_commands(self):
        """Limpiar comandos antiguos basado en configuración"""
        current_time = time.time()
        expired_commands = []

        for event_id, command_data in self.pending_commands.items():
            if current_time - command_data['timestamp'] > self.command_timeout:
                expired_commands.append(event_id)

        for event_id in expired_commands:
            del self.pending_commands[event_id]

        if expired_commands:
            logger.info(f"🧹 Limpiados {len(expired_commands)} comandos expirados")

    def get_pending_commands_summary(self):
        """Retorna resumen de comandos pendientes"""
        self._cleanup_old_commands()

        summary = {
            'total_events_with_commands': len(self.pending_commands),
            'total_commands': sum(len(p['commands_protobuf']) for p in self.pending_commands.values()),
            'oldest_pending': None,
            'max_pending': self.max_pending,
            'timeout_seconds': self.command_timeout
        }

        if self.pending_commands:
            oldest = min(self.pending_commands.values(), key=lambda x: x['timestamp'])
            summary['oldest_pending'] = time.time() - oldest['timestamp']

        return summary


def load_dashboard_config(config_file=None):
    """Cargar configuración del dashboard desde JSON"""
    default_config = {
        "agent_info": {
            "name": "real_zmq_dashboard_with_firewall",
            "version": "1.0.0",
            "description": "Dashboard SCADA con ML y firewall integrado"
        },
        "network": {
            "http_host": "127.0.0.1",
            "http_port": 8000,
            "zmq_input_port": 5560,
            "zmq_output_port": 5561,
            "zmq_context_threads": 1,
            "zmq_socket_timeout": 5000,
            "max_message_size": 1048576
        },
        "dashboard": {
            "max_events_buffer": 300,
            "max_markers_on_map": 500,
            "event_display_limit": 50,
            "gps_events_limit": 30,
            "auto_refresh_interval": 3000,
            "enable_real_time_updates": True
        },
        "firewall_integration": {
            "enabled": True,
            "auto_threat_detection": True,
            "require_manual_approval": True,
            "max_pending_commands": 100,
            "command_timeout_seconds": 300,
            "threat_thresholds": {
                "high_risk_score": 0.8,
                "critical_risk_score": 0.9,
                "anomaly_threshold": 0.7,
                "auto_block_enabled": False
            }
        },
        "threat_rules": {
            "port_scan": {
                "action": "block_ip",
                "duration_seconds": 3600,
                "priority": "high",
                "auto_apply": False
            },
            "anomaly_high": {
                "action": "block_ip",
                "duration_seconds": 1800,
                "priority": "medium",
                "auto_apply": False
            },
            "rate_limit_exceeded": {
                "action": "rate_limit",
                "duration_seconds": 900,
                "priority": "medium",
                "rate_limit_rule": "10/min",
                "auto_apply": False
            },
            "suspicious_port": {
                "action": "block_ip",
                "duration_seconds": 3600,
                "priority": "high",
                "auto_apply": False
            },
            "brute_force": {
                "action": "block_ip",
                "duration_seconds": 7200,
                "priority": "critical",
                "auto_apply": False
            }
        },
        "suspicious_ports": [22, 23, 135, 139, 445, 1433, 3389, 5900, 502, 1911, 4840, 20000],
        "logging": {
            "level": "INFO",
            "file": "logs/dashboard.log",
            "max_size_mb": 50,
            "backup_count": 5,
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "console_output": True,
            "log_api_requests": True,
            "log_firewall_commands": True
        },
        "security": {
            "enable_cors": True,
            "allowed_origins": ["*"],
            "max_request_size": 1048576,
            "rate_limiting": {
                "enabled": False,
                "max_requests_per_minute": 120
            }
        },
        "map_settings": {
            "default_center_lat": 40.0,
            "default_center_lon": 0.0,
            "default_zoom": 2,
            "marker_colors": {
                "low_risk": "#4CAF50",
                "medium_risk": "#FF9800",
                "high_risk": "#F44336",
                "no_risk": "#00ff88"
            },
            "marker_sizes": {
                "low_risk": 8,
                "medium_risk": 10,
                "high_risk": 12,
                "no_risk": 6
            }
        },
        "geoip": {
            "database_path": "GeoLite2-City.mmdb",
            "cache_size": 10000,
            "cache_ttl_seconds": 3600
        }
    }

    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                user_config = json.load(f)

            # Merge recursivo de configuraciones
            def merge_config(base, update):
                for key, value in update.items():
                    if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                        merge_config(base[key], value)
                    else:
                        base[key] = value

            merge_config(default_config, user_config)
            logger.info(f"📄 Dashboard configuración cargada desde {config_file}")

        except Exception as e:
            logger.error(f"❌ Error cargando configuración dashboard: {e}")
            logger.info("⚠️ Usando configuración por defecto")
    else:
        if config_file:
            logger.warning(f"⚠️ Dashboard config no encontrado: {config_file}")
        logger.info("⚠️ Usando configuración dashboard por defecto")

    return default_config


class DashboardHandler(BaseHTTPRequestHandler):
    """Handler del dashboard con configuración JSON completa"""

    # Datos compartidos entre instancias del handler
    shared_data = {
        'events': [],
        'zmq_listener': None,
        'firewall_sender': None,
        'firewall_integration': None,
        'config': None,
        'max_events_buffer': 300,
        'auto_refresh_interval': 3000
    }

    def __init__(self, *args, **kwargs):
        # Inicializar integración de firewall si no existe
        if not self.shared_data['firewall_integration'] and self.shared_data['config']:
            firewall_config = self.shared_data['config']['firewall_integration']
            firewall_config.update(self.shared_data['config'].get('threat_rules', {}))
            firewall_config['suspicious_ports'] = self.shared_data['config'].get('suspicious_ports', [])

            self.shared_data['firewall_integration'] = DashboardFirewallIntegration(self, firewall_config)

        super().__init__(*args, **kwargs)

    @property
    def firewall_integration(self):
        return self.shared_data['firewall_integration']

    @property
    def config(self):
        return self.shared_data['config']

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

            # Usar configuración para límites de request
            if self.config and self.config['security'].get('max_request_size'):
                if len(post_data) > self.config['security']['max_request_size']:
                    self.send_json({'error': 'Request too large'}, status=413)
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
            if self.firewall_integration and event_id in self.firewall_integration.pending_commands:
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
        """Generar comando de firewall usando configuración"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))

            # Información del evento
            event_info = request_data.get('event', {})

            # Generar comando inteligente usando configuración
            suggested_command = self._generate_intelligent_firewall_command(event_info)

            self.send_json({
                'success': True,
                'suggested_command': suggested_command
            })

        except Exception as e:
            logger.error(f"❌ Error generando comando: {e}")
            self.send_json({'error': str(e)}, status=500)

    def _generate_intelligent_firewall_command(self, event_info):
        """Generar comando de firewall inteligente basado en configuración y evento"""
        target_ip = event_info.get('target_ip', 'unknown')
        source_ip = event_info.get('source_ip', 'unknown')
        risk_score = event_info.get('risk_score', 0)
        dest_port = event_info.get('dest_port', 0)
        protocol = event_info.get('protocol', 'TCP')

        # Usar configuración para determinar tipo de regla
        threat_thresholds = self.config.get('firewall_integration', {}).get('threat_thresholds', {})
        critical_threshold = threat_thresholds.get('critical_risk_score', 0.9)
        high_threshold = threat_thresholds.get('high_risk_score', 0.8)

        # Determinar tipo de regla basado en configuración
        if risk_score >= critical_threshold:
            action = 'BLOCK_IP'
            duration = 86400  # 24h
            priority = 'CRITICAL'
        elif risk_score >= high_threshold:
            action = 'BLOCK_IP'
            duration = 3600  # 1h
            priority = 'HIGH'
        else:
            action = 'RATE_LIMIT_IP'
            duration = 900  # 15min
            priority = 'MEDIUM'

        # Verificar puertos sospechosos desde configuración
        suspicious_ports = self.config.get('suspicious_ports', [])

        # Generar comando específico del protocolo
        if dest_port in suspicious_ports:
            if dest_port in [22, 3389]:  # SSH, RDP
                command = f"iptables -A INPUT -s {source_ip} -p {protocol.lower()} --dport {dest_port} -j DROP"
            else:
                command = f"iptables -A INPUT -s {source_ip} -j DROP"
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
                'confidence': min(risk_score * 100, 95),
                'used_configuration': True
            }
        }

    def _analyze_threat_type(self, event_info):
        """Analizar tipo de amenaza basado en configuración"""
        dest_port = event_info.get('dest_port', 0)
        packet_size = event_info.get('packet_size', 0)

        # Usar puertos sospechosos de configuración
        suspicious_ports = self.config.get('suspicious_ports', [])

        if dest_port == 22:
            return 'SSH_BRUTE_FORCE'
        elif dest_port == 3389:
            return 'RDP_ATTACK'
        elif dest_port in [80, 443]:
            return 'WEB_ATTACK'
        elif dest_port in suspicious_ports:
            return 'SUSPICIOUS_PORT_ACCESS'
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
                'count': len(log_data),
                'configuration': {
                    'output_port': self.config['network']['zmq_output_port'] if self.config else 'unknown',
                    'max_message_size': self.config['network'].get('max_message_size', 0) if self.config else 0
                }
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
                'pending_commands': pending,
                'configuration': {
                    'max_pending': summary['max_pending'],
                    'timeout_seconds': summary['timeout_seconds']
                }
            })
        else:
            self.send_json({'summary': {}, 'pending_commands': {}})

    def serve_stats(self):
        """Estadísticas del sistema usando configuración"""
        if self.shared_data['zmq_listener']:
            stats = self.shared_data['zmq_listener'].get_stats()
        else:
            stats = {'error': 'ZeroMQ listener not initialized'}

        # Agregar estadísticas de firewall
        if self.firewall_integration:
            stats['firewall_stats'] = self.firewall_integration.get_pending_commands_summary()

        # Agregar información de configuración
        if self.config:
            stats['configuration'] = {
                'input_port': self.config['network']['zmq_input_port'],
                'output_port': self.config['network']['zmq_output_port'],
                'max_events_buffer': self.config['dashboard']['max_events_buffer'],
                'auto_refresh_interval': self.config['dashboard']['auto_refresh_interval'],
                'firewall_enabled': self.config['firewall_integration']['enabled'],
                'auto_threat_detection': self.config['firewall_integration']['auto_threat_detection']
            }

        self.send_json(stats)

    def serve_events(self):
        """Eventos recientes usando configuración"""
        # Usar límite de configuración
        limit = self.config['dashboard']['event_display_limit'] if self.config else 50
        events = self.shared_data['events'][-limit:]

        self.send_json({
            'events': events,
            'count': len(events),
            'total_events': len(self.shared_data['events']),
            'source': 'zeromq_ml_enriched_protobuf',
            'protobuf_available': PROTOBUF_AVAILABLE,
            'zmq_available': ZMQ_AVAILABLE,
            'configuration': {
                'display_limit': limit,
                'total_buffer_size': self.config['dashboard']['max_events_buffer'] if self.config else 'unknown'
            }
        })

    def serve_gps_events(self):
        """Solo eventos con GPS usando configuración"""
        all_events = self.shared_data['events']
        gps_events = [e for e in all_events if e.get('has_gps')]

        # Usar límite de configuración
        limit = self.config['dashboard']['gps_events_limit'] if self.config else 30

        self.send_json({
            'events': gps_events[-limit:],
            'count': len(gps_events),
            'total_events': len(all_events),
            'configuration': {
                'gps_limit': limit
            }
        })

    def serve_health(self):
        """Health check usando configuración"""
        stats = {}
        if self.shared_data['zmq_listener']:
            stats = self.shared_data['zmq_listener'].get_stats()

        health_data = {
            'status': 'healthy' if stats.get('total_events', 0) > 0 else 'waiting_for_events',
            'timestamp': datetime.now().isoformat(),
            'protobuf_enabled': PROTOBUF_AVAILABLE,
            'zmq_enabled': ZMQ_AVAILABLE,
            'total_events': stats.get('total_events', 0),
            'events_with_gps': stats.get('events_with_gps', 0),
            'firewall_enabled': self.shared_data['firewall_sender'] is not None,
            'communication_protocol': 'protobuf' if PROTOBUF_AVAILABLE else 'json_fallback',
            'handshakes_received': stats.get('handshakes_received', 0),
            'nodes_registered': stats.get('nodes_registered', 0)
        }

        # Agregar información de configuración
        if self.config:
            health_data.update({
                'zeromq_input_port': self.config['network']['zmq_input_port'],
                'zeromq_output_port': self.config['network']['zmq_output_port'],
                'http_port': self.config['network']['http_port'],
                'configuration_loaded': True,
                'threat_rules_count': len(self.config.get('threat_rules', {})),
                'suspicious_ports_count': len(self.config.get('suspicious_ports', []))
            })
        else:
            health_data['configuration_loaded'] = False

        self.send_json(health_data)

    def send_json(self, data, status=200):
        """Enviar respuesta JSON con configuración CORS"""
        json_data = json.dumps(data, indent=2, default=str)
        self.send_response(status)
        self.send_header('Content-type', 'application/json')

        # CORS desde configuración
        if self.config and self.config['security'].get('enable_cors', True):
            allowed_origins = self.config['security'].get('allowed_origins', ['*'])
            if '*' in allowed_origins:
                self.send_header('Access-Control-Allow-Origin', '*')
            else:
                # En producción, usar orígenes específicos
                self.send_header('Access-Control-Allow-Origin', allowed_origins[0])

        self.send_header('Content-length', str(len(json_data.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(json_data.encode('utf-8'))

    def serve_dashboard(self):
        """Dashboard HTML interactivo con configuración dinámica"""

        # Valores por defecto si no hay configuración
        refresh_interval = 3000
        if self.config:
            refresh_interval = self.config['dashboard'].get('auto_refresh_interval', 3000)

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SCADA Real - ML Enhanced + Firewall (JSON CONFIG)</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css" />
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3a 100%);
            color: #fff; overflow: hidden;
        }}
        .header {{ 
            background: rgba(0, 0, 0, 0.9); padding: 0.8rem;
            border-bottom: 2px solid #00ff88;
            display: flex; justify-content: space-between; align-items: center;
        }}
        .header h1 {{ color: #00ff88; font-size: 1.3rem; }}
        .status {{ display: flex; gap: 15px; align-items: center; font-size: 0.85rem; }}
        .status-item {{ 
            background: rgba(255, 255, 255, 0.1);
            padding: 4px 8px; border-radius: 12px;
        }}
        .status-dot {{ 
            width: 8px; height: 8px; border-radius: 50%;
            display: inline-block; margin-right: 5px;
            animation: pulse 2s infinite;
        }}
        .online {{ background: #00ff88; }}
        .warning {{ background: #ffaa00; }}
        .error {{ background: #ff4444; }}
        @keyframes pulse {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} 100% {{ opacity: 1; }} }}

        .main-container {{ 
            display: grid; grid-template-columns: 1fr 380px;
            height: calc(100vh - 70px); gap: 1rem; padding: 1rem;
        }}
        .map-container {{ position: relative; border-radius: 10px; overflow: hidden; }}
        #map {{ height: 100%; width: 100%; }}

        .sidebar {{ 
            background: rgba(0, 0, 0, 0.8); border-radius: 10px;
            padding: 1rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem;
        }}

        .stats-grid {{
            display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
        }}
        .stat-card {{
            background: rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 10px;
            text-align: center; border-left: 3px solid #00ff88;
        }}
        .stat-value {{ font-size: 1.4rem; font-weight: bold; color: #00ff88; }}
        .stat-label {{ font-size: 0.8rem; color: #ccc; margin-top: 3px; }}

        .config-info {{
            background: rgba(0, 100, 200, 0.1); border-radius: 8px; padding: 10px;
            border-left: 3px solid #0066cc; font-size: 0.8rem;
        }}

        .events-section {{ flex: 1; }}
        .events-header {{ color: #00ff88; font-size: 1.1rem; margin-bottom: 0.5rem; }}
        .event-item {{ 
            background: rgba(255, 255, 255, 0.1);
            border-left: 3px solid #00ff88; padding: 8px;
            margin-bottom: 8px; border-radius: 5px; font-size: 0.85rem;
            animation: slideIn 0.5s ease; cursor: pointer;
            transition: all 0.3s ease;
        }}
        .event-item:hover {{ 
            background: rgba(255, 255, 255, 0.2);
            border-left-color: #ff8800;
            transform: translateX(5px);
        }}
        .event-item.high-risk {{
            border-left-color: #ff4444;
            background: rgba(255, 68, 68, 0.1);
        }}
        .event-item.high-risk:hover {{
            background: rgba(255, 68, 68, 0.2);
            box-shadow: 0 0 10px rgba(255, 68, 68, 0.3);
        }}
        .event-time {{ font-size: 0.75rem; color: #aaa; }}
        .event-ip {{ font-weight: bold; color: #00ff88; font-family: monospace; }}
        .event-details {{ font-size: 0.75rem; color: #ccc; margin-top: 3px; }}
        .gps-badge {{ 
            background: #00ff88; color: #000; padding: 1px 4px; 
            border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }}
        .ml-badge {{
            background: #ff8800; color: #fff; padding: 1px 4px;
            border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }}
        .protobuf-badge {{
            background: #8800ff; color: #fff; padding: 1px 4px;
            border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }}
        .handshake-badge {{
            background: #00ffff; color: #000; padding: 1px 4px;
            border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }}
        .config-badge {{
            background: #0066cc; color: #fff; padding: 1px 4px;
            border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }}
        .risk-badge {{
            padding: 1px 4px; border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }}
        .risk-low {{ background: #4CAF50; color: white; }}
        .risk-medium {{ background: #FF9800; color: white; }}
        .risk-high {{ background: #F44336; color: white; }}

        .block-button {{
            background: #ff4444; color: white; border: none;
            padding: 4px 8px; border-radius: 3px; font-size: 0.7rem;
            cursor: pointer; margin-left: 5px; opacity: 0.8;
            transition: opacity 0.3s ease;
        }}
        .block-button:hover {{
            opacity: 1;
            background: #ff2222;
        }}

        .ml-models {{
            background: rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 10px;
        }}
        .ml-model {{ 
            background: rgba(0, 255, 136, 0.2); color: #00ff88;
            padding: 3px 8px; border-radius: 15px; font-size: 0.75rem;
            display: inline-block; margin: 2px;
        }}

        .btn {{ 
            background: #00ff88; color: #0f0f23; padding: 6px 12px;
            border: none; border-radius: 5px; cursor: pointer;
            margin: 3px; font-weight: bold; font-size: 0.8rem;
        }}
        .btn:hover {{ background: #00cc66; }}

        /* Modal styles */
        .modal {{
            display: none; position: fixed; z-index: 10000;
            left: 0; top: 0; width: 100%; height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
        }}
        .modal-content {{
            background: linear-gradient(135deg, #1a1a3a 0%, #2a2a4a 100%);
            margin: 5% auto; padding: 20px; border-radius: 10px;
            width: 80%; max-width: 600px; color: #fff;
            border: 2px solid #ff4444;
        }}
        .modal-header {{
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 20px; color: #ff4444;
        }}
        .close {{
            color: #aaa; font-size: 28px; font-weight: bold;
            cursor: pointer; line-height: 1;
        }}
        .close:hover {{ color: #fff; }}
        .command-preview {{
            background: rgba(0, 0, 0, 0.5); padding: 15px;
            border-radius: 5px; font-family: monospace;
            margin: 15px 0; color: #00ff88;
            border-left: 3px solid #ff4444;
        }}
        .modal-buttons {{
            display: flex; gap: 10px; margin-top: 20px;
        }}
        .btn-danger {{ background: #ff4444; color: white; }}
        .btn-danger:hover {{ background: #ff2222; }}
        .btn-cancel {{ background: #666; color: white; }}
        .btn-cancel:hover {{ background: #555; }}

        @keyframes slideIn {{ from {{ opacity: 0; transform: translateX(-20px); }} to {{ opacity: 1; transform: translateX(0); }} }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SCADA Real - ML Enhanced + Firewall (JSON CONFIG)</h1>
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
                <span class="status-dot" id="config-status"></span>
                <span>Config</span>
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
            <div class="config-info">
                <strong>📄 Configuración JSON:</strong><br>
                <span id="config-details">Cargando...</span>
            </div>

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
                <div class="events-header">🚨 Eventos ML Enriquecidos (JSON Config)</div>
                <div id="events-list">
                    <div class="event-item">
                        <div class="event-time">Conectando a ZeroMQ (puerto configurado)...</div>
                        <div class="event-ip">Esperando eventos protobuf enriquecidos por ML</div>
                    </div>
                </div>
            </div>

            <div style="margin-top: auto;">
                <button class="btn" onclick="refreshData()">🔄 Actualizar</button>
                <button class="btn" onclick="clearMap()">🗺️ Limpiar Mapa</button>
                <button class="btn" onclick="showFirewallLog()">🔥 Log Firewall</button>
                <button class="btn" onclick="showPendingCommands()">📋 Pendientes</button>
                <button class="btn" onclick="showConfig()">⚙️ Config</button>
            </div>
        </div>
    </div>

    <!-- Modal de confirmación de firewall -->
    <div id="firewallModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>🔥 Bloquear Evento de Alto Riesgo (→ Protobuf JSON Config)</h2>
                <span class="close" onclick="closeFirewallModal()">&times;</span>
            </div>
            <div id="modal-event-info"></div>
            <div class="command-preview" id="command-preview">
                Generando comando de firewall protobuf usando configuración JSON...
            </div>
            <div class="modal-buttons">
                <button class="btn btn-danger" onclick="executeFirewallCommand()">🛡️ Bloquear IP (JSON Config)</button>
                <button class="btn btn-cancel" onclick="closeFirewallModal()">❌ Cancelar</button>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
    <script>
        class MLFirewallDashboard {{
            constructor() {{
                this.map = null;
                this.markers = new Map();
                this.lastEventCount = 0;
                this.allEvents = [];
                this.selectedEvent = null;
                this.config = null;

                this.initMap();
                this.startPeriodicUpdates();
                this.log('🛡️ Dashboard ML + Firewall (JSON CONFIG) inicializado');
            }}

            initMap() {{
                this.map = L.map('map').setView([40.0, 0.0], 2);
                L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
                    attribution: '©OpenStreetMap, ©CartoDB'
                }}).addTo(this.map);
            }}

            log(message) {{
                const now = new Date().toLocaleTimeString();
                console.log(`[${{now}}] ${{message}}`);
            }}

            async refreshData() {{
                try {{
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
                    this.updateConfigInfo(stats, healthData);

                }} catch (e) {{
                    this.log('❌ Error actualizando datos: ' + e.message);
                }}
            }}

            updateConfigInfo(stats, healthData) {{
                const configDetails = document.getElementById('config-details');

                if (stats.configuration) {{
                    const config = stats.configuration;
                    configDetails.innerHTML = `
                        Input: ${{config.input_port || 'N/A'}} | 
                        Output: ${{config.output_port || 'N/A'}} | 
                        Buffer: ${{config.max_events_buffer || 'N/A'}} | 
                        Refresh: ${{config.auto_refresh_interval || 'N/A'}}ms
                    `;
                }} else {{
                    configDetails.innerHTML = 'No config info available';
                }}
            }}

            updateStatusIndicators(stats, eventsData, healthData) {{
                const zmqStatus = document.getElementById('zmq-status');
                const mlStatus = document.getElementById('ml-status');
                const firewallStatus = document.getElementById('firewall-status');
                const protobufStatus = document.getElementById('protobuf-status');
                const configStatus = document.getElementById('config-status');

                // Estado ZMQ
                if (stats.total_events > this.lastEventCount) {{
                    zmqStatus.className = 'status-dot online';

                    // Estado ML
                    const hasMLScores = eventsData.events && eventsData.events.some(e => 
                        (e.anomaly_score && e.anomaly_score > 0) || (e.risk_score && e.risk_score > 0)
                    );
                    mlStatus.className = hasMLScores ? 'status-dot online' : 'status-dot warning';
                }} else {{
                    zmqStatus.className = 'status-dot warning';
                    mlStatus.className = 'status-dot warning';
                }}

                // Estado del firewall
                firewallStatus.className = healthData.firewall_enabled ? 'status-dot online' : 'status-dot error';

                // Estado protobuf
                if (healthData.communication_protocol === 'protobuf') {{
                    protobufStatus.className = 'status-dot online';
                }} else {{
                    protobufStatus.className = 'status-dot warning';
                }}

                // Estado configuración
                if (healthData.configuration_loaded) {{
                    configStatus.className = 'status-dot online';
                }} else {{
                    configStatus.className = 'status-dot error';
                }}

                this.lastEventCount = stats.total_events || 0;
            }}

            updateStats(stats) {{
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
                if (stats.ml_models_active && stats.ml_models_active.length > 0) {{
                    mlContainer.innerHTML = stats.ml_models_active
                        .map(model => `<div class="ml-model">${{model}}</div>`)
                        .join('');
                }} else {{
                    mlContainer.innerHTML = '<div class="ml-model">Esperando ML...</div>';
                }}
            }}

            updateEvents(events) {{
                if (!events || events.length === 0) {{
                    document.getElementById('events-list').innerHTML = `
                        <div class="event-item">
                            <div class="event-time">Sin eventos recientes</div>
                            <div class="event-ip">Verifica que el ML Detector esté enviando protobuf (puerto configurado)</div>
                        </div>
                    `;
                    return;
                }}

                this.allEvents = events;
                const eventsList = document.getElementById('events-list');
                eventsList.innerHTML = '';

                events.slice(-20).reverse().forEach((event) => {{
                    const eventDiv = document.createElement('div');
                    eventDiv.className = 'event-item';
                    if (event.risk_level === 'high') {{
                        eventDiv.className += ' high-risk';
                    }}

                    const time = new Date(event.timestamp).toLocaleTimeString();
                    const gpsBadge = event.has_gps ? '<span class="gps-badge">GPS</span>' : '';
                    const mlBadge = event.ml_enhanced ? '<span class="ml-badge">ML</span>' : '';
                    const protobufBadge = event.source === 'protobuf' ? '<span class="protobuf-badge">PB</span>' : '';
                    const handshakeBadge = event.is_initial_handshake ? '<span class="handshake-badge">HS</span>' : '';
                    const configBadge = '<span class="config-badge">JSON</span>';

                    let riskBadge = '';
                    if (event.risk_level === 'high') {{
                        riskBadge = '<span class="risk-badge risk-high">ALTO</span>';
                    }} else if (event.risk_level === 'medium') {{
                        riskBadge = '<span class="risk-badge risk-medium">MEDIO</span>';
                    }} else if (event.risk_level === 'low') {{
                        riskBadge = '<span class="risk-badge risk-low">BAJO</span>';
                    }}

                    // Botón de bloqueo para eventos de alto riesgo
                    const blockButton = (event.risk_level === 'high' || event.risk_score > 0.7) ? 
                        '<button class="block-button" data-event-id="' + event.event_id + '">🛡️ BLOQUEAR</button>' : '';

                    eventDiv.innerHTML = `
                        <div class="event-time">${{time}} | ${{event.agent_id}}</div>
                        <div class="event-ip">${{event.source_ip}} → ${{event.target_ip}}:${{event.dest_port}}${{gpsBadge}}${{mlBadge}}${{protobufBadge}}${{handshakeBadge}}${{configBadge}}${{riskBadge}}${{blockButton}}</div>
                        <div class="event-details">
                            A: ${{(event.anomaly_score * 100).toFixed(1)}}% | 
                            R: ${{(event.risk_score * 100).toFixed(1)}}% | 
                            ${{event.packet_size}}B
                            ${{event.description ? ` | ${{event.description}}` : ''}}
                            ${{event.so_identifier ? ` | ${{event.so_identifier}}` : ''}}
                        </div>
                    `;

                    // Agregar event listener para click en el evento
                    eventDiv.addEventListener('click', (e) => {{
                        if (!e.target.classList.contains('block-button')) {{
                            this.showEventDetails(event);
                        }}
                    }});

                    // Event listener para el botón de bloqueo
                    const blockBtn = eventDiv.querySelector('.block-button');
                    if (blockBtn) {{
                        blockBtn.addEventListener('click', (e) => {{
                            e.stopPropagation();
                            this.showFirewallModal(event);
                        }});
                    }}

                    eventsList.appendChild(eventDiv);
                }});
            }}

            updateMap(gpsEvents) {{
                if (!gpsEvents || gpsEvents.length === 0) return;

                gpsEvents.forEach(event => {{
                    if (event.latitude && event.longitude) {{
                        const markerId = `${{event.event_id}}_${{event.latitude}}_${{event.longitude}}`;

                        if (!this.markers.has(markerId)) {{
                            let markerColor = '#00ff88';
                            let markerSize = 8;

                            if (event.risk_level === 'high') {{
                                markerColor = '#ff4444';
                                markerSize = 12;
                            }} else if (event.risk_level === 'medium') {{
                                markerColor = '#ffaa00';
                                markerSize = 10;
                            }}

                            const marker = L.circleMarker([event.latitude, event.longitude], {{
                                color: markerColor,
                                fillColor: markerColor,
                                fillOpacity: 0.8,
                                radius: markerSize,
                                weight: 2
                            }}).addTo(this.map);

                            const protocolBadge = event.source === 'protobuf' ? ' [PROTOBUF]' : '';
                            const handshakeBadge = event.is_initial_handshake ? ' [HANDSHAKE]' : '';
                            const configBadge = ' [JSON CONFIG]';

                            const popupContent = `
                                <div style="color: #000;">
                                    <strong>🌐 Evento ML${{protocolBadge}}${{handshakeBadge}}${{configBadge}}</strong><br>
                                    <strong>Origen:</strong> ${{event.source_ip}}<br>
                                    <strong>Destino:</strong> ${{event.target_ip}}:${{event.dest_port}}<br>
                                    <strong>Riesgo:</strong> ${{(event.risk_score * 100).toFixed(1)}}%<br>
                                    <strong>Anomalía:</strong> ${{(event.anomaly_score * 100).toFixed(1)}}%<br>
                                    <strong>Agente:</strong> ${{event.agent_id}}<br>
                                    <strong>SO:</strong> ${{event.so_identifier || 'unknown'}}<br>
                                    <strong>Hostname:</strong> ${{event.node_hostname || 'unknown'}}<br>
                                    ${{event.description ? `<strong>Desc:</strong> ${{event.description}}<br>` : ''}}
                                    <strong>Tiempo:</strong> ${{new Date(event.timestamp).toLocaleString()}}<br>
                                    ${{(event.risk_level === 'high' || event.risk_score > 0.7) ? 
                                        '<button onclick="dashboard.showFirewallModal(' + JSON.stringify(event).replace(/"/g, '&quot;') + ')" style="background: #ff4444; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; margin-top: 5px;">🛡️ Bloquear IP (JSON Config)</button>' : ''}}
                                </div>
                            `;

                            marker.bindPopup(popupContent, {{ maxWidth: 300 }});
                            this.markers.set(markerId, marker);

                            // Event listener para click en marcador
                            marker.on('click', () => {{
                                this.showEventDetails(event);
                            }});
                        }}
                    }}
                }});
            }}

            showEventDetails(event) {{
                this.log(`📋 Detalles del evento: ${{event.source_ip}} → ${{event.target_ip}} [${{event.source || 'unknown'}}]`);
                this.log(`🖥️  Nodo: ${{event.node_hostname}} (${{event.so_identifier}})`);
            }}

            showFirewallModal(event) {{
                this.selectedEvent = event;
                const modal = document.getElementById('firewallModal');
                const eventInfo = document.getElementById('modal-event-info');
                const commandPreview = document.getElementById('command-preview');

                eventInfo.innerHTML = `
                    <h3>Evento Detectado (${{event.source || 'unknown'}}):</h3>
                    <p><strong>IP Origen:</strong> ${{event.source_ip}}</p>
                    <p><strong>IP Destino:</strong> ${{event.target_ip}}:${{event.dest_port}}</p>
                    <p><strong>Riesgo:</strong> ${{(event.risk_score * 100).toFixed(1)}}%</p>
                    <p><strong>Anomalía:</strong> ${{(event.anomaly_score * 100).toFixed(1)}}%</p>
                    <p><strong>Agente:</strong> ${{event.agent_id}}</p>
                    <p><strong>SO:</strong> ${{event.so_identifier || 'unknown'}}</p>
                    <p><strong>Hostname:</strong> ${{event.node_hostname || 'unknown'}}</p>
                    <p><strong>Fuente:</strong> ${{event.source === 'protobuf' ? 'Protobuf ✅' : 'JSON (fallback)'}} + JSON Config ⚙️</p>
                `;

                commandPreview.innerHTML = 'Generando comando de firewall protobuf batch usando configuración JSON...';

                modal.style.display = 'block';

                // Generar comando de firewall
                this.generateFirewallCommand(event);
            }}

            async generateFirewallCommand(event) {{
                try {{
                    const response = await fetch('/api/firewall/generate', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{event: event}})
                    }});

                    const result = await response.json();
                    const commandPreview = document.getElementById('command-preview');

                    if (result.success) {{
                        const cmd = result.suggested_command;
                        commandPreview.innerHTML = `
                            <strong>Comando sugerido (JSON Config + será convertido a FirewallCommandBatch):</strong><br>
                            ${{cmd.firewall_rule.command}}<br><br>
                            <strong>Acción:</strong> ${{cmd.action}}<br>
                            <strong>Duración:</strong> ${{cmd.firewall_rule.duration}}<br>
                            <strong>Prioridad:</strong> ${{cmd.firewall_rule.priority}}<br>
                            <strong>Análisis:</strong> ${{cmd.analysis.threat_type}}<br>
                            <strong>Confianza:</strong> ${{cmd.analysis.confidence.toFixed(1)}}%<br>
                            <strong>Configuración:</strong> ${{cmd.analysis.used_configuration ? '✅ JSON Config' : '❌ Hardcoded'}}<br>
                            <em>📦 Este comando se enviará como FirewallCommandBatch protobuf al puerto configurado</em>
                        `;
                        this.suggestedCommand = cmd;
                    }} else {{
                        commandPreview.textContent = 'Error generando comando: ' + result.error;
                    }}
                }} catch (e) {{
                    const commandPreview = document.getElementById('command-preview');
                    commandPreview.textContent = 'Error de conexión: ' + e.message;
                }}
            }}

            async executeFirewallCommand() {{
                if (!this.selectedEvent || !this.suggestedCommand) return;

                try {{
                    const response = await fetch('/api/firewall/block', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            event_id: this.selectedEvent.event_id,
                            target_ip: this.selectedEvent.source_ip,
                            source_agent: this.selectedEvent.agent_id,
                            action: this.suggestedCommand.action,
                            target_port: this.selectedEvent.dest_port,
                            duration_seconds: this.suggestedCommand.duration_seconds,
                            reason: `High risk event: ${{(this.selectedEvent.risk_score * 100).toFixed(1)}}% risk score (JSON Config)`,
                            priority: this.suggestedCommand.priority,
                            dry_run: true,
                            ml_scores: {{
                                anomaly_score: this.selectedEvent.anomaly_score,
                                risk_score: this.selectedEvent.risk_score
                            }},
                            packet_info: `Packet from ${{this.selectedEvent.source_ip}} to ${{this.selectedEvent.target_ip}}:${{this.selectedEvent.dest_port}}`
                        }})
                    }});

                    const result = await response.json();

                    if (result.success) {{
                        this.log(`🛡️ Comando protobuf batch enviado (JSON Config): ${{result.command_id}}`);
                        alert(`✅ Comando de firewall enviado exitosamente como PROTOBUF BATCH (JSON CONFIG)\\nComando ID: ${{result.command_id}}`);
                    }} else {{
                        alert(`❌ Error: ${{result.error}}`);
                    }}

                    this.closeFirewallModal();

                }} catch (e) {{
                    alert(`❌ Error de conexión: ${{e.message}}`);
                }}
            }}

            closeFirewallModal() {{
                document.getElementById('firewallModal').style.display = 'none';
                this.selectedEvent = null;
                this.suggestedCommand = null;
            }}

            async showFirewallLog() {{
                try {{
                    const response = await fetch('/api/firewall/log');
                    const result = await response.json();

                    let logText = 'LOG DE COMANDOS DE FIREWALL (JSON CONFIG + PROTOBUF BATCH):\\n\\n';
                    if (result.configuration) {{
                        logText += `Configuración - Output: ${{result.configuration.output_port}}, Max Size: ${{result.configuration.max_message_size}} bytes\\n\\n`;
                    }}

                    result.commands.forEach(cmd => {{
                        logText += `${{cmd.timestamp}} - ${{cmd.action}} - ${{cmd.target_node}} (${{cmd.command_count}} cmd, ${{cmd.message_size || 'N/A'}} bytes)\\n`;
                    }});

                    alert(logText || 'No hay comandos en el log');
                }} catch (e) {{
                    alert('Error obteniendo log: ' + e.message);
                }}
            }}

            async showPendingCommands() {{
                try {{
                    const response = await fetch('/api/firewall/pending');
                    const result = await response.json();

                    const summary = result.summary;
                    let text = `COMANDOS PENDIENTES (JSON CONFIG + PROTOBUF BATCH):\\n\\n`;
                    text += `Eventos con comandos: ${{summary.total_events_with_commands || 0}}\\n`;
                    text += `Total comandos: ${{summary.total_commands || 0}}\\n`;
                    text += `Límite máximo: ${{summary.max_pending || 'N/A'}}\\n`;
                    text += `Timeout: ${{summary.timeout_seconds || 'N/A'}}s\\n`;

                    if (summary.oldest_pending) {{
                        text += `Más antiguo: ${{summary.oldest_pending.toFixed(1)}}s\\n`;
                    }}

                    text += '\\nEstos comandos serán enviados como FirewallCommandBatch protobuf al simple_firewall_agent.py usando configuración JSON';

                    alert(text);
                }} catch (e) {{
                    alert('Error obteniendo comandos pendientes: ' + e.message);
                }}
            }}

            async showConfig() {{
                try {{
                    const response = await fetch('/health');
                    const health = await response.json();

                    let configText = 'CONFIGURACIÓN CARGADA (JSON):\\n\\n';
                    configText += `Config loaded: ${{health.configuration_loaded ? '✅' : '❌'}}\\n`;
                    configText += `ZeroMQ Input: ${{health.zeromq_input_port || 'N/A'}}\\n`;
                    configText += `ZeroMQ Output: ${{health.zeromq_output_port || 'N/A'}}\\n`;
                    configText += `HTTP Port: ${{health.http_port || 'N/A'}}\\n`;
                    configText += `Threat Rules: ${{health.threat_rules_count || 'N/A'}}\\n`;
                    configText += `Suspicious Ports: ${{health.suspicious_ports_count || 'N/A'}}\\n`;
                    configText += `Protobuf: ${{health.protobuf_enabled ? '✅' : '❌'}}\\n`;
                    configText += `ZMQ: ${{health.zmq_enabled ? '✅' : '❌'}}\\n`;

                    alert(configText);
                }} catch (e) {{
                    alert('Error obteniendo configuración: ' + e.message);
                }}
            }}

            clearMap() {{
                this.markers.forEach(marker => {{
                    this.map.removeLayer(marker);
                }});
                this.markers.clear();
                this.log('🗺️ Mapa limpiado');
            }}

            startPeriodicUpdates() {{
                // Usar intervalo de configuración dinámico
                const refreshInterval = {refresh_interval};
                setInterval(() => this.refreshData(), refreshInterval);
                setTimeout(() => this.refreshData(), 1000);
            }}
        }}

        let dashboard;

        function refreshData() {{ dashboard.refreshData(); }}
        function clearMap() {{ dashboard.clearMap(); }}
        function showFirewallLog() {{ dashboard.showFirewallLog(); }}
        function showPendingCommands() {{ dashboard.showPendingCommands(); }}
        function showConfig() {{ dashboard.showConfig(); }}
        function closeFirewallModal() {{ dashboard.closeFirewallModal(); }}
        function executeFirewallCommand() {{ dashboard.executeFirewallCommand(); }}

        document.addEventListener('DOMContentLoaded', function() {{
            dashboard = new MLFirewallDashboard();
            console.log('🛡️ Dashboard ML Enhanced + Firewall - JSON CONFIG');
            console.log('🤖 ZeroMQ puertos configurados desde JSON');
            console.log('🔥 Comandos de firewall protobuf batch por puerto configurado');
            console.log('📦 Usando estructuras protobuf reales con enums');
            console.log('⚙️ Toda la configuración desde JSON');
        }});

        // Cerrar modal con ESC
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape') {{
                closeFirewallModal();
            }}
        }});

        // Cerrar modal clickeando fuera
        window.addEventListener('click', function(e) {{
            const modal = document.getElementById('firewallModal');
            if (e.target === modal) {{
                closeFirewallModal();
            }}
        }});
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


def setup_logging_from_config(config):
    """Configurar logging global desde configuración JSON"""
    log_config = config.get('logging', {})

    # Configurar nivel
    level = getattr(logging, log_config.get('level', 'INFO').upper())

    # Configurar logger principal
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
            maxBytes=log_config.get('max_size_mb', 50) * 1024 * 1024,
            backupCount=log_config.get('backup_count', 5)
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


def main():
    """Función principal del dashboard con configuración JSON completa"""
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Dashboard SCADA con configuración JSON')
    parser.add_argument('config_file', nargs='?',
                        default='dashboard_config.json',
                        help='Archivo de configuración JSON')
    parser.add_argument('--test-config', action='store_true',
                        help='Validar configuración y salir')

    args = parser.parse_args()

    # Cargar configuración
    config = load_dashboard_config(args.config_file)

    # Configurar logging desde JSON
    setup_logging_from_config(config)

    if args.test_config:
        print("✅ Configuración JSON válida para dashboard")
        print(f"🎯 HTTP: {config['network']['http_host']}:{config['network']['http_port']}")
        print(f"📡 ZMQ Input: {config['network']['zmq_input_port']}")
        print(f"🔥 ZMQ Output: {config['network']['zmq_output_port']}")
        print(f"🛡️ Firewall: {'✅ Enabled' if config['firewall_integration']['enabled'] else '❌ Disabled'}")
        print(f"🎯 Threat rules: {len(config.get('threat_rules', {}))}")
        print(f"🔍 Suspicious ports: {len(config.get('suspicious_ports', []))}")
        return 0

    print("🛡️ DASHBOARD SCADA REAL - Configuración JSON Completa")
    print("=" * 75)
    print(f"📄 Config: {args.config_file}")
    print(f"🎯 HTTP: {config['network']['http_host']}:{config['network']['http_port']}")
    print(f"📡 ZMQ Input: {config['network']['zmq_input_port']} (eventos enriquecidos por ML)")
    print(f"🔥 ZMQ Output: {config['network']['zmq_output_port']} (comandos de firewall)")
    print(f"🛡️ Firewall: {'✅ Enabled' if config['firewall_integration']['enabled'] else '❌ Disabled'}")
    print(
        f"🤖 Auto threat detection: {'✅ Enabled' if config['firewall_integration']['auto_threat_detection'] else '❌ Disabled'}")
    print(
        f"✋ Manual approval: {'✅ Required' if config['firewall_integration']['require_manual_approval'] else '❌ Auto apply'}")
    print(f"📋 Threat rules: {len(config.get('threat_rules', {}))}")
    print(f"🔍 Suspicious ports: {len(config.get('suspicious_ports', []))}")
    print(f"📊 Max events buffer: {config['dashboard']['max_events_buffer']}")
    print(f"🔄 Auto refresh: {config['dashboard']['auto_refresh_interval']}ms")
    print("")

    # Verificar puerto disponible
    host = config['network']['http_host']
    port = config['network']['http_port']

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            print(f"⚠️ Puerto {port} ocupado, intentando {port + 1}...")
            port = port + 1
            config['network']['http_port'] = port

        # Guardar configuración en shared_data para handlers
        DashboardHandler.shared_data['config'] = config
        DashboardHandler.shared_data['max_events_buffer'] = config['dashboard']['max_events_buffer']
        DashboardHandler.shared_data['auto_refresh_interval'] = config['dashboard']['auto_refresh_interval']

        # Crear servidor
        server = HTTPServer((host, port), DashboardHandler)

        # Inicializar firewall sender con configuración
        if ZMQ_AVAILABLE:
            firewall_sender = FirewallCommandSender(config['network'])
            DashboardHandler.shared_data['firewall_sender'] = firewall_sender

            if firewall_sender.socket:
                logger.info(f"🔥 Firewall sender configurado para puerto {config['network']['zmq_output_port']}")
            else:
                logger.warning("⚠️ Firewall sender no se pudo inicializar")
        else:
            logger.warning("ZMQ no disponible - Firewall sender deshabilitado")

        # Inicializar listener ZeroMQ con configuración
        if ZMQ_AVAILABLE:
            zmq_listener = ZeroMQListener(DashboardHandler, config['network'])
            DashboardHandler.shared_data['zmq_listener'] = zmq_listener
            zmq_listener.start()

            logger.info(f"📡 ZMQ listener configurado para puerto {config['network']['zmq_input_port']}")
        else:
            logger.warning("ZMQ no disponible - Listener deshabilitado")

        print(f"🚀 Dashboard iniciado en http://{host}:{port}")
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"📡 API Stats: http://{host}:{port}/api/stats")
        print(f"🗺️ Eventos GPS: http://{host}:{port}/api/events/gps")
        print(f"🔥 Firewall Log: http://{host}:{port}/api/firewall/log")
        print(f"📋 Comandos Pendientes: http://{host}:{port}/api/firewall/pending")
        print(f"🏥 Health Check: http://{host}:{port}/health")
        print("")
        print("✅ CONFIGURACIÓN CARGADA:")
        print(f"   🔌 ZeroMQ disponible: {ZMQ_AVAILABLE}")
        print(f"   📦 Protobuf disponible: {PROTOBUF_AVAILABLE}")
        if ZMQ_AVAILABLE:
            print(f"   🔌 ZeroMQ puerto {config['network']['zmq_input_port']} (entrada - PROTOBUF)")
            print(f"   🔥 ZeroMQ puerto {config['network']['zmq_output_port']} (salida firewall - PROTOBUF)")
        if PROTOBUF_AVAILABLE:
            print("   📦 network_event_extended_fixed_pb2 ✅")
            print("   📦 firewall_commands_pb2 ✅")
            print("   🔥 FirewallCommandBatch ✅")
            print("   📋 CommandAction & CommandPriority enums ✅")

        print(f"   📄 Configuración desde: {args.config_file}")
        print(f"   📝 Logging: {config['logging']['level']} → {config['logging'].get('file', 'console only')}")
        print("")
        print("🎯 FUNCIONALIDADES CONFIGURADAS:")
        print("   ✅ Recepción de eventos protobuf desde ML detector")
        print("   ✅ Procesamiento de handshakes iniciales")
        print("   ✅ Generación automática de comandos firewall (configurable)")
        print("   ✅ Envío de FirewallCommandBatch protobuf")
        print("   ✅ Modal de confirmación para bloqueos")
        print("   ✅ Gestión de comandos pendientes (configurable)")
        print("   ✅ Indicador de nodos registrados")
        print("   ✅ Soporte para todos los campos del protobuf")
        print("   ✅ Configuración completa desde JSON")
        print("   ✅ Puertos configurables")
        print("   ✅ Umbrales de amenazas configurables")
        print("   ✅ Rate limiting configurable")
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
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())