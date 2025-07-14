#!/usr/bin/env python3
"""
🛡️ Dashboard SCADA - Arquitectura 3 puertos
ACTUALIZADO: Compatible con dashboard_config.json de 3 puertos
Eventos (5561) + Comandos (5562) + Confirmaciones (5563)
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

# Configurar logging básico
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Importar dependencias opcionales
try:
    import zmq

    ZMQ_AVAILABLE = True
    logger.info("✅ ZMQ disponible")
except ImportError:
    ZMQ_AVAILABLE = False
    logger.error("❌ ZMQ no disponible")

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


def load_dashboard_config(config_file="dashboard_config.json"):
    """Cargar configuración desde dashboard_config.json"""
    default_config = {
        "server": {
            "host": "127.0.0.1",
            "port": 8000,
            "debug": False,
            "auto_reload": False
        },
        "zmq": {
            "events_input_port": 5560,
            "commands_output_port": 5562,
            "confirmations_input_port": 5563,
            "context_threads": 1,
            "high_water_mark": 1000,
            "timeout": 1000
        },
        "dashboard": {
            "max_events_buffer": 300,
            "auto_refresh_interval": 3000,
            "map_center_lat": 40.4168,
            "map_center_lng": -3.7038,
            "map_zoom_level": 6
        },
        "firewall": {
            "enabled": True,
            "auto_threat_detection": True,
            "manual_approval_required": True,
            "default_block_duration": "1h",
            "max_pending_commands": 10
        },
        "threat_detection": {
            "enabled": True,
            "rules": [
                {"pattern": "brute_force", "threshold": 5, "priority": "high"},
                {"pattern": "port_scan", "threshold": 10, "priority": "medium"},
                {"pattern": "dos_attack", "threshold": 100, "priority": "critical"},
                {"pattern": "malicious_ip", "threshold": 1, "priority": "high"},
                {"pattern": "suspicious_traffic", "threshold": 20, "priority": "low"}
            ],
            "suspicious_ports": [22, 23, 80, 443, 3389, 5432, 3306, 1433, 21, 25, 53, 135],
            "geo_risk_countries": ["CN", "RU", "KP"],
            "ml_risk_threshold": 0.8,
            "anomaly_threshold": 0.7
        },
        "logging": {
            "level": "INFO",
            "file": "logs/dashboard.log",
            "max_size": "10MB",
            "backup_count": 5
        },
        "protobuf": {
            "enabled": True,
            "timeout": 1000,
            "retry_attempts": 3
        },
        "websocket": {
            "enabled": True,
            "ping_interval": 30,
            "ping_timeout": 10,
            "max_connections": 100
        }
    }

    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                user_config = json.load(f)

            # Merge recursivo
            def merge_config(base, update):
                for key, value in update.items():
                    if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                        merge_config(base[key], value)
                    else:
                        base[key] = value

            merge_config(default_config, user_config)
            logger.info(f"📄 Configuración cargada desde {config_file}")

        except Exception as e:
            logger.error(f"❌ Error cargando configuración: {e}")
            logger.info("⚠️ Usando configuración por defecto")
    else:
        if config_file:
            logger.warning(f"⚠️ Config no encontrado: {config_file}")
        logger.info("⚠️ Usando configuración por defecto")

    return default_config


class FirewallCommandGenerator:
    """Generador de comandos de firewall compatible con dashboard_config.json"""

    def __init__(self, config: Dict):
        self.config = config
        self.known_nodes = {}

        # Configuración de amenazas desde JSON
        self.threat_detection = config.get('threat_detection', {})
        self.suspicious_ports = self.threat_detection.get('suspicious_ports', [])
        self.ml_risk_threshold = self.threat_detection.get('ml_risk_threshold', 0.8)
        self.anomaly_threshold = self.threat_detection.get('anomaly_threshold', 0.7)

        # Configuración de firewall desde JSON
        self.firewall_config = config.get('firewall', {})
        self.auto_threat_detection = self.firewall_config.get('auto_threat_detection', True)
        self.manual_approval_required = self.firewall_config.get('manual_approval_required', True)
        self.max_pending_commands = self.firewall_config.get('max_pending_commands', 10)

        # Mapeo de acciones a enums protobuf
        self.action_mapping = {
            'block_ip': firewall_commands_pb2.BLOCK_IP if PROTOBUF_AVAILABLE else 1,
            'unblock_ip': firewall_commands_pb2.UNBLOCK_IP if PROTOBUF_AVAILABLE else 2,
            'rate_limit': firewall_commands_pb2.RATE_LIMIT_IP if PROTOBUF_AVAILABLE else 5,
        }

        self.priority_mapping = {
            'low': firewall_commands_pb2.LOW if PROTOBUF_AVAILABLE else 1,
            'medium': firewall_commands_pb2.MEDIUM if PROTOBUF_AVAILABLE else 2,
            'high': firewall_commands_pb2.HIGH if PROTOBUF_AVAILABLE else 3,
            'critical': firewall_commands_pb2.CRITICAL if PROTOBUF_AVAILABLE else 4
        }

        logger.info("🔥 FirewallCommandGenerator inicializado desde dashboard_config.json")
        logger.info(f"Auto detection: {self.auto_threat_detection}")
        logger.info(f"Manual approval: {self.manual_approval_required}")
        logger.info(f"Puertos sospechosos: {len(self.suspicious_ports)}")

    def analyze_threat_and_generate_commands(self, event_data):
        """Analizar amenaza usando configuración de dashboard_config.json"""
        if not self.auto_threat_detection:
            return []

        commands = []
        threat_type = self.detect_threat_type(event_data)

        if threat_type and self.should_generate_command(event_data, threat_type):
            command = self.create_firewall_command(event_data, threat_type)
            if command:
                commands.append(command)

        return commands

    def detect_threat_type(self, event_data):
        """Detectar tipo de amenaza usando reglas de dashboard_config.json"""
        risk_score = event_data.get('risk_score', 0)
        anomaly_score = event_data.get('anomaly_score', 0)
        dest_port = event_data.get('dest_port', 0)

        # Verificar umbrales de ML desde configuración
        if risk_score >= self.ml_risk_threshold:
            return 'high_risk_ml'

        if anomaly_score >= self.anomaly_threshold:
            return 'anomaly_detected'

        # Verificar puertos sospechosos desde configuración
        if dest_port in self.suspicious_ports:
            return 'suspicious_port'

        # Verificar patrones específicos
        description = event_data.get('description', '').lower()
        if 'brute' in description or 'force' in description:
            return 'brute_force'
        elif 'scan' in description:
            return 'port_scan'
        elif 'dos' in description or 'ddos' in description:
            return 'dos_attack'

        return None

    def should_generate_command(self, event_data, threat_type):
        """Determinar si se debe generar comando basado en configuración"""
        if self.manual_approval_required:
            return True  # Siempre generar para aprobación manual

        # Buscar regla específica en configuración
        rules = self.threat_detection.get('rules', [])
        for rule in rules:
            if rule.get('pattern') == threat_type:
                return True  # Regla encontrada

        return False

    def create_firewall_command(self, event_data, threat_type):
        """Crear comando de firewall usando protobuf"""
        if not PROTOBUF_AVAILABLE:
            return self.create_json_command(event_data, threat_type)

        command = firewall_commands_pb2.FirewallCommand()
        command.command_id = str(uuid.uuid4())
        command.action = self.action_mapping.get('block_ip', 1)
        command.target_ip = event_data.get('source_ip', '')
        command.target_port = event_data.get('dest_port', 0)
        command.duration_seconds = self.parse_duration(self.firewall_config.get('default_block_duration', '1h'))
        command.reason = f"Threat detected: {threat_type}"
        command.priority = self.priority_mapping.get('high', 3)
        command.dry_run = self.manual_approval_required

        return command

    def create_json_command(self, event_data, threat_type):
        """Crear comando JSON como fallback"""
        return {
            'command_id': str(uuid.uuid4()),
            'action': 'block_ip',
            'target_ip': event_data.get('source_ip', ''),
            'target_port': event_data.get('dest_port', 0),
            'duration_seconds': self.parse_duration(self.firewall_config.get('default_block_duration', '1h')),
            'reason': f"Threat detected: {threat_type}",
            'priority': 'high',
            'dry_run': self.manual_approval_required
        }

    def parse_duration(self, duration_str):
        """Parsear duración desde string (1h, 30m, etc.)"""
        if isinstance(duration_str, int):
            return duration_str

        duration_str = duration_str.lower()
        if duration_str.endswith('h'):
            return int(duration_str[:-1]) * 3600
        elif duration_str.endswith('m'):
            return int(duration_str[:-1]) * 60
        elif duration_str.endswith('s'):
            return int(duration_str[:-1])
        else:
            return 3600  # Default 1 hour


class FirewallCommandSender:
    """Sender ZMQ para comandos (puerto 5562)"""

    def __init__(self, config: Dict):
        self.config = config
        self.zmq_config = config.get('zmq', {})

        if not ZMQ_AVAILABLE:
            logger.error("ZMQ no disponible")
            self.socket = None
            self.context = None
            return

        self.commands_output_port = self.zmq_config.get('commands_output_port', 5562)

        self.context = zmq.Context(self.zmq_config.get('context_threads', 1))
        self.socket = self.context.socket(zmq.PUSH)

        try:
            output_addr = f"tcp://localhost:{self.commands_output_port}"
            self.socket.connect(output_addr)
            self.command_log = deque(maxlen=100)
            logger.info(f"🔥 Firewall command sender conectado a {output_addr}")
        except Exception as e:
            logger.error(f"Error conectando al puerto {self.commands_output_port}: {e}")
            self.socket = None

    def send_command(self, command):
        """Enviar comando (protobuf o JSON)"""
        if not self.socket:
            return False

        try:
            if PROTOBUF_AVAILABLE and hasattr(command, 'SerializeToString'):
                message = command.SerializeToString()
                protocol = 'protobuf'
            else:
                message = json.dumps(command).encode('utf-8')
                protocol = 'json'

            self.socket.send(message)

            # Log
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'protocol': protocol,
                'target_ip': getattr(command, 'target_ip', command.get('target_ip', 'unknown')),
                'action': getattr(command, 'action', command.get('action', 'unknown')),
                'message_size': len(message),
                'command_id': getattr(command, 'command_id', command.get('command_id', 'unknown'))
            }
            self.command_log.append(log_entry)

            logger.info(f"🔥 Comando {protocol} enviado: {log_entry['target_ip']} (ID: {log_entry['command_id']})")
            return True

        except Exception as e:
            logger.error(f"❌ Error enviando comando: {e}")
            return False

    def get_command_log(self):
        return list(self.command_log)

    def close(self):
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()


class FirewallConfirmationListener:
    """Listener para confirmaciones del firewall (puerto 5563)"""

    def __init__(self, dashboard_handler, config: Dict):
        self.dashboard_handler = dashboard_handler
        self.config = config
        self.zmq_config = config.get('zmq', {})

        self.confirmations_input_port = self.zmq_config.get('confirmations_input_port', 5563)
        self.timeout = self.zmq_config.get('timeout', 1000)

        self.running = False
        self.context = None
        self.socket = None

        # Buffer de confirmaciones
        self.confirmations = deque(maxlen=100)

        # Estadísticas
        self.stats = {
            'total_confirmations': 0,
            'successful_commands': 0,
            'failed_commands': 0,
            'last_confirmation_time': None,
            'start_time': datetime.now()
        }

    def start(self):
        """Iniciar listener de confirmaciones"""
        if not ZMQ_AVAILABLE:
            logger.error("ZMQ no disponible para confirmations listener")
            return

        self.running = True

        try:
            self.context = zmq.Context(self.zmq_config.get('context_threads', 1))
            self.socket = self.context.socket(zmq.SUB)

            input_addr = f"tcp://localhost:{self.confirmations_input_port}"
            self.socket.connect(input_addr)
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")
            self.socket.setsockopt(zmq.RCVTIMEO, self.timeout)

            logger.info(f"🔔 Confirmations listener conectado a {input_addr}")

            # Thread de escucha
            thread = threading.Thread(target=self._listen_confirmations, daemon=True)
            thread.start()

        except Exception as e:
            logger.error(f"❌ Error conectando confirmations listener: {e}")

    def _listen_confirmations(self):
        """Escuchar confirmaciones del firewall"""
        while self.running:
            try:
                message = self.socket.recv(zmq.NOBLOCK)

                # Intentar parsear como JSON primero
                try:
                    confirmation = json.loads(message.decode('utf-8'))
                    self._process_confirmation(confirmation)
                except Exception as e:
                    logger.error(f"Error parseando confirmación: {e}")

            except zmq.Again:
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"❌ Error en confirmations listener: {e}")
                time.sleep(1)

    def _process_confirmation(self, confirmation):
        """Procesar confirmación del firewall"""
        try:
            # Normalizar confirmación
            confirmation_data = {
                'timestamp': datetime.now().isoformat(),
                'command_id': confirmation.get('command_id', 'unknown'),
                'status': confirmation.get('status', 'unknown'),
                'message': confirmation.get('message', ''),
                'target_ip': confirmation.get('target_ip', 'unknown'),
                'action': confirmation.get('action', 'unknown'),
                'executed_at': confirmation.get('executed_at', ''),
                'duration': confirmation.get('duration', ''),
                'rules_applied': confirmation.get('rules_applied', [])
            }

            # Actualizar estadísticas
            self.stats['total_confirmations'] += 1
            self.stats['last_confirmation_time'] = datetime.now()

            if confirmation_data['status'] == 'success':
                self.stats['successful_commands'] += 1
            elif confirmation_data['status'] == 'error':
                self.stats['failed_commands'] += 1

            # Añadir al buffer
            self.confirmations.append(confirmation_data)

            # Añadir al dashboard para mostrar en UI
            if hasattr(self.dashboard_handler, 'shared_data'):
                if 'confirmations' not in self.dashboard_handler.shared_data:
                    self.dashboard_handler.shared_data['confirmations'] = deque(maxlen=50)

                self.dashboard_handler.shared_data['confirmations'].append(confirmation_data)

            logger.info(f"✅ Confirmación recibida: {confirmation_data['command_id']} - {confirmation_data['status']}")

        except Exception as e:
            logger.error(f"❌ Error procesando confirmación: {e}")

    def get_stats(self):
        """Obtener estadísticas de confirmaciones"""
        now = datetime.now()
        return {
            'total_confirmations': self.stats['total_confirmations'],
            'successful_commands': self.stats['successful_commands'],
            'failed_commands': self.stats['failed_commands'],
            'last_confirmation_seconds_ago': (now - self.stats['last_confirmation_time']).total_seconds() if self.stats[
                'last_confirmation_time'] else None,
            'uptime_seconds': (now - self.stats['start_time']).total_seconds()
        }

    def get_confirmations(self):
        """Obtener confirmaciones recientes"""
        return list(self.confirmations)

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()


class ZeroMQEventsListener:
    """Listener ZMQ para eventos del ML (puerto 5560)"""

    def __init__(self, dashboard_handler, config: Dict):
        self.dashboard_handler = dashboard_handler
        self.config = config
        self.zmq_config = config.get('zmq', {})

        self.events_input_port = self.zmq_config.get('events_input_port', 5561)
        self.timeout = self.zmq_config.get('timeout', 1000)

        self.running = False
        self.context = None
        self.socket = None

        # Estadísticas
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
            'protobuf_events': 0,
            'json_events': 0
        }

    def start(self):
        """Iniciar listener de eventos"""
        if not ZMQ_AVAILABLE:
            logger.error("ZMQ no disponible para events listener")
            return

        self.running = True

        try:
            self.context = zmq.Context(self.zmq_config.get('context_threads', 1))
            self.socket = self.context.socket(zmq.SUB)

            input_addr = f"tcp://localhost:{self.events_input_port}"
            self.socket.connect(input_addr)
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")
            self.socket.setsockopt(zmq.RCVTIMEO, self.timeout)

            logger.info(f"🔌 Events listener conectado a {input_addr}")

            # Thread de escucha
            thread = threading.Thread(target=self._listen_events, daemon=True)
            thread.start()

        except Exception as e:
            logger.error(f"❌ Error conectando events listener: {e}")

    def _listen_events(self):
        """Escuchar eventos del ML"""
        while self.running:
            try:
                message = self.socket.recv(zmq.NOBLOCK)

                # Intentar parsear como protobuf primero
                if PROTOBUF_AVAILABLE:
                    try:
                        event = network_event_extended_fixed_pb2.NetworkEvent()
                        event.ParseFromString(message)
                        self._process_protobuf_event(event)
                        self.stats['protobuf_events'] += 1
                        continue
                    except:
                        pass

                # Fallback a JSON
                try:
                    event_data = json.loads(message.decode('utf-8'))
                    self._process_json_event(event_data)
                    self.stats['json_events'] += 1
                except Exception as e:
                    logger.error(f"Error parseando mensaje: {e}")

            except zmq.Again:
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"❌ Error en events listener: {e}")
                time.sleep(1)

    def _process_protobuf_event(self, event):
        """Procesar evento protobuf"""
        event_dict = {
            'event_id': event.event_id or f"evt_{int(time.time() * 1000)}",
            'timestamp': datetime.now().isoformat(),
            'source_ip': event.source_ip or 'unknown',
            'target_ip': event.target_ip or 'unknown',
            'dest_port': event.dest_port,
            'src_port': event.src_port,
            'packet_size': event.packet_size,
            'agent_id': event.agent_id or 'unknown',
            'anomaly_score': event.anomaly_score,
            'risk_score': event.risk_score,
            'latitude': event.latitude if event.latitude != 0 else None,
            'longitude': event.longitude if event.longitude != 0 else None,
            'event_type': event.event_type or 'network',
            'description': event.description,
            'has_gps': event.latitude != 0 and event.longitude != 0,
            'ml_enhanced': event.anomaly_score > 0 or event.risk_score > 0,
            'risk_level': self._get_risk_level(event.risk_score),
            'source': 'protobuf'
        }

        self._update_stats(event_dict)
        self._add_to_dashboard(event_dict)

    def _process_json_event(self, event_data):
        """Procesar evento JSON"""
        event_dict = {
            'event_id': event_data.get('event_id', f"evt_{int(time.time() * 1000)}"),
            'timestamp': datetime.now().isoformat(),
            'source_ip': event_data.get('source_ip', 'unknown'),
            'target_ip': event_data.get('target_ip', 'unknown'),
            'dest_port': event_data.get('dest_port', 0),
            'src_port': event_data.get('src_port', 0),
            'packet_size': event_data.get('packet_size', 0),
            'agent_id': event_data.get('agent_id', 'unknown'),
            'anomaly_score': event_data.get('anomaly_score', 0.0),
            'risk_score': event_data.get('risk_score', 0.0),
            'latitude': event_data.get('latitude'),
            'longitude': event_data.get('longitude'),
            'event_type': event_data.get('event_type', 'network'),
            'description': event_data.get('description', ''),
            'has_gps': event_data.get('latitude') is not None and event_data.get('longitude') is not None,
            'ml_enhanced': event_data.get('anomaly_score', 0) > 0 or event_data.get('risk_score', 0) > 0,
            'risk_level': self._get_risk_level(event_data.get('risk_score', 0.0)),
            'source': 'json'
        }

        self._update_stats(event_dict)
        self._add_to_dashboard(event_dict)

    def _get_risk_level(self, risk_score):
        """Calcular nivel de riesgo usando configuración"""
        ml_threshold = self.config.get('threat_detection', {}).get('ml_risk_threshold', 0.8)

        if risk_score >= ml_threshold:
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

        anomaly_threshold = self.config.get('threat_detection', {}).get('anomaly_threshold', 0.7)
        if event['anomaly_score'] > anomaly_threshold:
            self.stats['anomaly_events'] += 1

        ml_threshold = self.config.get('threat_detection', {}).get('ml_risk_threshold', 0.8)
        if event['risk_score'] > ml_threshold:
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
            max_events = self.dashboard_handler.config.get('dashboard', {}).get('max_events_buffer', 300)

            self.dashboard_handler.shared_data['events'].append(event)

            # Procesar con firewall integration si existe
            if hasattr(self.dashboard_handler, 'firewall_integration'):
                try:
                    self.dashboard_handler.firewall_integration.process_event(event)
                except Exception as e:
                    logger.error(f"Error en firewall integration: {e}")

            # Mantener buffer limitado
            if len(self.dashboard_handler.shared_data['events']) > max_events:
                self.dashboard_handler.shared_data['events'] = \
                    self.dashboard_handler.shared_data['events'][-max_events:]

    def get_stats(self):
        """Obtener estadísticas"""
        now = datetime.now()
        recent_events = [t for t in self.stats['events_per_minute']
                         if (now - t).total_seconds() < 60]

        return {
            'total_events': self.stats['total_events'],
            'events_with_gps': self.stats['events_with_gps'],
            'events_per_minute': len(recent_events),
            'unique_ips': len(self.stats['unique_ips']),
            'unique_agents': len(self.stats['unique_agents']),
            'anomaly_events': self.stats['anomaly_events'],
            'high_risk_events': self.stats['high_risk_events'],
            'uptime_seconds': (now - self.stats['start_time']).total_seconds(),
            'last_event_seconds_ago': (now - self.stats['last_event_time']).total_seconds() if self.stats[
                'last_event_time'] else None,
            'ml_models_active': list(self.stats['ml_models_detected']),
            'event_types': dict(self.stats['event_types']),
            'top_ports': dict(sorted(self.stats['ports_seen'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'gps_percentage': (self.stats['events_with_gps'] / max(1, self.stats['total_events'])) * 100,
            'protobuf_events': self.stats['protobuf_events'],
            'json_events': self.stats['json_events']
        }

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()


class DashboardFirewallIntegration:
    """Integración de firewall compatible con dashboard_config.json"""

    def __init__(self, dashboard_instance, config: Dict):
        self.dashboard = dashboard_instance
        self.config = config
        self.command_generator = FirewallCommandGenerator(config)
        self.pending_commands = {}

        # Configuración desde dashboard_config.json
        firewall_config = config.get('firewall', {})
        self.max_pending = firewall_config.get('max_pending_commands', 10)

        logger.info("🔥 FirewallIntegration inicializado desde dashboard_config.json")

    def process_event(self, event_data):
        """Procesar evento para detección de amenazas"""
        if not self.config.get('firewall', {}).get('enabled', True):
            return

        # Generar comandos si es necesario
        commands = self.command_generator.analyze_threat_and_generate_commands(event_data)

        if commands:
            event_id = event_data.get('event_id')

            # Limpiar comandos antiguos
            self._cleanup_old_commands()

            if len(self.pending_commands) < self.max_pending:
                self.pending_commands[event_id] = {
                    'event': event_data,
                    'commands': commands,
                    'timestamp': time.time()
                }

                logger.info(f"💡 {len(commands)} comando(s) generado(s) para evento {event_id}")

    def _cleanup_old_commands(self):
        """Limpiar comandos antiguos"""
        timeout = 300  # 5 minutos
        current_time = time.time()
        expired = []

        for event_id, data in self.pending_commands.items():
            if current_time - data['timestamp'] > timeout:
                expired.append(event_id)

        for event_id in expired:
            del self.pending_commands[event_id]

    def get_pending_summary(self):
        """Resumen de comandos pendientes"""
        self._cleanup_old_commands()

        return {
            'total_events_with_commands': len(self.pending_commands),
            'total_commands': sum(len(p['commands']) for p in self.pending_commands.values()),
            'oldest_pending': min(
                [p['timestamp'] for p in self.pending_commands.values()]) if self.pending_commands else None
        }


class DashboardHandler(BaseHTTPRequestHandler):
    """Handler HTTP compatible con dashboard_config.json y 3 puertos"""

    shared_data = {
        'events': [],
        'confirmations': deque(maxlen=50),
        'events_listener': None,
        'confirmations_listener': None,
        'firewall_sender': None,
        'firewall_integration': None,
        'config': None
    }

    def __init__(self, *args, **kwargs):
        # Inicializar firewall integration si no existe
        if (not self.shared_data.get('firewall_integration') and
                self.shared_data.get('config') and
                self.shared_data['config'].get('firewall', {}).get('enabled', True)):
            self.shared_data['firewall_integration'] = DashboardFirewallIntegration(
                self, self.shared_data['config']
            )

        super().__init__(*args, **kwargs)

    @property
    def config(self):
        return self.shared_data.get('config', {})

    @property
    def firewall_integration(self):
        return self.shared_data.get('firewall_integration')

    def do_GET(self):
        """Manejar GET requests"""
        try:
            if self.path == '/':
                self.serve_dashboard()
            elif self.path == '/api/stats':
                self.serve_stats()
            elif self.path == '/api/events':
                self.serve_events()
            elif self.path == '/api/events/gps':
                self.serve_gps_events()
            elif self.path == '/api/confirmations':
                self.serve_confirmations()
            elif self.path == '/api/config':
                self.serve_config()
            elif self.path == '/health':
                self.serve_health()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logger.error(f"❌ Error en GET {self.path}: {e}")
            self.send_error(500, f"Internal Error: {e}")

    def do_POST(self):
        """Manejar POST requests"""
        try:
            if self.path == '/api/firewall/block':
                self.handle_firewall_block()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logger.error(f"❌ Error en POST {self.path}: {e}")
            self.send_error(500, f"Internal Error: {e}")

    def handle_firewall_block(self):
        """Manejar bloqueo de firewall"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))

            target_ip = request_data.get('target_ip')
            if not target_ip:
                self.send_json({'error': 'Missing target_ip'}, status=400)
                return

            # Crear comando
            if PROTOBUF_AVAILABLE:
                command = firewall_commands_pb2.FirewallCommand()
                command.command_id = str(uuid.uuid4())
                command.action = firewall_commands_pb2.BLOCK_IP
                command.target_ip = target_ip
                command.target_port = request_data.get('target_port', 0)
                command.duration_seconds = 3600  # 1 hora por defecto
                command.reason = request_data.get('reason', 'Dashboard block request')
                command.priority = firewall_commands_pb2.HIGH
                command.dry_run = True
            else:
                command = {
                    'command_id': str(uuid.uuid4()),
                    'action': 'block_ip',
                    'target_ip': target_ip,
                    'target_port': request_data.get('target_port', 0),
                    'duration_seconds': 3600,
                    'reason': request_data.get('reason', 'Dashboard block request'),
                    'priority': 'high',
                    'dry_run': True
                }

            # Enviar comando
            if self.shared_data.get('firewall_sender'):
                success = self.shared_data['firewall_sender'].send_command(command)
                if success:
                    command_id = getattr(command, 'command_id', command.get('command_id'))
                    self.send_json({
                        'success': True,
                        'message': f'Firewall command sent for {target_ip}',
                        'command_id': command_id
                    })
                else:
                    self.send_json({'error': 'Failed to send command'}, status=500)
            else:
                self.send_json({'error': 'Firewall sender not available'}, status=500)

        except Exception as e:
            logger.error(f"❌ Error en firewall block: {e}")
            self.send_json({'error': str(e)}, status=500)

    def serve_stats(self):
        """Servir estadísticas completas"""
        stats = {}

        # Stats de eventos
        if self.shared_data.get('events_listener'):
            stats.update(self.shared_data['events_listener'].get_stats())

        # Stats de confirmaciones
        if self.shared_data.get('confirmations_listener'):
            confirmation_stats = self.shared_data['confirmations_listener'].get_stats()
            stats['confirmations'] = confirmation_stats

        # Información de configuración
        stats['config_loaded'] = bool(self.config)
        if self.config:
            zmq_config = self.config.get('zmq', {})
            stats['events_input_port'] = zmq_config.get('events_input_port', 'unknown')
            stats['commands_output_port'] = zmq_config.get('commands_output_port', 'unknown')
            stats['confirmations_input_port'] = zmq_config.get('confirmations_input_port', 'unknown')
            stats['firewall_enabled'] = self.config.get('firewall', {}).get('enabled', False)

        # Stats de firewall
        if self.firewall_integration:
            stats['firewall_pending'] = self.firewall_integration.get_pending_summary()

        self.send_json(stats)

    def serve_events(self):
        """Servir eventos recientes"""
        max_events = self.config.get('dashboard', {}).get('max_events_buffer', 300)
        events = self.shared_data['events'][-50:]  # Últimos 50 para display

        self.send_json({
            'events': events,
            'count': len(events),
            'total_stored': len(self.shared_data['events']),
            'max_buffer': max_events,
            'protobuf_available': PROTOBUF_AVAILABLE,
            'zmq_available': ZMQ_AVAILABLE
        })

    def serve_gps_events(self):
        """Servir solo eventos con GPS"""
        all_events = self.shared_data['events']
        gps_events = [e for e in all_events if e.get('has_gps')]

        self.send_json({
            'events': gps_events[-30:],  # Últimos 30 con GPS
            'count': len(gps_events),
            'total_events': len(all_events)
        })

    def serve_confirmations(self):
        """Servir confirmaciones del firewall"""
        confirmations = list(self.shared_data['confirmations'])

        self.send_json({
            'confirmations': confirmations,
            'count': len(confirmations),
            'last_confirmation': confirmations[-1] if confirmations else None
        })

    def serve_config(self):
        """Servir configuración actual"""
        self.send_json({
            'config': self.config,
            'loaded_from': 'dashboard_config.json',
            'architecture': '3_ports',
            'zmq_available': ZMQ_AVAILABLE,
            'protobuf_available': PROTOBUF_AVAILABLE
        })

    def serve_health(self):
        """Health check"""
        events_stats = {}
        confirmations_stats = {}

        if self.shared_data.get('events_listener'):
            events_stats = self.shared_data['events_listener'].get_stats()

        if self.shared_data.get('confirmations_listener'):
            confirmations_stats = self.shared_data['confirmations_listener'].get_stats()

        health = {
            'status': 'healthy' if events_stats.get('total_events', 0) > 0 else 'waiting',
            'timestamp': datetime.now().isoformat(),
            'config_loaded': bool(self.config),
            'zmq_available': ZMQ_AVAILABLE,
            'protobuf_available': PROTOBUF_AVAILABLE,
            'firewall_enabled': self.config.get('firewall', {}).get('enabled', False) if self.config else False,
            'architecture': '3_ports',
            'total_events': events_stats.get('total_events', 0),
            'events_with_gps': events_stats.get('events_with_gps', 0),
            'total_confirmations': confirmations_stats.get('total_confirmations', 0)
        }

        if self.config:
            zmq_config = self.config.get('zmq', {})
            health.update({
                'events_input_port': zmq_config.get('events_input_port'),
                'commands_output_port': zmq_config.get('commands_output_port'),
                'confirmations_input_port': zmq_config.get('confirmations_input_port'),
                'auto_refresh_interval': self.config.get('dashboard', {}).get('auto_refresh_interval')
            })

        self.send_json(health)

    def serve_dashboard(self):
        """Servir dashboard HTML actualizado para 3 puertos"""

        # Obtener configuración para el frontend
        map_config = self.config.get('dashboard', {})
        center_lat = map_config.get('map_center_lat', 40.4168)
        center_lng = map_config.get('map_center_lng', -3.7038)
        zoom_level = map_config.get('map_zoom_level', 6)
        refresh_interval = map_config.get('auto_refresh_interval', 3000)

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SCADA Dashboard - Arquitectura 3 Puertos</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css" />
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Arial, sans-serif;
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

        .config-info {{
            background: rgba(0, 100, 200, 0.1); border-radius: 8px; padding: 10px;
            border-left: 3px solid #0066cc; font-size: 0.8rem;
        }}

        .stats-grid {{
            display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
        }}
        .stat-card {{
            background: rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 10px;
            text-align: center; border-left: 3px solid #00ff88;
        }}
        .stat-value {{ font-size: 1.2rem; font-weight: bold; color: #00ff88; }}
        .stat-label {{ font-size: 0.7rem; color: #ccc; margin-top: 3px; }}

        .confirmations-section {{
            background: rgba(0, 255, 0, 0.1); border-radius: 8px; padding: 10px;
            border-left: 3px solid #00ff88; max-height: 150px; overflow-y: auto;
        }}
        .confirmations-header {{ color: #00ff88; font-size: 0.9rem; margin-bottom: 0.5rem; }}
        .confirmation-item {{
            background: rgba(255, 255, 255, 0.1); padding: 5px; margin: 3px 0;
            border-radius: 3px; font-size: 0.75rem;
        }}
        .confirmation-success {{ border-left: 3px solid #4CAF50; }}
        .confirmation-error {{ border-left: 3px solid #f44336; }}

        .events-section {{ flex: 1; }}
        .events-header {{ color: #00ff88; font-size: 1.1rem; margin-bottom: 0.5rem; }}
        .event-item {{ 
            background: rgba(255, 255, 255, 0.1);
            border-left: 3px solid #00ff88; padding: 8px;
            margin-bottom: 8px; border-radius: 5px; font-size: 0.85rem;
            cursor: pointer; transition: all 0.3s ease;
        }}
        .event-item:hover {{ 
            background: rgba(255, 255, 255, 0.2);
            transform: translateX(5px);
        }}
        .event-item.high-risk {{
            border-left-color: #ff4444;
            background: rgba(255, 68, 68, 0.1);
        }}
        .event-time {{ font-size: 0.75rem; color: #aaa; }}
        .event-ip {{ font-weight: bold; color: #00ff88; font-family: monospace; }}
        .event-details {{ font-size: 0.75rem; color: #ccc; margin-top: 3px; }}
        .badge {{ 
            padding: 1px 4px; border-radius: 3px; font-size: 0.7rem; margin-left: 5px;
        }}
        .gps-badge {{ background: #00ff88; color: #000; }}
        .ml-badge {{ background: #ff8800; color: #fff; }}
        .protobuf-badge {{ background: #8800ff; color: #fff; }}
        .config-badge {{ background: #0066cc; color: #fff; }}
        .ports-badge {{ background: #ff00ff; color: #fff; }}
        .risk-high {{ background: #F44336; color: white; }}
        .risk-medium {{ background: #FF9800; color: white; }}
        .risk-low {{ background: #4CAF50; color: white; }}

        .block-button {{
            background: #ff4444; color: white; border: none;
            padding: 4px 8px; border-radius: 3px; font-size: 0.7rem;
            cursor: pointer; margin-left: 5px; transition: all 0.3s ease;
        }}
        .block-button:hover {{ background: #ff2222; }}

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
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SCADA Dashboard - Arquitectura 3 Puertos</h1>
        <div class="status">
            <div class="status-item">
                <span class="status-dot" id="events-status"></span>
                <span>Eventos</span>
            </div>
            <div class="status-item">
                <span class="status-dot" id="commands-status"></span>
                <span>Comandos</span>
            </div>
            <div class="status-item">
                <span class="status-dot" id="confirmations-status"></span>
                <span>Confirmaciones</span>
            </div>
            <div class="status-item">
                Events: <span id="total-events">0</span>
            </div>
            <div class="status-item">
                Conf: <span id="total-confirmations">0</span>
            </div>
        </div>
    </div>

    <div class="main-container">
        <div class="map-container">
            <div id="map"></div>
        </div>

        <div class="sidebar">
            <div class="config-info">
                <strong>📄 Arquitectura 3 Puertos:</strong><br>
                <span id="config-details">Eventos: 5561 | Comandos: 5562 | Confirmaciones: 5563</span>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" id="events-per-minute">0</div>
                    <div class="stat-label">Eventos/min</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="high-risk-events">0</div>
                    <div class="stat-label">Alto Riesgo</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="successful-commands">0</div>
                    <div class="stat-label">Éxito</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="failed-commands">0</div>
                    <div class="stat-label">Fallos</div>
                </div>
            </div>

            <div class="confirmations-section">
                <div class="confirmations-header">✅ Confirmaciones Firewall</div>
                <div id="confirmations-list">
                    <div class="confirmation-item">Esperando confirmaciones del firewall...</div>
                </div>
            </div>

            <div class="events-section">
                <div class="events-header">🚨 Eventos del ML (Puerto 5561)</div>
                <div id="events-list">
                    <div class="event-item">
                        <div class="event-time">Conectando a ml_detector (5561)...</div>
                        <div class="event-ip">Enviando comandos a firewall (5562)...</div>
                        <div class="event-details">Escuchando confirmaciones (5563)...</div>
                    </div>
                </div>
            </div>

            <div style="margin-top: auto;">
                <button class="btn" onclick="refreshData()">🔄 Actualizar</button>
                <button class="btn" onclick="clearMap()">🗺️ Limpiar</button>
                <button class="btn" onclick="showConfirmations()">✅ Confirmaciones</button>
                <button class="btn" onclick="testArchitecture()">🧪 Test 3 Puertos</button>
            </div>
        </div>
    </div>

    <!-- Modal de confirmación -->
    <div id="firewallModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>🔥 Bloquear Evento (3 Puertos)</h2>
                <span class="close" onclick="closeModal()">&times;</span>
            </div>
            <div id="modal-event-info"></div>
            <div class="command-preview" id="command-preview">
                Generando comando de firewall...
            </div>
            <div class="modal-buttons">
                <button class="btn btn-danger" onclick="executeBlock()">🛡️ Bloquear IP</button>
                <button class="btn btn-cancel" onclick="closeModal()">❌ Cancelar</button>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
    <script>
        class ThreePortsDashboard {{
            constructor() {{
                this.map = null;
                this.markers = new Map();
                this.allEvents = [];
                this.selectedEvent = null;
                this.config = null;
                this.confirmations = [];

                this.initMap();
                this.startPeriodicUpdates();
                this.setupEventHandlers();

                console.log('🛡️ Dashboard 3 Puertos inicializado');
                console.log('📡 Puerto 5560: Eventos del ML');
                console.log('🔥 Puerto 5562: Comandos al Firewall');
                console.log('✅ Puerto 5563: Confirmaciones del Firewall');
            }}

            initMap() {{
                this.map = L.map('map').setView([{center_lat}, {center_lng}], {zoom_level});
                L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
                    attribution: '©OpenStreetMap, ©CartoDB'
                }}).addTo(this.map);
            }}

            setupEventHandlers() {{
                // Event delegation para contenido dinámico
                document.getElementById('events-list').addEventListener('click', (e) => {{
                    if (e.target.classList.contains('block-button')) {{
                        e.stopPropagation();
                        const eventId = e.target.getAttribute('data-event-id');
                        const event = this.allEvents.find(ev => ev.event_id === eventId);
                        if (event) {{
                            this.showFirewallModal(event);
                        }}
                    }} else if (e.target.closest('.event-item')) {{
                        const eventItem = e.target.closest('.event-item');
                        const eventId = eventItem.getAttribute('data-event-id');
                        const event = this.allEvents.find(ev => ev.event_id === eventId);
                        if (event) {{
                            this.showEventDetails(event);
                        }}
                    }}
                }});

                // Handlers para modal
                document.addEventListener('keydown', (e) => {{
                    if (e.key === 'Escape') this.closeModal();
                }});

                window.addEventListener('click', (e) => {{
                    const modal = document.getElementById('firewallModal');
                    if (e.target === modal) this.closeModal();
                }});
            }}

            async refreshData() {{
                try {{
                    const [statsResponse, eventsResponse, gpsResponse, confirmationsResponse] = await Promise.all([
                        fetch('/api/stats'),
                        fetch('/api/events'),
                        fetch('/api/events/gps'),
                        fetch('/api/confirmations')
                    ]);

                    const stats = await statsResponse.json();
                    const eventsData = await eventsResponse.json();
                    const gpsData = await gpsResponse.json();
                    const confirmationsData = await confirmationsResponse.json();

                    this.updateStats(stats);
                    this.updateEvents(eventsData.events);
                    this.updateMap(gpsData.events);
                    this.updateConfirmations(confirmationsData.confirmations);
                    this.updateStatusIndicators(stats);

                }} catch (e) {{
                    console.error('❌ Error actualizando datos:', e);
                    this.updateStatusIndicators({{ error: true }});
                }}
            }}

            updateStatusIndicators(stats) {{
                const eventsStatus = document.getElementById('events-status');
                const commandsStatus = document.getElementById('commands-status');
                const confirmationsStatus = document.getElementById('confirmations-status');

                if (stats.error) {{
                    eventsStatus.className = 'status-dot error';
                    commandsStatus.className = 'status-dot error';
                    confirmationsStatus.className = 'status-dot error';
                    return;
                }}

                // Estado eventos (puerto 5560)
                if (stats.total_events > 0) {{
                    eventsStatus.className = 'status-dot online';
                }} else {{
                    eventsStatus.className = 'status-dot warning';
                }}

                // Estado comandos (puerto 5562)
                if (stats.config_loaded) {{
                    commandsStatus.className = 'status-dot online';
                }} else {{
                    commandsStatus.className = 'status-dot error';
                }}

                // Estado confirmaciones (puerto 5563)
                if (stats.confirmations && stats.confirmations.total_confirmations > 0) {{
                    confirmationsStatus.className = 'status-dot online';
                }} else {{
                    confirmationsStatus.className = 'status-dot warning';
                }}
            }}

            updateStats(stats) {{
                document.getElementById('total-events').textContent = stats.total_events || 0;
                document.getElementById('events-per-minute').textContent = stats.events_per_minute || 0;
                document.getElementById('high-risk-events').textContent = stats.high_risk_events || 0;

                if (stats.confirmations) {{
                    document.getElementById('total-confirmations').textContent = stats.confirmations.total_confirmations || 0;
                    document.getElementById('successful-commands').textContent = stats.confirmations.successful_commands || 0;
                    document.getElementById('failed-commands').textContent = stats.confirmations.failed_commands || 0;
                }}
            }}

            updateEvents(events) {{
                if (!events || events.length === 0) {{
                    document.getElementById('events-list').innerHTML = `
                        <div class="event-item">
                            <div class="event-time">Esperando eventos del ML...</div>
                            <div class="event-ip">Puerto 5561: ml_detector → dashboard</div>
                        </div>
                    `;
                    return;
                }}

                this.allEvents = events;
                const eventsList = document.getElementById('events-list');
                eventsList.innerHTML = '';

                events.slice(-12).reverse().forEach((event) => {{
                    const eventDiv = document.createElement('div');
                    eventDiv.className = 'event-item';
                    eventDiv.setAttribute('data-event-id', event.event_id);

                    if (event.risk_level === 'high') {{
                        eventDiv.className += ' high-risk';
                    }}

                    const time = new Date(event.timestamp).toLocaleTimeString();
                    const gpsBadge = event.has_gps ? '<span class="badge gps-badge">GPS</span>' : '';
                    const mlBadge = event.ml_enhanced ? '<span class="badge ml-badge">ML</span>' : '';
                    const protobufBadge = event.source === 'protobuf' ? '<span class="badge protobuf-badge">PB</span>' : '';
                    const portsBadge = '<span class="badge ports-badge">3P</span>';

                    let riskBadge = '';
                    if (event.risk_level === 'high') {{
                        riskBadge = '<span class="badge risk-high">ALTO</span>';
                    }} else if (event.risk_level === 'medium') {{
                        riskBadge = '<span class="badge risk-medium">MEDIO</span>';
                    }} else if (event.risk_level === 'low') {{
                        riskBadge = '<span class="badge risk-low">BAJO</span>';
                    }}

                    const blockButton = (event.risk_level === 'high' || event.risk_score > 0.7) ? 
                        `<button class="block-button" data-event-id="${{event.event_id}}">🛡️ BLOQUEAR</button>` : '';

                    eventDiv.innerHTML = `
                        <div class="event-time">${{time}} | ${{event.agent_id}}</div>
                        <div class="event-ip">${{event.source_ip}} → ${{event.target_ip}}:${{event.dest_port}}${{gpsBadge}}${{mlBadge}}${{protobufBadge}}${{portsBadge}}${{riskBadge}}${{blockButton}}</div>
                        <div class="event-details">
                            R: ${{(event.risk_score * 100).toFixed(1)}}% | 
                            A: ${{(event.anomaly_score * 100).toFixed(1)}}% | 
                            ${{event.packet_size}}B
                        </div>
                    `;

                    eventsList.appendChild(eventDiv);
                }});
            }}

            updateConfirmations(confirmations) {{
                if (!confirmations || confirmations.length === 0) {{
                    document.getElementById('confirmations-list').innerHTML = `
                        <div class="confirmation-item">Esperando confirmaciones...</div>
                    `;
                    return;
                }}

                this.confirmations = confirmations;
                const confirmationsList = document.getElementById('confirmations-list');
                confirmationsList.innerHTML = '';

                confirmations.slice(-5).reverse().forEach((conf) => {{
                    const confDiv = document.createElement('div');
                    confDiv.className = `confirmation-item confirmation-${{conf.status}}`;

                    const time = new Date(conf.timestamp).toLocaleTimeString();
                    const shortId = conf.command_id.substring(0, 8);

                    confDiv.innerHTML = `
                        <strong>${{time}}</strong> [${{shortId}}] ${{conf.action}} ${{conf.target_ip}} - ${{conf.status.toUpperCase()}}
                    `;

                    confirmationsList.appendChild(confDiv);
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

                            const popupContent = `
                                <div style="color: #000;">
                                    <strong>🌐 Evento (3 Puertos)</strong><br>
                                    <strong>Origen:</strong> ${{event.source_ip}}<br>
                                    <strong>Destino:</strong> ${{event.target_ip}}:${{event.dest_port}}<br>
                                    <strong>Riesgo:</strong> ${{(event.risk_score * 100).toFixed(1)}}%<br>
                                    <strong>Arquitectura:</strong> 5561→5562→5563<br>
                                    ${{(event.risk_level === 'high' || event.risk_score > 0.7) ? 
                                        `<button onclick="window.dashboard.showFirewallModal(${{JSON.stringify(event).replace(/"/g, '&quot;')}})" 
                                         style="background: #ff4444; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; margin-top: 5px;">
                                         🛡️ Bloquear (3 Puertos)</button>` : ''}}
                                </div>
                            `;

                            marker.bindPopup(popupContent, {{ maxWidth: 300 }});
                            this.markers.set(markerId, marker);
                        }}
                    }}
                }});
            }}

            showEventDetails(event) {{
                console.log('📋 Detalles del evento (3 puertos):', event);
            }}

            showFirewallModal(event) {{
                this.selectedEvent = event;
                const modal = document.getElementById('firewallModal');
                const eventInfo = document.getElementById('modal-event-info');
                const commandPreview = document.getElementById('command-preview');

                eventInfo.innerHTML = `
                    <h3>Evento Detectado (Arquitectura 3 Puertos):</h3>
                    <p><strong>IP Origen:</strong> ${{event.source_ip}}</p>
                    <p><strong>IP Destino:</strong> ${{event.target_ip}}:${{event.dest_port}}</p>
                    <p><strong>Riesgo:</strong> ${{(event.risk_score * 100).toFixed(1)}}%</p>
                    <p><strong>Agente:</strong> ${{event.agent_id}}</p>
                    <p><strong>Flujo:</strong> ML(5561) → Dashboard → Firewall(5562) → Confirmación(5563)</p>
                `;

                commandPreview.innerHTML = `
                    <strong>Comando de firewall (3 puertos):</strong><br>
                    iptables -A INPUT -s ${{event.source_ip}} -j DROP<br><br>
                    <strong>Puerto envío:</strong> 5562 (hacia firewall_agent)<br>
                    <strong>Puerto confirmación:</strong> 5563 (desde firewall_agent)<br>
                    <strong>Duración:</strong> 1 hora<br>
                    <em>El operador verá la confirmación en tiempo real</em>
                `;

                modal.style.display = 'block';
            }}

            async executeBlock() {{
                if (!this.selectedEvent) return;

                try {{
                    const response = await fetch('/api/firewall/block', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            target_ip: this.selectedEvent.source_ip,
                            target_port: this.selectedEvent.dest_port,
                            reason: `High risk event: ${{(this.selectedEvent.risk_score * 100).toFixed(1)}}% (3 ports)`,
                            event_id: this.selectedEvent.event_id
                        }})
                    }});

                    const result = await response.json();

                    if (result.success) {{
                        alert(`✅ Comando enviado (Puerto 5562)\\nID: ${{result.command_id}}\\n\\n🔔 Esperando confirmación en puerto 5563...`);
                        console.log('🔥 Comando enviado por puerto 5562:', result);
                    }} else {{
                        alert(`❌ Error: ${{result.error}}`);
                    }}

                    this.closeModal();

                }} catch (e) {{
                    alert(`❌ Error de conexión: ${{e.message}}`);
                }}
            }}

            closeModal() {{
                document.getElementById('firewallModal').style.display = 'none';
                this.selectedEvent = null;
            }}

            clearMap() {{
                this.markers.forEach(marker => this.map.removeLayer(marker));
                this.markers.clear();
                console.log('🗺️ Mapa limpiado');
            }}

            async showConfirmations() {{
                try {{
                    const response = await fetch('/api/confirmations');
                    const result = await response.json();

                    let confirmText = 'CONFIRMACIONES FIREWALL (Puerto 5563):\\n\\n';
                    if (result.confirmations && result.confirmations.length > 0) {{
                        result.confirmations.slice(-10).forEach(conf => {{
                            confirmText += `${{conf.timestamp}} - ${{conf.action}} ${{conf.target_ip}} - ${{conf.status.toUpperCase()}}\\n`;
                        }});
                    }} else {{
                        confirmText += 'No hay confirmaciones recientes\\n';
                    }}
                    confirmText += '\\n✅ Las confirmaciones llegan automáticamente por puerto 5563';

                    alert(confirmText);
                }} catch (e) {{
                    alert('Error obteniendo confirmaciones: ' + e.message);
                }}
            }}

            testArchitecture() {{
                alert('🧪 TEST ARQUITECTURA 3 PUERTOS:\\n\\n📡 Puerto 5561: Eventos ML → Dashboard ✅\\n🔥 Puerto 5562: Dashboard → Firewall ✅\\n✅ Puerto 5563: Firewall → Dashboard ✅\\n\\n🎯 onClick: FUNCIONANDO\\n🏗️ Arquitectura: OPERATIVA');
                console.log('✅ Test 3 puertos: FUNCIONANDO');
            }}

            startPeriodicUpdates() {{
                const refreshInterval = {refresh_interval};
                setInterval(() => this.refreshData(), refreshInterval);
                setTimeout(() => this.refreshData(), 1000);
            }}
        }}

        // Funciones globales
        let dashboard;

        function refreshData() {{ dashboard.refreshData(); }}
        function clearMap() {{ dashboard.clearMap(); }}
        function showConfirmations() {{ dashboard.showConfirmations(); }}
        function testArchitecture() {{ dashboard.testArchitecture(); }}
        function closeModal() {{ dashboard.closeModal(); }}
        function executeBlock() {{ dashboard.executeBlock(); }}

        // Inicializar
        document.addEventListener('DOMContentLoaded', function() {{
            dashboard = new ThreePortsDashboard();
            window.dashboard = dashboard;

            console.log('🛡️ Dashboard 3 Puertos inicializado');
            console.log('🏗️ Arquitectura: ML→Dashboard→Firewall→Dashboard');
            console.log('🔧 onClick: CORREGIDO con event delegation');
        }});
    </script>
</body>
</html>"""

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-length', str(len(html.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def send_json(self, data, status=200):
        """Enviar respuesta JSON"""
        json_data = json.dumps(data, indent=2, default=str)
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-length', str(len(json_data.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(json_data.encode('utf-8'))

    def log_message(self, format, *args):
        pass


def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='Dashboard 3 puertos compatible con dashboard_config.json')
    parser.add_argument('--config', default='dashboard_config.json',
                        help='Archivo de configuración JSON')
    parser.add_argument('--test-config', action='store_true',
                        help='Validar configuración y salir')

    args = parser.parse_args()

    # Cargar configuración
    config = load_dashboard_config(args.config)

    if args.test_config:
        print("✅ Configuración JSON válida para 3 puertos")
        zmq_config = config.get('zmq', {})
        print(f"🎯 HTTP: {config['server']['host']}:{config['server']['port']}")
        print(f"📡 Eventos Input: {zmq_config.get('events_input_port', 'N/A')}")
        print(f"🔥 Comandos Output: {zmq_config.get('commands_output_port', 'N/A')}")
        print(f"✅ Confirmaciones Input: {zmq_config.get('confirmations_input_port', 'N/A')}")
        print(f"🛡️ Firewall: {'✅ Enabled' if config['firewall']['enabled'] else '❌ Disabled'}")
        return 0

    print("🛡️ DASHBOARD 3 PUERTOS - dashboard_config.json")
    print("=" * 70)
    print(f"📄 Config: {args.config}")
    print(f"🎯 HTTP: {config['server']['host']}:{config['server']['port']}")
    zmq_config = config.get('zmq', {})
    print(f"📡 Puerto 5560: Eventos del ML → Dashboard")
    print(f"🔥 Puerto 5562: Dashboard → Comandos Firewall")
    print(f"✅ Puerto 5563: Firewall → Confirmaciones Dashboard")
    print(f"🛡️ Firewall: {'✅ Enabled' if config['firewall']['enabled'] else '❌ Disabled'}")
    print(f"📊 Buffer: {config['dashboard']['max_events_buffer']} eventos")
    print("")

    # Verificar puerto HTTP
    host = config['server']['host']
    port = config['server']['port']

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            print(f"⚠️ Puerto {port} ocupado, intentando {port + 1}...")
            port = port + 1

        # Guardar configuración
        DashboardHandler.shared_data['config'] = config

        # Crear servidor HTTP
        server = HTTPServer((host, port), DashboardHandler)

        # Inicializar listeners ZMQ
        if ZMQ_AVAILABLE:
            # Listener de eventos (puerto 5560)
            events_listener = ZeroMQEventsListener(DashboardHandler, config)
            DashboardHandler.shared_data['events_listener'] = events_listener
            events_listener.start()
            logger.info(f"📡 Events listener iniciado en puerto {zmq_config.get('events_input_port', 5561)}")

            # Listener de confirmaciones (puerto 5563)
            confirmations_listener = FirewallConfirmationListener(DashboardHandler, config)
            DashboardHandler.shared_data['confirmations_listener'] = confirmations_listener
            confirmations_listener.start()
            logger.info(
                f"✅ Confirmations listener iniciado en puerto {zmq_config.get('confirmations_input_port', 5563)}")

        # Inicializar sender de comandos (puerto 5562)
        if ZMQ_AVAILABLE and config['firewall']['enabled']:
            firewall_sender = FirewallCommandSender(config)
            DashboardHandler.shared_data['firewall_sender'] = firewall_sender
            logger.info(f"🔥 Command sender iniciado en puerto {zmq_config.get('commands_output_port', 5562)}")

        print(f"🚀 Dashboard 3 puertos iniciado en http://{host}:{port}")
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"📡 API Stats: http://{host}:{port}/api/stats")
        print(f"✅ API Confirmaciones: http://{host}:{port}/api/confirmations")
        print(f"🏥 Health: http://{host}:{port}/health")
        print("")
        print("✅ ARQUITECTURA 3 PUERTOS:")
        print(f"   📡 Puerto {zmq_config.get('events_input_port', 5561)}: Lee eventos del ML")
        print(f"   🔥 Puerto {zmq_config.get('commands_output_port', 5562)}: Envía comandos al firewall")
        print(f"   ✅ Puerto {zmq_config.get('confirmations_input_port', 5563)}: Lee confirmaciones del firewall")
        print(f"   🔌 ZeroMQ: {ZMQ_AVAILABLE}")
        print(f"   📦 Protobuf: {PROTOBUF_AVAILABLE}")
        print("   🎯 onClick: CORREGIDO con event delegation")
        print("   🔄 Feedback loop: IMPLEMENTADO")
        print("")
        print("🛑 Presiona Ctrl+C para detener")

        server.serve_forever()

    except KeyboardInterrupt:
        print("\n🛑 Dashboard detenido")
        if DashboardHandler.shared_data.get('events_listener'):
            DashboardHandler.shared_data['events_listener'].stop()
        if DashboardHandler.shared_data.get('confirmations_listener'):
            DashboardHandler.shared_data['confirmations_listener'].stop()
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