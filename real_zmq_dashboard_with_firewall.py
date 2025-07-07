#!/usr/bin/env python3
"""
🛡️ Dashboard SCADA REAL - ZeroMQ 5560 + Mapa Interactivo + Comandos Firewall
Conectado a eventos enriquecidos por ML del puerto 5560
Envía comandos de firewall por puerto 5561
"""

import json
import time
import threading
import zmq
import socket
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging
from collections import defaultdict, deque
import urllib.parse

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Importar protobuf
try:
    from src.protocols.protobuf import network_event_pb2

    PROTOBUF_AVAILABLE = True
    logger.info("✅ Protobuf importado desde src.protocols.protobuf.network_event_pb2")
except ImportError:
    try:
        import network_event_pb2

        PROTOBUF_AVAILABLE = True
        logger.info("✅ Protobuf importado desde directorio local")
    except ImportError:
        PROTOBUF_AVAILABLE = False
        logger.error("❌ Protobuf no disponible")


class FirewallCommandSender:
    """Cliente ZeroMQ para enviar comandos de firewall al puerto 5561"""

    def __init__(self):
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUSH)
        self.socket.connect("tcp://localhost:5561")
        self.command_log = deque(maxlen=100)
        logger.info("🔥 Firewall command sender conectado al puerto 5561")

    def send_firewall_command(self, command_data):
        """Enviar comando de firewall"""
        try:
            # Agregar timestamp y ID único
            command_data.update({
                'command_id': f"fw_{int(time.time() * 1000)}",
                'sent_timestamp': datetime.now().isoformat(),
                'dashboard_version': "1.0"
            })

            # Enviar como JSON
            message = json.dumps(command_data).encode('utf-8')
            self.socket.send(message)

            # Log local
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': 'firewall_command_sent',
                'command_id': command_data['command_id'],
                'target_ip': command_data.get('target_ip'),
                'action_type': command_data.get('action'),
                'agent': command_data.get('source_agent')
            }
            self.command_log.append(log_entry)

            logger.info(f"🔥 Comando enviado: {command_data['action']} para {command_data.get('target_ip')}")
            return True

        except Exception as e:
            logger.error(f"❌ Error enviando comando firewall: {e}")
            return False

    def get_command_log(self):
        """Obtener log de comandos enviados"""
        return list(self.command_log)

    def close(self):
        """Cerrar conexión"""
        self.socket.close()
        self.context.term()


class ZeroMQListener:
    """Listener de ZeroMQ puerto 5560 (eventos enriquecidos por ML)"""

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
            'ports_seen': defaultdict(int)
        }

    def start(self):
        """Iniciar conexión a ZeroMQ 5560"""
        self.running = True

        try:
            self.context = zmq.Context()
            self.socket = self.context.socket(zmq.SUB)
            self.socket.connect("tcp://localhost:5560")
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")
            self.socket.setsockopt(zmq.RCVTIMEO, 5000)

            self.broker_stats['connection_time'] = datetime.now()

            logger.info("🔌 Conectado a ZeroMQ puerto 5560 (eventos enriquecidos por ML)")

            # Thread de escucha
            thread = threading.Thread(target=self._listen_events, daemon=True)
            thread.start()

            logger.info("🎯 Dashboard iniciado - Esperando eventos enriquecidos...")

        except Exception as e:
            logger.error(f"❌ Error conectando a ZeroMQ: {e}")

    def _listen_events(self):
        """Escuchar eventos del puerto 5560"""
        while self.running:
            try:
                message = self.socket.recv(zmq.NOBLOCK)

                # Estadísticas del broker
                self.broker_stats['total_messages'] += 1
                self.broker_stats['bytes_received'] += len(message)
                self.broker_stats['last_message_time'] = datetime.now()
                self.broker_stats['broker_health'] = 'healthy'

                if PROTOBUF_AVAILABLE:
                    try:
                        event = network_event_pb2.NetworkEvent()
                        event.ParseFromString(message)
                        self._process_event(event)
                    except Exception as e:
                        logger.debug(f"Error parsing evento: {e}")
                else:
                    try:
                        event_data = json.loads(message.decode('utf-8'))
                        self._process_json_event(event_data)
                    except:
                        pass

            except zmq.Again:
                time.sleep(0.1)
                if self.broker_stats['last_message_time']:
                    time_since = (datetime.now() - self.broker_stats['last_message_time']).total_seconds()
                    if time_since > 60:
                        self.broker_stats['broker_health'] = 'stale'
            except Exception as e:
                logger.error(f"❌ Error en listener: {e}")
                time.sleep(1)

    def _process_event(self, event):
        """Procesar evento protobuf"""
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
                'protocol': getattr(event, 'protocol', 'TCP'),  # Protocolo de red
                'flags': getattr(event, 'flags', [])  # Flags TCP si están disponibles
            }

            self._update_stats(event_dict)
            self._add_to_dashboard(event_dict)

            if event_dict['ml_enhanced']:
                logger.info(f"📡 Evento ML: {event_dict['source_ip']} → {event_dict['target_ip']} "
                            f"(R: {event_dict['risk_score']:.2f}, A: {event_dict['anomaly_score']:.2f})")

        except Exception as e:
            logger.error(f"❌ Error procesando evento: {e}")

    def _process_json_event(self, event_data):
        """Procesar evento JSON fallback"""
        try:
            event_dict = {
                'event_id': event_data.get('event_id', 'unknown'),
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
                'protocol': event_data.get('protocol', 'TCP'),
                'flags': event_data.get('flags', [])
            }

            self._update_stats(event_dict)
            self._add_to_dashboard(event_dict)

        except Exception as e:
            logger.error(f"❌ Error procesando JSON: {e}")

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
            'broker_stats': self.broker_stats
        }

    def stop(self):
        """Detener listener"""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()


class DashboardHandler(BaseHTTPRequestHandler):
    """Handler del dashboard con capacidades de firewall"""

    shared_data = {
        'events': [],
        'zmq_listener': None,
        'firewall_sender': None
    }

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
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logger.error(f"❌ Error en POST {self.path}: {e}")
            self.send_error(500, f"Internal Error: {e}")

    def handle_firewall_block(self):
        """Manejar solicitud de bloqueo de firewall"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))

            event_id = request_data.get('event_id')
            target_ip = request_data.get('target_ip')
            source_agent = request_data.get('source_agent')
            action = request_data.get('action', 'block_ip')

            if not target_ip or not source_agent:
                self.send_json({'error': 'Missing required fields'}, status=400)
                return

            # Crear comando de firewall
            firewall_command = {
                'action': action,
                'target_ip': target_ip,
                'source_agent': source_agent,
                'reason': request_data.get('reason', 'High risk event from dashboard'),
                'firewall_rule': {
                    'rule_type': 'iptables',
                    'command': f"iptables -A INPUT -s {target_ip} -j DROP",
                    'duration': request_data.get('duration', '1h'),
                    'priority': 'high'
                },
                'metadata': {
                    'event_id': event_id,
                    'ml_scores': request_data.get('ml_scores', {}),
                    'packet_info': request_data.get('packet_info', ''),
                    'dashboard_user': 'operator'
                }
            }

            # Enviar comando
            if self.shared_data['firewall_sender']:
                success = self.shared_data['firewall_sender'].send_firewall_command(firewall_command)
                if success:
                    self.send_json({
                        'success': True,
                        'message': f'Firewall command sent for {target_ip}',
                        'command_id': firewall_command.get('command_id')
                    })
                else:
                    self.send_json({'error': 'Failed to send firewall command'}, status=500)
            else:
                self.send_json({'error': 'Firewall sender not available'}, status=500)

        except Exception as e:
            logger.error(f"❌ Error en firewall block: {e}")
            self.send_json({'error': str(e)}, status=500)

    def handle_generate_firewall_command(self):
        """Generar comando de firewall usando Claude"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))

            # Información del evento
            event_info = request_data.get('event', {})

            # Generar comando inteligente (simulado - en tu implementación real usarías Claude)
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
            action = 'block_ip_permanent'
            duration = 'permanent'
            priority = 'critical'
        elif risk_score >= 0.8:
            action = 'block_ip'
            duration = '24h'
            priority = 'high'
        else:
            action = 'rate_limit'
            duration = '1h'
            priority = 'medium'

        # Generar comando específico del protocolo
        if dest_port in [22, 3389]:  # SSH, RDP
            command = f"iptables -A INPUT -s {source_ip} -p {protocol.lower()} --dport {dest_port} -j DROP"
        elif dest_port in [80, 443]:  # HTTP, HTTPS
            command = f"iptables -A INPUT -s {source_ip} -p {protocol.lower()} --dport {dest_port} -m limit --limit 10/min -j ACCEPT; iptables -A INPUT -s {source_ip} -p {protocol.lower()} --dport {dest_port} -j DROP"
        else:
            command = f"iptables -A INPUT -s {source_ip} -j DROP"

        return {
            'action': action,
            'target_ip': source_ip,  # Bloqueamos la IP de origen
            'firewall_rule': {
                'rule_type': 'iptables',
                'command': command,
                'duration': duration,
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

    def serve_stats(self):
        """Estadísticas del sistema"""
        if self.shared_data['zmq_listener']:
            stats = self.shared_data['zmq_listener'].get_stats()
        else:
            stats = {'error': 'ZeroMQ listener not initialized'}

        self.send_json(stats)

    def serve_events(self):
        """Eventos recientes"""
        events = self.shared_data['events'][-50:]
        self.send_json({
            'events': events,
            'count': len(events),
            'source': 'zeromq_5560_ml_enriched',
            'protobuf_available': PROTOBUF_AVAILABLE
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
            'total_events': stats.get('total_events', 0),
            'events_with_gps': stats.get('events_with_gps', 0),
            'firewall_enabled': self.shared_data['firewall_sender'] is not None
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
    <title>🛡️ SCADA Real - ML Enhanced + Firewall</title>
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
        <h1>🛡️ SCADA Real - ML Enhanced + Firewall (Puerto 5560)</h1>
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
                Eventos: <span id="total-events">0</span>
            </div>
            <div class="status-item">
                GPS: <span id="gps-events">0</span>
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
                <div class="events-header">🚨 Eventos ML Enriquecidos</div>
                <div id="events-list">
                    <div class="event-item">
                        <div class="event-time">Conectando a ZeroMQ 5560...</div>
                        <div class="event-ip">Esperando eventos enriquecidos por ML</div>
                    </div>
                </div>
            </div>

            <div style="margin-top: auto;">
                <button class="btn" onclick="refreshData()">🔄 Actualizar</button>
                <button class="btn" onclick="clearMap()">🗺️ Limpiar Mapa</button>
                <button class="btn" onclick="showFirewallLog()">🔥 Log Firewall</button>
            </div>
        </div>
    </div>

    <!-- Modal de confirmación de firewall -->
    <div id="firewallModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>🔥 Bloquear Evento de Alto Riesgo</h2>
                <span class="close" onclick="closeFirewallModal()">&times;</span>
            </div>
            <div id="modal-event-info"></div>
            <div class="command-preview" id="command-preview">
                Generando comando de firewall...
            </div>
            <div class="modal-buttons">
                <button class="btn btn-danger" onclick="executeFirewallCommand()">🛡️ Bloquear IP</button>
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
                this.log('🛡️ Dashboard ML + Firewall inicializado');
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
                    const [statsResponse, eventsResponse, gpsResponse] = await Promise.all([
                        fetch('/api/stats'),
                        fetch('/api/events'),
                        fetch('/api/events/gps')
                    ]);

                    const stats = await statsResponse.json();
                    const eventsData = await eventsResponse.json();
                    const gpsData = await gpsResponse.json();

                    this.updateStats(stats);
                    this.updateEvents(eventsData.events);
                    this.updateMap(gpsData.events);
                    this.updateStatusIndicators(stats, eventsData);

                } catch (e) {
                    this.log('❌ Error actualizando datos: ' + e.message);
                }
            }

            updateStatusIndicators(stats, eventsData) {
                const zmqStatus = document.getElementById('zmq-status');
                const mlStatus = document.getElementById('ml-status');
                const firewallStatus = document.getElementById('firewall-status');

                if (stats.total_events > this.lastEventCount) {
                    zmqStatus.className = 'status-dot online';
                    const hasMLScores = eventsData.events && eventsData.events.some(e => 
                        (e.anomaly_score && e.anomaly_score > 0) || (e.risk_score && e.risk_score > 0)
                    );
                    mlStatus.className = hasMLScores ? 'status-dot online' : 'status-dot warning';
                } else {
                    zmqStatus.className = 'status-dot warning';
                    mlStatus.className = 'status-dot warning';
                }

                // Estado del firewall
                firewallStatus.className = 'status-dot online'; // Asumimos que está activo

                this.lastEventCount = stats.total_events || 0;
            }

            updateStats(stats) {
                document.getElementById('total-events').textContent = stats.total_events || 0;
                document.getElementById('gps-events').textContent = stats.events_with_gps || 0;
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
                            <div class="event-ip">Verifica que el ML Detector esté enviando al puerto 5560</div>
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
                        '<button class="block-button" onclick="dashboard.showFirewallModal(event)">🛡️ BLOQUEAR</button>' : '';

                    eventDiv.innerHTML = `
                        <div class="event-time">${time} | ${event.agent_id}</div>
                        <div class="event-ip">${event.source_ip} → ${event.target_ip}:${event.dest_port}${gpsBadge}${mlBadge}${riskBadge}${blockButton}</div>
                        <div class="event-details">
                            A: ${(event.anomaly_score * 100).toFixed(1)}% | 
                            R: ${(event.risk_score * 100).toFixed(1)}% | 
                            ${event.packet_size}B
                            ${event.description ? ` | ${event.description}` : ''}
                        </div>
                    `;

                    // Agregar event listener para click en el evento
                    eventDiv.addEventListener('click', (e) => {
                        if (!e.target.classList.contains('block-button')) {
                            this.showEventDetails(event);
                        }
                    });

                    // Inyectar referencia al evento para el botón
                    if (blockButton) {
                        eventDiv.querySelector('.block-button').addEventListener('click', (e) => {
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

                            const popupContent = `
                                <div style="color: #000;">
                                    <strong>🌐 Evento ML</strong><br>
                                    <strong>Origen:</strong> ${event.source_ip}<br>
                                    <strong>Destino:</strong> ${event.target_ip}:${event.dest_port}<br>
                                    <strong>Riesgo:</strong> ${(event.risk_score * 100).toFixed(1)}%<br>
                                    <strong>Anomalía:</strong> ${(event.anomaly_score * 100).toFixed(1)}%<br>
                                    <strong>Agente:</strong> ${event.agent_id}<br>
                                    ${event.description ? `<strong>Desc:</strong> ${event.description}<br>` : ''}
                                    <strong>Tiempo:</strong> ${new Date(event.timestamp).toLocaleString()}<br>
                                    ${(event.risk_level === 'high' || event.risk_score > 0.7) ? 
                                        '<button onclick="dashboard.showFirewallModal(' + JSON.stringify(event).replace(/"/g, '&quot;') + ')" style="background: #ff4444; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; margin-top: 5px;">🛡️ Bloquear IP</button>' : ''}
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
                this.log(`📋 Detalles del evento: ${event.source_ip} → ${event.target_ip}`);
                // Aquí podrías mostrar un panel lateral con detalles completos
            }

            showFirewallModal(event) {
                this.selectedEvent = event;
                const modal = document.getElementById('firewallModal');
                const eventInfo = document.getElementById('modal-event-info');
                const commandPreview = document.getElementById('command-preview');

                eventInfo.innerHTML = `
                    <h3>Evento Detectado:</h3>
                    <p><strong>IP Origen:</strong> ${event.source_ip}</p>
                    <p><strong>IP Destino:</strong> ${event.target_ip}:${event.dest_port}</p>
                    <p><strong>Riesgo:</strong> ${(event.risk_score * 100).toFixed(1)}%</p>
                    <p><strong>Anomalía:</strong> ${(event.anomaly_score * 100).toFixed(1)}%</p>
                    <p><strong>Agente:</strong> ${event.agent_id}</p>
                    <p><strong>Protocolo:</strong> ${event.protocol || 'TCP'}</p>
                `;

                commandPreview.textContent = 'Generando comando de firewall inteligente...';

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
                            <strong>Comando sugerido:</strong><br>
                            ${cmd.firewall_rule.command}<br><br>
                            <strong>Acción:</strong> ${cmd.action}<br>
                            <strong>Duración:</strong> ${cmd.firewall_rule.duration}<br>
                            <strong>Prioridad:</strong> ${cmd.firewall_rule.priority}<br>
                            <strong>Análisis:</strong> ${cmd.analysis.threat_type}<br>
                            <strong>Confianza:</strong> ${cmd.analysis.confidence.toFixed(1)}%
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
                            target_ip: this.selectedEvent.source_ip, // Bloqueamos la IP de origen
                            source_agent: this.selectedEvent.agent_id,
                            action: this.suggestedCommand.action,
                            reason: `High risk event: ${(this.selectedEvent.risk_score * 100).toFixed(1)}% risk score`,
                            ml_scores: {
                                A: this.selectedEvent.anomaly_score,
                                R: this.selectedEvent.risk_score
                            },
                            packet_info: `Packet from ${this.selectedEvent.source_ip} to ${this.selectedEvent.target_ip}:${this.selectedEvent.dest_port}`,
                            duration: this.suggestedCommand.firewall_rule.duration
                        })
                    });

                    const result = await response.json();

                    if (result.success) {
                        this.log(`🛡️ Comando enviado: ${result.command_id}`);
                        alert(`✅ Comando de firewall enviado exitosamente\nComando ID: ${result.command_id}`);
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

                    let logText = 'LOG DE COMANDOS DE FIREWALL:\\n\\n';
                    result.commands.forEach(cmd => {
                        logText += `${cmd.timestamp} - ${cmd.action} - ${cmd.target_ip} (${cmd.agent})\\n`;
                    });

                    alert(logText || 'No hay comandos en el log');
                } catch (e) {
                    alert('Error obteniendo log: ' + e.message);
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
        function closeFirewallModal() { dashboard.closeFirewallModal(); }
        function executeFirewallCommand() { dashboard.executeFirewallCommand(); }

        document.addEventListener('DOMContentLoaded', function() {
            dashboard = new MLFirewallDashboard();
            console.log('🛡️ Dashboard ML Enhanced + Firewall - ZeroMQ 5560/5561');
            console.log('🤖 Mostrando eventos con ML scores en tiempo real');
            console.log('🔥 Comandos de firewall por puerto 5561');
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
    print("🛡️ DASHBOARD SCADA REAL - ZeroMQ 5560 + Firewall 5561")
    print("=" * 60)
    print("🎯 Conectándose a:")
    print("   📡 ZeroMQ 5560 (eventos enriquecidos por ML)")
    print("   🔥 ZeroMQ 5561 (comandos de firewall)")
    print("   🤖 Eventos con anomaly_score y risk_score")
    print("   🗺️ Coordenadas GPS cuando disponibles")
    print("   🛡️ Respuesta automática a amenazas")
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
        firewall_sender = FirewallCommandSender()
        DashboardHandler.shared_data['firewall_sender'] = firewall_sender

        # Inicializar listener ZeroMQ
        zmq_listener = ZeroMQListener(DashboardHandler)
        DashboardHandler.shared_data['zmq_listener'] = zmq_listener
        zmq_listener.start()

        print(f"🚀 Dashboard iniciado en http://{host}:{port}")
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"📡 API Stats: http://{host}:{port}/api/stats")
        print(f"🗺️ Eventos GPS: http://{host}:{port}/api/events/gps")
        print(f"🔥 Firewall Log: http://{host}:{port}/api/firewall/log")
        print("")
        print("✅ CONECTADO A:")
        print("   🔌 ZeroMQ puerto 5560 (entrada)")
        print("   🔥 ZeroMQ puerto 5561 (salida firewall)")
        print("   📦 Eventos enriquecidos con ML")
        print("   🗺️ Mapas interactivos con GPS")
        print("   🛡️ Sistema de respuesta automática")
        print("")
        print("🎯 FUNCIONALIDADES:")
        print("   ✅ Eventos clickeables en mapa y lista")
        print("   ✅ Modal de confirmación para bloqueos")
        print("   ✅ Generación inteligente de comandos")
        print("   ✅ Envío automático al puerto 5561")
        print("   ✅ Log de comandos ejecutados")
        print("")
        print("🛑 Presiona Ctrl+C para detener")

        server.serve_forever()

    except KeyboardInterrupt:
        print("\n🛑 Dashboard detenido por usuario")
        if 'zmq_listener' in DashboardHandler.shared_data:
            DashboardHandler.shared_data['zmq_listener'].stop()
        if 'firewall_sender' in DashboardHandler.shared_data:
            DashboardHandler.shared_data['firewall_sender'].close()
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()