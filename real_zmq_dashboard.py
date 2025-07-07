#!/usr/bin/env python3
"""
🛡️ Dashboard SCADA REAL - ZeroMQ 5560 + Mapa Interactivo
Conectado a eventos enriquecidos por ML del puerto 5560
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
                        # Los eventos del puerto 5560 deberían estar corregidos
                        logger.debug(f"Error parsing evento: {e}")
                else:
                    try:
                        event_data = json.loads(message.decode('utf-8'))
                        self._process_json_event(event_data)
                    except:
                        pass

            except zmq.Again:
                time.sleep(0.1)
                # Actualizar health si no hay mensajes
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
            # Crear diccionario del evento
            event_dict = {
                'event_id': event.event_id or f"evt_{int(time.time() * 1000)}",
                'timestamp': datetime.now().isoformat(),  # Usar tiempo actual para visualización
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
                'risk_level': self._get_risk_level(event.risk_score)
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
                'risk_level': self._get_risk_level(event_data.get('risk_score', 0.0))
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

        # Detectar modelos ML
        if event['anomaly_score'] > 0:
            self.stats['ml_models_detected'].add('Anomaly Detection')
        if event['risk_score'] > 0:
            self.stats['ml_models_detected'].add('Risk Assessment')

    def _add_to_dashboard(self, event):
        """Añadir evento al dashboard"""
        if hasattr(self.dashboard_handler, 'shared_data'):
            self.dashboard_handler.shared_data['events'].append(event)

            # Mantener últimos 300 eventos
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
    """Handler del dashboard"""

    shared_data = {
        'events': [],
        'zmq_listener': None
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
            elif self.path == '/health':
                self.serve_health()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logger.error(f"❌ Error en GET {self.path}: {e}")
            self.send_error(500, f"Internal Error: {e}")

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
            'protobuf_enabled': PROTOBUF_AVAILABLE,
            'total_events': stats.get('total_events', 0),
            'events_with_gps': stats.get('events_with_gps', 0)
        }
        self.send_json(health_data)

    def send_json(self, data):
        """Enviar respuesta JSON"""
        json_data = json.dumps(data, indent=2, default=str)
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-length', str(len(json_data.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(json_data.encode('utf-8'))

    def serve_dashboard(self):
        """Dashboard HTML"""
        html = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SCADA Real - ML Enhanced</title>
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
        }
        .event-item:hover { background: rgba(255, 255, 255, 0.2); }
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

        @keyframes slideIn { from { opacity: 0; transform: translateX(-20px); } to { opacity: 1; transform: translateX(0); } }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SCADA Real - ML Enhanced (Puerto 5560)</h1>
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
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
    <script>
        class MLDashboard {
            constructor() {
                this.map = null;
                this.markers = new Map();
                this.lastEventCount = 0;
                this.allEvents = [];

                this.initMap();
                this.startPeriodicUpdates();
                this.log('🛡️ Dashboard ML inicializado');
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

                    eventDiv.innerHTML = `
                        <div class="event-time">${time} | ${event.agent_id}</div>
                        <div class="event-ip">${event.source_ip} → ${event.target_ip}:${event.dest_port}${gpsBadge}${mlBadge}${riskBadge}</div>
                        <div class="event-details">
                            A: ${(event.anomaly_score * 100).toFixed(1)}% | 
                            R: ${(event.risk_score * 100).toFixed(1)}% | 
                            ${event.packet_size}B
                            ${event.description ? ` | ${event.description}` : ''}
                        </div>
                    `;

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
                                    <strong>Tiempo:</strong> ${new Date(event.timestamp).toLocaleString()}
                                </div>
                            `;

                            marker.bindPopup(popupContent, { maxWidth: 300 });
                            this.markers.set(markerId, marker);
                        }
                    }
                });
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

        document.addEventListener('DOMContentLoaded', function() {
            dashboard = new MLDashboard();
            console.log('🛡️ Dashboard ML Enhanced - ZeroMQ 5560');
            console.log('🤖 Mostrando eventos con ML scores en tiempo real');
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
    print("🛡️ DASHBOARD SCADA REAL - ZeroMQ 5560")
    print("=" * 50)
    print("🎯 Conectándose a:")
    print("   📡 ZeroMQ 5560 (eventos enriquecidos por ML)")
    print("   🤖 Eventos con anomaly_score y risk_score")
    print("   🗺️ Coordenadas GPS cuando disponibles")
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

        # Inicializar listener ZeroMQ
        zmq_listener = ZeroMQListener(DashboardHandler)
        DashboardHandler.shared_data['zmq_listener'] = zmq_listener
        zmq_listener.start()

        print(f"🚀 Dashboard iniciado en http://{host}:{port}")
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"📡 API Stats: http://{host}:{port}/api/stats")
        print(f"🗺️ Eventos GPS: http://{host}:{port}/api/events/gps")
        print("")
        print("✅ CONECTADO A:")
        print("   🔌 ZeroMQ puerto 5560")
        print("   📦 Eventos enriquecidos con ML")
        print("   🗺️ Mapas interactivos con GPS")
        print("")
        print("🎯 Los eventos aparecerán automáticamente")
        print("🛑 Presiona Ctrl+C para detener")

        server.serve_forever()

    except KeyboardInterrupt:
        print("\n🛑 Dashboard detenido por usuario")
        if 'zmq_listener' in DashboardHandler.shared_data:
            DashboardHandler.shared_data['zmq_listener'].stop()
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()