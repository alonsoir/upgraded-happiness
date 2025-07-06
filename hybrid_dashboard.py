#!/usr/bin/env python3
"""
🛡️ Dashboard SCADA REAL - Conectado a ZeroMQ 5559
Muestra SOLO eventos reales del Enhanced Promiscuous Agent
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
import sys
import os

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Intentar importar protobuf desde la ruta correcta del proyecto
try:
    from src.protocols.protobuf import network_event_pb2

    PROTOBUF_AVAILABLE = True
    logger.info("✅ Protobuf importado desde src.protocols.protobuf.network_event_pb2")
except ImportError:
    # Fallback: intentar desde directorio local
    try:
        import network_event_pb2

        PROTOBUF_AVAILABLE = True
        logger.info("✅ Protobuf importado desde directorio local")
    except ImportError:
        PROTOBUF_AVAILABLE = False
        logger.error("❌ No se pudo importar network_event_pb2")
        logger.error("   Asegúrate de que el archivo esté en src/protocols/protobuf/network_event_pb2.py")
        logger.error("   O copia network_event_pb2.py al directorio del dashboard")


class ZeroMQListener:
    """Listener real de ZeroMQ puerto 5559"""

    def __init__(self, dashboard_handler):
        self.dashboard_handler = dashboard_handler
        self.running = False
        self.context = None
        self.socket = None
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
            'connection_errors': 0,
            'ml_models_detected': set(),
            'event_types': defaultdict(int),
            'ports_seen': defaultdict(int),
            'protocols_seen': defaultdict(int)
        }

    def start(self):
        """Iniciar conexión a ZeroMQ 5559"""
        self.running = True

        try:
            # Configurar ZeroMQ
            self.context = zmq.Context()
            self.socket = self.context.socket(zmq.SUB)
            self.socket.connect("tcp://localhost:5559")
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")  # Suscribirse a todos los mensajes
            self.socket.setsockopt(zmq.RCVTIMEO, 5000)  # Timeout 5 segundos

            logger.info("🔌 Conectado a ZeroMQ puerto 5559")

            if PROTOBUF_AVAILABLE:
                logger.info("📦 Decodificación protobuf habilitada")
            else:
                logger.warning("⚠️ Protobuf no disponible - usando fallback JSON")

            # Iniciar thread de escucha
            thread = threading.Thread(target=self._listen_events, daemon=True)
            thread.start()

            logger.info("🎯 Listener ZeroMQ iniciado - Esperando eventos reales...")

        except Exception as e:
            logger.error(f"❌ Error conectando a ZeroMQ: {e}")
            logger.error("   Verifica que el Enhanced Promiscuous Agent esté ejecutándose")
            logger.error("   Y que esté enviando eventos al puerto 5559")
            self.stats['connection_errors'] += 1

    def _listen_events(self):
        """Escuchar eventos reales de ZeroMQ"""
        while self.running:
            try:
                # Recibir mensaje
                message = self.socket.recv(zmq.NOBLOCK)

                if PROTOBUF_AVAILABLE:
                    # Decodificar protobuf
                    event = network_event_pb2.NetworkEvent()
                    event.ParseFromString(message)
                    self._process_protobuf_event(event)
                else:
                    # Tratar como JSON fallback
                    try:
                        event_data = json.loads(message.decode('utf-8'))
                        self._process_json_event(event_data)
                    except:
                        logger.warning("⚠️ Mensaje no es JSON válido")

            except zmq.Again:
                # No hay mensajes, continuar
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"❌ Error recibiendo mensaje: {e}")
                self.stats['connection_errors'] += 1
                time.sleep(1)

    def _process_protobuf_event(self, event):
        """Procesar evento protobuf real"""
        try:
            # Convertir a diccionario
            event_dict = {
                'event_id': event.event_id,
                'timestamp': datetime.fromtimestamp(event.timestamp).isoformat(),
                'source_ip': event.source_ip,
                'target_ip': event.target_ip,
                'packet_size': event.packet_size,
                'dest_port': event.dest_port,
                'src_port': event.src_port,
                'agent_id': event.agent_id,
                'anomaly_score': event.anomaly_score,
                'latitude': event.latitude if event.latitude != 0 else None,
                'longitude': event.longitude if event.longitude != 0 else None,
                'event_type': event.event_type,
                'risk_score': event.risk_score,
                'description': event.description,
                'has_gps': event.latitude != 0 and event.longitude != 0
            }

            self._update_stats(event_dict)
            self._add_to_dashboard(event_dict)

            logger.info(f"📡 Evento real: {event.source_ip} → {event.target_ip} "
                        f"(GPS: {event_dict['has_gps']}, Risk: {event.risk_score:.2f})")

        except Exception as e:
            logger.error(f"❌ Error procesando evento protobuf: {e}")

    def _process_json_event(self, event_data):
        """Procesar evento JSON fallback"""
        try:
            # Normalizar evento JSON
            event_dict = {
                'event_id': event_data.get('event_id', 'unknown'),
                'timestamp': event_data.get('timestamp', datetime.now().isoformat()),
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
                'has_gps': event_data.get('latitude') is not None and event_data.get('longitude') is not None
            }

            self._update_stats(event_dict)
            self._add_to_dashboard(event_dict)

            logger.info(f"📡 Evento JSON: {event_dict['source_ip']} → {event_dict['target_ip']}")

        except Exception as e:
            logger.error(f"❌ Error procesando evento JSON: {e}")

    def _update_stats(self, event):
        """Actualizar estadísticas reales"""
        self.stats['total_events'] += 1
        self.stats['last_event_time'] = datetime.now()

        # Eventos con GPS
        if event['has_gps']:
            self.stats['events_with_gps'] += 1

        # IPs únicas
        self.stats['unique_ips'].add(event['source_ip'])
        self.stats['unique_ips'].add(event['target_ip'])

        # Agentes únicos
        self.stats['unique_agents'].add(event['agent_id'])

        # Eventos de riesgo
        if event['anomaly_score'] > 0.7:
            self.stats['anomaly_events'] += 1

        if event['risk_score'] > 0.8:
            self.stats['high_risk_events'] += 1

        # Tipos de evento
        self.stats['event_types'][event['event_type']] += 1

        # Puertos vistos
        if event['dest_port']:
            self.stats['ports_seen'][event['dest_port']] += 1

        # Eventos por minuto
        self.stats['events_per_minute'].append(datetime.now())

        # Detectar modelos ML (basado en anomaly_score > 0)
        if event['anomaly_score'] > 0:
            self.stats['ml_models_detected'].add('Anomaly Detection')
        if event['risk_score'] > 0:
            self.stats['ml_models_detected'].add('Risk Assessment')

    def _add_to_dashboard(self, event):
        """Añadir evento a datos del dashboard"""
        if hasattr(self.dashboard_handler, 'shared_data'):
            self.dashboard_handler.shared_data['events'].append(event)

            # Mantener solo últimos 200 eventos
            if len(self.dashboard_handler.shared_data['events']) > 200:
                self.dashboard_handler.shared_data['events'] = \
                    self.dashboard_handler.shared_data['events'][-200:]

    def get_stats(self):
        """Obtener estadísticas actuales"""
        # Calcular eventos por minuto
        now = datetime.now()
        recent_events = [t for t in self.stats['events_per_minute']
                         if (now - t).total_seconds() < 60]
        events_per_minute = len(recent_events)

        # Tiempo desde último evento
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
            'connection_errors': self.stats['connection_errors'],
            'ml_models_active': list(self.stats['ml_models_detected']),
            'event_types': dict(self.stats['event_types']),
            'top_ports': dict(sorted(self.stats['ports_seen'].items(),
                                     key=lambda x: x[1], reverse=True)[:10]),
            'gps_percentage': (self.stats['events_with_gps'] / max(1, self.stats['total_events'])) * 100
        }

    def stop(self):
        """Detener listener"""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()


class RealSCADAHandler(BaseHTTPRequestHandler):
    """Handler para dashboard REAL conectado a ZeroMQ"""

    # Inicializar datos compartidos a nivel de clase
    shared_data = {
        'events': [],
        'zmq_listener': None
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Manejar peticiones GET"""
        try:
            if self.path == '/':
                self.serve_dashboard()
            elif self.path == '/api/stats':
                self.serve_real_stats()
            elif self.path == '/api/events':
                self.serve_real_events()
            elif self.path == '/api/events/gps':
                self.serve_gps_events()
            elif self.path == '/health':
                self.serve_health()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logger.error(f"❌ Error en GET {self.path}: {e}")
            self.send_error(500, f"Internal Error: {e}")

    def serve_real_stats(self):
        """Estadísticas reales del ZeroMQ"""
        if self.shared_data['zmq_listener']:
            stats = self.shared_data['zmq_listener'].get_stats()
        else:
            stats = {
                'total_events': 0,
                'events_with_gps': 0,
                'events_per_minute': 0,
                'unique_ips': 0,
                'unique_agents': 0,
                'error': 'ZeroMQ listener not initialized'
            }

        self.send_json(stats)

    def serve_real_events(self):
        """Eventos reales recientes"""
        events = self.shared_data['events'][-50:]  # Últimos 50
        self.send_json({
            'events': events,
            'count': len(events),
            'source': 'zeromq_5559',
            'protobuf_available': PROTOBUF_AVAILABLE
        })

    def serve_gps_events(self):
        """Solo eventos con coordenadas GPS"""
        all_events = self.shared_data['events']
        gps_events = [e for e in all_events if e.get('has_gps')]

        self.send_json({
            'events': gps_events[-30:],  # Últimos 30 con GPS
            'count': len(gps_events),
            'total_events': len(all_events)
        })

    def serve_health(self):
        """Health check real"""
        stats = {}
        if self.shared_data['zmq_listener']:
            stats = self.shared_data['zmq_listener'].get_stats()

        health_data = {
            'status': 'healthy' if stats.get('total_events', 0) > 0 else 'waiting_for_events',
            'timestamp': datetime.now().isoformat(),
            'zeromq_port': 5559,
            'protobuf_enabled': PROTOBUF_AVAILABLE,
            'total_events': stats.get('total_events', 0),
            'events_with_gps': stats.get('events_with_gps', 0),
            'last_event_ago': stats.get('last_event_seconds_ago'),
            'connection_errors': stats.get('connection_errors', 0)
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
        """Dashboard HTML para eventos reales"""
        html = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SCADA Real - ZeroMQ 5559</title>
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
            display: grid; grid-template-columns: 1fr 400px;
            height: calc(100vh - 70px); gap: 1rem; padding: 1rem;
        }
        .map-container { position: relative; border-radius: 10px; overflow: hidden; }
        #map { height: 100%; width: 100%; }

        .sidebar { 
            background: rgba(0, 0, 0, 0.7); border-radius: 10px;
            padding: 1rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem;
        }

        .stats-grid {
            display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 10px;
            text-align: center; border-left: 3px solid #00ff88;
        }
        .stat-value { font-size: 1.5rem; font-weight: bold; color: #00ff88; }
        .stat-label { font-size: 0.8rem; color: #ccc; margin-top: 2px; }

        .events-section { flex: 1; }
        .events-header { color: #00ff88; font-size: 1.1rem; margin-bottom: 0.5rem; }
        .event-item { 
            background: rgba(255, 255, 255, 0.1);
            border-left: 3px solid #00ff88; padding: 8px;
            margin-bottom: 8px; border-radius: 5px; font-size: 0.85rem;
            animation: slideIn 0.5s ease;
        }
        .event-time { font-size: 0.75rem; color: #aaa; }
        .event-ip { font-weight: bold; color: #00ff88; font-family: monospace; }
        .event-details { font-size: 0.75rem; color: #ccc; margin-top: 3px; }
        .gps-badge { 
            background: #00ff88; color: #000; padding: 1px 4px; 
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
        <h1>🛡️ SCADA Real - ZeroMQ 5559 + GPS</h1>
        <div class="status">
            <div class="status-item">
                <span class="status-dot online" id="zmq-status"></span>
                <span>ZeroMQ</span>
            </div>
            <div class="status-item">
                <span class="status-dot" id="protobuf-status"></span>
                <span>Protobuf</span>
            </div>
            <div class="status-item">
                Eventos: <span id="total-events">0</span>
            </div>
            <div class="status-item">
                GPS: <span id="gps-events">0</span>
            </div>
            <div class="status-item">
                IPs: <span id="unique-ips">0</span>
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
                <h4 style="color: #00ff88; margin-bottom: 8px;">🤖 Modelos ML Activos</h4>
                <div id="ml-models-list">
                    <div class="ml-model">Cargando...</div>
                </div>
            </div>

            <div class="events-section">
                <div class="events-header">🚨 Eventos Reales ZeroMQ</div>
                <div id="events-list">
                    <div class="event-item">
                        <div class="event-time">Conectando a ZeroMQ 5559...</div>
                        <div class="event-ip">Esperando eventos reales</div>
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
        class RealSCADADashboard {
            constructor() {
                this.map = null;
                this.markers = new Map();
                this.lastEventCount = 0;

                this.initMap();
                this.startPeriodicUpdates();
                this.log('🛡️ Dashboard Real ZeroMQ 5559 inicializado');
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

                    // Actualizar indicadores de estado
                    const zmqStatus = document.getElementById('zmq-status');
                    const protobufStatus = document.getElementById('protobuf-status');

                    if (stats.total_events > this.lastEventCount) {
                        zmqStatus.className = 'status-dot online';
                    } else {
                        zmqStatus.className = 'status-dot warning';
                    }

                    protobufStatus.className = eventsData.protobuf_available ? 
                        'status-dot online' : 'status-dot warning';

                    this.lastEventCount = stats.total_events;

                } catch (e) {
                    this.log('❌ Error actualizando datos: ' + e.message);
                    document.getElementById('zmq-status').className = 'status-dot error';
                }
            }

            updateStats(stats) {
                document.getElementById('total-events').textContent = stats.total_events || 0;
                document.getElementById('gps-events').textContent = stats.events_with_gps || 0;
                document.getElementById('unique-ips').textContent = stats.unique_ips || 0;
                document.getElementById('events-per-minute').textContent = stats.events_per_minute || 0;
                document.getElementById('anomaly-events').textContent = stats.anomaly_events || 0;
                document.getElementById('high-risk-events').textContent = stats.high_risk_events || 0;
                document.getElementById('gps-percentage').textContent = 
                    (stats.gps_percentage || 0).toFixed(1) + '%';

                // Actualizar modelos ML
                const mlContainer = document.getElementById('ml-models-list');
                if (stats.ml_models_active && stats.ml_models_active.length > 0) {
                    mlContainer.innerHTML = stats.ml_models_active
                        .map(model => `<div class="ml-model">${model}</div>`)
                        .join('');
                } else {
                    mlContainer.innerHTML = '<div class="ml-model">Esperando detecciones ML...</div>';
                }
            }

            updateEvents(events) {
                const eventsList = document.getElementById('events-list');
                if (!events || events.length === 0) {
                    eventsList.innerHTML = `
                        <div class="event-item">
                            <div class="event-time">Sin eventos recientes</div>
                            <div class="event-ip">Verificar que el Enhanced Promiscuous Agent esté ejecutándose</div>
                        </div>
                    `;
                    return;
                }

                eventsList.innerHTML = '';
                events.slice(-15).reverse().forEach(event => {
                    const eventDiv = document.createElement('div');
                    eventDiv.className = 'event-item';

                    const time = new Date(event.timestamp).toLocaleTimeString();
                    const gpsBadge = event.has_gps ? '<span class="gps-badge">GPS</span>' : '';

                    let riskBadge = '';
                    if (event.risk_score > 0.8) {
                        riskBadge = '<span class="risk-badge risk-high">ALTO RIESGO</span>';
                    } else if (event.risk_score > 0.5) {
                        riskBadge = '<span class="risk-badge risk-medium">RIESGO</span>';
                    } else if (event.risk_score > 0) {
                        riskBadge = '<span class="risk-badge risk-low">BAJO</span>';
                    }

                    eventDiv.innerHTML = `
                        <div class="event-time">${time} | Agent: ${event.agent_id}</div>
                        <div class="event-ip">${event.source_ip} → ${event.target_ip}${gpsBadge}${riskBadge}</div>
                        <div class="event-details">
                            Puerto: ${event.dest_port} | Tamaño: ${event.packet_size}B | 
                            Anomalía: ${(event.anomaly_score * 100).toFixed(1)}%
                            ${event.description ? `| ${event.description}` : ''}
                        </div>
                    `;

                    eventsList.appendChild(eventDiv);
                });
            }

            updateMap(gpsEvents) {
                if (!gpsEvents || gpsEvents.length === 0) {
                    return;
                }

                gpsEvents.forEach(event => {
                    if (event.latitude && event.longitude) {
                        const markerId = `${event.event_id}_${event.latitude}_${event.longitude}`;

                        if (!this.markers.has(markerId)) {
                            // Determinar color del marcador basado en el riesgo
                            let markerColor = '#00ff88'; // Verde por defecto
                            if (event.risk_score > 0.8) markerColor = '#ff4444'; // Rojo alto riesgo
                            else if (event.risk_score > 0.5) markerColor = '#ffaa00'; // Naranja riesgo medio

                            const marker = L.circleMarker([event.latitude, event.longitude], {
                                color: markerColor,
                                fillColor: markerColor,
                                fillOpacity: 0.7,
                                radius: 8
                            }).addTo(this.map)
                            .bindPopup(`
                                <div style="color: #000;">
                                    <strong>🌐 Evento GPS Real</strong><br>
                                    <strong>ID:</strong> ${event.event_id}<br>
                                    <strong>Origen:</strong> ${event.source_ip}<br>
                                    <strong>Destino:</strong> ${event.target_ip}<br>
                                    <strong>Puerto:</strong> ${event.dest_port}<br>
                                    <strong>Agente:</strong> ${event.agent_id}<br>
                                    <strong>Riesgo:</strong> ${(event.risk_score * 100).toFixed(1)}%<br>
                                    <strong>Anomalía:</strong> ${(event.anomaly_score * 100).toFixed(1)}%<br>
                                    <strong>Tipo:</strong> ${event.event_type}<br>
                                    <strong>Tiempo:</strong> ${new Date(event.timestamp).toLocaleString()}
                                </div>
                            `);

                            this.markers.set(markerId, marker);
                            this.log(`📍 Nuevo evento GPS: ${event.source_ip} (Riesgo: ${(event.risk_score * 100).toFixed(1)}%)`);
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
                // Actualizar cada 3 segundos para eventos en tiempo real
                setInterval(() => this.refreshData(), 3000);

                // Primera actualización inmediata
                setTimeout(() => this.refreshData(), 1000);
            }
        }

        // Funciones globales
        let dashboard;

        function refreshData() { dashboard.refreshData(); }
        function clearMap() { dashboard.clearMap(); }

        // Inicializar
        document.addEventListener('DOMContentLoaded', function() {
            dashboard = new RealSCADADashboard();
            console.log('🛡️ Dashboard Real ZeroMQ 5559');
            console.log('📡 Conectado a Enhanced Promiscuous Agent');
            console.log('🗺️ Mostrando eventos GPS reales');
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
    """Función principal del dashboard real"""
    print("🛡️ DASHBOARD SCADA REAL - ZeroMQ 5559")
    print("=" * 50)
    print("🎯 Conectándose a:")
    print("   📡 Enhanced Promiscuous Agent (ZeroMQ 5559)")
    print("   🔄 Eventos protobuf reales")
    print("   🗺️ GPS coordinates cuando disponibles")
    print("   🤖 Estadísticas ML en tiempo real")
    print("")

    # Verificar estado de protobuf
    if PROTOBUF_AVAILABLE:
        print("✅ Protobuf: Listo para decodificar eventos")
    else:
        print("❌ Protobuf: No disponible - eventos se procesarán como JSON")
        print("   Para usar protobuf, ejecuta desde el directorio raíz del proyecto")
    print("")

    # Verificar puerto disponible
    host = '127.0.0.1'
    port = 8000

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            print(f"⚠️ Puerto {port} ocupado, usando 8003...")
            port = 8003

        # Crear servidor
        server = HTTPServer((host, port), RealSCADAHandler)

        # Inicializar listener ZeroMQ
        zmq_listener = ZeroMQListener(RealSCADAHandler)
        RealSCADAHandler.shared_data['zmq_listener'] = zmq_listener
        zmq_listener.start()

        print(f"🚀 Dashboard Real iniciado en http://{host}:{port}")
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"💊 Health: http://{host}:{port}/health")
        print(f"📡 Stats ZeroMQ: http://{host}:{port}/api/stats")
        print(f"🗺️ Eventos GPS: http://{host}:{port}/api/events/gps")
        print("")
        print("✅ CONECTADO A SISTEMA REAL:")
        print("   🔌 ZeroMQ puerto 5559")
        print("   📦 Decodificando protobuf")
        print("   📍 Filtrando eventos con GPS")
        print("   🤖 Mostrando estadísticas ML")
        print("")
        print("🎯 Los eventos aparecerán cuando lleguen del agente")
        print("🛑 Presiona Ctrl+C para detener")

        server.serve_forever()

    except KeyboardInterrupt:
        print("\n🛑 Dashboard detenido por usuario")
        if 'zmq_listener' in RealSCADAHandler.shared_data:
            RealSCADAHandler.shared_data['zmq_listener'].stop()
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()