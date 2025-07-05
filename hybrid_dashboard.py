#!/usr/bin/env python3
"""
🛡️ Dashboard SCADA con Simulación Forzada - EVENTOS GARANTIZADOS
Versión que garantiza eventos visibles en el mapa
"""

import json
import time
import threading
import socket
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import random
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class IPGeoLocator:
    """Geolocalizador con ubicaciones predefinidas realistas"""

    def __init__(self):
        self.cache = {}
        # Ubicaciones realistas basadas en IPs comunes
        self.ip_locations = {
            # IPs del agente promiscuo real
            '192.168.1.123': {'latitude': 37.3891, 'longitude': -5.9845, 'city': 'Sevilla', 'country': 'España',
                              'isp': 'Red Local', 'is_private': True},
            '172.224.53.8': {'latitude': 37.4419, 'longitude': -122.1430, 'city': 'Mountain View',
                             'country': 'Estados Unidos', 'isp': 'Google', 'is_private': False},
            '34.117.41.85': {'latitude': 40.7128, 'longitude': -74.0060, 'city': 'Nueva York',
                             'country': 'Estados Unidos', 'isp': 'Google Cloud', 'is_private': False},

            # IPs DNS comunes
            '8.8.8.8': {'latitude': 37.4419, 'longitude': -122.1430, 'city': 'Mountain View',
                        'country': 'Estados Unidos', 'isp': 'Google DNS', 'is_private': False},
            '1.1.1.1': {'latitude': -33.8688, 'longitude': 151.2093, 'city': 'Sydney', 'country': 'Australia',
                        'isp': 'Cloudflare', 'is_private': False},
            '208.67.222.222': {'latitude': 37.7749, 'longitude': -122.4194, 'city': 'San Francisco',
                               'country': 'Estados Unidos', 'isp': 'OpenDNS', 'is_private': False},

            # IPs locales comunes
            '192.168.1.1': {'latitude': 37.3891, 'longitude': -5.9845, 'city': 'Sevilla', 'country': 'España',
                            'isp': 'Router Local', 'is_private': True},
            '192.168.1.100': {'latitude': 37.3891, 'longitude': -5.9845, 'city': 'Sevilla', 'country': 'España',
                              'isp': 'Dispositivo Local', 'is_private': True},
            '10.0.0.1': {'latitude': 37.3891, 'longitude': -5.9845, 'city': 'Sevilla', 'country': 'España',
                         'isp': 'Red Corporativa', 'is_private': True},

            # Servidores internacionales
            '142.250.200.14': {'latitude': 37.4419, 'longitude': -122.1430, 'city': 'Mountain View',
                               'country': 'Estados Unidos', 'isp': 'Google', 'is_private': False},
            '13.107.42.14': {'latitude': 47.6062, 'longitude': -122.3321, 'city': 'Seattle',
                             'country': 'Estados Unidos', 'isp': 'Microsoft', 'is_private': False},
            '52.96.0.0': {'latitude': 51.5074, 'longitude': -0.1278, 'city': 'Londres', 'country': 'Reino Unido',
                          'isp': 'Microsoft Azure', 'is_private': False},
            '185.199.108.153': {'latitude': 37.7749, 'longitude': -122.4194, 'city': 'San Francisco',
                                'country': 'Estados Unidos', 'isp': 'GitHub', 'is_private': False},
        }

    def geolocate_ip(self, ip: str) -> dict:
        """Geolocalizar IP con datos predefinidos o generados"""
        if ip in self.cache:
            return self.cache[ip]

        # Usar ubicación predefinida si existe
        if ip in self.ip_locations:
            location = self.ip_locations[ip]
        else:
            # Generar ubicación basada en el tipo de IP
            location = self._generate_location_for_ip(ip)

        self.cache[ip] = location
        return location

    def _generate_location_for_ip(self, ip: str) -> dict:
        """Generar ubicación realista para IP"""
        if ip.startswith('192.168'):
            return {'latitude': 37.3891, 'longitude': -5.9845, 'city': 'Sevilla', 'country': 'España',
                    'isp': 'Red Local', 'is_private': True}
        elif ip.startswith('10.'):
            return {'latitude': 37.3891, 'longitude': -5.9845, 'city': 'Sevilla', 'country': 'España',
                    'isp': 'Red Corporativa', 'is_private': True}
        elif ip.startswith('172.'):
            return {'latitude': 40.7128, 'longitude': -74.0060, 'city': 'Nueva York', 'country': 'Estados Unidos',
                    'isp': 'Servidor Externo', 'is_private': False}
        else:
            # IPs públicas - ubicaciones variadas
            locations = [
                {'latitude': 48.8566, 'longitude': 2.3522, 'city': 'París', 'country': 'Francia',
                 'isp': 'Proveedor Europeo'},
                {'latitude': 52.5200, 'longitude': 13.4050, 'city': 'Berlín', 'country': 'Alemania',
                 'isp': 'Proveedor Alemán'},
                {'latitude': 41.9028, 'longitude': 12.4964, 'city': 'Roma', 'country': 'Italia',
                 'isp': 'Proveedor Italiano'},
                {'latitude': 35.6762, 'longitude': 139.6503, 'city': 'Tokio', 'country': 'Japón',
                 'isp': 'Proveedor Asiático'},
                {'latitude': -23.5505, 'longitude': -46.6333, 'city': 'São Paulo', 'country': 'Brasil',
                 'isp': 'Proveedor Sudamericano'},
            ]
            location = random.choice(locations)
            location['is_private'] = False
            return location


class EventSimulator:
    """Simulador de eventos de red realistas y forzados"""

    def __init__(self, handler_class):
        self.handler_class = handler_class
        self.running = False
        self.event_templates = [
            # Basados en el tráfico real capturado
            {'source_ip': '192.168.1.123', 'destination_ip': '172.224.53.8', 'protocol': 'HTTPS', 'port': 443},
            {'source_ip': '192.168.1.123', 'destination_ip': '8.8.8.8', 'protocol': 'DNS', 'port': 53},
            {'source_ip': '192.168.1.100', 'destination_ip': '1.1.1.1', 'protocol': 'DNS', 'port': 53},
            {'source_ip': '10.0.0.5', 'destination_ip': '34.117.41.85', 'protocol': 'QUIC', 'port': 443},
            {'source_ip': '192.168.1.150', 'destination_ip': '142.250.200.14', 'protocol': 'HTTPS', 'port': 443},
            {'source_ip': '192.168.1.200', 'destination_ip': '13.107.42.14', 'protocol': 'HTTPS', 'port': 443},
            {'source_ip': '172.16.1.10', 'destination_ip': '185.199.108.153', 'protocol': 'HTTPS', 'port': 443},
            {'source_ip': '192.168.1.75', 'destination_ip': '208.67.222.222', 'protocol': 'DNS', 'port': 53},
        ]

    def start(self):
        """Iniciar simulación inmediata y forzada"""
        self.running = True

        # Generar eventos iniciales inmediatamente
        self._generate_initial_events()

        # Iniciar simulación continua
        thread = threading.Thread(target=self._simulate_events, daemon=True)
        thread.start()

        logger.info("🎭 Simulador de eventos FORZADO iniciado - Eventos garantizados cada 3-8 segundos")

    def _generate_initial_events(self):
        """Generar 5 eventos iniciales para que aparezcan inmediatamente"""
        logger.info("🚀 Generando eventos iniciales para visualización inmediata...")

        for i in range(5):
            template = random.choice(self.event_templates)
            self._create_and_add_event(template, event_type='initial')
            time.sleep(0.5)  # Pequeña pausa entre eventos iniciales

    def _simulate_events(self):
        """Simular eventos continuamente"""
        while self.running:
            try:
                # Generar evento basado en plantilla
                template = random.choice(self.event_templates)
                self._create_and_add_event(template, event_type='simulated')

                # Esperar entre 3-8 segundos para el siguiente evento
                wait_time = random.randint(3, 8)
                logger.debug(f"⏱️ Próximo evento en {wait_time} segundos...")
                time.sleep(wait_time)

            except Exception as e:
                logger.error(f"❌ Error en simulador: {e}")
                time.sleep(5)

    def _create_and_add_event(self, template, event_type='simulated'):
        """Crear y añadir evento a los datos compartidos"""
        try:
            event = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': template['source_ip'],
                'destination_ip': template['destination_ip'],
                'protocol': template['protocol'],
                'source_port': random.randint(1024, 65535),
                'destination_port': template['port'],
                'packet_size': random.randint(64, 1500),
                'type': event_type
            }

            # Añadir a datos compartidos
            if hasattr(self.handler_class, 'shared_data'):
                self.handler_class.shared_data['events'].append(event)
                self.handler_class.shared_data['stats']['total_events'] += 1

                # Añadir IPs a estadísticas
                self.handler_class.shared_data['stats']['unique_ips'].add(event['source_ip'])
                self.handler_class.shared_data['stats']['unique_ips'].add(event['destination_ip'])

                # Mantener solo los últimos 100 eventos
                if len(self.handler_class.shared_data['events']) > 100:
                    self.handler_class.shared_data['events'] = self.handler_class.shared_data['events'][-100:]

                logger.info(
                    f"📡 Evento {event_type}: {event['source_ip']} → {event['destination_ip']} ({event['protocol']})")

        except Exception as e:
            logger.error(f"❌ Error creando evento: {e}")


class SCADAHandler(BaseHTTPRequestHandler):
    """Handler HTTP mejorado con simulación forzada"""

    def __init__(self, *args, **kwargs):
        # Inicializar datos compartidos
        if not hasattr(SCADAHandler, 'shared_data'):
            SCADAHandler.shared_data = {
                'events': [],
                'stats': {
                    'total_events': 0,
                    'unique_ips': set(),
                    'start_time': datetime.now()
                }
            }

        # Inicializar geolocalizador
        if not hasattr(SCADAHandler, 'geolocator'):
            SCADAHandler.geolocator = IPGeoLocator()

        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Manejar peticiones GET"""
        try:
            if self.path == '/':
                self.serve_dashboard()
            elif self.path == '/health':
                self.serve_health()
            elif self.path == '/api/stats':
                self.serve_stats()
            elif self.path == '/api/events':
                self.serve_events()
            elif self.path == '/api/events/geolocated':
                self.serve_geolocated_events()
            elif self.path == '/api/force_event':
                self.force_event()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logger.error(f"❌ Error en GET {self.path}: {e}")
            self.send_error(500, f"Internal Error: {e}")

    def force_event(self):
        """Forzar la creación de un evento (para testing)"""
        try:
            # Crear evento inmediato
            event = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': '192.168.1.123',
                'destination_ip': '8.8.8.8',
                'protocol': 'DNS',
                'source_port': random.randint(1024, 65535),
                'destination_port': 53,
                'packet_size': random.randint(64, 512),
                'type': 'forced'
            }

            self.shared_data['events'].append(event)
            self.shared_data['stats']['total_events'] += 1
            self.shared_data['stats']['unique_ips'].add(event['source_ip'])
            self.shared_data['stats']['unique_ips'].add(event['destination_ip'])

            logger.info("🔥 Evento FORZADO creado")
            self.send_json({'status': 'event_created', 'event': event})

        except Exception as e:
            logger.error(f"❌ Error forzando evento: {e}")
            self.send_json({'status': 'error', 'message': str(e)})

    def serve_geolocated_events(self):
        """Servir eventos con geolocalización"""
        try:
            events = self.shared_data['events'][-50:]  # Últimos 50 eventos
            geolocated_events = []

            for event in events:
                enhanced_event = event.copy()

                # Geolocalizar IP origen
                if event.get('source_ip'):
                    location = self.geolocator.geolocate_ip(event['source_ip'])
                    enhanced_event['source_location'] = location
                    # Usar coordenadas de origen para el mapa
                    enhanced_event.update({
                        'latitude': location['latitude'],
                        'longitude': location['longitude'],
                        'city': location['city'],
                        'country': location['country']
                    })

                # Geolocalizar IP destino si no hay origen
                elif event.get('destination_ip'):
                    location = self.geolocator.geolocate_ip(event['destination_ip'])
                    enhanced_event['destination_location'] = location
                    enhanced_event.update({
                        'latitude': location['latitude'],
                        'longitude': location['longitude'],
                        'city': location['city'],
                        'country': location['country']
                    })

                geolocated_events.append(enhanced_event)

            self.send_json({'events': geolocated_events, 'count': len(geolocated_events)})

        except Exception as e:
            logger.error(f"❌ Error geolocalizando eventos: {e}")
            self.send_json({'events': [], 'error': str(e)})

    def serve_health(self):
        """Health check mejorado"""
        health_data = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': (datetime.now() - self.shared_data['stats']['start_time']).total_seconds(),
            'total_events': self.shared_data['stats']['total_events'],
            'unique_ips': len(self.shared_data['stats']['unique_ips']),
            'cache_size': len(self.geolocator.cache),
            'server_type': 'scada_dashboard_forced_simulation',
            'simulation_active': True
        }
        self.send_json(health_data)

    def serve_stats(self):
        """Estadísticas mejoradas"""
        stats = {
            'total_events': self.shared_data['stats']['total_events'],
            'unique_ips': len(self.shared_data['stats']['unique_ips']),
            'uptime_seconds': (datetime.now() - self.shared_data['stats']['start_time']).total_seconds(),
            'events_in_memory': len(self.shared_data['events']),
            'geolocation_cache_size': len(self.geolocator.cache)
        }
        self.send_json(stats)

    def serve_events(self):
        """Eventos recientes"""
        events = self.shared_data['events'][-50:]
        self.send_json({'events': events, 'count': len(events)})

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
        """Dashboard HTML optimizado"""
        html = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCADA Dashboard - Eventos Garantizados</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css" />
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3a 100%);
            color: #fff; overflow: hidden;
        }
        .header { 
            background: rgba(0, 0, 0, 0.8); padding: 1rem;
            border-bottom: 2px solid #00ff88;
            display: flex; justify-content: space-between; align-items: center;
        }
        .header h1 { color: #00ff88; font-size: 1.5rem; }
        .status { display: flex; gap: 20px; align-items: center; }
        .status-item { 
            background: rgba(255, 255, 255, 0.1);
            padding: 5px 10px; border-radius: 15px; font-size: 0.9rem;
        }
        .status-dot { 
            width: 10px; height: 10px; border-radius: 50%;
            display: inline-block; margin-right: 5px;
            animation: pulse 2s infinite;
        }
        .online { background: #00ff88; }
        .warning { background: #ffaa00; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .main-container { 
            display: grid; grid-template-columns: 1fr 350px;
            height: calc(100vh - 80px); gap: 1rem; padding: 1rem;
        }
        .map-container { position: relative; border-radius: 10px; overflow: hidden; }
        #map { height: 100%; width: 100%; }
        .sidebar { 
            background: rgba(0, 0, 0, 0.6); border-radius: 10px;
            padding: 1rem; overflow-y: auto;
        }
        .events-header { color: #00ff88; font-size: 1.2rem; margin-bottom: 1rem; }
        .event-item { 
            background: rgba(255, 255, 255, 0.1);
            border-left: 3px solid #00ff88; padding: 10px;
            margin-bottom: 10px; border-radius: 5px;
            animation: slideIn 0.5s ease;
        }
        .event-time { font-size: 0.8rem; color: #aaa; }
        .event-ip { font-weight: bold; color: #00ff88; font-family: monospace; }
        .event-protocol { 
            background: rgba(0, 255, 136, 0.2); color: #00ff88;
            padding: 2px 6px; border-radius: 3px; font-size: 0.8rem;
            display: inline-block; margin-top: 5px;
        }
        .stats-panel { 
            background: rgba(255, 255, 255, 0.1);
            border-radius: 8px; padding: 15px; margin-top: 20px;
        }
        .stat-item { 
            display: flex; justify-content: space-between;
            margin-bottom: 10px; font-size: 0.9rem;
        }
        .stat-value { color: #00ff88; font-weight: bold; }
        .btn { 
            background: #00ff88; color: #0f0f23; padding: 8px 16px;
            border: none; border-radius: 5px; cursor: pointer;
            margin: 5px; font-weight: bold; font-size: 0.8rem;
        }
        .btn:hover { background: #00cc66; }
        .btn-danger { background: #ff4444; color: white; }
        @keyframes slideIn { from { opacity: 0; transform: translateX(-20px); } to { opacity: 1; transform: translateX(0); } }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SCADA Dashboard - Eventos Garantizados</h1>
        <div class="status">
            <div class="status-item">
                <span class="status-dot online"></span>
                <span>Simulación</span>
            </div>
            <div class="status-item">
                <span class="status-dot online"></span>
                <span>Geoloc</span>
            </div>
            <div class="status-item">
                Eventos: <span id="event-counter">0</span>
            </div>
            <div class="status-item">
                IPs: <span id="ip-counter">0</span>
            </div>
        </div>
    </div>

    <div class="main-container">
        <div class="map-container">
            <div id="map"></div>
        </div>

        <div class="sidebar">
            <div class="events-header">🚨 Eventos en Tiempo Real</div>
            <div id="events-list">
                <div class="event-item">
                    <div class="event-time">Sistema iniciado</div>
                    <div class="event-ip">Generando eventos automáticamente...</div>
                    <div class="event-protocol">Simulación activa</div>
                </div>
            </div>

            <div class="stats-panel">
                <h3 style="color: #00ff88; margin-bottom: 10px;">📊 Estadísticas en Vivo</h3>
                <div class="stat-item">
                    <span>Total Eventos:</span>
                    <span class="stat-value" id="total-events">0</span>
                </div>
                <div class="stat-item">
                    <span>IPs Únicas:</span>
                    <span class="stat-value" id="unique-ips">0</span>
                </div>
                <div class="stat-item">
                    <span>Cache Geo:</span>
                    <span class="stat-value" id="geo-cache">0</span>
                </div>
                <div class="stat-item">
                    <span>Tiempo Activo:</span>
                    <span class="stat-value" id="uptime">0s</span>
                </div>

                <button class="btn" onclick="refreshData()">🔄 Actualizar</button>
                <button class="btn" onclick="forceEvent()">⚡ Forzar Evento</button>
                <button class="btn" onclick="clearMap()">🗺️ Limpiar Mapa</button>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
    <script>
        class SCADADashboard {
            constructor() {
                this.map = null;
                this.markers = new Map();
                this.eventCounter = 0;
                this.startTime = Date.now();

                this.initMap();
                this.startPeriodicUpdates();
                this.log('🚀 Dashboard con simulación forzada inicializado');

                // Actualización inmediata para ver eventos iniciales
                setTimeout(() => this.refreshData(), 2000);
            }

            initMap() {
                this.map = L.map('map').setView([37.3891, -5.9845], 6);

                L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                    attribution: '©OpenStreetMap, ©CartoDB'
                }).addTo(this.map);

                L.marker([37.3891, -5.9845])
                    .addTo(this.map)
                    .bindPopup('🏭 SCADA Base - Sevilla')
                    .openPopup();
            }

            log(message) {
                const now = new Date().toLocaleTimeString();
                console.log(`[${now}] ${message}`);
            }

            async refreshData() {
                try {
                    const [statsResponse, eventsResponse] = await Promise.all([
                        fetch('/api/stats'),
                        fetch('/api/events/geolocated')
                    ]);

                    const stats = await statsResponse.json();
                    const eventsData = await eventsResponse.json();

                    // Actualizar contadores
                    document.getElementById('total-events').textContent = stats.total_events;
                    document.getElementById('unique-ips').textContent = stats.unique_ips;
                    document.getElementById('geo-cache').textContent = stats.geolocation_cache_size || 0;
                    document.getElementById('uptime').textContent = Math.floor(stats.uptime_seconds) + 's';

                    document.getElementById('event-counter').textContent = stats.total_events;
                    document.getElementById('ip-counter').textContent = stats.unique_ips;

                    if (eventsData.events && eventsData.events.length > 0) {
                        this.updateEventsDisplay(eventsData.events);
                        this.updateMapMarkers(eventsData.events);
                        this.log(`📊 Actualizados ${eventsData.events.length} eventos`);
                    }

                } catch (e) {
                    this.log('❌ Error actualizando datos: ' + e.message);
                }
            }

            async forceEvent() {
                try {
                    const response = await fetch('/api/force_event');
                    const result = await response.json();
                    if (result.status === 'event_created') {
                        this.log('⚡ Evento forzado creado');
                        setTimeout(() => this.refreshData(), 500);
                    }
                } catch (e) {
                    this.log('❌ Error forzando evento: ' + e.message);
                }
            }

            updateEventsDisplay(events) {
                const eventsList = document.getElementById('events-list');
                eventsList.innerHTML = '';

                events.slice(-15).reverse().forEach(event => {
                    const eventDiv = document.createElement('div');
                    eventDiv.className = 'event-item';

                    const time = new Date(event.timestamp).toLocaleTimeString();
                    const sourceIP = event.source_ip || 'Unknown';
                    const destIP = event.destination_ip || 'Unknown';
                    const protocol = event.protocol || 'Unknown';
                    const city = event.city || 'Unknown';

                    eventDiv.innerHTML = `
                        <div class="event-time">${time}</div>
                        <div class="event-ip">${sourceIP} → ${destIP}</div>
                        <div class="event-protocol">${protocol}</div>
                        <div style="font-size: 0.8rem; color: #ccc; margin-top: 3px;">
                            📍 ${city} | ${event.type || 'simulated'}
                        </div>
                    `;

                    eventsList.appendChild(eventDiv);
                });
            }

            updateMapMarkers(events) {
                events.forEach(event => {
                    if (event.latitude && event.longitude) {
                        const markerId = `${event.source_ip || event.destination_ip}_${event.latitude}_${event.longitude}`;

                        if (!this.markers.has(markerId)) {
                            const marker = L.marker([event.latitude, event.longitude])
                                .addTo(this.map)
                                .bindPopup(`
                                    <div style="color: #000;">
                                        <strong>🌐 Evento de Red</strong><br>
                                        <strong>Origen:</strong> ${event.source_ip}<br>
                                        <strong>Destino:</strong> ${event.destination_ip}<br>
                                        <strong>Protocolo:</strong> ${event.protocol}<br>
                                        <strong>Ciudad:</strong> ${event.city}<br>
                                        <strong>País:</strong> ${event.country}<br>
                                        <strong>Tipo:</strong> ${event.type}<br>
                                        <strong>Tiempo:</strong> ${new Date(event.timestamp).toLocaleString()}
                                    </div>
                                `);

                            this.markers.set(markerId, marker);
                            this.log(`📍 Nuevo marcador: ${event.city}`);
                        }
                    }
                });
            }

            clearMap() {
                this.markers.forEach(marker => {
                    this.map.removeLayer(marker);
                });
                this.markers.clear();

                L.marker([37.3891, -5.9845])
                    .addTo(this.map)
                    .bindPopup('🏭 SCADA Base - Sevilla')
                    .openPopup();

                this.log('🗺️ Mapa limpiado');
            }

            startPeriodicUpdates() {
                // Actualizar cada 5 segundos
                setInterval(() => this.refreshData(), 5000);
            }
        }

        // Funciones globales
        let dashboard;

        function refreshData() { dashboard.refreshData(); }
        function forceEvent() { dashboard.forceEvent(); }
        function clearMap() { dashboard.clearMap(); }

        // Inicializar
        document.addEventListener('DOMContentLoaded', function() {
            dashboard = new SCADADashboard();
            console.log('🛡️ Dashboard SCADA con Eventos Garantizados');
            console.log('⚡ Usa el botón "Forzar Evento" para generar eventos inmediatos');
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
    """Función principal con simulación garantizada"""
    print("🛡️ DASHBOARD SCADA - EVENTOS GARANTIZADOS")
    print("=" * 50)
    print("🎯 Funcionalidades:")
    print("   ✅ Eventos inmediatos al iniciar")
    print("   ✅ Simulación automática cada 3-8 segundos")
    print("   ✅ Geolocalización realista de IPs")
    print("   ✅ Mapa con marcadores garantizados")
    print("   ✅ Botón para forzar eventos")
    print("")

    # Configuración
    host = '127.0.0.1'
    port = 8000

    try:
        # Verificar puerto
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            print(f"⚠️ Puerto {port} ocupado, probando 8002...")
            port = 8002

        # Crear servidor
        server = HTTPServer((host, port), SCADAHandler)

        print(f"🚀 Servidor iniciado en http://{host}:{port}")
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"💊 Health: http://{host}:{port}/health")
        print(f"⚡ Forzar evento: http://{host}:{port}/api/force_event")
        print("")

        # Iniciar simulador FORZADO
        simulator = EventSimulator(SCADAHandler)
        simulator.start()

        print("✅ SISTEMA CON EVENTOS GARANTIZADOS:")
        print("   🎭 Simulador automático activo")
        print("   📍 5 eventos iniciales generados")
        print("   🌍 Geolocalización activada")
        print("   🗺️ Marcadores aparecerán automáticamente")
        print("")
        print("🎯 EVENTOS APARECERÁN EN 5 SEGUNDOS")
        print("🛑 Presiona Ctrl+C para detener")

        # Ejecutar servidor
        server.serve_forever()

    except KeyboardInterrupt:
        print("\n🛑 Dashboard detenido por usuario")
        simulator.running = False
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")


if __name__ == "__main__":
    main()