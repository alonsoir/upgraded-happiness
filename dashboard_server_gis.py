# dashboard_server_gis.py
# Dashboard SCADA con Mapa GIS Interactivo para visualización geográfica de eventos

import asyncio
import json
import logging
import aiohttp
from datetime import datetime
from aiohttp import web, WSMsgType, ClientSession
import aiohttp_cors
import zmq
import zmq.asyncio
import ipaddress
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GeoLocator:
    """Servicio de geolocalización de IPs"""

    def __init__(self):
        self.cache = {}  # Cache de geolocalizaciones
        self.session = None

    async def get_session(self):
        if not self.session:
            self.session = ClientSession()
        return self.session

    async def geolocate_ip(self, ip_address):
        """Obtener coordenadas geográficas de una IP"""
        if ip_address in self.cache:
            return self.cache[ip_address]

        # Verificar si es IP privada
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                # IPs privadas -> coordenadas locales (Madrid como ejemplo)
                location = {
                    'lat': 40.4168 + (hash(ip_address) % 100) / 10000,  # Variación local
                    'lng': -3.7038 + (hash(ip_address) % 100) / 10000,
                    'city': 'Local Network',
                    'country': 'ES',
                    'org': 'Private Network'
                }
                self.cache[ip_address] = location
                return location
        except ValueError:
            pass

        try:
            session = await self.get_session()
            # Usar servicio gratuito de geolocalización
            async with session.get(f'http://ip-api.com/json/{ip_address}') as response:
                if response.status == 200:
                    data = await response.json()
                    if data['status'] == 'success':
                        location = {
                            'lat': data['lat'],
                            'lng': data['lon'],
                            'city': data['city'],
                            'country': data['country'],
                            'org': data.get('org', 'Unknown')
                        }
                        self.cache[ip_address] = location
                        return location
        except Exception as e:
            logger.error(f"Error geolocating {ip_address}: {e}")

        # Fallback: coordenadas por defecto
        default_location = {
            'lat': 40.4168,
            'lng': -3.7038,
            'city': 'Unknown',
            'country': 'Unknown',
            'org': 'Unknown'
        }
        self.cache[ip_address] = default_location
        return default_location

    async def close(self):
        if self.session:
            await self.session.close()


class EventProcessor:
    """Procesador de eventos con enriquecimiento geográfico"""

    def __init__(self, geolocator):
        self.geolocator = geolocator
        self.event_types = {
            'port_scan': {'color': '#ff4444', 'icon': '🔍', 'severity': 'high'},
            'connection_flood': {'color': '#ff8800', 'icon': '🌊', 'severity': 'medium'},
            'suspicious_port': {'color': '#ffaa00', 'icon': '🚪', 'severity': 'medium'},
            'protocol_anomaly': {'color': '#8844ff', 'icon': '⚠️', 'severity': 'low'},
            'ml_anomaly': {'color': '#44ff44', 'icon': '🤖', 'severity': 'info'},
            'heartbeat': {'color': '#4488ff', 'icon': '💓', 'severity': 'info'}
        }

    def extract_ip_from_event(self, event_data):
        """Extraer IP del evento"""
        # Buscar IPs en diferentes campos
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

        text_to_search = str(event_data)
        ips = re.findall(ip_pattern, text_to_search)

        if ips:
            # Filtrar IPs válidas y no locales
            for ip in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_loopback and ip != '0.0.0.0':
                        return ip
                except ValueError:
                    continue

        # IP por defecto si no se encuentra
        return '192.168.1.100'

    def classify_event(self, event_data):
        """Clasificar tipo de evento"""
        text = str(event_data).lower()

        if 'port scan' in text or 'scan' in text:
            return 'port_scan'
        elif 'flood' in text or 'ddos' in text:
            return 'connection_flood'
        elif 'suspicious' in text or 'ssh' in text or 'rdp' in text:
            return 'suspicious_port'
        elif 'protocol' in text or 'anomaly' in text:
            return 'protocol_anomaly'
        elif 'ml' in text or 'machine learning' in text:
            return 'ml_anomaly'
        else:
            return 'heartbeat'

    async def process_event(self, raw_event):
        """Procesar evento y añadir información geográfica"""
        try:
            # Extraer IP del evento
            ip_address = self.extract_ip_from_event(raw_event)

            # Geolocalizar IP
            location = await self.geolocator.geolocate_ip(ip_address)

            # Clasificar evento
            event_type = self.classify_event(raw_event)
            event_config = self.event_types.get(event_type, self.event_types['heartbeat'])

            # Crear evento enriquecido
            enriched_event = {
                'id': f"evt_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
                'timestamp': datetime.now().isoformat(),
                'type': event_type,
                'severity': event_config['severity'],
                'icon': event_config['icon'],
                'color': event_config['color'],
                'ip_address': ip_address,
                'location': location,
                'title': f"{event_config['icon']} {event_type.replace('_', ' ').title()}",
                'description': f"Event from {ip_address} ({location['city']}, {location['country']})",
                'raw_data': str(raw_event),
                'coordinates': [location['lat'], location['lng']]
            }

            return enriched_event

        except Exception as e:
            logger.error(f"Error processing event: {e}")
            return None


class DashboardGISServer:
    def __init__(self, host='localhost', port=8766):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.websockets = set()
        self.geolocator = GeoLocator()
        self.event_processor = EventProcessor(self.geolocator)
        self.recent_events = []  # Buffer de eventos recientes
        self.setup_routes()
        self.setup_cors()

        # ZeroMQ context
        self.zmq_context = zmq.asyncio.Context()
        self.subscriber = None

    def setup_routes(self):
        """Setup HTTP routes with GIS support"""
        self.app.router.add_get('/', self.serve_dashboard)
        self.app.router.add_get('/ws', self.websocket_handler)
        self.app.router.add_get('/api/status', self.api_status)
        self.app.router.add_get('/api/events', self.api_events)
        self.app.router.add_get('/api/events/geo', self.api_events_geo)
        self.app.router.add_post('/api/events/simulate', self.api_simulate_event)

    def setup_cors(self):
        """Setup CORS properly"""
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })

        # Add CORS to all routes
        for route in list(self.app.router.routes()):
            cors.add(route)

    async def serve_dashboard(self, request):
        """Serve main dashboard HTML with GIS map"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SCADA Security Monitor - GIS Enhanced</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">

            <!-- Leaflet CSS -->
            <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />

            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    background: #0a0a0a; color: #fff; overflow-x: hidden;
                }

                .container { 
                    display: grid; 
                    grid-template-columns: 1fr 400px; 
                    grid-template-rows: auto 1fr; 
                    height: 100vh; 
                    gap: 10px; 
                    padding: 10px;
                }

                .header { 
                    grid-column: 1 / -1; 
                    display: flex; 
                    justify-content: space-between; 
                    align-items: center; 
                    background: linear-gradient(135deg, #1a1a2e, #16213e); 
                    padding: 15px 25px; 
                    border-radius: 10px; 
                    border: 1px solid #333;
                }

                .header h1 { 
                    color: #4CAF50; 
                    font-size: 1.8rem; 
                    display: flex; 
                    align-items: center; 
                    gap: 10px;
                }

                .status-indicator {
                    width: 12px; height: 12px; 
                    border-radius: 50%; 
                    background: #4CAF50; 
                    animation: pulse 2s infinite;
                }

                @keyframes pulse {
                    0% { transform: scale(1); opacity: 1; }
                    50% { transform: scale(1.2); opacity: 0.7; }
                    100% { transform: scale(1); opacity: 1; }
                }

                .metrics { 
                    display: flex; 
                    gap: 20px; 
                    align-items: center;
                }

                .metric { 
                    text-align: center; 
                    padding: 10px 15px; 
                    background: rgba(255,255,255,0.1); 
                    border-radius: 8px; 
                    backdrop-filter: blur(10px);
                }

                .metric-value { 
                    font-size: 1.5rem; 
                    font-weight: bold; 
                    color: #4CAF50; 
                }

                .metric-label { 
                    font-size: 0.8rem; 
                    color: #ccc; 
                    margin-top: 5px;
                }

                .map-container { 
                    background: #1a1a1a; 
                    border-radius: 10px; 
                    border: 1px solid #333; 
                    overflow: hidden; 
                    position: relative;
                }

                #map { 
                    height: 100%; 
                    border-radius: 10px;
                }

                .sidebar { 
                    background: #1a1a1a; 
                    border-radius: 10px; 
                    border: 1px solid #333; 
                    display: flex; 
                    flex-direction: column; 
                    overflow: hidden;
                }

                .sidebar-header { 
                    background: #2d2d2d; 
                    padding: 15px; 
                    border-bottom: 1px solid #333;
                }

                .sidebar-header h3 { 
                    color: #4CAF50; 
                    margin: 0;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }

                .events-list { 
                    flex: 1; 
                    overflow-y: auto; 
                    padding: 10px;
                }

                .event-item { 
                    background: rgba(255,255,255,0.05); 
                    margin-bottom: 8px; 
                    padding: 12px; 
                    border-radius: 8px; 
                    border-left: 4px solid #4CAF50; 
                    transition: all 0.3s ease;
                    animation: slideIn 0.5s ease-out;
                }

                .event-item:hover { 
                    background: rgba(255,255,255,0.1); 
                    transform: translateX(5px);
                }

                .event-item.severity-high { border-left-color: #ff4444; }
                .event-item.severity-medium { border-left-color: #ff8800; }
                .event-item.severity-low { border-left-color: #ffaa00; }
                .event-item.severity-info { border-left-color: #4488ff; }

                @keyframes slideIn {
                    from { opacity: 0; transform: translateX(-20px); }
                    to { opacity: 1; transform: translateX(0); }
                }

                .event-header { 
                    display: flex; 
                    justify-content: space-between; 
                    align-items: flex-start; 
                    margin-bottom: 8px;
                }

                .event-title { 
                    font-weight: bold; 
                    color: #fff; 
                    font-size: 0.9rem;
                }

                .event-time { 
                    font-size: 0.7rem; 
                    color: #888; 
                    white-space: nowrap;
                }

                .event-description { 
                    font-size: 0.8rem; 
                    color: #ccc; 
                    line-height: 1.4;
                }

                .event-location { 
                    font-size: 0.7rem; 
                    color: #4CAF50; 
                    margin-top: 5px; 
                    display: flex; 
                    align-items: center; 
                    gap: 5px;
                }

                .map-controls { 
                    position: absolute; 
                    top: 15px; 
                    right: 15px; 
                    z-index: 1000; 
                    display: flex; 
                    flex-direction: column; 
                    gap: 10px;
                }

                .control-btn { 
                    background: rgba(0,0,0,0.8); 
                    color: white; 
                    border: none; 
                    padding: 10px; 
                    border-radius: 5px; 
                    cursor: pointer; 
                    font-size: 0.8rem; 
                    backdrop-filter: blur(10px);
                    transition: all 0.3s ease;
                }

                .control-btn:hover { 
                    background: rgba(76,175,80,0.8); 
                    transform: scale(1.05);
                }

                .legend { 
                    position: absolute; 
                    bottom: 15px; 
                    left: 15px; 
                    background: rgba(0,0,0,0.8); 
                    padding: 15px; 
                    border-radius: 8px; 
                    backdrop-filter: blur(10px); 
                    z-index: 1000;
                }

                .legend h4 { 
                    color: #4CAF50; 
                    margin: 0 0 10px 0; 
                    font-size: 0.9rem;
                }

                .legend-item { 
                    display: flex; 
                    align-items: center; 
                    gap: 8px; 
                    margin-bottom: 5px; 
                    font-size: 0.8rem;
                }

                .legend-color { 
                    width: 12px; 
                    height: 12px; 
                    border-radius: 50%; 
                }

                .connection-status { 
                    display: flex; 
                    align-items: center; 
                    gap: 8px; 
                    font-size: 0.9rem;
                }

                .status-connected { color: #4CAF50; }
                .status-disconnected { color: #ff4444; }

                /* Responsive */
                @media (max-width: 1200px) {
                    .container { 
                        grid-template-columns: 1fr; 
                        grid-template-rows: auto auto 1fr; 
                    }
                    .sidebar { 
                        grid-row: 2; 
                        height: 300px; 
                    }
                    .map-container { 
                        grid-row: 3; 
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>
                        <div class="status-indicator"></div>
                        🗺️ SCADA Security Monitor - GIS Enhanced
                    </h1>
                    <div class="metrics">
                        <div class="metric">
                            <div class="metric-value" id="threats-count">0</div>
                            <div class="metric-label">Threats</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value" id="ml-precision">0%</div>
                            <div class="metric-label">ML Precision</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value" id="active-agents">0</div>
                            <div class="metric-label">Agents</div>
                        </div>
                        <div class="metric">
                            <div class="connection-status">
                                <span id="connection-status" class="status-disconnected">Disconnected</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="map-container">
                    <div id="map"></div>
                    <div class="map-controls">
                        <button class="control-btn" onclick="centerMap()">🎯 Center</button>
                        <button class="control-btn" onclick="toggleClustering()">📍 Cluster</button>
                        <button class="control-btn" onclick="clearEvents()">🗑️ Clear</button>
                        <button class="control-btn" onclick="simulateEvent()">⚡ Test Event</button>
                    </div>
                    <div class="legend">
                        <h4>Event Types</h4>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #ff4444;"></div>
                            <span>🔍 Port Scan (High)</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #ff8800;"></div>
                            <span>🌊 Connection Flood (Medium)</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #ffaa00;"></div>
                            <span>🚪 Suspicious Port (Medium)</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #8844ff;"></div>
                            <span>⚠️ Protocol Anomaly (Low)</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #44ff44;"></div>
                            <span>🤖 ML Anomaly (Info)</span>
                        </div>
                    </div>
                </div>

                <div class="sidebar">
                    <div class="sidebar-header">
                        <h3>🚨 Real-time Events</h3>
                    </div>
                    <div class="events-list" id="events-list">
                        <div style="text-align: center; color: #666; padding: 20px;">
                            No events yet... Waiting for security events to appear on the map.
                        </div>
                    </div>
                </div>
            </div>

            <!-- Leaflet JS -->
            <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

            <script>
                // Global variables
                let map;
                let ws = null;
                let markers = [];
                let clustering = true;
                let reconnectAttempts = 0;
                const maxReconnectAttempts = 10;

                // Initialize map
                function initMap() {
                    map = L.map('map').setView([40.4168, -3.7038], 6); // Centered on Madrid

                    // Add dark theme tile layer
                    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                        attribution: '© OpenStreetMap contributors',
                        subdomains: 'abcd',
                        maxZoom: 19
                    }).addTo(map);

                    // Add scale control
                    L.control.scale().addTo(map);
                }

                // WebSocket management
                function connectWebSocket() {
                    try {
                        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                        const wsUrl = `${protocol}//${window.location.host}/ws`;

                        console.log('🔗 Connecting to WebSocket:', wsUrl);
                        ws = new WebSocket(wsUrl);

                        ws.onopen = function(event) {
                            console.log('✅ WebSocket connected - GIS Enhanced!');
                            reconnectAttempts = 0;
                            updateConnectionStatus('Connected', true);
                        };

                        ws.onmessage = function(event) {
                            try {
                                const data = JSON.parse(event.data);
                                handleMessage(data);
                            } catch (e) {
                                console.error('❌ Error parsing message:', e);
                            }
                        };

                        ws.onclose = function(event) {
                            console.log('🔌 WebSocket disconnected');
                            updateConnectionStatus('Disconnected', false);

                            if (reconnectAttempts < maxReconnectAttempts) {
                                reconnectAttempts++;
                                const delay = Math.pow(2, reconnectAttempts) * 1000;
                                console.log(`🔄 Reconnecting in ${delay}ms...`);
                                setTimeout(connectWebSocket, delay);
                            }
                        };

                        ws.onerror = function(error) {
                            console.error('❌ WebSocket error:', error);
                            updateConnectionStatus('Error', false);
                        };

                    } catch (e) {
                        console.error('❌ Failed to create WebSocket:', e);
                        updateConnectionStatus('Connection Failed', false);
                    }
                }

                function handleMessage(data) {
                    console.log('📡 Received:', data);

                    if (data.type === 'gis_event') {
                        addEventToMap(data);
                        addEventToSidebar(data);
                    } else if (data.type === 'metrics') {
                        updateMetrics(data);
                    } else if (data.type === 'connection') {
                        console.log('🔗', data.message);
                    }
                }

                function addEventToMap(event) {
                    if (!event.coordinates || event.coordinates.length !== 2) return;

                    const [lat, lng] = event.coordinates;

                    // Create custom marker icon
                    const markerHtml = `
                        <div style="
                            background-color: ${event.color}; 
                            width: 20px; 
                            height: 20px; 
                            border-radius: 50%; 
                            border: 3px solid white; 
                            display: flex; 
                            align-items: center; 
                            justify-content: center; 
                            font-size: 10px;
                            animation: markerPulse 2s infinite;
                        ">
                            ${event.icon}
                        </div>
                        <style>
                            @keyframes markerPulse {
                                0% { box-shadow: 0 0 0 0 ${event.color}80; }
                                70% { box-shadow: 0 0 0 20px ${event.color}00; }
                                100% { box-shadow: 0 0 0 0 ${event.color}00; }
                            }
                        </style>
                    `;

                    const customIcon = L.divIcon({
                        html: markerHtml,
                        className: 'custom-marker',
                        iconSize: [20, 20],
                        iconAnchor: [10, 10]
                    });

                    // Create marker
                    const marker = L.marker([lat, lng], { icon: customIcon }).addTo(map);

                    // Create popup
                    const popupContent = `
                        <div style="color: #333; min-width: 200px;">
                            <h4 style="margin: 0 0 10px 0; color: ${event.color};">
                                ${event.icon} ${event.title}
                            </h4>
                            <p style="margin: 5px 0;"><strong>IP:</strong> ${event.ip_address}</p>
                            <p style="margin: 5px 0;"><strong>Location:</strong> ${event.location.city}, ${event.location.country}</p>
                            <p style="margin: 5px 0;"><strong>Severity:</strong> ${event.severity.toUpperCase()}</p>
                            <p style="margin: 5px 0;"><strong>Time:</strong> ${new Date(event.timestamp).toLocaleString()}</p>
                            <p style="margin: 5px 0;"><strong>Org:</strong> ${event.location.org}</p>
                        </div>
                    `;

                    marker.bindPopup(popupContent);

                    // Add to markers array
                    markers.push({
                        marker: marker,
                        event: event,
                        timestamp: Date.now()
                    });

                    // Auto-remove old markers (keep last 100)
                    if (markers.length > 100) {
                        const oldMarker = markers.shift();
                        map.removeLayer(oldMarker.marker);
                    }

                    // Animate marker appearance
                    marker.setOpacity(0);
                    setTimeout(() => {
                        marker.setOpacity(1);
                    }, 100);
                }

                function addEventToSidebar(event) {
                    const eventsList = document.getElementById('events-list');

                    // Remove placeholder text
                    if (eventsList.children.length === 1 && eventsList.children[0].style.textAlign === 'center') {
                        eventsList.innerHTML = '';
                    }

                    const eventElement = document.createElement('div');
                    eventElement.className = `event-item severity-${event.severity}`;
                    eventElement.innerHTML = `
                        <div class="event-header">
                            <div class="event-title">${event.title}</div>
                            <div class="event-time">${new Date(event.timestamp).toLocaleTimeString()}</div>
                        </div>
                        <div class="event-description">${event.description}</div>
                        <div class="event-location">
                            📍 ${event.location.city}, ${event.location.country} • ${event.ip_address}
                        </div>
                    `;

                    // Add click handler to focus on map
                    eventElement.addEventListener('click', () => {
                        if (event.coordinates) {
                            map.setView(event.coordinates, 10);
                            // Find and open the corresponding marker popup
                            const markerData = markers.find(m => m.event.id === event.id);
                            if (markerData) {
                                markerData.marker.openPopup();
                            }
                        }
                    });

                    // Insert at top
                    eventsList.insertBefore(eventElement, eventsList.firstChild);

                    // Keep only last 50 events
                    while (eventsList.children.length > 50) {
                        eventsList.removeChild(eventsList.lastChild);
                    }
                }

                function updateMetrics(metrics) {
                    if (metrics.threats_count !== undefined) {
                        document.getElementById('threats-count').textContent = metrics.threats_count;
                    }
                    if (metrics.ml_precision !== undefined) {
                        document.getElementById('ml-precision').textContent = metrics.ml_precision + '%';
                    }
                    if (metrics.active_agents !== undefined) {
                        document.getElementById('active-agents').textContent = metrics.active_agents;
                    }
                }

                function updateConnectionStatus(status, connected) {
                    const statusEl = document.getElementById('connection-status');
                    statusEl.textContent = status;
                    statusEl.className = connected ? 'status-connected' : 'status-disconnected';
                }

                // Map control functions
                function centerMap() {
                    if (markers.length > 0) {
                        const group = new L.featureGroup(markers.map(m => m.marker));
                        map.fitBounds(group.getBounds().pad(0.1));
                    } else {
                        map.setView([40.4168, -3.7038], 6);
                    }
                }

                function toggleClustering() {
                    clustering = !clustering;
                    // TODO: Implement marker clustering
                    console.log('Clustering:', clustering);
                }

                function clearEvents() {
                    markers.forEach(markerData => {
                        map.removeLayer(markerData.marker);
                    });
                    markers = [];

                    const eventsList = document.getElementById('events-list');
                    eventsList.innerHTML = `
                        <div style="text-align: center; color: #666; padding: 20px;">
                            Events cleared. Waiting for new security events...
                        </div>
                    `;
                }

                async function simulateEvent() {
                    try {
                        const response = await fetch('/api/events/simulate', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ type: 'test_event' })
                        });

                        if (response.ok) {
                            console.log('✅ Test event simulated');
                        }
                    } catch (e) {
                        console.error('❌ Error simulating event:', e);
                    }
                }

                // Initialize everything when page loads
                document.addEventListener('DOMContentLoaded', function() {
                    console.log('🗺️ GIS Enhanced SCADA Dashboard Loading...');
                    initMap();
                    connectWebSocket();

                    // Periodic status updates
                    setInterval(async function() {
                        if (ws && ws.readyState === WebSocket.OPEN) return;

                        try {
                            const response = await fetch('/api/status');
                            const data = await response.json();
                            updateMetrics(data);
                        } catch (e) {
                            console.log('HTTP fallback failed:', e);
                        }
                    }, 5000);
                });
            </script>
        </body>
        </html>
        """
        return web.Response(text=html_content, content_type='text/html')

    async def websocket_handler(self, request):
        """Handle WebSocket connections with GIS support"""
        ws = web.WebSocketResponse(
            protocols=['chat'],
            heartbeat=30,
            max_msg_size=1024 * 1024
        )

        if not ws.can_prepare(request):
            logger.error("Cannot prepare WebSocket connection")
            return web.Response(status=400, text="Cannot upgrade to WebSocket")

        await ws.prepare(request)
        self.websockets.add(ws)

        logger.info(f"WebSocket connected. Total connections: {len(self.websockets)}")

        try:
            # Send initial connection message
            await ws.send_str(json.dumps({
                'type': 'connection',
                'message': 'Connected to SCADA Security Monitor - GIS Enhanced'
            }))

            # Send recent events if any
            for event in self.recent_events[-10:]:  # Last 10 events
                await ws.send_str(json.dumps({
                    'type': 'gis_event',
                    **event
                }))

            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        logger.info(f"Received WebSocket message: {data}")
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON from WebSocket: {msg.data}")
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")
                    break
                elif msg.type == WSMsgType.CLOSE:
                    logger.info("WebSocket closed")
                    break

        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            self.websockets.discard(ws)
            logger.info(f"WebSocket disconnected. Remaining connections: {len(self.websockets)}")

        return ws

    async def api_status(self, request):
        """API endpoint for system status"""
        try:
            status = {
                'timestamp': datetime.now().isoformat(),
                'threats_count': len([e for e in self.recent_events if e['severity'] in ['high', 'medium']]),
                'ml_precision': 93.9,
                'active_agents': 1,
                'components': {
                    'zmq_broker': 'active',
                    'ml_detector': 'active',
                    'promiscuous_agent': 'active',
                    'gis_service': 'active'
                },
                'websocket_connections': len(self.websockets),
                'total_events': len(self.recent_events),
                'gis_enhanced': True
            }
            return web.json_response(status)
        except Exception as e:
            logger.error(f"Error in api_status: {e}")
            return web.json_response({'error': str(e)}, status=500)

    async def api_events(self, request):
        """API endpoint for recent events"""
        try:
            return web.json_response(self.recent_events[-20:])  # Last 20 events
        except Exception as e:
            logger.error(f"Error in api_events: {e}")
            return web.json_response({'error': str(e)}, status=500)

    async def api_events_geo(self, request):
        """API endpoint for events with geographic data"""
        try:
            geo_events = [
                {
                    'type': 'Feature',
                    'geometry': {
                        'type': 'Point',
                        'coordinates': [event['location']['lng'], event['location']['lat']]
                    },
                    'properties': event
                }
                for event in self.recent_events[-50:]  # Last 50 events
                if 'location' in event and 'coordinates' in event
            ]

            geojson = {
                'type': 'FeatureCollection',
                'features': geo_events
            }

            return web.json_response(geojson)
        except Exception as e:
            logger.error(f"Error in api_events_geo: {e}")
            return web.json_response({'error': str(e)}, status=500)

    async def api_simulate_event(self, request):
        """API endpoint to simulate events for testing"""
        try:
            # Create a simulated event
            import random

            test_ips = [
                '8.8.8.8',  # Google DNS
                '1.1.1.1',  # Cloudflare DNS
                '185.199.108.1',  # GitHub
                '104.16.133.229',  # Cloudflare
                '192.168.1.' + str(random.randint(100, 200))  # Local network
            ]

            event_types = ['port_scan', 'connection_flood', 'suspicious_port', 'ml_anomaly']

            simulated_event = {
                'ip_address': random.choice(test_ips),
                'event_type': random.choice(event_types),
                'description': f'Simulated {random.choice(event_types)} event for testing'
            }

            # Process the simulated event
            processed_event = await self.event_processor.process_event(simulated_event)

            if processed_event:
                # Add to recent events
                self.recent_events.append(processed_event)
                if len(self.recent_events) > 1000:  # Keep last 1000 events
                    self.recent_events = self.recent_events[-1000:]

                # Broadcast to all WebSocket connections
                await self.broadcast_to_websockets({
                    'type': 'gis_event',
                    **processed_event
                })

                return web.json_response({'success': True, 'event': processed_event})
            else:
                return web.json_response({'error': 'Failed to process event'}, status=500)

        except Exception as e:
            logger.error(f"Error simulating event: {e}")
            return web.json_response({'error': str(e)}, status=500)

    async def setup_zmq_subscriber(self):
        """Setup ZeroMQ subscriber for real-time events"""
        try:
            self.subscriber = self.zmq_context.socket(zmq.SUB)
            self.subscriber.connect("tcp://localhost:5555")
            self.subscriber.setsockopt(zmq.SUBSCRIBE, b"")

            logger.info("ZeroMQ subscriber connected for GIS events")
            asyncio.create_task(self.zmq_message_loop())

        except Exception as e:
            logger.error(f"Failed to setup ZeroMQ subscriber: {e}")

    async def zmq_message_loop(self):
        """Listen for ZeroMQ messages and process for GIS"""
        while True:
            try:
                if await self.subscriber.poll(1000, zmq.POLLIN):
                    message = await self.subscriber.recv_json()
                    logger.info(f"Received ZeroMQ message for GIS processing: {message}")

                    # Process event with geographic enhancement
                    processed_event = await self.event_processor.process_event(message)

                    if processed_event:
                        # Add to recent events
                        self.recent_events.append(processed_event)
                        if len(self.recent_events) > 1000:  # Keep last 1000 events
                            self.recent_events = self.recent_events[-1000:]

                        # Broadcast to WebSocket clients
                        await self.broadcast_to_websockets({
                            'type': 'gis_event',
                            **processed_event
                        })

            except Exception as e:
                logger.error(f"Error in ZeroMQ GIS message loop: {e}")
                await asyncio.sleep(1)

    async def broadcast_to_websockets(self, message):
        """Broadcast message to all connected WebSocket clients"""
        if not self.websockets:
            return

        websockets_copy = self.websockets.copy()

        for ws in websockets_copy:
            try:
                if ws.closed:
                    self.websockets.discard(ws)
                    continue

                await ws.send_str(json.dumps(message))
            except Exception as e:
                logger.error(f"Error sending to WebSocket: {e}")
                self.websockets.discard(ws)

    async def start_server(self):
        """Start the GIS-enhanced dashboard server"""
        try:
            await self.setup_zmq_subscriber()

            runner = web.AppRunner(self.app)
            await runner.setup()

            site = web.TCPSite(runner, self.host, self.port)
            await site.start()

            logger.info(f"🗺️ GIS Enhanced Dashboard server started at http://{self.host}:{self.port}")
            return runner

        except Exception as e:
            logger.error(f"Failed to start GIS server: {e}")
            raise

    async def cleanup(self):
        """Cleanup resources"""
        await self.geolocator.close()


async def main():
    """Main function to run the GIS-enhanced dashboard"""
    server = DashboardGISServer()
    runner = None

    try:
        runner = await server.start_server()

        print(f"🚀 GIS Enhanced SCADA Dashboard running at http://{server.host}:{server.port}")
        print("🗺️ Features: Geographic event visualization, real-time mapping, IP geolocation")
        print("Press Ctrl+C to stop...")

        await asyncio.Event().wait()

    except KeyboardInterrupt:
        print("\n🛑 Shutting down GIS dashboard...")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        if runner:
            await runner.cleanup()
        if server.subscriber:
            server.subscriber.close()
        server.zmq_context.term()
        await server.cleanup()


if __name__ == "__main__":
    asyncio.run(main())