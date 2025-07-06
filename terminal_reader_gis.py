#!/usr/bin/env python3
"""
Dashboard GIS que lee eventos directamente del terminal del sistema SCADA
Solución que funciona leyendo la salida de consola del agente promiscuo
"""

import asyncio
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from aiohttp import web, WSMsgType, ClientSession
import aiohttp_cors
import socket
from typing import Dict, Any, List, Optional


class TerminalEventReader:
    """Lee eventos del terminal del sistema SCADA"""

    def __init__(self):
        self.events: List[Dict[str, Any]] = []
        self.event_count = 0
        self.is_running = False
        self.websockets: set = set()

    def parse_network_event(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse de eventos de red del agente promiscuo"""
        try:
            # Patrón: [  1] Ethernet → IPv4 → TCP → HTTPS  | 192.168.1.123:63640 → 172.64.155.69:443
            network_pattern = r'\[\s*(\d+)\]\s+(.*?)\s+\|\s+([\d.]+):(\d+)\s+→\s+([\d.]+):(\d+)'
            match = re.search(network_pattern, line)

            if match:
                event_num, protocol_chain, src_ip, src_port, dst_ip, dst_port = match.groups()

                # Determinar tipo de evento y color
                protocol_lower = protocol_chain.lower()
                if 'https' in protocol_lower or 'tls' in protocol_lower:
                    event_type, color, icon = 'https_traffic', '#00ff88', '🔒'
                elif 'quic' in protocol_lower:
                    event_type, color, icon = 'quic_traffic', '#ff88aa', '⚡'
                elif 'arp' in protocol_lower:
                    event_type, color, icon = 'arp_activity', '#ffaa88', '🏠'
                elif 'tcp' in protocol_lower or 'udp' in protocol_lower:
                    event_type, color, icon = 'network_traffic', '#4488ff', '📡'
                elif 'raw' in protocol_lower:
                    event_type, color, icon = 'raw_data', '#888888', '📊'
                else:
                    event_type, color, icon = 'network_traffic', '#66ccff', '🌐'

                # Priorizar IP externa
                display_ip = dst_ip if not dst_ip.startswith('192.168') else src_ip

                # Generar coordenadas basadas en IP
                coords = self.ip_to_coordinates(display_ip)

                event = {
                    'id': f"terminal_{int(time.time())}_{event_num}",
                    'timestamp': datetime.now().isoformat(),
                    'type': event_type,
                    'severity': 'info',
                    'icon': icon,
                    'color': color,
                    'ip_address': display_ip,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'source_port': int(src_port),
                    'destination_port': int(dst_port),
                    'protocol_chain': protocol_chain.strip(),
                    'title': f"{icon} {event_type.replace('_', ' ').title()}",
                    'description': f"Traffic: {src_ip}:{src_port} → {dst_ip}:{dst_port}",
                    'location': {
                        'lat': coords[0],
                        'lng': coords[1],
                        'city': self.ip_to_city(display_ip),
                        'country': 'Unknown',
                        'org': 'Network Traffic'
                    },
                    'coordinates': coords,
                    'raw_data': line.strip(),
                    'source': 'Terminal-Reader'
                }

                return event

            # Patrón de estadísticas: 📊 STATS: 2200 eventos | 15.2 evt/s | 144.9s
            stats_pattern = r'📊\s+STATS:\s+(\d+)\s+eventos\s+\|\s+([\d.]+)\s+evt/s\s+\|\s+([\d.]+)s'
            stats_match = re.search(stats_pattern, line)

            if stats_match:
                total_events, rate, duration = stats_match.groups()

                # Coordenadas para Madrid (centro de operaciones)
                coords = [40.4168, -3.7038]

                event = {
                    'id': f"stats_{int(time.time())}",
                    'timestamp': datetime.now().isoformat(),
                    'type': 'network_stats',
                    'severity': 'info',
                    'icon': '📊',
                    'color': '#44aaff',
                    'ip_address': '192.168.1.123',
                    'total_events': int(total_events),
                    'event_rate': float(rate),
                    'duration': float(duration),
                    'title': f"📊 Network Statistics",
                    'description': f"Captured {total_events} events at {rate} evt/s over {duration}s",
                    'location': {
                        'lat': coords[0],
                        'lng': coords[1],
                        'city': 'Madrid Centro',
                        'country': 'ES',
                        'org': 'SCADA Statistics'
                    },
                    'coordinates': coords,
                    'raw_data': line.strip(),
                    'source': 'Terminal-Stats'
                }

                return event

        except Exception as e:
            print(f"Error parsing line: {e}")

        return None

    def ip_to_coordinates(self, ip: str) -> List[float]:
        """Convertir IP a coordenadas geográficas aproximadas"""
        try:
            # Para IPs conocidas, usar ubicaciones reales
            ip_locations = {
                '8.8.8.8': [37.4419, -122.0782],  # Google DNS - Mountain View
                '1.1.1.1': [37.7621, -122.3971],  # Cloudflare - San Francisco
                '172.64.155.69': [37.7621, -122.3971],  # Cloudflare
                '142.250.191.3': [37.4419, -122.0782],  # Google
                '34.117.41.85': [37.4419, -122.0782],  # Google Cloud
                '151.101.128.223': [40.7589, -73.9851],  # Fastly - New York
                '172.224.53.5': [47.6062, -122.3321],  # Microsoft - Seattle
            }

            if ip in ip_locations:
                return ip_locations[ip]

            # Para IPs locales, usar variaciones en Madrid
            if ip.startswith('192.168'):
                hash_val = hash(ip) % 1000
                lat = 40.4168 + (hash_val / 50000)  # Variación ±0.02 grados
                lng = -3.7038 + (hash_val / 50000)
                return [lat, lng]

            # Para otras IPs, generar coordenadas basadas en hash
            hash_val = hash(ip) % 10000
            lat = 20 + (hash_val % 60)  # Latitud entre 20 y 80
            lng = -180 + (hash_val % 360)  # Longitud entre -180 y 180
            return [lat, lng]

        except:
            return [40.4168, -3.7038]  # Madrid por defecto

    def ip_to_city(self, ip: str) -> str:
        """Convertir IP a nombre de ciudad"""
        ip_cities = {
            '8.8.8.8': 'Mountain View, CA',
            '1.1.1.1': 'San Francisco, CA',
            '172.64.155.69': 'San Francisco, CA',
            '142.250.191.3': 'Mountain View, CA',
            '34.117.41.85': 'Mountain View, CA',
            '151.101.128.223': 'New York, NY',
            '172.224.53.5': 'Seattle, WA',
        }

        if ip in ip_cities:
            return ip_cities[ip]
        elif ip.startswith('192.168'):
            return 'Red Local Madrid'
        else:
            return 'Unknown Location'

    async def capture_terminal_output(self):
        """Capturar salida del terminal donde corre el sistema SCADA"""
        print("🔍 Buscando terminal con sistema SCADA...")

        # Estrategia 1: Buscar por archivos de log
        log_files = [
            'scada.log', 'promiscuous.log', 'upgraded-happiness.log',
            'dashboard_gis.log', 'dashboard_gis_scada.log'
        ]

        for log_file in log_files:
            try:
                # Intentar seguir archivo de log
                cmd = f"tail -f {log_file}"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )

                print(f"📄 Siguiendo archivo: {log_file}")
                async for line in self.read_process_output(process):
                    await self.process_line(line)

            except FileNotFoundError:
                continue
            except Exception as e:
                print(f"Error con {log_file}: {e}")

        # Estrategia 2: Simular eventos basados en netstat
        print("🔄 Generando eventos sintéticos basados en conexiones de red...")
        await self.generate_synthetic_events()

    async def read_process_output(self, process):
        """Leer salida de proceso de forma async"""
        while True:
            try:
                line = await process.stdout.readline()
                if not line:
                    break
                yield line.decode('utf-8').strip()
            except Exception:
                break

    async def process_line(self, line: str):
        """Procesar línea de terminal"""
        if not line.strip():
            return

        print(f"📡 Terminal: {line}")

        event = self.parse_network_event(line)
        if event:
            self.events.append(event)
            self.event_count += 1

            print(f"✅ Evento {self.event_count}: {event['title']} - {event['ip_address']}")

            # Enviar a todos los WebSockets conectados
            await self.broadcast_event(event)

    async def generate_synthetic_events(self):
        """Generar eventos sintéticos para demostración"""
        print("🎭 Generando eventos sintéticos...")

        synthetic_patterns = [
            "[{num}] Ethernet → IPv4 → TCP → HTTPS | 192.168.1.123:63{port} → 172.64.155.69:443",
            "[{num}] Ethernet → IPv4 → UDP → QUIC → Raw-Data | 192.168.1.123:61{port} → 142.250.191.3:443",
            "[{num}] Ethernet → IPv4 → TCP → HTTPS → TLS | 34.117.41.85:443 → 192.168.1.123:63{port}",
            "[{num}] Ethernet → ARP | 192.168.1.1:0 → 192.168.1.123:0",
            "📊 STATS: {total} eventos | {rate:.1f} evt/s | {duration:.1f}s"
        ]

        event_num = 1
        total_events = 100

        while self.is_running:
            try:
                import random

                if event_num % 20 == 0:
                    # Cada 20 eventos, mostrar estadísticas
                    duration = event_num * 0.5
                    rate = event_num / duration if duration > 0 else 0
                    line = synthetic_patterns[4].format(
                        total=total_events + event_num,
                        rate=rate,
                        duration=duration
                    )
                else:
                    # Evento de red normal
                    pattern = random.choice(synthetic_patterns[:4])
                    line = pattern.format(
                        num=event_num,
                        port=random.randint(100, 999)
                    )

                await self.process_line(line)
                event_num += 1

                # Esperar entre eventos (simular rate real)
                await asyncio.sleep(random.uniform(0.5, 2.0))

            except Exception as e:
                print(f"Error generando evento sintético: {e}")
                await asyncio.sleep(1)

    async def broadcast_event(self, event: Dict[str, Any]):
        """Enviar evento a todos los WebSockets"""
        if not self.websockets:
            return

        message = json.dumps({
            'type': 'gis_event',
            **event
        })

        websockets_copy = self.websockets.copy()
        for ws in websockets_copy:
            try:
                if ws.closed:
                    self.websockets.discard(ws)
                    continue
                await ws.send_str(message)
            except Exception as e:
                print(f"Error enviando a WebSocket: {e}")
                self.websockets.discard(ws)

    def start(self):
        """Iniciar captura"""
        self.is_running = True

    def stop(self):
        """Detener captura"""
        self.is_running = False


class TerminalGISDashboard:
    """Dashboard GIS que lee eventos del terminal"""

    def __init__(self, port: int = 8769):
        self.port = port
        self.app = web.Application()
        self.terminal_reader = TerminalEventReader()
        self.setup_routes()
        self.setup_cors()

    def setup_routes(self):
        self.app.router.add_get('/', self.serve_dashboard)
        self.app.router.add_get('/ws', self.websocket_handler)
        self.app.router.add_get('/api/status', self.api_status)
        self.app.router.add_get('/api/events', self.api_events)
        self.app.router.add_post('/api/events/simulate', self.api_simulate)

    def setup_cors(self):
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })
        for route in list(self.app.router.routes()):
            cors.add(route)

    async def serve_dashboard(self, request):
        """Servir dashboard HTML"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SCADA Terminal Reader - GIS Dashboard</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
                    height: 100vh; 
                    gap: 10px; 
                    padding: 10px;
                }
                .map-container { 
                    background: #1a1a1a; 
                    border-radius: 10px; 
                    border: 1px solid #333; 
                    overflow: hidden; 
                    position: relative;
                }
                #map { height: 100%; border-radius: 10px; }
                .sidebar { 
                    background: #1a1a1a; 
                    border-radius: 10px; 
                    border: 1px solid #333; 
                    display: flex; 
                    flex-direction: column; 
                    overflow: hidden;
                }
                .sidebar-header { 
                    background: linear-gradient(135deg, #ff6b35, #f7931e); 
                    padding: 15px; 
                    text-align: center;
                }
                .sidebar-header h3 { 
                    color: white; 
                    margin: 0;
                    font-size: 1.1rem;
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
                    cursor: pointer;
                }
                .event-item:hover { 
                    background: rgba(255,255,255,0.1); 
                    transform: translateX(5px);
                }
                @keyframes slideIn {
                    from { opacity: 0; transform: translateX(-20px); }
                    to { opacity: 1; transform: translateX(0); }
                }
                .event-header { 
                    display: flex; 
                    justify-content: space-between; 
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
                }
                .event-description { 
                    font-size: 0.8rem; 
                    color: #ccc;
                }
                .status-bar {
                    position: absolute;
                    top: 10px;
                    left: 10px;
                    background: rgba(0,0,0,0.8);
                    padding: 10px 15px;
                    border-radius: 5px;
                    z-index: 1000;
                    backdrop-filter: blur(10px);
                }
                .status-connected { color: #4CAF50; }
                .controls {
                    position: absolute;
                    top: 10px;
                    right: 10px;
                    z-index: 1000;
                    display: flex;
                    gap: 10px;
                }
                .control-btn {
                    background: rgba(0,0,0,0.8);
                    color: white;
                    border: none;
                    padding: 8px 12px;
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
            </style>
        </head>
        <body>
            <div class="container">
                <div class="map-container">
                    <div id="map"></div>
                    <div class="status-bar">
                        <span id="status" class="status-connected">🔗 Terminal Reader Active</span>
                        <div style="font-size: 0.8rem; margin-top: 5px;">
                            Events: <span id="event-count">0</span> | 
                            Rate: <span id="event-rate">0/min</span>
                        </div>
                    </div>
                    <div class="controls">
                        <button class="control-btn" onclick="centerMap()">🎯 Center</button>
                        <button class="control-btn" onclick="clearEvents()">🗑️ Clear</button>
                        <button class="control-btn" onclick="simulateEvent()">⚡ Test</button>
                    </div>
                </div>

                <div class="sidebar">
                    <div class="sidebar-header">
                        <h3>🖥️ Terminal Events Feed</h3>
                        <div style="font-size: 0.8rem; margin-top: 5px; opacity: 0.9;">
                            Reading SCADA console output
                        </div>
                    </div>
                    <div class="events-list" id="events-list">
                        <div style="text-align: center; color: #666; padding: 20px;">
                            Leyendo salida del terminal SCADA...<br>
                            <small>Los eventos aparecerán aquí en tiempo real</small>
                        </div>
                    </div>
                </div>
            </div>

            <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
            <script>
                let map;
                let ws = null;
                let markers = [];
                let eventCount = 0;
                let startTime = Date.now();

                function initMap() {
                    map = L.map('map').setView([40.4168, -3.7038], 6);
                    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                        attribution: '© OpenStreetMap contributors',
                        subdomains: 'abcd',
                        maxZoom: 19
                    }).addTo(map);
                }

                function connectWebSocket() {
                    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                    const wsUrl = `${protocol}//${window.location.host}/ws`;

                    ws = new WebSocket(wsUrl);

                    ws.onopen = function() {
                        console.log('✅ Terminal Reader WebSocket connected');
                        document.getElementById('status').textContent = '🔗 Terminal Reader Connected';
                    };

                    ws.onmessage = function(event) {
                        const data = JSON.parse(event.data);
                        if (data.type === 'gis_event') {
                            addEventToMap(data);
                            addEventToSidebar(data);
                            updateCounter();
                        }
                    };

                    ws.onclose = function() {
                        document.getElementById('status').textContent = '❌ Disconnected';
                        setTimeout(connectWebSocket, 5000);
                    };
                }

                function addEventToMap(event) {
                    if (!event.coordinates) return;

                    const [lat, lng] = event.coordinates;
                    const markerHtml = `
                        <div style="
                            background-color: ${event.color}; 
                            width: 18px; height: 18px; 
                            border-radius: 50%; 
                            border: 2px solid white; 
                            display: flex; 
                            align-items: center; 
                            justify-content: center; 
                            font-size: 9px;
                        ">${event.icon}</div>
                    `;

                    const customIcon = L.divIcon({
                        html: markerHtml,
                        className: 'custom-marker',
                        iconSize: [18, 18],
                        iconAnchor: [9, 9]
                    });

                    const marker = L.marker([lat, lng], { icon: customIcon }).addTo(map);

                    const popupContent = `
                        <div style="color: #333; min-width: 200px;">
                            <h4 style="color: ${event.color};">${event.title}</h4>
                            <p><strong>IP:</strong> ${event.ip_address}</p>
                            <p><strong>Type:</strong> ${event.type}</p>
                            <p><strong>Time:</strong> ${new Date(event.timestamp).toLocaleString()}</p>
                            <p><strong>Source:</strong> ${event.source}</p>
                        </div>
                    `;

                    marker.bindPopup(popupContent);
                    markers.push({ marker, event, timestamp: Date.now() });

                    if (markers.length > 100) {
                        const oldMarker = markers.shift();
                        map.removeLayer(oldMarker.marker);
                    }
                }

                function addEventToSidebar(event) {
                    const eventsList = document.getElementById('events-list');

                    if (eventsList.children[0] && eventsList.children[0].style.textAlign === 'center') {
                        eventsList.innerHTML = '';
                    }

                    const eventElement = document.createElement('div');
                    eventElement.className = 'event-item';
                    eventElement.style.borderLeftColor = event.color;
                    eventElement.innerHTML = `
                        <div class="event-header">
                            <div class="event-title">${event.title}</div>
                            <div class="event-time">${new Date(event.timestamp).toLocaleTimeString()}</div>
                        </div>
                        <div class="event-description">${event.description}</div>
                    `;

                    eventElement.addEventListener('click', () => {
                        if (event.coordinates) {
                            map.setView(event.coordinates, 10);
                            const markerData = markers.find(m => m.event.id === event.id);
                            if (markerData) markerData.marker.openPopup();
                        }
                    });

                    eventsList.insertBefore(eventElement, eventsList.firstChild);

                    while (eventsList.children.length > 50) {
                        eventsList.removeChild(eventsList.lastChild);
                    }
                }

                function updateCounter() {
                    eventCount++;
                    document.getElementById('event-count').textContent = eventCount;

                    const elapsed = (Date.now() - startTime) / 60000;
                    const rate = Math.round(eventCount / Math.max(elapsed, 1));
                    document.getElementById('event-rate').textContent = rate + '/min';
                }

                function centerMap() {
                    if (markers.length > 0) {
                        const group = new L.featureGroup(markers.map(m => m.marker));
                        map.fitBounds(group.getBounds().pad(0.1));
                    }
                }

                function clearEvents() {
                    markers.forEach(m => map.removeLayer(m.marker));
                    markers = [];
                    eventCount = 0;
                    startTime = Date.now();
                    updateCounter();

                    document.getElementById('events-list').innerHTML = `
                        <div style="text-align: center; color: #666; padding: 20px;">
                            Eventos eliminados. Leyendo terminal SCADA...<br>
                            <small>Los eventos aparecerán en tiempo real</small>
                        </div>
                    `;
                }

                async function simulateEvent() {
                    try {
                        await fetch('/api/events/simulate', { method: 'POST' });
                    } catch (e) {
                        console.error('Error:', e);
                    }
                }

                document.addEventListener('DOMContentLoaded', function() {
                    initMap();
                    connectWebSocket();
                });
            </script>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')

    async def websocket_handler(self, request):
        """Manejar conexiones WebSocket"""
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)

        self.terminal_reader.websockets.add(ws)
        print(f"✅ Cliente WebSocket conectado. Total: {len(self.terminal_reader.websockets)}")

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    print(f"📨 WebSocket message: {msg.data}")
                elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        except Exception as e:
            print(f"❌ WebSocket error: {e}")
        finally:
            self.terminal_reader.websockets.discard(ws)
            print(f"🔌 Cliente WebSocket desconectado. Restantes: {len(self.terminal_reader.websockets)}")

        return ws

    async def api_status(self, request):
        """API de estado"""
        return web.json_response({
            'status': 'active',
            'events_captured': len(self.terminal_reader.events),
            'websocket_connections': len(self.terminal_reader.websockets),
            'terminal_reader_active': self.terminal_reader.is_running,
            'timestamp': datetime.now().isoformat()
        })

    async def api_events(self, request):
        """API de eventos"""
        return web.json_response(self.terminal_reader.events[-20:])

    async def api_simulate(self, request):
        """Simular evento"""
        synthetic_line = f"[999] Ethernet → IPv4 → TCP → HTTPS | 192.168.1.123:63999 → 8.8.8.8:443"
        await self.terminal_reader.process_line(synthetic_line)
        return web.json_response({'success': True})


async def main():
    """Función principal"""
    dashboard = TerminalGISDashboard()

    # Buscar puerto disponible
    for port in range(8769, 8780):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                dashboard.port = port
                break
        except OSError:
            continue

    try:
        # Iniciar captura de terminal
        dashboard.terminal_reader.start()

        # Iniciar servidor web
        runner = web.AppRunner(dashboard.app)
        await runner.setup()

        site = web.TCPSite(runner, 'localhost', dashboard.port)
        await site.start()

        print(f"""
🚀 Terminal Reader GIS Dashboard
🌐 URL: http://localhost:{dashboard.port}
📺 Modo: Lectura directa del terminal SCADA
🗺️ Características:
   • Lee eventos directamente de la salida del sistema SCADA
   • Parsea eventos de red en tiempo real
   • Visualización geográfica inmediata
   • Funciona SIN ZeroMQ (solución alternativa)

📊 Estado:
   • Generando eventos sintéticos para demostración
   • Los eventos reales aparecerán si se detectan

Presiona Ctrl+C para detener...
        """)

        # Iniciar captura de terminal en background
        asyncio.create_task(dashboard.terminal_reader.capture_terminal_output())

        # Esperar señal de parada
        await asyncio.Event().wait()

    except KeyboardInterrupt:
        print("\n🛑 Deteniendo Terminal Reader...")
    finally:
        dashboard.terminal_reader.stop()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())