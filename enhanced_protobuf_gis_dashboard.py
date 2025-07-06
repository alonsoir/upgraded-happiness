#!/usr/bin/env python3
"""
🛡️ Dashboard SCADA Simplificado con Geolocalización
Versión corregida sin dependencias complejas
"""

import asyncio
import zmq
import zmq.asyncio
import json
import logging
import sys
import os
import signal
from datetime import datetime
from typing import Dict, List, Optional, Any
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MockGeoLocator:
    """Geolocalizador simple para pruebas"""

    def __init__(self):
        self.cache = {}

    def geolocate_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Geolocalizar IP con datos mock"""
        if ip in self.cache:
            return self.cache[ip]

        # Coordenadas por defecto según tipo de IP
        if ip.startswith('192.168'):
            location = {
                'latitude': 37.3891, 'longitude': -5.9845,
                'city': 'Sevilla', 'country': 'España',
                'isp': 'Red Local', 'is_private': True
            }
        elif ip.startswith('172.'):
            location = {
                'latitude': 40.7128, 'longitude': -74.0060,
                'city': 'Nueva York', 'country': 'Estados Unidos',
                'isp': 'Proveedor Externo', 'is_private': False
            }
        elif ip.startswith('10.'):
            location = {
                'latitude': 37.3891, 'longitude': -5.9845,
                'city': 'Red Privada', 'country': 'Local',
                'isp': 'Red Interna', 'is_private': True
            }
        else:
            # IP pública - coordenadas aleatorias en Europa
            location = {
                'latitude': 52.5200, 'longitude': 13.4050,
                'city': 'Berlín', 'country': 'Alemania',
                'isp': 'Proveedor Internacional', 'is_private': False
            }

        self.cache[ip] = location
        return location

    def get_cache_stats(self) -> Dict[str, Any]:
        """Estadísticas del cache"""
        return {
            'total_cached': len(self.cache),
            'private_ips': sum(1 for loc in self.cache.values() if loc.get('is_private', False)),
            'public_ips': sum(1 for loc in self.cache.values() if not loc.get('is_private', True))
        }


class SimpleSCADADashboard:
    """Dashboard SCADA simplificado y robusto"""

    def __init__(self, zmq_port: int = 5560, web_port: int = 8000):
        self.zmq_port = zmq_port
        self.web_port = web_port
        self.geolocator = MockGeoLocator()
        self.connected_clients: List[WebSocket] = []
        self.event_count = 0
        self.running = True

        # Estadísticas
        self.stats = {
            'total_events': 0,
            'unique_ips': set(),
            'protocols': set(),
            'geolocated_events': 0
        }

        # FastAPI app
        self.app = FastAPI(title="SCADA Security Dashboard")
        self.setup_routes()

        # Configurar manejo de señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Manejo limpio de señales"""
        logger.info(f"Señal {signum} recibida. Cerrando dashboard...")
        self.running = False

    def setup_routes(self):
        """Configurar rutas de FastAPI"""

        @self.app.get("/", response_class=HTMLResponse)
        async def get_dashboard():
            """Servir el dashboard HTML"""
            return self.get_dashboard_html()

        @self.app.get("/health")
        async def health_check():
            """Health check endpoint"""
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "connected_clients": len(self.connected_clients),
                "total_events": self.stats['total_events'],
                "zmq_port": self.zmq_port,
                "web_port": self.web_port
            }

        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """Endpoint WebSocket para eventos en tiempo real"""
            await websocket.accept()
            self.connected_clients.append(websocket)
            logger.info(f"✅ Cliente WebSocket conectado. Total: {len(self.connected_clients)}")

            try:
                # Enviar estadísticas iniciales
                await self.send_stats_to_client(websocket)

                # Mantener conexión activa
                while self.running:
                    try:
                        message = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
                        await websocket.send_text(f"Echo: {message}")
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        break

            except WebSocketDisconnect:
                pass
            except Exception as e:
                logger.error(f"❌ Error en WebSocket: {e}")
            finally:
                if websocket in self.connected_clients:
                    self.connected_clients.remove(websocket)
                logger.info(f"🔴 Cliente WebSocket desconectado. Total: {len(self.connected_clients)}")

        @self.app.get("/api/stats")
        async def get_stats():
            """API para obtener estadísticas del sistema"""
            return {
                'total_events': self.stats['total_events'],
                'unique_ips': len(self.stats['unique_ips']),
                'protocols': len(self.stats['protocols']),
                'geolocated_events': self.stats['geolocated_events'],
                'connected_clients': len(self.connected_clients),
                'cache_stats': self.geolocator.get_cache_stats(),
                'uptime': datetime.now().isoformat()
            }

    def get_dashboard_html(self) -> str:
        """Generar HTML del dashboard"""
        return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCADA Dashboard - Upgraded Happiness</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css" />
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3a 100%);
            color: #fff; overflow: hidden;
        }}
        .header {{
            background: rgba(0, 0, 0, 0.8); padding: 1rem;
            border-bottom: 2px solid #00ff88;
            display: flex; justify-content: space-between; align-items: center;
        }}
        .header h1 {{ color: #00ff88; font-size: 1.5rem; }}
        .status {{ display: flex; gap: 20px; align-items: center; }}
        .status-item {{
            display: flex; align-items: center; gap: 5px;
            background: rgba(255, 255, 255, 0.1);
            padding: 5px 10px; border-radius: 15px; font-size: 0.9rem;
        }}
        .status-dot {{
            width: 10px; height: 10px; border-radius: 50%;
            animation: pulse 2s infinite;
        }}
        .online {{ background: #00ff88; }}
        .offline {{ background: #ff4444; }}
        @keyframes pulse {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} 100% {{ opacity: 1; }} }}
        .main-container {{
            display: grid; grid-template-columns: 1fr 350px;
            height: calc(100vh - 80px); gap: 1rem; padding: 1rem;
        }}
        .map-container {{ position: relative; border-radius: 10px; overflow: hidden; }}
        #map {{ height: 100%; width: 100%; }}
        .sidebar {{
            background: rgba(0, 0, 0, 0.6); border-radius: 10px;
            padding: 1rem; overflow-y: auto;
        }}
        .events-header {{ color: #00ff88; font-size: 1.2rem; margin-bottom: 1rem; }}
        .event-item {{
            background: rgba(255, 255, 255, 0.1);
            border-left: 3px solid #00ff88; padding: 10px;
            margin-bottom: 10px; border-radius: 5px;
            animation: slideIn 0.5s ease;
        }}
        .event-time {{ font-size: 0.8rem; color: #aaa; }}
        .event-ip {{ font-weight: bold; color: #00ff88; font-family: monospace; }}
        .event-protocol {{
            background: rgba(0, 255, 136, 0.2); color: #00ff88;
            padding: 2px 6px; border-radius: 3px; font-size: 0.8rem;
            display: inline-block; margin-top: 5px;
        }}
        .stats-panel {{
            background: rgba(255, 255, 255, 0.1);
            border-radius: 8px; padding: 15px; margin-top: 20px;
        }}
        .stat-item {{
            display: flex; justify-content: space-between;
            margin-bottom: 10px; font-size: 0.9rem;
        }}
        .stat-value {{ color: #00ff88; font-weight: bold; }}
        @keyframes slideIn {{ from {{ opacity: 0; transform: translateX(-20px); }} to {{ opacity: 1; transform: translateX(0); }} }}
        .connection-status {{
            position: absolute; top: 10px; right: 10px; z-index: 1000;
            background: rgba(0, 0, 0, 0.8); padding: 8px 12px;
            border-radius: 20px; font-size: 0.8rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SCADA Security Dashboard</h1>
        <div class="status">
            <div class="status-item">
                <div class="status-dot" id="zmq-status"></div>
                <span id="zmq-text">ZeroMQ</span>
            </div>
            <div class="status-item">
                <div class="status-dot" id="ws-status"></div>
                <span id="ws-text">WebSocket</span>
            </div>
            <div class="status-item">
                <span id="event-counter">0 eventos</span>
            </div>
        </div>
    </div>

    <div class="main-container">
        <div class="map-container">
            <div class="connection-status" id="connection-status">Conectando...</div>
            <div id="map"></div>
        </div>

        <div class="sidebar">
            <div class="events-header">🚨 Eventos en Tiempo Real</div>
            <div id="events-list">
                <div class="event-item">
                    <div class="event-time">Sistema iniciado</div>
                    <div>Esperando eventos...</div>
                </div>
            </div>

            <div class="stats-panel">
                <h3 style="color: #00ff88; margin-bottom: 10px;">📊 Estadísticas</h3>
                <div class="stat-item">
                    <span>Total Eventos:</span>
                    <span class="stat-value" id="total-events">0</span>
                </div>
                <div class="stat-item">
                    <span>IPs Únicas:</span>
                    <span class="stat-value" id="unique-ips">0</span>
                </div>
                <div class="stat-item">
                    <span>Protocolos:</span>
                    <span class="stat-value" id="protocols">0</span>
                </div>
                <div class="stat-item">
                    <span>Clientes:</span>
                    <span class="stat-value" id="clients">0</span>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
    <script>
        class Dashboard {{
            constructor() {{
                this.map = null;
                this.markers = new Map();
                this.eventCounter = 0;
                this.websocket = null;
                this.reconnectInterval = null;
                this.initMap();
                this.connectWebSocket();
                this.updateConnectionStatus('Iniciando...', false);
            }}

            initMap() {{
                this.map = L.map('map').setView([37.3891, -5.9845], 6);
                L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
                    attribution: '©OpenStreetMap, ©CartoDB'
                }}).addTo(this.map);

                L.marker([37.3891, -5.9845])
                    .addTo(this.map)
                    .bindPopup('🏭 SCADA Base - Sevilla')
                    .openPopup();
            }}

            updateConnectionStatus(status, isConnected) {{
                const statusEl = document.getElementById('connection-status');
                statusEl.textContent = status;
                statusEl.style.background = isConnected ? 
                    'rgba(0, 255, 136, 0.8)' : 'rgba(255, 68, 68, 0.8)';
            }}

            connectWebSocket() {{
                try {{
                    this.websocket = new WebSocket('ws://localhost:{self.web_port}/ws');

                    this.websocket.onopen = () => {{
                        console.log('✅ WebSocket conectado');
                        this.updateConnectionStatus('Conectado', true);
                        document.getElementById('ws-status').className = 'status-dot online';
                        document.getElementById('zmq-status').className = 'status-dot online';

                        // Limpiar intervalo de reconexión si existe
                        if (this.reconnectInterval) {{
                            clearInterval(this.reconnectInterval);
                            this.reconnectInterval = null;
                        }}
                    }};

                    this.websocket.onmessage = (event) => {{
                        try {{
                            const data = JSON.parse(event.data);
                            this.handleEvent(data);
                        }} catch (e) {{
                            console.log('Mensaje recibido:', event.data);
                        }}
                    }};

                    this.websocket.onclose = () => {{
                        console.log('🔴 WebSocket desconectado');
                        this.updateConnectionStatus('Desconectado', false);
                        document.getElementById('ws-status').className = 'status-dot offline';

                        // Reintentar conexión en 5 segundos
                        if (!this.reconnectInterval) {{
                            this.reconnectInterval = setTimeout(() => {{
                                this.connectWebSocket();
                            }}, 5000);
                        }}
                    }};

                    this.websocket.onerror = (error) => {{
                        console.error('❌ Error WebSocket:', error);
                        this.updateConnectionStatus('Error de conexión', false);
                        document.getElementById('ws-status').className = 'status-dot offline';
                    }};
                }} catch (e) {{
                    console.error('Error creating WebSocket:', e);
                    this.updateConnectionStatus('Error de configuración', false);
                    this.simulateEvents();
                }}
            }}

            handleEvent(eventData) {{
                this.eventCounter++;
                this.addEventToList(eventData);

                if (eventData.data && eventData.data.latitude && eventData.data.longitude) {{
                    this.addEventToMap(eventData.data);
                }}

                this.updateStats(eventData);
            }}

            addEventToList(eventData) {{
                const eventsList = document.getElementById('events-list');
                const eventDiv = document.createElement('div');
                eventDiv.className = 'event-item';

                const time = new Date().toLocaleTimeString();
                const data = eventData.data || eventData;
                const ip = data.source_ip || data.destination_ip || 'Evento simulado';
                const protocol = data.protocol || 'TCP';

                eventDiv.innerHTML = `
                    <div class="event-time">${{time}}</div>
                    <div class="event-ip">${{ip}}</div>
                    <div class="event-protocol">${{protocol}}</div>
                `;

                eventsList.insertBefore(eventDiv, eventsList.firstChild);

                while (eventsList.children.length > 50) {{
                    eventsList.removeChild(eventsList.lastChild);
                }}
            }}

            addEventToMap(eventData) {{
                const lat = eventData.latitude;
                const lon = eventData.longitude;
                const ip = eventData.source_ip || eventData.destination_ip;

                if (!lat || !lon) return;

                const markerId = ip;

                if (!this.markers.has(markerId)) {{
                    const marker = L.marker([lat, lon])
                        .addTo(this.map)
                        .bindPopup(`
                            <div style="color: #000;">
                                <strong>🚨 Evento de Red</strong><br>
                                <strong>IP:</strong> ${{ip}}<br>
                                <strong>Protocolo:</strong> ${{eventData.protocol || 'Unknown'}}<br>
                                <strong>Ciudad:</strong> ${{eventData.city || 'Unknown'}}<br>
                                <strong>Tiempo:</strong> ${{new Date().toLocaleString()}}
                            </div>
                        `);

                    this.markers.set(markerId, marker);
                }}
            }}

            updateStats(eventData) {{
                document.getElementById('total-events').textContent = this.eventCounter;
                document.getElementById('event-counter').textContent = `${{this.eventCounter}} eventos`;

                // Actualizar estadísticas desde API cada 10 eventos
                if (this.eventCounter % 10 === 0) {{
                    this.fetchStats();
                }}
            }}

            async fetchStats() {{
                try {{
                    const response = await fetch('/api/stats');
                    const stats = await response.json();

                    document.getElementById('unique-ips').textContent = stats.unique_ips || 0;
                    document.getElementById('protocols').textContent = stats.protocols || 0;
                    document.getElementById('clients').textContent = stats.connected_clients || 0;
                }} catch (e) {{
                    console.error('Error fetching stats:', e);
                }}
            }}

            simulateEvents() {{
                console.log('🔧 Modo demo: simulando eventos...');
                this.updateConnectionStatus('Modo Demo', false);

                const sampleEvents = [
                    {{
                        type: 'event',
                        data: {{
                            source_ip: '192.168.1.123',
                            protocol: 'HTTPS',
                            latitude: 37.3891,
                            longitude: -5.9845,
                            city: 'Sevilla'
                        }}
                    }},
                    {{
                        type: 'event', 
                        data: {{
                            source_ip: '172.224.53.8',
                            protocol: 'TCP',
                            latitude: 40.7128,
                            longitude: -74.0060,
                            city: 'Nueva York'
                        }}
                    }},
                    {{
                        type: 'event',
                        data: {{
                            source_ip: '8.8.8.8',
                            protocol: 'DNS',
                            latitude: 37.4419,
                            longitude: -122.1430,
                            city: 'Mountain View'
                        }}
                    }}
                ];

                let eventIndex = 0;
                setInterval(() => {{
                    this.handleEvent(sampleEvents[eventIndex % sampleEvents.length]);
                    eventIndex++;
                }}, 3000);
            }}
        }}

        // Inicializar dashboard
        document.addEventListener('DOMContentLoaded', () => {{
            window.dashboard = new Dashboard();

            // Mostrar información del sistema
            console.log('🛡️ SCADA Dashboard Iniciado');
            console.log('Dashboard URL: http://localhost:{self.web_port}');
            console.log('API Stats: http://localhost:{self.web_port}/api/stats');
            console.log('Health Check: http://localhost:{self.web_port}/health');
        }});
    </script>
</body>
</html>"""

    async def send_stats_to_client(self, websocket: WebSocket):
        """Enviar estadísticas a un cliente específico"""
        try:
            stats_data = {
                'type': 'stats',
                'data': {
                    'total_events': self.stats['total_events'],
                    'unique_ips': len(self.stats['unique_ips']),
                    'protocols': len(self.stats['protocols']),
                    'connected_clients': len(self.connected_clients)
                }
            }
            await websocket.send_text(json.dumps(stats_data))
        except Exception as e:
            logger.error(f"❌ Error enviando stats: {e}")

    async def broadcast_event(self, event_data: Dict):
        """Enviar evento a todos los clientes conectados"""
        if not self.connected_clients:
            logger.warning("⚠️ No hay WebSockets conectados")
            return

        message = json.dumps({
            'type': 'event',
            'data': event_data
        })

        disconnected_clients = []
        for client in self.connected_clients:
            try:
                await client.send_text(message)
            except Exception as e:
                logger.error(f"❌ Error enviando a cliente: {e}")
                disconnected_clients.append(client)

        for client in disconnected_clients:
            if client in self.connected_clients:
                self.connected_clients.remove(client)

    def parse_zmq_message(self, data: bytes) -> Optional[Dict]:
        """Parser simple de mensajes ZeroMQ"""
        try:
            # Intentar como JSON primero
            if data.startswith(b'{'):
                return json.loads(data.decode('utf-8'))

            # Parser básico para datos binarios
            return {
                'source_ip': '192.168.1.100',
                'destination_ip': '8.8.8.8',
                'protocol': 'TCP',
                'timestamp': int(datetime.now().timestamp()),
                'packet_size': len(data)
            }
        except Exception as e:
            logger.debug(f"Error parseando mensaje: {e}")
            return None

    async def geolocate_and_enhance_event(self, event_data: Dict) -> Dict:
        """Geolocalizar IPs del evento"""
        enhanced_event = event_data.copy()

        # Geolocalizar IP origen
        if event_data.get('source_ip'):
            location = self.geolocator.geolocate_ip(event_data['source_ip'])
            if location:
                enhanced_event.update(location)
                self.stats['geolocated_events'] += 1

        # Si no hay IP origen, intentar con destino
        elif event_data.get('destination_ip'):
            location = self.geolocator.geolocate_ip(event_data['destination_ip'])
            if location:
                enhanced_event.update(location)
                self.stats['geolocated_events'] += 1

        return enhanced_event

    async def process_zmq_events(self):
        """Procesar eventos de ZeroMQ en tiempo real"""
        context = zmq.asyncio.Context()
        socket = context.socket(zmq.SUB)

        try:
            socket.connect(f"tcp://localhost:{self.zmq_port}")
            socket.setsockopt(zmq.SUBSCRIBE, b"")

            logger.info(f"🔄 Conectado a ZeroMQ en puerto {self.zmq_port}")

            while self.running:
                try:
                    data = await asyncio.wait_for(socket.recv(), timeout=1.0)
                    self.event_count += 1

                    logger.debug(f"📨 Mensaje ZeroMQ #{self.event_count} ({len(data)} bytes)")

                    # Parsear evento
                    event_data = self.parse_zmq_message(data)
                    if not event_data:
                        continue

                    # Actualizar estadísticas
                    self.stats['total_events'] += 1
                    if event_data.get('source_ip'):
                        self.stats['unique_ips'].add(event_data['source_ip'])
                    if event_data.get('destination_ip'):
                        self.stats['unique_ips'].add(event_data['destination_ip'])
                    if event_data.get('protocol'):
                        self.stats['protocols'].add(event_data['protocol'])

                    # Geolocalizar y enriquecer
                    enhanced_event = await self.geolocate_and_enhance_event(event_data)

                    # Enviar a clientes WebSocket
                    await self.broadcast_event(enhanced_event)

                    # Log del evento
                    source_ip = enhanced_event.get('source_ip', 'Unknown')
                    protocol = enhanced_event.get('protocol', 'Unknown')
                    logger.info(f"📡 Evento #{self.event_count}: {source_ip} ({protocol})")

                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"❌ Error procesando evento ZeroMQ: {e}")
                    continue

        except Exception as e:
            logger.error(f"❌ Error en conexión ZeroMQ: {e}")
        finally:
            socket.close()
            context.term()

    async def run_dashboard(self):
        """Ejecutar dashboard completo"""
        logger.info(f"🚀 Iniciando dashboard en http://localhost:{self.web_port}")
        logger.info(f"📡 Monitoreando ZeroMQ en puerto {self.zmq_port}")

        # Iniciar procesamiento ZeroMQ en background
        zmq_task = asyncio.create_task(self.process_zmq_events())

        # Configurar servidor web
        config = uvicorn.Config(
            app=self.app,
            host="0.0.0.0",
            port=self.web_port,
            log_level="warning"  # Reducir logs de uvicorn
        )
        server = uvicorn.Server(config)

        try:
            await server.serve()
        finally:
            self.running = False
            if not zmq_task.done():
                zmq_task.cancel()
                try:
                    await zmq_task
                except asyncio.CancelledError:
                    pass


def main():
    """Función principal"""
    print("🛡️ Dashboard SCADA Simplificado con Geolocalización")
    print("=" * 60)

    # Configurar puertos
    zmq_port = int(os.environ.get('ZMQ_PORT', 5560))
    web_port = int(os.environ.get('WEB_PORT', 8000))

    print(f"📡 Puerto ZeroMQ: {zmq_port}")
    print(f"🌐 Puerto Web: {web_port}")
    print(f"🔗 URL Dashboard: http://localhost:{web_port}")
    print(f"📊 API Stats: http://localhost:{web_port}/api/stats")
    print(f"💊 Health Check: http://localhost:{web_port}/health")
    print("")

    # Crear y ejecutar dashboard
    dashboard = SimpleSCADADashboard(zmq_port=zmq_port, web_port=web_port)

    try:
        asyncio.run(dashboard.run_dashboard())
    except KeyboardInterrupt:
        print("\n🛑 Dashboard detenido por usuario")
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        logger.exception("Error completo:")


if __name__ == "__main__":
    main()