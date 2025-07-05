# dashboard_server_gis_scada.py
# Dashboard GIS conectado al sistema SCADA existente
# Versión que se integra correctamente con upgraded-happiness

import asyncio
import json
import logging
import socket
import signal
import sys
from datetime import datetime

import aiohttp
from aiohttp import web, WSMsgType, ClientSession, TCPConnector
import aiohttp_cors
import zmq
import zmq.asyncio
import ipaddress
import re
from contextlib import asynccontextmanager
from typing import Optional, Dict, List, Tuple, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('dashboard_gis_scada.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)


class SCADAPortDetector:
    """Detecta automáticamente los puertos del sistema SCADA"""

    @staticmethod
    def find_zmq_broker_ports():
        """Busca puertos activos de ZeroMQ broker"""
        common_ports = [5555, 5556, 5557, 5558, 5559, 5560, 55565]
        active_ports = []

        for port in common_ports:
            if SCADAPortDetector.is_port_active(port):
                active_ports.append(port)

        logger.info(f"🔍 Puertos ZeroMQ activos encontrados: {active_ports}")
        return active_ports

    @staticmethod
    def is_port_active(port):
        """Verifica si un puerto está activo"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(('localhost', port))
                return result == 0
        except:
            return False


class EnhancedEventProcessor:
    """Procesador de eventos mejorado para el sistema SCADA"""

    def __init__(self, geolocator):
        self.geolocator = geolocator
        self.event_counter = 0

        # Tipos de eventos expandidos para SCADA
        self.event_types = {
            'port_scan': {'color': '#ff4444', 'icon': '🔍', 'severity': 'high'},
            'connection_flood': {'color': '#ff8800', 'icon': '🌊', 'severity': 'medium'},
            'suspicious_port': {'color': '#ffaa00', 'icon': '🚪', 'severity': 'medium'},
            'protocol_anomaly': {'color': '#8844ff', 'icon': '⚠️', 'severity': 'low'},
            'ml_anomaly': {'color': '#44ff44', 'icon': '🤖', 'severity': 'info'},
            'network_traffic': {'color': '#4488ff', 'icon': '📡', 'severity': 'info'},
            'https_traffic': {'color': '#00ff88', 'icon': '🔒', 'severity': 'info'},
            'quic_traffic': {'color': '#ff88aa', 'icon': '⚡', 'severity': 'info'},
            'arp_activity': {'color': '#ffaa88', 'icon': '🏠', 'severity': 'low'},
            'raw_data': {'color': '#888888', 'icon': '📊', 'severity': 'info'},
            'heartbeat': {'color': '#4488ff', 'icon': '💓', 'severity': 'info'}
        }

    def extract_ip_from_scada_event(self, event_data):
        """Extraer IP específicamente de eventos SCADA"""
        try:
            # Si es un diccionario (evento estructurado)
            if isinstance(event_data, dict):
                # Buscar campos comunes de IP
                for field in ['source_ip', 'src_ip', 'destination_ip', 'dst_ip', 'ip_src', 'ip_dst', 'remote_ip']:
                    if field in event_data and event_data[field]:
                        return event_data[field]

                # Buscar en texto de descripción
                if 'description' in event_data:
                    ip = self._extract_ip_from_text(event_data['description'])
                    if ip:
                        return ip

            # Si es texto o formato no estructurado
            text = str(event_data)

            # Buscar patrones específicos del agente promiscuo
            # Ejemplo: "192.168.1.123:63494 → 172.64.155.69:443"
            arrow_pattern = r'(\d+\.\d+\.\d+\.\d+):\d+\s*→\s*(\d+\.\d+\.\d+\.\d+):\d+'
            match = re.search(arrow_pattern, text)
            if match:
                src_ip, dst_ip = match.groups()
                # Priorizar IP externa sobre IP local
                try:
                    src_obj = ipaddress.ip_address(src_ip)
                    dst_obj = ipaddress.ip_address(dst_ip)

                    if not dst_obj.is_private and not dst_obj.is_loopback:
                        return dst_ip
                    elif not src_obj.is_private and not src_obj.is_loopback:
                        return src_ip
                    else:
                        return dst_ip  # Retornar cualquiera si ambos son privados
                except:
                    return dst_ip

            # Buscar IPs individuales
            ip = self._extract_ip_from_text(text)
            if ip:
                return ip

        except Exception as e:
            logger.debug(f"Error extrayendo IP: {e}")

        # IP por defecto
        return '192.168.1.123'  # IP local del sistema

    def _extract_ip_from_text(self, text):
        """Extraer IP de texto plano"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)

        if ips:
            for ip in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_loopback and ip != '0.0.0.0':
                        return ip
                except ValueError:
                    continue
        return None

    def classify_scada_event(self, event_data):
        """Clasificar eventos específicos del sistema SCADA"""
        text = str(event_data).lower()

        # Clasificaciones específicas del tráfico de red
        if 'https' in text or 'tls' in text:
            return 'https_traffic'
        elif 'quic' in text:
            return 'quic_traffic'
        elif 'arp' in text:
            return 'arp_activity'
        elif 'raw' in text or 'raw-data' in text:
            return 'raw_data'
        elif any(protocol in text for protocol in ['tcp', 'udp', 'icmp']):
            return 'network_traffic'

        # Clasificaciones de seguridad
        elif 'scan' in text or 'port scan' in text:
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
            return 'network_traffic'

    async def process_scada_event(self, raw_event):
        """Procesar evento del sistema SCADA"""
        try:
            self.event_counter += 1

            # Extraer IP
            ip_address = self.extract_ip_from_scada_event(raw_event)

            # Solo geolocalizar IPs externas para no saturar la API
            if self._is_external_ip(ip_address):
                location = await self.geolocator.geolocate_ip(ip_address)
            else:
                location = self._get_local_location(ip_address)

            # Clasificar evento
            event_type = self.classify_scada_event(raw_event)
            event_config = self.event_types.get(event_type, self.event_types['network_traffic'])

            # Crear título más descriptivo
            title = self._create_event_title(event_type, raw_event)

            enriched_event = {
                'id': f"scada_{self.event_counter}_{datetime.now().strftime('%H%M%S_%f')}",
                'timestamp': datetime.now().isoformat(),
                'type': event_type,
                'severity': event_config['severity'],
                'icon': event_config['icon'],
                'color': event_config['color'],
                'ip_address': ip_address,
                'location': location,
                'title': title,
                'description': self._create_description(raw_event, ip_address, location),
                'raw_data': str(raw_event)[:500],  # Limitamos el tamaño
                'coordinates': [location['lat'], location['lng']],
                'source': 'SCADA-System'
            }

            return enriched_event

        except Exception as e:
            logger.error(f"Error procesando evento SCADA: {e}")
            return None

    def _is_external_ip(self, ip_address):
        """Verificar si es IP externa"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            return not ip_obj.is_private and not ip_obj.is_loopback
        except:
            return False

    def _get_local_location(self, ip_address):
        """Ubicación para IPs locales"""
        hash_offset = hash(ip_address) % 1000
        return {
            'lat': 40.4168 + (hash_offset / 50000),  # Variación en Madrid
            'lng': -3.7038 + (hash_offset / 50000),
            'city': 'Red Local Madrid',
            'country': 'ES',
            'org': 'Red Privada'
        }

    def _create_event_title(self, event_type, raw_event):
        """Crear título descriptivo del evento"""
        base_title = self.event_types[event_type]['icon'] + " " + event_type.replace('_', ' ').title()

        # Añadir información específica si está disponible
        text = str(raw_event)
        if '→' in text:
            # Es tráfico de red
            return f"{base_title} (Network)"
        elif 'stats' in text.lower():
            return f"{base_title} (Stats)"

        return base_title

    def _create_description(self, raw_event, ip_address, location):
        """Crear descripción del evento"""
        base_desc = f"Evento de {ip_address} ({location['city']}, {location['country']})"

        # Añadir contexto del evento
        text = str(raw_event)
        if len(text) > 100:
            context = text[:100] + "..."
        else:
            context = text

        return f"{base_desc} - {context}"


# Importar las clases base del archivo anterior
class RobustGeoLocator:
    """Reutilizamos la clase de geolocalización robusta"""

    def __init__(self, max_retries: int = 2, timeout: int = 3):  # Reducimos timeouts para SCADA
        self.cache = {}
        self.session: Optional[ClientSession] = None
        self.max_retries = max_retries
        self.timeout = timeout
        self.backup_apis = [
            'http://ip-api.com/json/{ip}',
            'https://ipapi.co/{ip}/json/'
        ]

    async def get_session(self) -> ClientSession:
        if not self.session or self.session.closed:
            connector = TCPConnector(limit=5, limit_per_host=3)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = ClientSession(connector=connector, timeout=timeout)
        return self.session

    async def geolocate_ip(self, ip_address: str) -> Dict[str, Any]:
        if ip_address in self.cache:
            return self.cache[ip_address]

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                location = self._get_private_ip_location(ip_address)
                self.cache[ip_address] = location
                return location
        except ValueError:
            pass

        # Solo intentar geolocalización para IPs externas importantes
        for attempt in range(self.max_retries):
            try:
                location = await self._try_geolocation_apis(ip_address)
                if location:
                    self.cache[ip_address] = location
                    return location
            except Exception as e:
                logger.debug(f"Geoloc intento {attempt + 1} falló para {ip_address}: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(0.5)

        default_location = self._get_default_location(ip_address)
        self.cache[ip_address] = default_location
        return default_location

    def _get_private_ip_location(self, ip_address: str) -> Dict[str, Any]:
        hash_offset = hash(ip_address) % 500
        return {
            'lat': 40.4168 + (hash_offset / 100000),
            'lng': -3.7038 + (hash_offset / 100000),
            'city': 'Red Local',
            'country': 'ES',
            'org': 'Red Privada'
        }

    def _get_default_location(self, ip_address: str) -> Dict[str, Any]:
        return {
            'lat': 40.4168,
            'lng': -3.7038,
            'city': 'Desconocida',
            'country': 'Desconocido',
            'org': 'Desconocido'
        }

    async def _try_geolocation_apis(self, ip_address: str) -> Optional[Dict[str, Any]]:
        session = await self.get_session()

        for api_url in self.backup_apis:
            try:
                url = api_url.format(ip=ip_address)
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()

                        if 'ip-api.com' in url and data.get('status') == 'success':
                            return {
                                'lat': data['lat'],
                                'lng': data['lon'],
                                'city': data['city'],
                                'country': data['country'],
                                'org': data.get('org', 'Unknown')
                            }
                        elif 'ipapi.co' in url and data.get('latitude'):
                            return {
                                'lat': data['latitude'],
                                'lng': data['longitude'],
                                'city': data.get('city', 'Unknown'),
                                'country': data.get('country_name', 'Unknown'),
                                'org': data.get('org', 'Unknown')
                            }
            except Exception as e:
                logger.debug(f"API {api_url} falló: {e}")
                continue

        return None

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()


class SCADAGISDashboard:
    """Dashboard GIS específicamente integrado con el sistema SCADA"""

    def __init__(self, host: str = 'localhost', start_port: int = 8768):
        self.host = host
        self.port = None
        self.app = web.Application()
        self.websockets: set = set()
        self.geolocator = RobustGeoLocator()
        self.event_processor = EnhancedEventProcessor(self.geolocator)
        self.recent_events: List[Dict[str, Any]] = []
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None

        # ZeroMQ setup
        self.zmq_context = zmq.asyncio.Context()
        self.subscriber: Optional[zmq.asyncio.Socket] = None
        self.zmq_task: Optional[asyncio.Task] = None

        # SCADA integration
        self.scada_ports = []
        self.connected_to_scada = False

        # Control
        self.is_running = False
        self.shutdown_event = asyncio.Event()

        self.setup_routes()
        self.setup_cors()

    def setup_routes(self):
        """Setup routes"""
        self.app.router.add_get('/', self.serve_dashboard)
        self.app.router.add_get('/ws', self.websocket_handler)
        self.app.router.add_get('/api/status', self.api_status)
        self.app.router.add_get('/api/events', self.api_events)
        self.app.router.add_get('/api/scada-status', self.api_scada_status)
        self.app.router.add_post('/api/events/simulate', self.api_simulate_event)
        self.app.router.add_get('/health', self.health_check)

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

    async def health_check(self, request):
        return web.json_response({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'port': self.port,
            'scada_connected': self.connected_to_scada,
            'scada_ports': self.scada_ports,
            'websockets': len(self.websockets),
            'events': len(self.recent_events)
        })

    async def api_scada_status(self, request):
        """Estado específico de la conexión SCADA"""
        return web.json_response({
            'connected': self.connected_to_scada,
            'ports': self.scada_ports,
            'events_received': len(self.recent_events),
            'event_rate': len(self.recent_events) / max(1, (
                        datetime.now().timestamp() - getattr(self, 'start_time', datetime.now().timestamp())) / 60),
            'cache_size': len(self.geolocator.cache)
        })

    async def serve_dashboard(self, request):
        """Dashboard HTML con información SCADA"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SCADA Security Monitor - GIS Integration</title>
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
                .scada-badge {
                    background: linear-gradient(45deg, #ff6b35, #f7931e);
                    color: white;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.7rem;
                    font-weight: bold;
                    animation: glow 2s ease-in-out infinite alternate;
                }
                @keyframes glow {
                    from { box-shadow: 0 0 5px #ff6b35; }
                    to { box-shadow: 0 0 20px #ff6b35, 0 0 30px #ff6b35; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>
                        <div class="status-indicator"></div>
                        🗺️ SCADA Security Monitor - GIS Integration
                        <span class="scada-badge">SCADA CONNECTED</span>
                    </h1>
                    <div class="metrics">
                        <div class="metric">
                            <div class="metric-value" id="events-count">0</div>
                            <div class="metric-label">SCADA Events</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value" id="event-rate">0/min</div>
                            <div class="metric-label">Event Rate</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value" id="scada-status">Unknown</div>
                            <div class="metric-label">SCADA Status</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value" id="port-info">:----</div>
                            <div class="metric-label">Port</div>
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
                        <button class="control-btn" onclick="clearEvents()">🗑️ Clear</button>
                        <button class="control-btn" onclick="simulateEvent()">⚡ Test Event</button>
                        <button class="control-btn" onclick="checkSCADAStatus()">🔧 SCADA Status</button>
                    </div>
                    <div class="legend">
                        <h4>SCADA Event Types</h4>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #00ff88;"></div>
                            <span>🔒 HTTPS Traffic</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #ff88aa;"></div>
                            <span>⚡ QUIC Traffic</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #4488ff;"></div>
                            <span>📡 Network Traffic</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #ffaa88;"></div>
                            <span>🏠 ARP Activity</span>
                        </div>
                        <div class="legend-item">
                            <div class="legend-color" style="background-color: #ff4444;"></div>
                            <span>🔍 Security Threats</span>
                        </div>
                    </div>
                </div>

                <div class="sidebar">
                    <div class="sidebar-header">
                        <h3>🚨 SCADA Events <span style="font-size: 0.7rem; color: #666;">(Live Feed)</span></h3>
                    </div>
                    <div class="events-list" id="events-list">
                        <div style="text-align: center; color: #666; padding: 20px;">
                            Conectando al sistema SCADA...<br>
                            <small>Esperando eventos de seguridad en tiempo real...</small>
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
                    L.control.scale().addTo(map);
                }

                function connectWebSocket() {
                    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                    const wsUrl = `${protocol}//${window.location.host}/ws`;

                    ws = new WebSocket(wsUrl);

                    ws.onopen = function() {
                        console.log('✅ Conectado al dashboard SCADA GIS');
                        updateConnectionStatus('Connected to SCADA', true);
                        fetch('/health')
                            .then(r => r.json())
                            .then(data => {
                                document.getElementById('port-info').textContent = ':' + data.port;
                                document.getElementById('scada-status').textContent = data.scada_connected ? 'Connected' : 'Disconnected';
                            });
                    };

                    ws.onmessage = function(event) {
                        const data = JSON.parse(event.data);
                        handleMessage(data);
                    };

                    ws.onclose = function() {
                        updateConnectionStatus('Disconnected', false);
                        setTimeout(connectWebSocket, 5000);
                    };
                }

                function handleMessage(data) {
                    if (data.type === 'gis_event') {
                        addEventToMap(data);
                        addEventToSidebar(data);
                        updateEventCounter();
                    }
                }

                function addEventToMap(event) {
                    if (!event.coordinates || event.coordinates.length !== 2) return;

                    const [lat, lng] = event.coordinates;
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
                    `;

                    const customIcon = L.divIcon({
                        html: markerHtml,
                        className: 'custom-marker',
                        iconSize: [20, 20],
                        iconAnchor: [10, 10]
                    });

                    const marker = L.marker([lat, lng], { icon: customIcon }).addTo(map);

                    const popupContent = `
                        <div style="color: #333; min-width: 250px;">
                            <h4 style="margin: 0 0 10px 0; color: ${event.color};">
                                ${event.icon} ${event.title}
                            </h4>
                            <p style="margin: 5px 0;"><strong>IP:</strong> ${event.ip_address}</p>
                            <p style="margin: 5px 0;"><strong>Location:</strong> ${event.location.city}, ${event.location.country}</p>
                            <p style="margin: 5px 0;"><strong>Type:</strong> ${event.type.replace('_', ' ')}</p>
                            <p style="margin: 5px 0;"><strong>Source:</strong> ${event.source || 'SCADA System'}</p>
                            <p style="margin: 5px 0;"><strong>Time:</strong> ${new Date(event.timestamp).toLocaleString()}</p>
                            <p style="margin: 5px 0; font-size: 0.8em;"><strong>Raw:</strong> ${event.raw_data.substring(0, 100)}...</p>
                        </div>
                    `;

                    marker.bindPopup(popupContent);
                    markers.push({ marker: marker, event: event, timestamp: Date.now() });

                    if (markers.length > 100) {
                        const oldMarker = markers.shift();
                        map.removeLayer(oldMarker.marker);
                    }
                }

                function addEventToSidebar(event) {
                    const eventsList = document.getElementById('events-list');

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

                    eventElement.addEventListener('click', () => {
                        if (event.coordinates) {
                            map.setView(event.coordinates, 10);
                            const markerData = markers.find(m => m.event.id === event.id);
                            if (markerData) {
                                markerData.marker.openPopup();
                            }
                        }
                    });

                    eventsList.insertBefore(eventElement, eventsList.firstChild);

                    while (eventsList.children.length > 50) {
                        eventsList.removeChild(eventsList.lastChild);
                    }
                }

                function updateEventCounter() {
                    eventCount++;
                    document.getElementById('events-count').textContent = eventCount;

                    const timeElapsed = (Date.now() - startTime) / 60000; // minutes
                    const rate = Math.round(eventCount / Math.max(timeElapsed, 1));
                    document.getElementById('event-rate').textContent = rate + '/min';
                }

                function updateConnectionStatus(status, connected) {
                    const statusEl = document.getElementById('connection-status');
                    statusEl.textContent = status;
                    statusEl.className = connected ? 'status-connected' : 'status-disconnected';
                }

                function centerMap() {
                    if (markers.length > 0) {
                        const group = new L.featureGroup(markers.map(m => m.marker));
                        map.fitBounds(group.getBounds().pad(0.1));
                    } else {
                        map.setView([40.4168, -3.7038], 6);
                    }
                }

                function clearEvents() {
                    markers.forEach(markerData => {
                        map.removeLayer(markerData.marker);
                    });
                    markers = [];
                    eventCount = 0;
                    startTime = Date.now();
                    updateEventCounter();

                    const eventsList = document.getElementById('events-list');
                    eventsList.innerHTML = `
                        <div style="text-align: center; color: #666; padding: 20px;">
                            Eventos eliminados. Monitoreando SCADA en tiempo real...<br>
                            <small>Conectado al sistema upgraded-happiness</small>
                        </div>
                    `;
                }

                async function simulateEvent() {
                    try {
                        const response = await fetch('/api/events/simulate', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ type: 'scada_test_event' })
                        });
                        if (response.ok) {
                            console.log('✅ Evento SCADA simulado');
                        }
                    } catch (e) {
                        console.error('❌ Error simulando evento:', e);
                    }
                }

                async function checkSCADAStatus() {
                    try {
                        const response = await fetch('/api/scada-status');
                        const data = await response.json();
                        console.log('🔧 SCADA Status:', data);

                        document.getElementById('scada-status').textContent = 
                            data.connected ? `Connected (${data.ports.join(',')})` : 'Disconnected';
                    } catch (e) {
                        console.error('❌ Error checking SCADA status:', e);
                    }
                }

                // Initialize
                document.addEventListener('DOMContentLoaded', function() {
                    console.log('🗺️ SCADA GIS Dashboard Loading...');
                    initMap();
                    connectWebSocket();

                    // Check SCADA status periodically
                    setInterval(checkSCADAStatus, 10000);
                });
            </script>
        </body>
        </html>
        """
        return web.Response(text=html_content, content_type='text/html')

    async def websocket_handler(self, request):
        """WebSocket handler"""
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        self.websockets.add(ws)

        logger.info(f"✅ Cliente GIS conectado. Total: {len(self.websockets)}")

        try:
            await ws.send_str(json.dumps({
                'type': 'connection',
                'message': f'Conectado al Dashboard SCADA GIS - Puerto {self.port}',
                'scada_status': self.connected_to_scada,
                'scada_ports': self.scada_ports
            }))

            # Send recent events
            for event in self.recent_events[-10:]:
                await ws.send_str(json.dumps({
                    'type': 'gis_event',
                    **event
                }))

            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        logger.info(f"📨 Mensaje WebSocket: {data}")
                    except json.JSONDecodeError:
                        logger.error(f"❌ JSON inválido: {msg.data}")
                elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break

        except Exception as e:
            logger.error(f"❌ Error WebSocket: {e}")
        finally:
            self.websockets.discard(ws)
            logger.info(f"🔌 Cliente GIS desconectado. Restantes: {len(self.websockets)}")

        return ws

    async def api_status(self, request):
        return web.json_response({
            'timestamp': datetime.now().isoformat(),
            'port': self.port,
            'scada_connected': self.connected_to_scada,
            'scada_ports': self.scada_ports,
            'events_total': len(self.recent_events),
            'events_rate': len(self.recent_events) / max(1, (
                        datetime.now().timestamp() - getattr(self, 'start_time', datetime.now().timestamp())) / 60),
            'websockets': len(self.websockets),
            'gis_enhanced': True,
            'mode': 'SCADA_INTEGRATED'
        })

    async def api_events(self, request):
        return web.json_response(self.recent_events[-50:])

    async def api_simulate_event(self, request):
        """Simular evento SCADA"""
        try:
            import random

            # Crear evento simulado que parece del sistema SCADA
            scada_event_examples = [
                "Ethernet → IPv4 → TCP → HTTPS | 192.168.1.123:63494 → 172.64.155.69:443",
                "Ethernet → IPv4 → UDP → QUIC → Raw-Data | 192.168.1.123:61989 → 142.250.191.3:443",
                "Ethernet → ARP | 192.168.1.1:0 → 192.168.1.123:0",
                "📊 STATS: 500 eventos | 25.3 evt/s | Network activity detected",
                "🔍 Anomaly detected: Unusual traffic pattern from 185.199.108.1"
            ]

            simulated_event = random.choice(scada_event_examples)
            processed_event = await self.event_processor.process_scada_event(simulated_event)

            if processed_event:
                self.recent_events.append(processed_event)
                if len(self.recent_events) > 1000:
                    self.recent_events = self.recent_events[-1000:]

                await self.broadcast_to_websockets({
                    'type': 'gis_event',
                    **processed_event
                })

                logger.info(f"✅ Evento SCADA simulado: {processed_event['title']}")
                return web.json_response({'success': True, 'event': processed_event})
            else:
                return web.json_response({'error': 'Failed to process event'}, status=500)

        except Exception as e:
            logger.error(f"❌ Error simulando evento SCADA: {e}")
            return web.json_response({'error': str(e)}, status=500)

    async def setup_scada_connection(self):
        """Configurar conexión al sistema SCADA"""
        self.scada_ports = SCADAPortDetector.find_zmq_broker_ports()

        if not self.scada_ports:
            logger.warning("❌ No se encontraron puertos ZeroMQ activos del sistema SCADA")
            logger.info("💡 Iniciando en modo autónomo - usa el botón 'Test Event' para probar")
            return

        # Intentar conectar al primer puerto disponible
        for port in self.scada_ports:
            try:
                self.subscriber = self.zmq_context.socket(zmq.SUB)
                self.subscriber.connect(f"tcp://localhost:{port}")
                self.subscriber.setsockopt(zmq.SUBSCRIBE, b"")

                logger.info(f"✅ Conectado al sistema SCADA en puerto {port}")
                self.connected_to_scada = True
                self.zmq_task = asyncio.create_task(self.scada_message_loop())
                break

            except Exception as e:
                logger.warning(f"❌ Error conectando al puerto {port}: {e}")
                if self.subscriber:
                    self.subscriber.close()
                    self.subscriber = None

        if not self.connected_to_scada:
            logger.warning("❌ No se pudo conectar al sistema SCADA")
            logger.info("💡 Iniciando en modo autónomo")

    async def scada_message_loop(self):
        """Loop para recibir mensajes del sistema SCADA"""
        logger.info("🔄 Iniciando loop de mensajes SCADA...")

        while not self.shutdown_event.is_set():
            try:
                if await self.subscriber.poll(1000, zmq.POLLIN):
                    message = await self.subscriber.recv_json()
                    logger.debug(f"📡 Mensaje SCADA recibido: {message}")

                    processed_event = await self.event_processor.process_scada_event(message)

                    if processed_event:
                        self.recent_events.append(processed_event)
                        if len(self.recent_events) > 1000:
                            self.recent_events = self.recent_events[-1000:]

                        await self.broadcast_to_websockets({
                            'type': 'gis_event',
                            **processed_event
                        })

            except Exception as e:
                logger.error(f"❌ Error en loop SCADA: {e}")
                await asyncio.sleep(1)

    async def broadcast_to_websockets(self, message):
        """Broadcast a WebSockets"""
        if not self.websockets:
            return

        websockets_copy = self.websockets.copy()
        failed_websockets = []

        for ws in websockets_copy:
            try:
                if ws.closed:
                    failed_websockets.append(ws)
                    continue
                await ws.send_str(json.dumps(message))
            except Exception as e:
                logger.debug(f"Error enviando a WebSocket: {e}")
                failed_websockets.append(ws)

        for ws in failed_websockets:
            self.websockets.discard(ws)

    async def find_available_port(self, start_port=8768):
        """Encontrar puerto disponible"""
        for port in range(start_port, start_port + 10):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(('127.0.0.1', port))
                    self.port = port
                    logger.info(f"✅ Puerto {port} seleccionado para dashboard SCADA GIS")
                    return port
            except OSError:
                continue
        raise RuntimeError("No se pudo encontrar un puerto disponible")

    async def start_server(self):
        """Iniciar servidor"""
        self.start_time = datetime.now().timestamp()

        # Buscar puerto disponible
        await self.find_available_port()

        # Conectar al sistema SCADA
        await self.setup_scada_connection()

        # Iniciar servidor HTTP
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()

        self.is_running = True

        logger.info(f"🚀 Dashboard SCADA GIS iniciado en http://{self.host}:{self.port}")
        logger.info(f"🔗 Estado SCADA: {'Conectado' if self.connected_to_scada else 'Autónomo'}")
        if self.scada_ports:
            logger.info(f"🔌 Puertos SCADA detectados: {self.scada_ports}")

        return self.runner

    async def graceful_shutdown(self):
        """Apagado graceful"""
        logger.info("🛑 Iniciando apagado del dashboard SCADA GIS...")

        self.shutdown_event.set()
        self.is_running = False

        if self.zmq_task and not self.zmq_task.done():
            self.zmq_task.cancel()

        if self.websockets:
            websockets_copy = self.websockets.copy()
            for ws in websockets_copy:
                try:
                    await ws.close()
                except:
                    pass
            self.websockets.clear()

        if self.subscriber:
            self.subscriber.close()
        self.zmq_context.term()

        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

        await self.geolocator.close()
        logger.info("✅ Dashboard SCADA GIS apagado correctamente")


async def main():
    """Función principal"""
    dashboard = SCADAGISDashboard()

    try:
        runner = await dashboard.start_server()

        print(f"""
🚀 SCADA GIS Dashboard Integrado
🌐 URL: http://{dashboard.host}:{dashboard.port}
🔗 Sistema SCADA: {'✅ Conectado' if dashboard.connected_to_scada else '❌ Modo Autónomo'}
🗺️ Características:
   • Integración directa con sistema SCADA upgraded-happiness
   • Visualización geográfica de eventos de red en tiempo real
   • Procesamiento inteligente de eventos del agente promiscuo
   • Detección automática de puertos ZeroMQ
   • Clasificación de tráfico de red (HTTPS, QUIC, ARP, etc.)

📊 API Endpoints:
   • /health - Estado del sistema
   • /api/scada-status - Estado específico SCADA
   • /api/events - Eventos recientes

🎮 Controles:
   • Test Event - Simular evento SCADA
   • SCADA Status - Verificar conexión al sistema

Presiona Ctrl+C para detener...
        """)

        await dashboard.shutdown_event.wait()

    except KeyboardInterrupt:
        logger.info("🛑 Interrupción del usuario")
    except Exception as e:
        logger.error(f"❌ Error: {e}")
    finally:
        await dashboard.graceful_shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("✅ Dashboard SCADA GIS terminado")
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        sys.exit(1)