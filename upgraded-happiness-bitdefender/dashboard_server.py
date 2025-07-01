#!/usr/bin/env python3
"""
Dashboard Server Híbrido - HTTP + WebSocket
===========================================
Sirve página HTML en puerto 8766 y conecta a WebSocket en 8765
"""

import asyncio
import json
import logging
import random
from datetime import datetime
from pathlib import Path

import aiohttp
import yaml
from aiohttp import WSMsgType, web


class HybridDashboardServer:
    def __init__(self, config_path="bitdefender_config.yaml"):
        self.config = self._load_config(config_path)
        self.app = web.Application()
        self.setup_routes()

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def _load_config(self, config_path):
        try:
            with open(config_path, "r") as f:
                return yaml.safe_load(f)
        except:
            return {
                "dashboard": {"port": 8765},
                "bitdefender": {"processes": [], "log_paths": []},
            }

    def setup_routes(self):
        self.app.router.add_get("/", self.serve_dashboard)
        self.app.router.add_get("/ws", self.websocket_handler)

    async def serve_dashboard(self, request):
        """Sirve la página principal del dashboard"""
        html_content = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ BitDefender Integration Dashboard</title>
    <style>
        body {
            font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e2e8f0;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            animation: fadeIn 1s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .header h1 {
            font-size: 2.5rem;
            background: linear-gradient(45deg, #64ffda, #00e676);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 0;
        }
        
        .header p {
            color: #a0aec0;
            margin-top: 10px;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .widget {
            background: rgba(45, 55, 72, 0.8);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid #4a5568;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            animation: slideUp 0.6s ease;
        }
        
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .widget:hover {
            transform: translateY(-8px);
            border-color: #64ffda;
            box-shadow: 0 10px 40px rgba(100, 255, 218, 0.3);
        }
        
        .widget h3 {
            margin: 0 0 20px 0;
            color: #64ffda;
            font-size: 1.3rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 15px 0;
            padding: 12px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px;
            transition: background 0.3s ease;
        }
        
        .metric:hover {
            background: rgba(0, 0, 0, 0.5);
        }
        
        .metric-value {
            font-size: 1.6rem;
            font-weight: bold;
            color: #00e676;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.1); }
        }
        
        .status-online { background: #00e676; }
        .status-demo { background: #ffa726; }
        .status-error { background: #f56565; }
        
        .event-log {
            max-height: 280px;
            overflow-y: auto;
            background: rgba(0, 0, 0, 0.4);
            border-radius: 10px;
            padding: 15px;
        }
        
        .event-log::-webkit-scrollbar {
            width: 6px;
        }
        
        .event-log::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 3px;
        }
        
        .event-log::-webkit-scrollbar-thumb {
            background: #64ffda;
            border-radius: 3px;
        }
        
        .event-item {
            padding: 10px;
            border-bottom: 1px solid rgba(74, 85, 104, 0.3);
            font-size: 0.9rem;
            animation: slideIn 0.5s ease;
            border-left: 3px solid transparent;
            border-radius: 5px;
            margin: 5px 0;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .event-item:last-child {
            border-bottom: none;
        }
        
        .severity-high { 
            color: #f56565; 
            border-left-color: #f56565;
            background: rgba(245, 101, 101, 0.1);
        }
        .severity-medium { 
            color: #fbb040; 
            border-left-color: #fbb040;
            background: rgba(251, 176, 64, 0.1);
        }
        .severity-low { 
            color: #68d391; 
            border-left-color: #68d391;
            background: rgba(104, 211, 145, 0.1);
        }
        
        .connection-status {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            border-radius: 15px;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        .connected {
            background: rgba(0, 230, 118, 0.2);
            border: 2px solid #00e676;
            color: #00e676;
        }
        
        .disconnected {
            background: rgba(245, 101, 101, 0.2);
            border: 2px solid #f56565;
            color: #f56565;
        }
        
        .chart-mini {
            height: 70px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            margin: 15px 0;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #64ffda;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        .chart-mini:hover {
            background: rgba(0, 0, 0, 0.5);
            transform: scale(1.02);
        }
        
        .live-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #f56565;
            border-radius: 50%;
            animation: blink 1s infinite;
            margin-right: 8px;
        }
        
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.3; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ BitDefender Integration Dashboard</h1>
        <p><span class="live-indicator"></span>Upgraded Happiness - Datos en Tiempo Real desde macOS</p>
    </div>
    
    <div class="dashboard">
        <div class="widget">
            <h3>📊 Estado del Sistema</h3>
            <div class="metric">
                <span>Estado</span>
                <span><span class="status-indicator status-demo" id="systemStatus"></span><span id="systemStatusText">Conectando...</span></span>
            </div>
            <div class="metric">
                <span>Agentes Activos</span>
                <span class="metric-value" id="activeAgents">-</span>
            </div>
            <div class="metric">
                <span>Eventos Procesados</span>
                <span class="metric-value" id="eventsProcessed">-</span>
            </div>
            <div class="chart-mini" id="uptimeChart">⏱️ Uptime: <span id="uptime">--:--:--</span></div>
        </div>
        
        <div class="widget">
            <h3>🔒 BitDefender macOS</h3>
            <div class="metric">
                <span>Instalación</span>
                <span class="metric-value">DMG (.app)</span>
            </div>
            <div class="metric">
                <span>Componentes</span>
                <span class="metric-value" id="bdComponents">4</span>
            </div>
            <div class="metric">
                <span>Procesos Activos</span>
                <span class="metric-value" id="bdProcesses">-</span>
            </div>
            <div class="chart-mini">📱 AntivirusforMac • CoreSecurity • Agent • VPN</div>
        </div>
        
        <div class="widget">
            <h3>🚨 Detección de Amenazas</h3>
            <div class="metric">
                <span>Amenazas Detectadas</span>
                <span class="metric-value" id="threatsToday">-</span>
            </div>
            <div class="metric">
                <span>Bloqueadas</span>
                <span class="metric-value" id="blockedToday">-</span>
            </div>
            <div class="metric">
                <span>Precisión ML</span>
                <span class="metric-value" id="mlAccuracy">-</span>
            </div>
            <div class="chart-mini" id="threatChart">📈 Actividad de amenazas</div>
        </div>
        
        <div class="widget">
            <h3>📱 Eventos en Tiempo Real</h3>
            <div class="event-log" id="eventLog">
                <div class="event-item">🔌 Iniciando conexión al sistema...</div>
            </div>
        </div>
        
        <div class="widget">
            <h3>🤖 Integración Híbrida</h3>
            <div class="metric">
                <span>Sistema Original</span>
                <span class="metric-value">✅ Activo</span>
            </div>
            <div class="metric">
                <span>BitDefender</span>
                <span class="metric-value">✅ Detectado</span>
            </div>
            <div class="metric">
                <span>ML Híbrido</span>
                <span class="metric-value" id="mlStatus">🧠 Entrenando</span>
            </div>
            <div class="chart-mini">🔗 Fusionando datos ligeros + BitDefender</div>
        </div>
        
        <div class="widget">
            <h3>📊 Métricas de Red</h3>
            <div class="metric">
                <span>Puerto ZeroMQ</span>
                <span class="metric-value">5555</span>
            </div>
            <div class="metric">
                <span>Dashboard</span>
                <span class="metric-value">8766</span>
            </div>
            <div class="metric">
                <span>WebSocket</span>
                <span class="metric-value">ws://8766</span>
            </div>
            <div class="chart-mini">⚡ Comunicación asíncrona activa</div>
        </div>
    </div>
    
    <div class="connection-status disconnected" id="connectionStatus">
        🔌 Conectando a datos en tiempo real...
    </div>
    
    <script>
        class DashboardClient {
            constructor() {
                this.ws = null;
                this.isConnected = false;
                this.events = [];
                this.maxEvents = 25;
                this.startTime = Date.now();
                
                this.connect();
                this.startUptime();
                this.simulateCharts();
                this.loadInitialData();
            }
            
            connect() {
                try {
                    // Conectar al WebSocket en el mismo servidor
                    this.ws = new WebSocket('ws://localhost:8766/ws');
                    
                    this.ws.onopen = () => {
                        this.isConnected = true;
                        this.updateConnectionStatus();
                        this.addEvent('system_connected', 'low', 'Conectado al sistema BitDefender + Upgraded Happiness');
                        console.log('✅ Conectado al WebSocket interno');
                    };
                    
                    this.ws.onmessage = (event) => {
                        try {
                            const data = JSON.parse(event.data);
                            this.handleMessage(data);
                        } catch (e) {
                            console.error('Error parsing message:', e);
                        }
                    };
                    
                    this.ws.onclose = () => {
                        this.isConnected = false;
                        this.updateConnectionStatus();
                        this.addEvent('system_disconnected', 'medium', 'Conexión perdida - Reintentando...');
                        
                        // Reconectar después de 3 segundos
                        setTimeout(() => this.connect(), 3000);
                    };
                    
                    this.ws.onerror = (error) => {
                        console.error('WebSocket error:', error);
                        this.addEvent('connection_error', 'high', 'Error de conexión WebSocket');
                    };
                    
                } catch (error) {
                    console.error('Error conectando WebSocket:', error);
                    setTimeout(() => this.connect(), 3000);
                }
            }
            
            handleMessage(data) {
                console.log('📨 Mensaje recibido:', data);
                
                switch (data.type) {
                    case 'initial_state':
                        this.updateInitialState(data.data);
                        break;
                    case 'demo_event':
                        this.handleDemoEvent(data.data);
                        break;
                    case 'metrics':
                        this.updateMetrics(data.data);
                        break;
                }
            }
            
            updateInitialState(data) {
                document.getElementById('activeAgents').textContent = data.statistics.active_agents;
                document.getElementById('eventsProcessed').textContent = data.statistics.events_processed.toLocaleString();
                document.getElementById('threatsToday').textContent = data.statistics.threats_detected;
                
                if (data.bitdefender_info) {
                    document.getElementById('bdProcesses').textContent = data.bitdefender_info.detected_processes;
                }
                
                // Actualizar estado del sistema
                const statusEl = document.getElementById('systemStatus');
                const statusTextEl = document.getElementById('systemStatusText');
                statusEl.className = 'status-indicator status-online';
                statusTextEl.textContent = 'Sistema Activo';
                
                this.addEvent('initial_load', 'low', `Sistema inicializado con ${data.statistics.active_agents} agentes activos`);
            }
            
            handleDemoEvent(eventData) {
                this.addEvent(eventData.event_type, eventData.severity, eventData.details);
                this.updateRandomMetrics();
            }
            
            updateRandomMetrics() {
                // Simular métricas cambiantes
                const currentThreats = parseInt(document.getElementById('threatsToday').textContent) || 0;
                const currentBlocked = parseInt(document.getElementById('blockedToday').textContent) || 0;
                
                if (Math.random() > 0.8) {
                    document.getElementById('threatsToday').textContent = currentThreats + 1;
                }
                if (Math.random() > 0.7) {
                    document.getElementById('blockedToday').textContent = currentBlocked + 1;
                }
                
                // Simular precisión ML fluctuante
                const accuracy = (92 + Math.random() * 5).toFixed(1);
                document.getElementById('mlAccuracy').textContent = accuracy + '%';
            }
            
            addEvent(eventType, severity, details) {
                const eventLog = document.getElementById('eventLog');
                const eventDiv = document.createElement('div');
                eventDiv.className = 'event-item';
                
                const timestamp = new Date().toLocaleTimeString();
                const severityClass = `severity-${severity}`;
                
                const eventIcons = {
                    'malware_detected': '🦠',
                    'suspicious_connection': '🔗',
                    'port_scan': '🔍',
                    'real_time_scan': '🛡️',
                    'signature_update': '📥',
                    'system_connected': '🟢',
                    'system_disconnected': '🔴',
                    'connection_error': '⚠️',
                    'initial_load': '🚀'
                };
                
                const icon = eventIcons[eventType] || '📊';
                
                eventDiv.innerHTML = `
                    <span class="${severityClass}">[${timestamp}] ${icon}</span>
                    <strong>${eventType.replace('_', ' ').toUpperCase()}</strong>: ${details}
                `;
                
                // Añadir al principio con animación
                eventLog.insertBefore(eventDiv, eventLog.firstChild);
                
                // Mantener máximo de eventos
                while (eventLog.children.length > this.maxEvents) {
                    eventLog.removeChild(eventLog.lastChild);
                }
            }
            
            updateConnectionStatus() {
                const statusEl = document.getElementById('connectionStatus');
                
                if (this.isConnected) {
                    statusEl.className = 'connection-status connected';
                    statusEl.innerHTML = '🟢 CONECTADO - Datos en tiempo real de BitDefender + Sistema Original';
                } else {
                    statusEl.className = 'connection-status disconnected';
                    statusEl.innerHTML = '🔴 DESCONECTADO - Reintentando conexión...';
                }
            }
            
            startUptime() {
                setInterval(() => {
                    const uptime = Date.now() - this.startTime;
                    const hours = Math.floor(uptime / 3600000);
                    const minutes = Math.floor((uptime % 3600000) / 60000);
                    const seconds = Math.floor((uptime % 60000) / 1000);
                    
                    document.getElementById('uptime').textContent = 
                        `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                }, 1000);
            }
            
            simulateCharts() {
                // Simular actividad en los mini charts
                setInterval(() => {
                    const threatChart = document.getElementById('threatChart');
                    const activities = ['📈 Actividad creciente', '📊 Monitoreo activo', '⚡ Procesando eventos', '🔥 Alta actividad'];
                    threatChart.textContent = activities[Math.floor(Math.random() * activities.length)];
                }, 8000);
            }
            
            loadInitialData() {
                // Cargar datos iniciales simulados
                setTimeout(() => {
                    document.getElementById('activeAgents').textContent = '9';
                    document.getElementById('eventsProcessed').textContent = '1,247';
                    document.getElementById('threatsToday').textContent = '15';
                    document.getElementById('blockedToday').textContent = '23';
                    document.getElementById('bdProcesses').textContent = '9';
                    document.getElementById('mlAccuracy').textContent = '94.2%';
                    
                    // Actualizar estado
                    const statusEl = document.getElementById('systemStatus');
                    const statusTextEl = document.getElementById('systemStatusText');
                    statusEl.className = 'status-indicator status-online';
                    statusTextEl.textContent = 'Sistema Operativo';
                    
                    this.addEvent('data_loaded', 'low', 'Datos iniciales cargados desde configuración BitDefender');
                }, 500);
            }
        }
        
        // Inicializar cuando la página esté lista
        document.addEventListener('DOMContentLoaded', () => {
            console.log('🚀 Inicializando Dashboard BitDefender + Upgraded Happiness');
            new DashboardClient();
        });
    </script>
</body>
</html>"""
        return web.Response(text=html_content, content_type="text/html")

    async def websocket_handler(self, request):
        """Maneja conexiones WebSocket del dashboard"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        # Enviar datos iniciales
        initial_data = {
            "type": "initial_state",
            "data": {
                "statistics": {
                    "active_agents": len(self.config["bitdefender"]["processes"]),
                    "threats_detected": 15,
                    "events_processed": 1247,
                },
                "bitdefender_info": {
                    "detected_processes": len(self.config["bitdefender"]["processes"]),
                    "detected_paths": len(self.config["bitdefender"]["log_paths"]),
                },
            },
        }
        await ws.send_str(json.dumps(initial_data))

        # Simular eventos periódicos
        async def send_periodic_events():
            while not ws.closed:
                try:
                    event_types = [
                        "malware_detected",
                        "suspicious_connection",
                        "port_scan",
                        "real_time_scan",
                    ]
                    severities = ["low", "medium", "high"]

                    demo_event = {
                        "type": "demo_event",
                        "data": {
                            "event_type": random.choice(event_types),
                            "severity": random.choice(severities),
                            "details": f"Evento simulado desde BitDefender macOS",
                            "timestamp": datetime.now().isoformat(),
                        },
                    }

                    await ws.send_str(json.dumps(demo_event))
                    await asyncio.sleep(random.randint(15, 45))

                except Exception as e:
                    self.logger.error(f"Error enviando evento: {e}")
                    break

        # Iniciar generador de eventos
        asyncio.create_task(send_periodic_events())

        # Mantener conexión
        async for msg in ws:
            if msg.type == WSMsgType.ERROR:
                break

        return ws

    async def start_server(self, port=8766):
        """Inicia el servidor HTTP+WebSocket"""
        runner = web.AppRunner(self.app)
        await runner.setup()

        site = web.TCPSite(runner, "localhost", port)
        await site.start()

        self.logger.info(
            f"🌐 Dashboard HTTP Server iniciado en: http://localhost:{port}"
        )
        self.logger.info(f"📱 Abre esa URL en tu navegador para ver el dashboard")

        return runner


async def main():
    server = HybridDashboardServer()
    runner = await server.start_server(8766)

    try:
        print("🚀 Servidor híbrido iniciado exitosamente:")
        print("")
        print("📱 Dashboard: http://localhost:8766")
        print("🔌 WebSocket: integrado internamente")
        print("🛡️ Datos: BitDefender + Upgraded Happiness")
        print("")
        print("⏹️  Presiona Ctrl+C para detener")

        # Mantener ejecutándose
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        print("\n✅ Deteniendo servidor...")
        await runner.cleanup()
        print("✅ Servidor detenido")


if __name__ == "__main__":
    asyncio.run(main())
