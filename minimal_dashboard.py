#!/usr/bin/env python3
"""
🛡️ Dashboard SCADA Minimalista - GARANTIZADO FUNCIONAMIENTO
Solo dependencias básicas, máxima compatibilidad
"""

import json
import time
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse


class SCADAHandler(BaseHTTPRequestHandler):
    """Handler HTTP para el dashboard SCADA"""

    def __init__(self, *args, **kwargs):
        # Inicializar datos compartidos si no existen
        if not hasattr(SCADAHandler, 'shared_data'):
            SCADAHandler.shared_data = {
                'events': [],
                'stats': {
                    'total_events': 0,
                    'unique_ips': set(),
                    'start_time': datetime.now()
                }
            }
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
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            print(f"❌ Error en GET {self.path}: {e}")
            self.send_error(500, f"Internal Error: {e}")

    def serve_dashboard(self):
        """Servir el dashboard HTML"""
        html = self.get_dashboard_html()
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-length', str(len(html.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def serve_health(self):
        """Servir health check"""
        health_data = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': (datetime.now() - self.shared_data['stats']['start_time']).total_seconds(),
            'total_events': self.shared_data['stats']['total_events'],
            'server_type': 'minimal_scada_dashboard'
        }
        self.send_json(health_data)

    def serve_stats(self):
        """Servir estadísticas"""
        stats = {
            'total_events': self.shared_data['stats']['total_events'],
            'unique_ips': len(self.shared_data['stats']['unique_ips']),
            'uptime_seconds': (datetime.now() - self.shared_data['stats']['start_time']).total_seconds(),
            'events_in_memory': len(self.shared_data['events'])
        }
        self.send_json(stats)

    def serve_events(self):
        """Servir eventos recientes"""
        events = self.shared_data['events'][-50:]  # Últimos 50 eventos
        self.send_json({'events': events})

    def send_json(self, data):
        """Enviar respuesta JSON"""
        json_data = json.dumps(data, indent=2)
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-length', str(len(json_data.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(json_data.encode('utf-8'))

    def get_dashboard_html(self):
        """Generar HTML del dashboard minimalista"""
        return """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCADA Dashboard Minimalista</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace;
            background: #0f0f23; color: #00ff88;
            padding: 20px; line-height: 1.6;
        }
        .header { 
            text-align: center; border-bottom: 2px solid #00ff88;
            padding: 20px 0; margin-bottom: 30px;
        }
        .header h1 { font-size: 2rem; margin-bottom: 10px; }
        .status { display: flex; justify-content: center; gap: 30px; }
        .status-item { 
            background: rgba(0,255,136,0.1); padding: 10px 20px;
            border: 1px solid #00ff88; border-radius: 5px;
        }
        .container { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }
        .panel { 
            background: rgba(0,255,136,0.05); border: 1px solid #00ff88;
            border-radius: 10px; padding: 20px;
        }
        .panel h2 { margin-bottom: 15px; color: #00ff88; }
        .event-item { 
            background: rgba(255,255,255,0.1); margin: 10px 0;
            padding: 10px; border-left: 3px solid #00ff88;
        }
        .event-time { font-size: 0.8rem; color: #aaa; }
        .event-ip { color: #00ff88; font-weight: bold; }
        .stat-item { 
            display: flex; justify-content: space-between;
            padding: 5px 0; border-bottom: 1px solid rgba(0,255,136,0.3);
        }
        .btn { 
            background: #00ff88; color: #0f0f23; padding: 10px 20px;
            border: none; border-radius: 5px; cursor: pointer;
            margin: 5px; font-weight: bold;
        }
        .btn:hover { background: #00cc66; }
        #log { 
            background: #000; color: #00ff88; padding: 15px;
            height: 200px; overflow-y: auto; font-size: 0.9rem;
            border: 1px solid #00ff88; margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SCADA Dashboard Minimalista</h1>
        <div class="status">
            <div class="status-item">
                <span id="status-indicator">🟢 ONLINE</span>
            </div>
            <div class="status-item">
                Eventos: <span id="event-counter">0</span>
            </div>
            <div class="status-item">
                Tiempo: <span id="uptime">00:00:00</span>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="panel">
            <h2>📊 Estadísticas del Sistema</h2>
            <div class="stat-item">
                <span>Total Eventos:</span>
                <span id="total-events">0</span>
            </div>
            <div class="stat-item">
                <span>IPs Únicas:</span>
                <span id="unique-ips">0</span>
            </div>
            <div class="stat-item">
                <span>Tiempo Activo:</span>
                <span id="uptime-detailed">0 segundos</span>
            </div>
            <div class="stat-item">
                <span>Estado del Sistema:</span>
                <span id="system-status">Operacional</span>
            </div>

            <h2 style="margin-top: 20px;">🔧 Controles</h2>
            <button class="btn" onclick="generateTestEvent()">Generar Evento Test</button>
            <button class="btn" onclick="clearEvents()">Limpiar Eventos</button>
            <button class="btn" onclick="refreshStats()">Actualizar Stats</button>
        </div>

        <div class="panel">
            <h2>🚨 Eventos Recientes</h2>
            <div id="events-list">
                <div class="event-item">
                    <div class="event-time">Sistema iniciado</div>
                    <div class="event-ip">Dashboard minimalista activo</div>
                </div>
            </div>
        </div>
    </div>

    <div id="log"></div>

    <script>
        class MinimalDashboard {
            constructor() {
                this.eventCounter = 0;
                this.startTime = Date.now();
                this.log('🚀 Dashboard inicializado');
                this.startPeriodicUpdates();
            }

            log(message) {
                const logEl = document.getElementById('log');
                const timestamp = new Date().toLocaleTimeString();
                logEl.innerHTML += `[${timestamp}] ${message}\\n`;
                logEl.scrollTop = logEl.scrollHeight;
            }

            async refreshStats() {
                try {
                    const response = await fetch('/api/stats');
                    const stats = await response.json();

                    document.getElementById('total-events').textContent = stats.total_events;
                    document.getElementById('unique-ips').textContent = stats.unique_ips;
                    document.getElementById('uptime-detailed').textContent = 
                        Math.floor(stats.uptime_seconds) + ' segundos';

                    this.log('📊 Estadísticas actualizadas');
                } catch (e) {
                    this.log('❌ Error actualizando estadísticas: ' + e.message);
                }
            }

            generateTestEvent() {
                this.eventCounter++;
                const event = {
                    timestamp: new Date().toLocaleTimeString(),
                    ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
                    protocol: ['HTTP', 'HTTPS', 'TCP', 'UDP'][Math.floor(Math.random() * 4)],
                    type: 'test'
                };

                this.addEventToList(event);
                document.getElementById('event-counter').textContent = this.eventCounter;
                this.log(`📡 Evento test generado: ${event.ip} (${event.protocol})`);
            }

            addEventToList(event) {
                const eventsList = document.getElementById('events-list');
                const eventDiv = document.createElement('div');
                eventDiv.className = 'event-item';
                eventDiv.innerHTML = `
                    <div class="event-time">${event.timestamp}</div>
                    <div class="event-ip">${event.ip} - ${event.protocol}</div>
                `;
                eventsList.insertBefore(eventDiv, eventsList.firstChild);

                // Mantener solo los últimos 20 eventos
                while (eventsList.children.length > 20) {
                    eventsList.removeChild(eventsList.lastChild);
                }
            }

            clearEvents() {
                document.getElementById('events-list').innerHTML = `
                    <div class="event-item">
                        <div class="event-time">Eventos limpiados</div>
                        <div class="event-ip">Lista de eventos reiniciada</div>
                    </div>
                `;
                this.eventCounter = 0;
                document.getElementById('event-counter').textContent = this.eventCounter;
                this.log('🧹 Eventos limpiados');
            }

            updateUptime() {
                const uptimeSeconds = Math.floor((Date.now() - this.startTime) / 1000);
                const hours = Math.floor(uptimeSeconds / 3600);
                const minutes = Math.floor((uptimeSeconds % 3600) / 60);
                const seconds = uptimeSeconds % 60;

                const uptime = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                document.getElementById('uptime').textContent = uptime;
            }

            startPeriodicUpdates() {
                // Actualizar uptime cada segundo
                setInterval(() => this.updateUptime(), 1000);

                // Actualizar estadísticas cada 10 segundos
                setInterval(() => this.refreshStats(), 10000);

                // Generar evento automático cada 30 segundos
                setInterval(() => {
                    if (Math.random() > 0.7) { // 30% probabilidad
                        this.generateTestEvent();
                    }
                }, 30000);
            }
        }

        // Funciones globales para los botones
        let dashboard;

        function generateTestEvent() {
            dashboard.generateTestEvent();
        }

        function clearEvents() {
            dashboard.clearEvents();
        }

        function refreshStats() {
            dashboard.refreshStats();
        }

        // Inicializar cuando la página cargue
        document.addEventListener('DOMContentLoaded', function() {
            dashboard = new MinimalDashboard();
            dashboard.log('✅ Dashboard completamente cargado');
        });
    </script>
</body>
</html>"""

    def log_message(self, format, *args):
        """Silenciar logs HTTP por defecto"""
        pass  # Comentar esta línea para ver logs HTTP


class EventSimulator:
    """Simulador de eventos para testing"""

    def __init__(self, handler_class):
        self.handler_class = handler_class
        self.running = False

    def start(self):
        """Iniciar simulación de eventos"""
        self.running = True
        thread = threading.Thread(target=self._simulate_events, daemon=True)
        thread.start()
        print("🎭 Simulador de eventos iniciado")

    def _simulate_events(self):
        """Simular eventos periódicamente"""
        import random

        while self.running:
            try:
                # Generar evento simulado
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': f"192.168.1.{random.randint(1, 254)}",
                    'destination_ip': f"8.8.{random.randint(8, 8)}.8",
                    'protocol': random.choice(['HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS']),
                    'type': 'simulated'
                }

                # Añadir a datos compartidos
                if hasattr(self.handler_class, 'shared_data'):
                    self.handler_class.shared_data['events'].append(event)
                    self.handler_class.shared_data['stats']['total_events'] += 1
                    self.handler_class.shared_data['stats']['unique_ips'].add(event['source_ip'])

                    # Mantener solo los últimos 100 eventos
                    if len(self.handler_class.shared_data['events']) > 100:
                        self.handler_class.shared_data['events'] = self.handler_class.shared_data['events'][-100:]

                # Esperar entre 5-15 segundos para el siguiente evento
                time.sleep(random.randint(5, 15))

            except Exception as e:
                print(f"❌ Error en simulador: {e}")
                time.sleep(5)


def main():
    """Función principal"""
    print("🛡️ DASHBOARD SCADA MINIMALISTA")
    print("=" * 40)
    print("🎯 Objetivo: Máxima compatibilidad y estabilidad")
    print("📦 Dependencias: Solo biblioteca estándar de Python")
    print("")

    # Configuración
    host = '127.0.0.1'
    port = 8000

    try:
        # Verificar que el puerto esté libre
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            print(f"⚠️ Puerto {port} está ocupado, probando puerto 8001...")
            port = 8001

        # Crear servidor HTTP
        server = HTTPServer((host, port), SCADAHandler)

        print(f"🚀 Servidor iniciado en http://{host}:{port}")
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"💊 Health: http://{host}:{port}/health")
        print(f"📈 Stats: http://{host}:{port}/api/stats")
        print("")
        print("✅ FUNCIONALIDADES DISPONIBLES:")
        print("   • Dashboard web completo")
        print("   • API REST para estadísticas")
        print("   • Simulador de eventos automático")
        print("   • Health check endpoint")
        print("   • Generación manual de eventos test")
        print("")
        print("🛑 Presiona Ctrl+C para detener")

        # Iniciar simulador de eventos
        simulator = EventSimulator(SCADAHandler)
        simulator.start()

        # Ejecutar servidor
        server.serve_forever()

    except KeyboardInterrupt:
        print("\n🛑 Servidor detenido por usuario")
        simulator.running = False
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()