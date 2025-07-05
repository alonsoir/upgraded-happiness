#!/usr/bin/env python3
"""
Dashboard Debug Version - Para identificar problemas de WebSocket
"""

import asyncio
import json
import logging
import sys
import os
from datetime import datetime
from aiohttp import web
import zmq
import zmq.asyncio

# Configurar logging más detallado
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Importar protobuf
sys.path.insert(0, os.getcwd())

try:
    from src.protocols.protobuf import network_event_pb2

    print("✅ Protobuf importado exitosamente")
    HAS_PROTOBUF = True
except ImportError as e:
    print(f"❌ Error importando protobuf: {e}")
    HAS_PROTOBUF = False


class DebugDashboard:
    def __init__(self):
        self.app = web.Application()
        self.websockets = set()
        self.events_sent = 0
        self.events_received = 0

        # ZeroMQ
        self.context = zmq.asyncio.Context()
        self.subscriber = None
        self.is_running = False

        self.setup_routes()

    def setup_routes(self):
        self.app.router.add_get('/', self.serve_debug_page)
        self.app.router.add_get('/ws', self.websocket_handler)
        self.app.router.add_get('/debug', self.debug_info)

    async def serve_debug_page(self, request):
        """Página con debug intensivo"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard Debug - Protobuf Events</title>
            <style>
                body { 
                    font-family: Arial; 
                    background: #000; 
                    color: #0f0; 
                    margin: 20px;
                }
                .debug { 
                    border: 1px solid #0f0; 
                    padding: 15px; 
                    margin: 10px 0; 
                    background: #001100;
                }
                .error { color: #f00; }
                .success { color: #0f0; }
                .warning { color: #ff0; }
                #events { 
                    height: 400px; 
                    overflow-y: scroll; 
                    border: 1px solid #0f0; 
                    padding: 10px;
                    background: #001100;
                }
                .event-item {
                    border-bottom: 1px solid #333;
                    padding: 5px 0;
                    font-size: 12px;
                }
            </style>
        </head>
        <body>
            <h1>🔍 Dashboard Debug - Protobuf Stream</h1>

            <div class="debug">
                <h3>📊 Estadísticas en Tiempo Real</h3>
                <p>Estado WebSocket: <span id="ws-status" class="error">Desconectado</span></p>
                <p>Eventos recibidos: <span id="events-count">0</span></p>
                <p>Errores: <span id="errors-count">0</span></p>
                <p>Último evento: <span id="last-event">Ninguno</span></p>
                <button onclick="testConnection()">🔄 Test Conexión</button>
                <button onclick="clearLog()">🗑️ Limpiar Log</button>
            </div>

            <div class="debug">
                <h3>📡 Log de Eventos WebSocket</h3>
                <div id="events"></div>
            </div>

            <div class="debug">
                <h3>🛠️ Debug Console</h3>
                <div id="console"></div>
            </div>

            <script>
                let ws = null;
                let eventsReceived = 0;
                let errorsCount = 0;

                function log(message, type = 'info') {
                    const console = document.getElementById('console');
                    const time = new Date().toLocaleTimeString();
                    const className = type === 'error' ? 'error' : type === 'success' ? 'success' : 'warning';
                    console.innerHTML += `<div class="${className}">[${time}] ${message}</div>`;
                    console.scrollTop = console.scrollHeight;
                }

                function updateStats() {
                    document.getElementById('events-count').textContent = eventsReceived;
                    document.getElementById('errors-count').textContent = errorsCount;
                }

                function connectWebSocket() {
                    log('🔄 Intentando conectar WebSocket...', 'warning');

                    const wsUrl = `ws://${window.location.host}/ws`;
                    ws = new WebSocket(wsUrl);

                    ws.onopen = function() {
                        log('✅ WebSocket conectado exitosamente', 'success');
                        document.getElementById('ws-status').textContent = 'Conectado';
                        document.getElementById('ws-status').className = 'success';
                    };

                    ws.onmessage = function(event) {
                        eventsReceived++;
                        log(`📨 Evento recibido #${eventsReceived}: ${event.data.substring(0, 100)}...`, 'success');

                        try {
                            const data = JSON.parse(event.data);
                            log(`🔍 Tipo: ${data.type}, Título: ${data.title}`, 'info');

                            // Añadir a la lista de eventos
                            const eventsDiv = document.getElementById('events');
                            const eventItem = document.createElement('div');
                            eventItem.className = 'event-item';
                            eventItem.innerHTML = `
                                <strong>${data.title || 'Unknown'}</strong> - 
                                IP: ${data.ip_address || 'N/A'} - 
                                Protocol: ${data.protocol_stack || 'N/A'} - 
                                Time: ${new Date(data.timestamp).toLocaleTimeString()}
                            `;
                            eventsDiv.insertBefore(eventItem, eventsDiv.firstChild);

                            // Mantener solo últimos 50 eventos
                            while (eventsDiv.children.length > 50) {
                                eventsDiv.removeChild(eventsDiv.lastChild);
                            }

                            document.getElementById('last-event').textContent = data.title || 'Unknown';

                        } catch (e) {
                            errorsCount++;
                            log(`❌ Error parseando evento: ${e.message}`, 'error');
                        }

                        updateStats();
                    };

                    ws.onclose = function() {
                        log('❌ WebSocket desconectado', 'error');
                        document.getElementById('ws-status').textContent = 'Desconectado';
                        document.getElementById('ws-status').className = 'error';

                        // Reconectar en 5 segundos
                        setTimeout(() => {
                            log('🔄 Reintentando conexión...', 'warning');
                            connectWebSocket();
                        }, 5000);
                    };

                    ws.onerror = function(error) {
                        errorsCount++;
                        log(`❌ Error WebSocket: ${error}`, 'error');
                        updateStats();
                    };
                }

                function testConnection() {
                    log('🧪 Ejecutando test de conexión...', 'warning');

                    fetch('/debug')
                        .then(response => response.json())
                        .then(data => {
                            log(`📊 Estado servidor: ${JSON.stringify(data)}`, 'info');
                        })
                        .catch(error => {
                            errorsCount++;
                            log(`❌ Error test: ${error.message}`, 'error');
                            updateStats();
                        });
                }

                function clearLog() {
                    document.getElementById('console').innerHTML = '';
                    document.getElementById('events').innerHTML = '';
                    eventsReceived = 0;
                    errorsCount = 0;
                    updateStats();
                    log('🗑️ Log limpiado', 'success');
                }

                // Inicializar cuando se carga la página
                document.addEventListener('DOMContentLoaded', function() {
                    log('🚀 Página cargada, iniciando dashboard debug...', 'success');
                    connectWebSocket();

                    // Test automático cada 10 segundos
                    setInterval(testConnection, 10000);
                });
            </script>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')

    async def websocket_handler(self, request):
        """WebSocket con logging detallado"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        self.websockets.add(ws)
        logger.info(f"✅ Cliente WebSocket conectado. Total: {len(self.websockets)}")

        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    logger.debug(f"📨 Mensaje recibido: {msg.data}")
                elif msg.type in (web.WSMsgType.ERROR, web.WSMsgType.CLOSE):
                    break
        except Exception as e:
            logger.error(f"❌ Error WebSocket: {e}")
        finally:
            self.websockets.discard(ws)
            logger.info(f"🔌 Cliente desconectado. Restantes: {len(self.websockets)}")

        return ws

    async def debug_info(self, request):
        """Información de debug"""
        return web.json_response({
            'timestamp': datetime.now().isoformat(),
            'events_received_zmq': self.events_received,
            'events_sent_websocket': self.events_sent,
            'websocket_connections': len(self.websockets),
            'zmq_connected': self.subscriber is not None,
            'protobuf_available': HAS_PROTOBUF,
            'is_running': self.is_running
        })

    async def setup_zmq_subscriber(self):
        """Configurar ZeroMQ con debug"""
        try:
            self.subscriber = self.context.socket(zmq.SUB)
            self.subscriber.connect("tcp://localhost:5560")
            self.subscriber.setsockopt(zmq.SUBSCRIBE, b"")

            logger.info("✅ ZeroMQ subscriber configurado en puerto 5560")

            # Iniciar loop de mensajes
            asyncio.create_task(self.zmq_message_loop())
            return True

        except Exception as e:
            logger.error(f"❌ Error configurando ZeroMQ: {e}")
            return False

    async def zmq_message_loop(self):
        """Loop de mensajes con debug intensivo"""
        logger.info("🔄 Iniciando loop ZeroMQ debug...")

        while self.is_running:
            try:
                if await self.subscriber.poll(1000, zmq.POLLIN):
                    raw_message = await self.subscriber.recv()
                    self.events_received += 1

                    logger.debug(f"📨 Mensaje ZeroMQ #{self.events_received} ({len(raw_message)} bytes)")

                    if HAS_PROTOBUF:
                        try:
                            # Deserializar protobuf
                            event = network_event_pb2.NetworkEvent()
                            event.ParseFromString(raw_message)

                            # Crear evento simplificado para debug
                            debug_event = {
                                'type': 'debug_event',
                                'id': f"debug_{self.events_received}",
                                'title': f"Debug Event #{self.events_received}",
                                'ip_address': event.target_ip or 'unknown',
                                'source_ip': event.source_ip or 'unknown',
                                'protocol_stack': 'Debug Protocol',
                                'timestamp': datetime.now().isoformat(),
                                'raw_size': len(raw_message)
                            }

                            # Enviar a WebSockets
                            await self.broadcast_to_websockets(debug_event)

                            logger.info(f"📡 Evento #{self.events_received} enviado: {event.target_ip}")

                        except Exception as e:
                            logger.error(f"❌ Error procesando protobuf: {e}")

            except Exception as e:
                logger.error(f"❌ Error en loop ZeroMQ: {e}")
                await asyncio.sleep(1)

    async def broadcast_to_websockets(self, event):
        """Enviar evento a WebSockets con debug"""
        if not self.websockets:
            logger.warning("⚠️ No hay WebSockets conectados")
            return

        message = json.dumps(event)
        self.events_sent += 1

        logger.debug(f"📤 Enviando evento #{self.events_sent} a {len(self.websockets)} clientes")

        for ws in self.websockets.copy():
            try:
                if ws.closed:
                    self.websockets.discard(ws)
                    continue
                await ws.send_str(message)
                logger.debug(f"✅ Evento enviado a cliente WebSocket")
            except Exception as e:
                logger.error(f"❌ Error enviando a WebSocket: {e}")
                self.websockets.discard(ws)


async def main():
    """Función principal debug"""
    dashboard = DebugDashboard()
    dashboard.is_running = True

    # Configurar ZeroMQ
    zmq_ok = await dashboard.setup_zmq_subscriber()

    # Iniciar servidor
    runner = web.AppRunner(dashboard.app)
    await runner.setup()

    site = web.TCPSite(runner, 'localhost', 8771)
    await site.start()

    print(f"""
🔍 DEBUG DASHBOARD INICIADO
🌐 URL: http://localhost:8771
📊 Estado ZeroMQ: {'✅ Conectado' if zmq_ok else '❌ Error'}
📡 Protobuf: {'✅ Disponible' if HAS_PROTOBUF else '❌ No disponible'}

💡 Este dashboard muestra EXACTAMENTE qué está pasando:
   • Eventos recibidos de ZeroMQ
   • Eventos enviados por WebSocket  
   • Errores en tiempo real
   • Estado de conexiones

Presiona Ctrl+C para detener...
    """)

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        print("\n🛑 Deteniendo debug dashboard...")
    finally:
        dashboard.is_running = False
        if dashboard.subscriber:
            dashboard.subscriber.close()
        dashboard.context.term()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())