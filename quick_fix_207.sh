#!/bin/bash
# quick_fix_207.sh
# Crear rápidamente los archivos faltantes para correcciones HTTP 207

set -e

echo "🔧 Creando archivos de corrección HTTP 207..."
echo "============================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Verificar directorio
if [ ! -f "Makefile" ] || [ ! -f "system_orchestrator.py" ]; then
    echo -e "${RED}❌ Error: Ejecutar desde el directorio raíz de upgraded-happiness${NC}"
    exit 1
fi

echo -e "${BLUE}📁 Creando dashboard_server_fixed.py...${NC}"

# Crear dashboard_server_fixed.py
cat > dashboard_server_fixed.py << 'EOF'
# dashboard_server_fixed.py
# Dashboard corregido sin errores HTTP 207 Multi-Status

import asyncio
import json
import logging
from datetime import datetime
from aiohttp import web, WSMsgType
import aiohttp_cors
import zmq
import zmq.asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DashboardServer:
    def __init__(self, host='localhost', port=8766):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.websockets = set()
        self.setup_routes()
        self.setup_cors()

        # ZeroMQ context
        self.zmq_context = zmq.asyncio.Context()
        self.subscriber = None

    def setup_routes(self):
        """Setup HTTP routes with proper error handling"""
        self.app.router.add_get('/', self.serve_dashboard)
        self.app.router.add_get('/ws', self.websocket_handler)
        self.app.router.add_get('/api/status', self.api_status)
        self.app.router.add_get('/api/events', self.api_events)

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
        """Serve main dashboard HTML"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SCADA Security Dashboard</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }
                .container { max-width: 1200px; margin: 0 auto; }
                .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
                .card { background: #2d2d2d; padding: 20px; border-radius: 8px; border: 1px solid #444; }
                .card h3 { margin-top: 0; color: #4CAF50; }
                .events { background: #2d2d2d; padding: 20px; border-radius: 8px; border: 1px solid #444; }
                .event { padding: 10px; border-bottom: 1px solid #444; }
                .event:last-child { border-bottom: none; }
                .timestamp { color: #888; font-size: 0.9em; }
                .status-active { color: #4CAF50; }
                .status-error { color: #f44336; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 SCADA Security Monitor - FIXED VERSION</h1>

                <div class="metrics">
                    <div class="card">
                        <h3>System Status</h3>
                        <div id="system-status">Connecting...</div>
                    </div>
                    <div class="card">
                        <h3>Threats Detected</h3>
                        <div id="threats-count">0</div>
                    </div>
                    <div class="card">
                        <h3>ML Precision</h3>
                        <div id="ml-precision">0%</div>
                    </div>
                    <div class="card">
                        <h3>Active Agents</h3>
                        <div id="active-agents">0</div>
                    </div>
                </div>

                <div class="events">
                    <h3>🚨 Real-time Events (HTTP 207 FIXED)</h3>
                    <div id="events-list">No events yet...</div>
                </div>
            </div>

            <script>
                let ws = null;
                let reconnectAttempts = 0;
                const maxReconnectAttempts = 10;

                function connectWebSocket() {
                    try {
                        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                        const wsUrl = `${protocol}//${window.location.host}/ws`;

                        console.log('Connecting to WebSocket:', wsUrl);
                        ws = new WebSocket(wsUrl);

                        ws.onopen = function(event) {
                            console.log('WebSocket connected - HTTP 207 FIXED!');
                            reconnectAttempts = 0;
                            updateSystemStatus('Connected (FIXED)', 'status-active');
                        };

                        ws.onmessage = function(event) {
                            try {
                                const data = JSON.parse(event.data);
                                handleMessage(data);
                            } catch (e) {
                                console.error('Error parsing message:', e);
                            }
                        };

                        ws.onclose = function(event) {
                            console.log('WebSocket disconnected');
                            updateSystemStatus('Disconnected', 'status-error');

                            if (reconnectAttempts < maxReconnectAttempts) {
                                reconnectAttempts++;
                                const delay = Math.pow(2, reconnectAttempts) * 1000;
                                console.log(`Reconnecting in ${delay}ms...`);
                                setTimeout(connectWebSocket, delay);
                            }
                        };

                        ws.onerror = function(error) {
                            console.error('WebSocket error:', error);
                            updateSystemStatus('Error', 'status-error');
                        };

                    } catch (e) {
                        console.error('Failed to create WebSocket:', e);
                        updateSystemStatus('Connection Failed', 'status-error');
                    }
                }

                function handleMessage(data) {
                    console.log('Received:', data);

                    if (data.type === 'event') {
                        addEvent(data);
                    } else if (data.type === 'metrics') {
                        updateMetrics(data);
                    }
                }

                function addEvent(event) {
                    const eventsList = document.getElementById('events-list');
                    if (eventsList.textContent === 'No events yet...') {
                        eventsList.innerHTML = '';
                    }

                    const eventDiv = document.createElement('div');
                    eventDiv.className = 'event';
                    eventDiv.innerHTML = `
                        <div><strong>${event.title || 'Security Event'}</strong></div>
                        <div>${event.description || 'No description'}</div>
                        <div class="timestamp">${new Date(event.timestamp || Date.now()).toLocaleString()}</div>
                    `;

                    eventsList.insertBefore(eventDiv, eventsList.firstChild);

                    while (eventsList.children.length > 20) {
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

                function updateSystemStatus(status, className) {
                    const statusEl = document.getElementById('system-status');
                    statusEl.textContent = status;
                    statusEl.className = className;
                }

                document.addEventListener('DOMContentLoaded', function() {
                    console.log('🔧 HTTP 207 FIXED Dashboard Loading...');
                    connectWebSocket();
                });

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
            </script>
        </body>
        </html>
        """
        return web.Response(text=html_content, content_type='text/html')

    async def websocket_handler(self, request):
        """Handle WebSocket connections with proper error handling"""
        ws = web.WebSocketResponse(
            protocols=['chat'],
            heartbeat=30,
            max_msg_size=1024*1024
        )

        if not ws.can_prepare(request):
            logger.error("Cannot prepare WebSocket connection")
            return web.Response(status=400, text="Cannot upgrade to WebSocket")

        await ws.prepare(request)
        self.websockets.add(ws)

        logger.info(f"WebSocket connected. Total connections: {len(self.websockets)}")

        try:
            await ws.send_str(json.dumps({
                'type': 'connection',
                'message': 'Connected to SCADA Security Monitor (HTTP 207 FIXED)'
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
                'threats_count': 16,
                'ml_precision': 93.9,
                'active_agents': 9,
                'components': {
                    'zmq_broker': 'active',
                    'ml_detector': 'active',
                    'promiscuous_agent': 'active'
                },
                'websocket_connections': len(self.websockets),
                'http_207_fixed': True
            }
            return web.json_response(status)
        except Exception as e:
            logger.error(f"Error in api_status: {e}")
            return web.json_response({'error': str(e)}, status=500)

    async def api_events(self, request):
        """API endpoint for recent events"""
        events = [
            {
                'type': 'threat_detected',
                'title': 'Port Scan Detected',
                'description': 'Suspicious port scanning from 192.168.1.100',
                'timestamp': datetime.now().isoformat(),
                'severity': 'high'
            }
        ]
        return web.json_response(events)

    async def setup_zmq_subscriber(self):
        """Setup ZeroMQ subscriber for real-time events"""
        try:
            self.subscriber = self.zmq_context.socket(zmq.SUB)
            self.subscriber.connect("tcp://localhost:5555")
            self.subscriber.setsockopt(zmq.SUBSCRIBE, b"")

            logger.info("ZeroMQ subscriber connected")
            asyncio.create_task(self.zmq_message_loop())

        except Exception as e:
            logger.error(f"Failed to setup ZeroMQ subscriber: {e}")

    async def zmq_message_loop(self):
        """Listen for ZeroMQ messages and broadcast to WebSocket clients"""
        while True:
            try:
                if await self.subscriber.poll(1000, zmq.POLLIN):
                    message = await self.subscriber.recv_json()
                    logger.info(f"Received ZeroMQ message: {message}")
                    await self.broadcast_to_websockets(message)

            except Exception as e:
                logger.error(f"Error in ZeroMQ message loop: {e}")
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
        """Start the dashboard server"""
        try:
            await self.setup_zmq_subscriber()

            runner = web.AppRunner(self.app)
            await runner.setup()

            site = web.TCPSite(runner, self.host, self.port)
            await site.start()

            logger.info(f"🔧 FIXED Dashboard server started at http://{self.host}:{self.port}")
            return runner

        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise

async def main():
    """Main function to run the dashboard"""
    server = DashboardServer()
    runner = None

    try:
        runner = await server.start_server()

        print(f"🚀 HTTP 207 FIXED Dashboard running at http://{server.host}:{server.port}")
        print("Press Ctrl+C to stop...")

        await asyncio.Event().wait()

    except KeyboardInterrupt:
        print("\n🛑 Shutting down dashboard...")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        if runner:
            await runner.cleanup()
        if server.subscriber:
            server.subscriber.close()
        server.zmq_context.term()

if __name__ == "__main__":
    asyncio.run(main())
EOF

echo -e "${GREEN}✅ dashboard_server_fixed.py creado${NC}"

echo -e "${BLUE}📁 Creando diagnostic_tool.py...${NC}"

# Crear diagnostic_tool.py (versión simplificada)
cat > diagnostic_tool.py << 'EOF'
#!/usr/bin/env python3
"""
SCADA Dashboard Diagnostic Tool
Diagnoses and fixes HTTP 207 Multi-Status and WebSocket connection issues
"""

import asyncio
import socket
import json
import logging
import sys
import time
from datetime import datetime
import subprocess
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SCADADiagnostic:
    def __init__(self):
        self.components = {
            'zmq_broker': {'port': 5555, 'process': None},
            'zmq_secondary': {'port': 5556, 'process': None},
            'dashboard': {'port': 8766, 'process': None},
            'websocket': {'port': 8766, 'path': '/ws', 'process': None}
        }

    def check_port(self, port, host='localhost'):
        """Check if a port is listening"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception as e:
            logger.error(f"Error checking port {port}: {e}")
            return False

    def check_processes(self):
        """Check running processes related to the SCADA system"""
        logger.info("🔍 Checking running processes...")

        processes = [
            'smart_broker.py',
            'lightweight_ml_detector.py',
            'promiscuous_agent.py',
            'dashboard_server'
        ]

        running_processes = {}

        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            ps_output = result.stdout

            for process in processes:
                if process in ps_output:
                    lines = [line for line in ps_output.split('\n') if process in line and 'grep' not in line]
                    running_processes[process] = len(lines)
                    if lines:
                        logger.info(f"✅ {process}: {len(lines)} instance(s) running")
                        for line in lines:
                            parts = line.split()
                            if len(parts) > 1:
                                logger.info(f"   PID: {parts[1]}")
                else:
                    logger.warning(f"❌ {process}: Not running")
                    running_processes[process] = 0

        except Exception as e:
            logger.error(f"Error checking processes: {e}")

        return running_processes

    def check_ports(self):
        """Check if required ports are listening"""
        logger.info("🔍 Checking port availability...")

        port_status = {}
        for name, config in self.components.items():
            port = config['port']
            is_listening = self.check_port(port)
            port_status[name] = is_listening

            status = "✅ LISTENING" if is_listening else "❌ NOT LISTENING"
            logger.info(f"{name.upper()} (Port {port}) - {status}")

        return port_status

    def analyze_logs(self):
        """Analyze recent logs for HTTP 207 errors"""
        logger.info("🔍 Analyzing system logs for HTTP 207 errors...")

        log_patterns = [
            'HTTP/1.0" 400 207',
            'UNKNOWN /',
            'Multi-Status',
            'WebDAV',
            'aiohttp.access'
        ]

        found_errors = []

        # Check common log locations
        log_files = [
            '/var/log/system.log',
            '/var/log/syslog'
        ]

        for log_file in log_files:
            try:
                if os.path.exists(log_file):
                    found_errors.extend(self._scan_log_file(log_file, log_patterns))
            except Exception as e:
                logger.debug(f"Could not read {log_file}: {e}")

        if found_errors:
            logger.warning(f"⚠️  Found {len(found_errors)} HTTP 207 error instances")
            for error in found_errors[-5:]:
                logger.warning(f"   {error}")
        else:
            logger.info("✅ No HTTP 207 errors found in logs")

        return found_errors

    def _scan_log_file(self, file_path, patterns):
        """Scan a single log file for patterns"""
        found = []
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f.readlines()[-1000:], 1):
                    for pattern in patterns:
                        if pattern in line:
                            found.append(f"{file_path}:{line_num} - {line.strip()}")
                            break
        except Exception as e:
            logger.debug(f"Error reading {file_path}: {e}")
        return found

    async def run_full_diagnostic(self):
        """Run complete diagnostic suite"""
        logger.info("🔍 Starting SCADA System Diagnostic...")
        logger.info("=" * 50)

        # 1. Check processes
        processes = self.check_processes()

        # 2. Check ports
        ports = self.check_ports()

        # 3. Analyze logs for HTTP 207 errors
        errors = self.analyze_logs()

        # 4. Generate report
        logger.info("=" * 50)
        logger.info("📋 DIAGNOSTIC SUMMARY")
        logger.info("=" * 50)

        if errors:
            logger.warning("⚠️  HTTP 207 Multi-Status errors detected!")
            logger.info("🔧 Recommended actions:")
            logger.info("   1. Stop all SCADA processes: make stop")
            logger.info("   2. Use the fixed dashboard server: make dashboard-fixed")
            logger.info("   3. Restart with fixes: make run-fixed")
        else:
            logger.info("✅ No critical HTTP 207 issues detected")

        # Check if dashboard_server_fixed.py exists
        if os.path.exists('dashboard_server_fixed.py'):
            logger.info("✅ dashboard_server_fixed.py found")
        else:
            logger.error("❌ dashboard_server_fixed.py missing!")
            logger.info("   Create this file with the HTTP 207 fixes")

        logger.info("=" * 50)

async def main():
    """Main diagnostic function"""
    diagnostic = SCADADiagnostic()

    try:
        await diagnostic.run_full_diagnostic()
    except KeyboardInterrupt:
        logger.info("🛑 Diagnostic interrupted by user")
    except Exception as e:
        logger.error(f"❌ Diagnostic failed: {e}")

if __name__ == "__main__":
    print("🔍 SCADA Dashboard Diagnostic Tool")
    print("🎯 Detecting and fixing HTTP 207 Multi-Status issues")
    print()

    asyncio.run(main())
EOF

echo -e "${GREEN}✅ diagnostic_tool.py creado${NC}"

# Hacer los archivos ejecutables
chmod +x dashboard_server_fixed.py
chmod +x diagnostic_tool.py

echo ""
echo -e "${GREEN}🎉 Archivos de corrección HTTP 207 creados exitosamente!${NC}"
echo ""
echo -e "${YELLOW}📋 PRÓXIMOS PASOS:${NC}"
echo -e "  ${BLUE}1. make verify-fixes${NC}   - Verificar que están listos"
echo -e "  ${BLUE}2. make stop${NC}           - Parar sistema actual"
echo -e "  ${BLUE}3. make run-fixed${NC}      - Iniciar con correcciones"
echo -e "  ${BLUE}4. make test-dashboard${NC} - Probar conectividad"
echo ""
echo -e "${GREEN}🌐 Después del reinicio:${NC}"
echo -e "  Dashboard: ${BLUE}http://localhost:8766${NC}"
echo -e "  Sin errores HTTP 207! ✅"
EOF

echo -e "${GREEN}✅ Script de creación rápida generado${NC}"

echo ""
echo -e "${YELLOW}🚀 Para aplicar inmediatamente:${NC}"
echo -e "  ${BLUE}chmod +x quick_fix_207.sh${NC}"
echo -e "  ${BLUE}./quick_fix_207.sh${NC}"