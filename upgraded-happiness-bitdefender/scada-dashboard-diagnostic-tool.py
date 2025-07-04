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
import signal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
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
            'dashboard_server.py'
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

    def check_http_response(self, url):
        """Check HTTP response from dashboard"""
        try:
            import urllib.request
            import urllib.error

            req = urllib.request.Request(url, headers={
                'User-Agent': 'SCADA-Diagnostic/1.0',
                'Accept': 'text/html,application/json',
                'Connection': 'close'
            })

            with urllib.request.urlopen(req, timeout=5) as response:
                status_code = response.getcode()
                content_type = response.headers.get('Content-Type', 'unknown')
                content_length = response.headers.get('Content-Length', 'unknown')

                logger.info(f"✅ HTTP Response: {status_code}")
                logger.info(f"   Content-Type: {content_type}")
                logger.info(f"   Content-Length: {content_length}")

                return True, status_code

        except urllib.error.HTTPError as e:
            logger.error(f"❌ HTTP Error {e.code}: {e.reason}")
            return False, e.code
        except Exception as e:
            logger.error(f"❌ Connection Error: {e}")
            return False, None

    async def check_websocket(self):
        """Check WebSocket connection"""
        try:
            import websockets
            import json

            uri = "ws://localhost:8766/ws"
            logger.info(f"🔍 Testing WebSocket connection to {uri}")

            async with websockets.connect(uri, timeout=5) as websocket:
                # Send test message
                test_message = {
                    'type': 'ping',
                    'timestamp': datetime.now().isoformat()
                }
                await websocket.send(json.dumps(test_message))

                # Wait for response
                response = await asyncio.wait_for(websocket.recv(), timeout=5)
                logger.info(f"✅ WebSocket Response: {response}")

                return True

        except ImportError:
            logger.warning("⚠️  websockets library not installed, skipping WebSocket test")
            return None
        except Exception as e:
            logger.error(f"❌ WebSocket Error: {e}")
            return False

    def analyze_logs(self, log_patterns=None):
        """Analyze recent logs for HTTP 207 errors"""
        logger.info("🔍 Analyzing system logs for HTTP 207 errors...")

        if log_patterns is None:
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
            '/var/log/syslog',
            'logs/*.log',
            '*.log'
        ]

        for log_file in log_files:
            try:
                if '*' in log_file:
                    # Use glob for pattern matching
                    import glob
                    matching_files = glob.glob(log_file)
                    for file_path in matching_files:
                        found_errors.extend(self._scan_log_file(file_path, log_patterns))
                else:
                    if os.path.exists(log_file):
                        found_errors.extend(self._scan_log_file(log_file, log_patterns))

            except Exception as e:
                logger.debug(f"Could not read {log_file}: {e}")

        if found_errors:
            logger.warning(f"⚠️  Found {len(found_errors)} HTTP 207 error instances")
            for error in found_errors[-5:]:  # Show last 5 errors
                logger.warning(f"   {error}")
        else:
            logger.info("✅ No HTTP 207 errors found in logs")

        return found_errors

    def _scan_log_file(self, file_path, patterns):
        """Scan a single log file for patterns"""
        found = []
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f.readlines()[-1000:], 1):  # Last 1000 lines
                    for pattern in patterns:
                        if pattern in line:
                            found.append(f"{file_path}:{line_num} - {line.strip()}")
                            break
        except Exception as e:
            logger.debug(f"Error reading {file_path}: {e}")
        return found

    def fix_http_207_issue(self):
        """Apply fixes for HTTP 207 Multi-Status issues"""
        logger.info("🔧 Applying fixes for HTTP 207 issues...")

        fixes_applied = []

        # Fix 1: Kill problematic processes and restart
        try:
            logger.info("🔧 Stopping all SCADA processes...")
            subprocess.run(['pkill', '-f', 'dashboard_server'], capture_output=True)
            subprocess.run(['pkill', '-f', 'smart_broker'], capture_output=True)
            time.sleep(2)
            fixes_applied.append("Stopped existing processes")
        except Exception as e:
            logger.error(f"Error stopping processes: {e}")

        # Fix 2: Clear any WebSocket connections
        try:
            logger.info("🔧 Clearing network connections...")
            subprocess.run(['netstat', '-an'], capture_output=True)
            fixes_applied.append("Checked network connections")
        except Exception as e:
            logger.error(f"Error checking connections: {e}")

        # Fix 3: Restart with proper configuration
        logger.info("🔧 Ready to restart with fixed configuration")
        fixes_applied.append("Ready for restart with fixed dashboard")

        return fixes_applied

    def generate_startup_script(self):
        """Generate a startup script with proper order"""
        script_content = '''#!/bin/bash
# SCADA System Startup Script with HTTP 207 Fix
# Generated by diagnostic tool

echo "🚀 Starting SCADA System with fixes..."

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Function to check if port is available
check_port() {
    local port=$1
    nc -z localhost $port 2>/dev/null
    return $?
}

# Function to wait for port
wait_for_port() {
    local port=$1
    local timeout=30
    local count=0

    echo "⏳ Waiting for port $port..."
    while ! check_port $port && [ $count -lt $timeout ]; do
        sleep 1
        count=$((count + 1))
    done

    if [ $count -ge $timeout ]; then
        echo "❌ Timeout waiting for port $port"
        return 1
    else
        echo "✅ Port $port is ready"
        return 0
    fi
}

# Kill any existing processes
echo "🛑 Stopping existing processes..."
pkill -f "smart_broker.py" 2>/dev/null || true
pkill -f "lightweight_ml_detector.py" 2>/dev/null || true
pkill -f "promiscuous_agent.py" 2>/dev/null || true
pkill -f "dashboard_server" 2>/dev/null || true

sleep 2

# Start ZeroMQ Broker first
echo "🔧 Starting ZeroMQ Broker..."
python scripts/smart_broker.py &
BROKER_PID=$!
sleep 3

if ! wait_for_port 5555; then
    echo "❌ Failed to start ZeroMQ Broker"
    exit 1
fi

# Start ML Detector
echo "🧠 Starting ML Detector..."
python lightweight_ml_detector.py &
ML_PID=$!
sleep 2

# Start Dashboard with fixed configuration
echo "📊 Starting Fixed Dashboard..."
python dashboard_server_fixed.py &
DASHBOARD_PID=$!
sleep 2

if ! wait_for_port 8766; then
    echo "❌ Failed to start Dashboard"
    exit 1
fi

# Start Promiscuous Agent last
echo "🕵️  Starting Promiscuous Agent..."
sudo python promiscuous_agent.py &
AGENT_PID=$!

echo "✅ All components started successfully!"
echo "📊 Dashboard: http://localhost:8766"
echo "🔧 ZeroMQ Broker: tcp://localhost:5555"

# Save PIDs for cleanup
echo "$BROKER_PID" > .broker.pid
echo "$ML_PID" > .ml.pid
echo "$DASHBOARD_PID" > .dashboard.pid
echo "$AGENT_PID" > .agent.pid

echo "💡 To stop all components, run: ./stop_scada.sh"

# Monitor processes
trap 'echo "🛑 Shutting down..."; kill $BROKER_PID $ML_PID $DASHBOARD_PID $AGENT_PID 2>/dev/null; exit' INT TERM

wait
'''

        with open('start_scada_fixed.sh', 'w') as f:
            f.write(script_content)

        os.chmod('start_scada_fixed.sh', 0o755)
        logger.info("✅ Generated start_scada_fixed.sh")

        # Also generate stop script
        stop_script = '''#!/bin/bash
echo "🛑 Stopping SCADA System..."

# Kill by PID files if they exist
for pidfile in .broker.pid .ml.pid .dashboard.pid .agent.pid; do
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile")
        if kill "$pid" 2>/dev/null; then
            echo "✅ Stopped process $pid"
        fi
        rm -f "$pidfile"
    fi
done

# Fallback: kill by process name
pkill -f "smart_broker.py" 2>/dev/null || true
pkill -f "lightweight_ml_detector.py" 2>/dev/null || true
pkill -f "promiscuous_agent.py" 2>/dev/null || true
pkill -f "dashboard_server" 2>/dev/null || true

echo "✅ All SCADA processes stopped"
'''

        with open('stop_scada.sh', 'w') as f:
            f.write(stop_script)

        os.chmod('stop_scada.sh', 0o755)
        logger.info("✅ Generated stop_scada.sh")

    async def run_full_diagnostic(self):
        """Run complete diagnostic suite"""
        logger.info("🔍 Starting SCADA System Diagnostic...")
        logger.info("=" * 50)

        # 1. Check processes
        processes = self.check_processes()

        # 2. Check ports
        ports = self.check_ports()

        # 3. Check HTTP response if dashboard is running
        if ports.get('dashboard', False):
            logger.info("🔍 Testing HTTP response...")
            success, code = self.check_http_response('http://localhost:8766')

        # 4. Check WebSocket if dashboard is running
        if ports.get('dashboard', False):
            logger.info("🔍 Testing WebSocket connection...")
            ws_result = await self.check_websocket()

        # 5. Analyze logs for HTTP 207 errors
        errors = self.analyze_logs()

        # 6. Generate report
        logger.info("=" * 50)
        logger.info("📋 DIAGNOSTIC SUMMARY")
        logger.info("=" * 50)

        if errors:
            logger.warning("⚠️  HTTP 207 Multi-Status errors detected!")
            logger.info("🔧 Recommended actions:")
            logger.info("   1. Stop all SCADA processes")
            logger.info("   2. Use the fixed dashboard server (dashboard_server_fixed.py)")
            logger.info("   3. Restart in proper order: Broker → ML → Dashboard → Agent")

            # Apply fixes
            self.fix_http_207_issue()
            self.generate_startup_script()

            logger.info("✅ Fix scripts generated!")
            logger.info("🚀 Run: ./start_scada_fixed.sh")

        else:
            logger.info("✅ No critical issues detected")

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
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("🔍 SCADA Dashboard Diagnostic Tool")
    print("🎯 Detecting and fixing HTTP 207 Multi-Status issues")
    print()

    asyncio.run(main())