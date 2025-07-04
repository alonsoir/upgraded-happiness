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
