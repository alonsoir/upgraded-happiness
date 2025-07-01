#!/usr/bin/env python3
"""
Colector REAL de BitDefender para macOS
======================================
Lee logs reales, monitorea procesos reales, envía datos reales al dashboard
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
import zmq


@dataclass
class RealBitDefenderEvent:
    """Evento real de BitDefender"""

    timestamp: str
    event_type: str
    severity: str
    source_file: Optional[str] = None
    process_name: Optional[str] = None
    details: Optional[str] = None
    raw_log: Optional[str] = None
    file_path: Optional[str] = None
    threat_name: Optional[str] = None


class RealBitDefenderCollector:
    """Colector que obtiene datos REALES de BitDefender en macOS"""

    def __init__(self, config_path="bitdefender_config.yaml"):
        self.config = self._load_config(config_path)
        self.running = False

        # ZeroMQ para enviar al dashboard
        self.zmq_context = zmq.Context()
        self.zmq_socket = self.zmq_context.socket(zmq.PUB)

        # Logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # Archivos de log monitoreados
        self.log_files = []
        self.log_positions = {}  # Para tracking de posición en archivos

        self._discover_log_files()

    def _load_config(self, config_path):
        try:
            with open(config_path, "r") as f:
                return yaml.safe_load(f)
        except:
            return {"bitdefender": {"log_paths": [], "processes": []}}

    def _discover_log_files(self):
        """Descubre archivos de log reales de BitDefender"""
        potential_paths = [
            "/Applications/Bitdefender/AntivirusforMac.app/Contents/Resources/Logs",
            "/Applications/Bitdefender/CoreSecurity.app/Contents/Resources/Logs",
            "/Applications/Bitdefender/BitdefenderAgent.app/Contents/Resources/Logs",
            "/Library/Application Support/Bitdefender/Logs",
            "/Library/Logs/Bitdefender",
            "/var/log",
        ]

        log_extensions = [".log", ".txt"]

        for base_path in potential_paths:
            path = Path(base_path)
            if path.exists() and path.is_dir():
                try:
                    for file_path in path.rglob("*"):
                        if (
                            file_path.is_file()
                            and any(
                                file_path.name.endswith(ext) for ext in log_extensions
                            )
                            and any(
                                keyword in file_path.name.lower()
                                for keyword in [
                                    "bitdefender",
                                    "bd",
                                    "antivirus",
                                    "security",
                                ]
                            )
                        ):
                            self.log_files.append(str(file_path))
                            self.log_positions[str(file_path)] = 0
                            self.logger.info(f"📁 Log encontrado: {file_path}")
                except PermissionError:
                    self.logger.debug(f"⚠️ Sin permisos para {base_path}")

        if not self.log_files:
            self.logger.warning(
                "⚠️ No se encontraron logs de BitDefender. Usando datos de procesos solamente."
            )

    async def start_collection(self):
        """Inicia la recolección de datos reales"""
        self.running = True
        self.logger.info("🚀 Iniciando colector REAL de BitDefender...")

        # Conectar ZeroMQ al puerto del dashboard
        self.zmq_socket.connect("tcp://localhost:8766")

        # Iniciar workers asíncronos
        tasks = [
            asyncio.create_task(self._monitor_processes()),
            asyncio.create_task(self._monitor_log_files()),
            asyncio.create_task(self._monitor_syslog()),
            asyncio.create_task(self._send_periodic_stats()),
        ]

        self.logger.info("✅ Colector REAL iniciado")

        try:
            # Ejecutar todos los workers
            await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"❌ Error en colector: {e}")
            raise

    async def _monitor_processes(self):
        """Monitorea procesos REALES de BitDefender"""
        while self.running:
            try:
                # Ejecutar ps aux y buscar procesos de BitDefender
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True)

                bd_processes = []
                for line in result.stdout.splitlines():
                    # Buscar líneas que contengan BitDefender
                    if any(
                        keyword in line.lower()
                        for keyword in ["bitdefender", "bdl", "bd"]
                    ):
                        parts = line.split()
                        if len(parts) >= 11:
                            process_name = parts[10]  # Comando
                            cpu_usage = parts[2]  # %CPU
                            mem_usage = parts[3]  # %MEM

                            if any(
                                bd_proc in process_name
                                for bd_proc in ["bitdefender", "BDL", "bd"]
                            ):
                                bd_processes.append(
                                    {
                                        "process": process_name,
                                        "cpu": cpu_usage,
                                        "memory": mem_usage,
                                        "full_line": line,
                                    }
                                )

                # Enviar evento de estado de procesos
                if bd_processes:
                    event = RealBitDefenderEvent(
                        timestamp=datetime.now().isoformat(),
                        event_type="process_status",
                        severity="info",
                        details=f"{len(bd_processes)} procesos BitDefender activos",
                        raw_log=json.dumps(bd_processes),
                    )
                    await self._send_event(event)

                await asyncio.sleep(30)  # Cada 30 segundos

            except Exception as e:
                self.logger.error(f"Error monitoreando procesos: {e}")
                await asyncio.sleep(60)

    async def _monitor_log_files(self):
        """Monitorea archivos de log REALES"""
        while self.running:
            try:
                for log_file in self.log_files:
                    await self._read_log_file(log_file)

                await asyncio.sleep(10)  # Cada 10 segundos

            except Exception as e:
                self.logger.error(f"Error monitoreando logs: {e}")
                await asyncio.sleep(30)

    async def _read_log_file(self, log_file: str):
        """Lee nuevas líneas de un archivo de log"""
        try:
            path = Path(log_file)
            if not path.exists():
                return

            current_size = path.stat().st_size
            last_position = self.log_positions.get(log_file, 0)

            # Si el archivo creció, leer nuevas líneas
            if current_size > last_position:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    self.log_positions[log_file] = f.tell()

                # Procesar nuevas líneas
                for line in new_lines:
                    await self._process_log_line(line.strip(), log_file)

        except Exception as e:
            self.logger.debug(f"Error leyendo {log_file}: {e}")

    async def _process_log_line(self, line: str, source_file: str):
        """Procesa una línea de log y extrae eventos"""
        if not line or len(line) < 10:
            return

        # Detectar tipos de eventos en los logs
        line_lower = line.lower()

        event_type = "general"
        severity = "info"
        threat_name = None

        # Detección de malware/virus
        if any(
            keyword in line_lower
            for keyword in ["virus", "malware", "threat", "infected", "trojan"]
        ):
            event_type = "malware_detected"
            severity = "high"

            # Extraer nombre de amenaza
            threat_match = re.search(
                r"(trojan|virus|malware|threat)[:\s]+([^\s,]+)", line_lower
            )
            if threat_match:
                threat_name = threat_match.group(2)

        # Detección de escaneo
        elif any(keyword in line_lower for keyword in ["scan", "scanning"]):
            event_type = "real_time_scan"
            severity = "low"

        # Detección de cuarentena
        elif any(
            keyword in line_lower for keyword in ["quarantine", "blocked", "deleted"]
        ):
            event_type = "threat_blocked"
            severity = "medium"

        # Detección de conexiones sospechosas
        elif any(
            keyword in line_lower for keyword in ["connection", "network", "suspicious"]
        ):
            event_type = "suspicious_connection"
            severity = "medium"

        # Actualizaciones
        elif any(
            keyword in line_lower for keyword in ["update", "signature", "definition"]
        ):
            event_type = "signature_update"
            severity = "info"

        # Solo enviar eventos relevantes (no todo el ruido)
        if event_type != "general" or severity in ["medium", "high"]:
            event = RealBitDefenderEvent(
                timestamp=datetime.now().isoformat(),
                event_type=event_type,
                severity=severity,
                source_file=source_file,
                details=line[:200],  # Primeros 200 caracteres
                raw_log=line,
                threat_name=threat_name,
            )
            await self._send_event(event)

    async def _monitor_syslog(self):
        """Monitorea syslog de macOS para eventos de BitDefender"""
        while self.running:
            try:
                # Usar log command de macOS para obtener logs recientes
                cmd = [
                    "log",
                    "show",
                    "--last",
                    "5m",
                    "--predicate",
                    'process CONTAINS "bitdefender" OR process CONTAINS "BDL" OR subsystem CONTAINS "bitdefender"',
                    "--style",
                    "json",
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0 and result.stdout.strip():
                    try:
                        log_data = json.loads(result.stdout)
                        for entry in log_data:
                            await self._process_syslog_entry(entry)
                    except json.JSONDecodeError:
                        # Fallback: procesar como texto plano
                        for line in result.stdout.splitlines():
                            if any(
                                keyword in line.lower()
                                for keyword in ["bitdefender", "bdl"]
                            ):
                                await self._process_log_line(line, "syslog")

                await asyncio.sleep(60)  # Cada minuto

            except subprocess.TimeoutExpired:
                self.logger.warning("Timeout en syslog")
                await asyncio.sleep(120)
            except Exception as e:
                self.logger.error(f"Error en syslog: {e}")
                await asyncio.sleep(180)

    async def _process_syslog_entry(self, entry: Dict):
        """Procesa entrada JSON del syslog"""
        try:
            message = entry.get("eventMessage", "")
            process = entry.get("processImagePath", "")
            timestamp = entry.get("timestamp", datetime.now().isoformat())

            if message and any(
                keyword in message.lower()
                for keyword in ["bitdefender", "threat", "virus"]
            ):
                event = RealBitDefenderEvent(
                    timestamp=timestamp,
                    event_type="syslog_event",
                    severity="info",
                    process_name=process,
                    details=message[:200],
                    raw_log=json.dumps(entry),
                )
                await self._send_event(event)

        except Exception as e:
            self.logger.debug(f"Error procesando syslog entry: {e}")

    async def _send_periodic_stats(self):
        """Envía estadísticas periódicas"""
        while self.running:
            try:
                # Estadísticas del sistema
                stats_event = RealBitDefenderEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="system_stats",
                    severity="info",
                    details=f"Monitoreando {len(self.log_files)} archivos de log",
                    raw_log=json.dumps(
                        {
                            "log_files": len(self.log_files),
                            "monitored_processes": len(
                                self.config["bitdefender"]["processes"]
                            ),
                            "status": "active",
                        }
                    ),
                )
                await self._send_event(stats_event)

                await asyncio.sleep(300)  # Cada 5 minutos

            except Exception as e:
                self.logger.error(f"Error enviando stats: {e}")
                await asyncio.sleep(300)

    async def _send_event(self, event: RealBitDefenderEvent):
        """Envía evento al dashboard via ZeroMQ"""
        try:
            payload = {
                "type": "real_bitdefender_event",
                "source": "real_collector",
                "timestamp": event.timestamp,
                "data": asdict(event),
            }

            # Enviar via ZeroMQ
            message = json.dumps(payload).encode("utf-8")
            self.zmq_socket.send_multipart([b"real.bitdefender", message])

            self.logger.debug(f"📤 Evento enviado: {event.event_type}")

        except Exception as e:
            self.logger.error(f"Error enviando evento: {e}")

    async def stop(self):
        """Detiene el colector"""
        self.running = False
        self.zmq_socket.close()
        self.zmq_context.term()
        self.logger.info("🛑 Colector REAL detenido")


async def main():
    collector = RealBitDefenderCollector()

    try:
        print("🚀 Iniciando colector REAL de BitDefender...")
        print("📊 Esto reemplazará los datos simulados con datos REALES")
        print("⏹️ Presiona Ctrl+C para detener")

        await collector.start_collection()

    except KeyboardInterrupt:
        print("\n🛑 Deteniendo colector REAL...")
        await collector.stop()
        print("✅ Colector REAL detenido")


if __name__ == "__main__":
    asyncio.run(main())
