#!/usr/bin/env python3
"""
GIS Dashboard que lee eventos directamente de logs del agente promiscuo
Solución alternativa mientras debuggeamos ZeroMQ
"""

import asyncio
import json
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path


class LogWatcherGIS:
    """Watcher que lee logs del agente promiscuo en tiempo real"""

    def __init__(self):
        self.events = []
        self.is_running = False

    def extract_network_event_from_log(self, log_line):
        """Extraer evento de red de una línea de log"""
        try:
            # Buscar líneas como: [  1] Ethernet → IPv4 → TCP → HTTPS  | 192.168.1.123:63640 → 172.64.155.69:443
            pattern = r'\[\s*(\d+)\]\s+(.*?)\s+\|\s+([\d.]+):(\d+)\s+→\s+([\d.]+):(\d+)'
            match = re.search(pattern, log_line)

            if match:
                event_num, protocol_chain, src_ip, src_port, dst_ip, dst_port = match.groups()

                # Determinar tipo de evento
                protocol_chain_lower = protocol_chain.lower()
                if 'https' in protocol_chain_lower:
                    event_type = 'https_traffic'
                    color = '#00ff88'
                    icon = '🔒'
                elif 'quic' in protocol_chain_lower:
                    event_type = 'quic_traffic'
                    color = '#ff88aa'
                    icon = '⚡'
                elif 'arp' in protocol_chain_lower:
                    event_type = 'arp_activity'
                    color = '#ffaa88'
                    icon = '🏠'
                elif 'tcp' in protocol_chain_lower:
                    event_type = 'network_traffic'
                    color = '#4488ff'
                    icon = '📡'
                else:
                    event_type = 'raw_data'
                    color = '#888888'
                    icon = '📊'

                # Usar IP externa preferentemente
                display_ip = dst_ip if not dst_ip.startswith('192.168') else src_ip

                event = {
                    'id': f"log_{int(time.time())}_{event_num}",
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
                    'protocol_chain': protocol_chain,
                    'title': f"{icon} {event_type.replace('_', ' ').title()}",
                    'description': f"Network traffic: {src_ip}:{src_port} → {dst_ip}:{dst_port}",
                    'raw_data': log_line.strip(),
                    'source': 'Log-Watcher'
                }

                return event

            # Buscar líneas de estadísticas: 📊 STATS: 2200 eventos | 15.2 evt/s | 144.9s
            stats_pattern = r'📊\s+STATS:\s+(\d+)\s+eventos\s+\|\s+([\d.]+)\s+evt/s'
            stats_match = re.search(stats_pattern, log_line)

            if stats_match:
                total_events, rate = stats_match.groups()

                event = {
                    'id': f"stats_{int(time.time())}",
                    'timestamp': datetime.now().isoformat(),
                    'type': 'network_stats',
                    'severity': 'info',
                    'icon': '📊',
                    'color': '#44aaff',
                    'ip_address': '192.168.1.123',  # IP local
                    'total_events': int(total_events),
                    'event_rate': float(rate),
                    'title': f"📊 Network Statistics",
                    'description': f"Captured {total_events} events at {rate} evt/s",
                    'raw_data': log_line.strip(),
                    'source': 'Log-Watcher-Stats'
                }

                return event

        except Exception as e:
            print(f"Error parsing log line: {e}")
            print(f"Line: {log_line}")

        return None

    async def watch_agent_output(self):
        """Monitorear output del agente promiscuo"""
        print("🔍 Buscando proceso del agente promiscuo...")

        try:
            # Buscar PID del agente promiscuo
            result = subprocess.run(
                ['pgrep', '-f', 'promiscuous_agent.py'],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print("❌ Agente promiscuo no encontrado")
                print("💡 Asegúrate de que esté corriendo: make run-daemon")
                return

            pid = result.stdout.strip().split('\n')[0]
            print(f"✅ Agente promiscuo encontrado (PID: {pid})")

            # Usar script de shell para capturar output en tiempo real
            cmd = f"""
            # Función para capturar stdout de un proceso
            tail -f /proc/{pid}/fd/1 2>/dev/null || {{
                # Fallback: usar ps para monitorear
                while true; do
                    ps -p {pid} -o pid,command --no-headers 2>/dev/null || break
                    sleep 1
                done
            }}
            """

            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            print("🔄 Monitoring agent output...")
            self.is_running = True
            event_count = 0

            while self.is_running and process.returncode is None:
                try:
                    line = await asyncio.wait_for(
                        process.stdout.readline(),
                        timeout=1.0
                    )

                    if line:
                        line_str = line.decode('utf-8').strip()
                        if line_str:
                            print(f"📡 Agent: {line_str}")

                            # Procesar línea
                            event = self.extract_network_event_from_log(line_str)
                            if event:
                                self.events.append(event)
                                event_count += 1
                                print(f"✅ Event {event_count}: {event['title']} - {event['ip_address']}")

                                # Simular envío al dashboard
                                await self.send_event_to_dashboard(event)

                except asyncio.TimeoutError:
                    # No hay output - normal
                    continue
                except Exception as e:
                    print(f"Error reading agent output: {e}")
                    break

            process.terminate()
            await process.wait()

        except Exception as e:
            print(f"❌ Error monitoring agent: {e}")

    async def send_event_to_dashboard(self, event):
        """Simular envío de evento al dashboard (para testing)"""
        # Aquí podrías enviar el evento al dashboard real via WebSocket
        # Por ahora solo mostrar
        print(f"🗺️ → Dashboard: {event['title']} at {event['ip_address']}")

    async def run_alternative_capture(self):
        """Captura alternativa usando comandos del sistema"""
        print("🔄 Iniciando captura alternativa...")

        # Monitorear logs del sistema o usar netstat
        while self.is_running:
            try:
                # Ejemplo: capturar conexiones de red activas
                result = subprocess.run(
                    ['netstat', '-n', '|', 'grep', 'ESTABLISHED', '|', 'head', '-5'],
                    shell=True,
                    capture_output=True,
                    text=True
                )

                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if 'tcp' in line.lower():
                            # Parsear netstat output
                            parts = line.split()
                            if len(parts) >= 5:
                                local_addr = parts[3]
                                remote_addr = parts[4]

                                # Crear evento sintético
                                event = {
                                    'id': f"netstat_{int(time.time())}_{hash(line) % 1000}",
                                    'timestamp': datetime.now().isoformat(),
                                    'type': 'active_connection',
                                    'severity': 'info',
                                    'icon': '🔗',
                                    'color': '#66ccff',
                                    'ip_address': remote_addr.split(':')[0],
                                    'title': '🔗 Active Connection',
                                    'description': f"Connection: {local_addr} → {remote_addr}",
                                    'raw_data': line.strip(),
                                    'source': 'Netstat-Monitor'
                                }

                                self.events.append(event)
                                await self.send_event_to_dashboard(event)

                await asyncio.sleep(5)  # Check every 5 seconds

            except Exception as e:
                print(f"Error in alternative capture: {e}")
                await asyncio.sleep(5)

    def stop(self):
        """Detener monitoring"""
        self.is_running = False

    def get_events(self):
        """Obtener eventos capturados"""
        return self.events


async def main():
    """Main function"""
    watcher = LogWatcherGIS()

    print("🚀 Log Watcher GIS - Alternative Event Capture")
    print("=" * 50)
    print("Este script intentará capturar eventos directamente de los logs")
    print("del agente promiscuo como alternativa a ZeroMQ")
    print()

    try:
        # Intentar monitorear agente promiscuo
        await watcher.watch_agent_output()

        if len(watcher.events) == 0:
            print("\n💡 No se capturaron eventos del agente promiscuo")
            print("🔄 Intentando captura alternativa...")
            await watcher.run_alternative_capture()

    except KeyboardInterrupt:
        print("\n🛑 Stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        watcher.stop()

        # Mostrar resumen
        events = watcher.get_events()
        print(f"\n📊 SUMMARY:")
        print(f"Events captured: {len(events)}")

        if events:
            print("\n📋 Last 5 events:")
            for event in events[-5:]:
                print(f"  • {event['timestamp'][11:19]} - {event['title']} - {event['ip_address']}")


if __name__ == "__main__":
    asyncio.run(main())