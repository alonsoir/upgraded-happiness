#!/usr/bin/env python3
"""
Monitor en tiempo real para eventos ZeroMQ del sistema SCADA
Muestra en vivo qué eventos están llegando/no llegando
realtime-monitor.py
"""

import zmq
import time
import json
import threading
import signal
import sys
from datetime import datetime
from collections import deque, defaultdict
from typing import Dict, List


class RealtimeEventMonitor:
    def __init__(self):
        self.running = True
        self.events_buffer = deque(maxlen=100)
        self.stats = defaultdict(int)
        self.last_event_time = None
        self.zmq_context = zmq.Context()

        # Configurar manejo de señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Manejo graceful de interrupción"""
        print("\n🛑 Deteniendo monitor...")
        self.running = False

    def clear_screen(self):
        """Limpiar pantalla"""
        print("\033[2J\033[H", end="")

    def print_header(self):
        """Imprimir cabecera del monitor"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("=" * 80)
        print(f"🔍 MONITOR EN TIEMPO REAL - EVENTOS ZEROMQ")
        print(f"📅 {timestamp}")
        print("=" * 80)

    def monitor_zmq_port(self, port: int, topic_filter: str = "") -> None:
        """Monitorear un puerto ZeroMQ específico"""
        try:
            socket = self.zmq_context.socket(zmq.SUB)
            socket.setsockopt(zmq.SUBSCRIBE, topic_filter.encode())
            socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 segundo timeout
            socket.connect(f"tcp://localhost:{port}")

            print(f"📡 Monitoreando puerto {port} (filtro: '{topic_filter}')...")

            while self.running:
                try:
                    # Intentar recibir mensaje
                    message = socket.recv_string(zmq.NOBLOCK)

                    # Procesar evento
                    event_data = {
                        'timestamp': datetime.now().isoformat(),
                        'port': port,
                        'message': message,
                        'size': len(message)
                    }

                    self.events_buffer.append(event_data)
                    self.stats[f'port_{port}'] += 1
                    self.stats['total_events'] += 1
                    self.last_event_time = time.time()

                except zmq.Again:
                    # No hay mensajes, continuar
                    pass
                except Exception as e:
                    print(f"❌ Error en puerto {port}: {e}")
                    break

                time.sleep(0.1)

        except Exception as e:
            print(f"❌ No se pudo conectar al puerto {port}: {e}")
        finally:
            socket.close()

    def monitor_multiple_ports(self):
        """Monitorear múltiples puertos en hilos separados"""
        ports_to_monitor = [5559, 5560]
        threads = []

        for port in ports_to_monitor:
            thread = threading.Thread(
                target=self.monitor_zmq_port,
                args=(port,),
                daemon=True
            )
            thread.start()
            threads.append(thread)

        return threads

    def display_stats(self):
        """Mostrar estadísticas en tiempo real"""
        current_time = time.time()

        print(f"\n📊 ESTADÍSTICAS:")
        print(f"   Total eventos: {self.stats['total_events']}")
        print(f"   Puerto 5559:   {self.stats['port_5559']}")
        print(f"   Puerto 5560:   {self.stats['port_5560']}")

        if self.last_event_time:
            seconds_since_last = current_time - self.last_event_time
            if seconds_since_last < 5:
                status = "✅ ACTIVO"
            elif seconds_since_last < 30:
                status = "⚠️  LENTO"
            else:
                status = "❌ INACTIVO"

            print(f"   Último evento: {seconds_since_last:.1f}s ago - {status}")
        else:
            print(f"   Último evento: ❌ NUNCA")

    def display_recent_events(self):
        """Mostrar eventos recientes"""
        print(f"\n📨 EVENTOS RECIENTES (últimos 10):")

        if not self.events_buffer:
            print("   📭 No hay eventos para mostrar")
            return

        recent_events = list(self.events_buffer)[-10:]

        for i, event in enumerate(recent_events, 1):
            timestamp = event['timestamp'].split('T')[1][:8]  # Solo hora
            port = event['port']
            size = event['size']
            message_preview = event['message'][:50] + "..." if len(event['message']) > 50 else event['message']

            print(f"   {i:2d}. [{timestamp}] Port {port} ({size}b): {message_preview}")

    def display_event_analysis(self):
        """Análisis de patrones de eventos"""
        print(f"\n🔍 ANÁLISIS:")

        if not self.events_buffer:
            print("   ❌ Sin datos para analizar")
            return

        # Análizar últimos 60 segundos
        now = time.time()
        recent_events = [
            e for e in self.events_buffer
            if (now - time.mktime(time.strptime(e['timestamp'][:19], "%Y-%m-%dT%H:%M:%S"))) < 60
        ]

        if not recent_events:
            print("   ⚠️  No hay eventos en los últimos 60 segundos")
            return

        # Calcular rate
        events_per_minute = len(recent_events)
        print(f"   📈 Rate: {events_per_minute} eventos/minuto")

        # Análizar por puerto
        port_counts = defaultdict(int)
        for event in recent_events:
            port_counts[event['port']] += 1

        for port, count in port_counts.items():
            percentage = (count / len(recent_events)) * 100
            print(f"   📊 Puerto {port}: {count} eventos ({percentage:.1f}%)")

        # Detectar problemas
        if events_per_minute == 0:
            print("   🚨 PROBLEMA: No hay eventos")
        elif events_per_minute < 5:
            print("   ⚠️  PROBLEMA: Rate muy bajo (esperado >5/min)")
        elif port_counts[5559] == 0:
            print("   🚨 PROBLEMA: No hay eventos en puerto principal (5559)")

    def run_monitor(self):
        """Ejecutar monitor principal"""
        print("🚀 Iniciando monitor en tiempo real...")

        # Iniciar monitoreo de puertos
        monitor_threads = self.monitor_multiple_ports()

        try:
            while self.running:
                self.clear_screen()
                self.print_header()
                self.display_stats()
                self.display_recent_events()
                self.display_event_analysis()

                print(f"\n💡 CONTROLES:")
                print(f"   Ctrl+C: Salir")
                print(f"   Actualización automática cada 3 segundos")

                # Esperar 3 segundos o hasta interrupción
                for _ in range(30):  # 30 x 0.1s = 3s
                    if not self.running:
                        break
                    time.sleep(0.1)

        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            print("\n🏁 Monitor detenido")

            # Esperar threads
            for thread in monitor_threads:
                thread.join(timeout=1)

            self.zmq_context.term()


def main():
    """Función principal con menú"""
    monitor = RealtimeEventMonitor()

    print("🔧 Monitor de Eventos ZeroMQ - Sistema SCADA")
    print("=" * 50)
    print("1. Monitor en tiempo real")
    print("2. Test rápido de conectividad")
    print("3. Monitor de puerto específico")
    print("=" * 50)

    try:
        choice = input("Seleccione opción (1-3): ").strip()

        if choice == "1":
            monitor.run_monitor()

        elif choice == "2":
            print("\n🔍 Ejecutando test rápido...")

            # Test rápido de cada puerto
            for port in [5559, 5560]:
                try:
                    socket = monitor.zmq_context.socket(zmq.SUB)
                    socket.setsockopt(zmq.SUBSCRIBE, b"")
                    socket.setsockopt(zmq.RCVTIMEO, 3000)
                    socket.connect(f"tcp://localhost:{port}")

                    print(f"📡 Puerto {port}: ", end="")

                    try:
                        message = socket.recv_string(zmq.NOBLOCK)
                        print(f"✅ ACTIVO - Último mensaje: {message[:30]}...")
                    except zmq.Again:
                        print("⚠️  CONECTADO pero sin datos")

                    socket.close()

                except Exception as e:
                    print(f"❌ ERROR: {e}")

            monitor.zmq_context.term()

        elif choice == "3":
            port = int(input("Puerto a monitorear (5559/5560): "))
            topic = input("Filtro de topic (Enter para todos): ").strip()

            print(f"\n📡 Monitoreando puerto {port}...")
            print("Ctrl+C para salir\n")

            monitor.monitor_zmq_port(port, topic)
            monitor.zmq_context.term()

        else:
            print("❌ Opción inválida")

    except KeyboardInterrupt:
        print("\n🛑 Operación cancelada")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        if monitor.zmq_context:
            monitor.zmq_context.term()


if __name__ == "__main__":
    main()