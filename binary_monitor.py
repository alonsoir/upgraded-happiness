#!/usr/bin/env python3
"""
Monitor específico para datos binarios protobuf del sistema SCADA
Detecta tanto mensajes string como binarios
"""

import zmq
import time
import threading
import signal
from datetime import datetime
from collections import deque, defaultdict


class BinaryRealtimeMonitor:
    def __init__(self):
        self.running = True
        self.events_buffer = deque(maxlen=100)
        self.stats = defaultdict(int)
        self.last_event_time = None
        self.zmq_context = zmq.Context()

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print("\n🛑 Deteniendo monitor...")
        self.running = False

    def clear_screen(self):
        print("\033[2J\033[H", end="")

    def print_header(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("=" * 80)
        print(f"🔍 MONITOR BINARIO - EVENTOS ZEROMQ PROTOBUF")
        print(f"📅 {timestamp}")
        print("=" * 80)

    def monitor_binary_port(self, port: int) -> None:
        """Monitorear puerto con datos binarios protobuf"""
        try:
            socket = self.zmq_context.socket(zmq.SUB)
            socket.setsockopt(zmq.SUBSCRIBE, b"")  # Suscribirse a todo
            socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 segundo timeout
            socket.connect(f"tcp://localhost:{port}")

            print(f"📡 Monitoreando puerto {port} (modo binario)...")

            while self.running:
                try:
                    # Intentar recibir datos binarios
                    binary_data = socket.recv(zmq.NOBLOCK)

                    # Procesar evento binario
                    event_data = {
                        'timestamp': datetime.now().isoformat(),
                        'port': port,
                        'data_type': 'binary',
                        'size': len(binary_data),
                        'preview': self.get_binary_preview(binary_data)
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

    def get_binary_preview(self, binary_data):
        """Generar preview de datos binarios"""
        try:
            # Intentar decodificar como string
            try:
                string_data = binary_data.decode('utf-8')
                return f"STRING: {string_data[:50]}..."
            except:
                pass

            # Mostrar hex preview
            hex_preview = binary_data[:20].hex()
            return f"HEX: {hex_preview}... (protobuf likely)"

        except Exception as e:
            return f"BINARY: {len(binary_data)} bytes"

    def monitor_multiple_ports(self):
        """Monitorear múltiples puertos en hilos separados"""
        ports_to_monitor = [5559, 5560]
        threads = []

        for port in ports_to_monitor:
            thread = threading.Thread(
                target=self.monitor_binary_port,
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
            preview = event['preview']

            print(f"   {i:2d}. [{timestamp}] Port {port} ({size}b): {preview}")

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
        total_size = 0
        for event in recent_events:
            port_counts[event['port']] += 1
            total_size += event['size']

        avg_size = total_size / len(recent_events) if recent_events else 0
        print(f"   📦 Tamaño promedio: {avg_size:.1f} bytes")

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
        else:
            print("   ✅ FLUJO DE DATOS DETECTADO")

    def run_monitor(self):
        """Ejecutar monitor principal"""
        print("🚀 Iniciando monitor binario en tiempo real...")

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
                print(f"   Monitor optimizado para protobuf binario")

                # Esperar 3 segundos o hasta interrupción
                for _ in range(30):  # 30 x 0.1s = 3s
                    if not self.running:
                        break
                    time.sleep(0.1)

        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            print("\n🏁 Monitor binario detenido")

            # Esperar threads
            for thread in monitor_threads:
                thread.join(timeout=1)

            self.zmq_context.term()


def main():
    """Función principal"""
    monitor = BinaryRealtimeMonitor()

    print("🔧 Monitor Binario ZeroMQ - Sistema SCADA")
    print("=" * 50)
    print("Optimizado para detectar datos protobuf del agente")
    print("=" * 50)

    try:
        monitor.run_monitor()
    except KeyboardInterrupt:
        print("\n🛑 Operación cancelada")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        if monitor.zmq_context:
            monitor.zmq_context.term()


if __name__ == "__main__":
    main()