#!/usr/bin/env python3
"""
Test Subscriber para verificar eventos del Enhanced Promiscuous Agent
Escucha en ZeroMQ puerto 5559 y muestra eventos recibidos
"""

import sys
import time
import zmq
import json
from datetime import datetime

# Importar protobuf
try:
    from src.protocols.protobuf import network_event_pb2

    print("✅ Protobuf importado exitosamente")
    PROTOBUF_AVAILABLE = True
except ImportError as e:
    print(f"❌ Error importando protobuf: {e}")
    PROTOBUF_AVAILABLE = False


class EventSubscriber:
    def __init__(self, port=5559):
        self.port = port
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.SUB)
        self.running = False
        self.stats = {
            'events_received': 0,
            'events_with_gps': 0,
            'unique_ips': set(),
            'start_time': time.time()
        }

    def connect(self):
        """Conectar al agente promiscuo"""
        try:
            self.socket.connect(f"tcp://localhost:{self.port}")

            # Suscribirse a todos los eventos de red
            self.socket.setsockopt(zmq.SUBSCRIBE, b"network_event")

            # Timeout para recv (no bloqueante)
            self.socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 segundo

            print(f"🔌 Conectado a ZeroMQ puerto {self.port}")
            print("👂 Escuchando eventos de red...")
            print("=" * 60)

        except Exception as e:
            print(f"❌ Error conectando a ZeroMQ: {e}")
            raise

    def parse_event(self, data):
        """Parsear evento protobuf"""
        if not PROTOBUF_AVAILABLE:
            return None

        try:
            event = network_event_pb2.NetworkEvent()
            event.ParseFromString(data)
            return event
        except Exception as e:
            print(f"⚠️  Error parseando protobuf: {e}")
            return None

    def display_event(self, event):
        """Mostrar evento formateado"""
        timestamp = datetime.fromtimestamp(event.timestamp / 1000).strftime('%H:%M:%S')

        # Determinar si tiene GPS
        has_gps = event.latitude != 0.0 or event.longitude != 0.0
        gps_icon = "🎯" if has_gps else "🌐"

        if has_gps:
            self.stats['events_with_gps'] += 1

        # Actualizar estadísticas
        self.stats['unique_ips'].add(event.source_ip)
        self.stats['unique_ips'].add(event.target_ip)

        print(f"{gps_icon} {timestamp} | {event.source_ip}:{event.src_port} → {event.target_ip}:{event.dest_port}")

        if has_gps:
            print(f"   📍 GPS: {event.latitude:.6f}, {event.longitude:.6f}")

        print(f"   📦 Size: {event.packet_size}B | Type: {event.event_type}")
        print(f"   🔍 Agent: {event.agent_id}")

        if event.description:
            print(f"   💬 {event.description}")

        print("-" * 60)

    def show_stats(self):
        """Mostrar estadísticas cada cierto tiempo"""
        runtime = time.time() - self.stats['start_time']
        events_per_sec = self.stats['events_received'] / max(runtime, 1)
        gps_percentage = (self.stats['events_with_gps'] / max(self.stats['events_received'], 1)) * 100

        print(f"\n📊 ESTADÍSTICAS ({runtime:.0f}s)")
        print(f"   📨 Eventos recibidos: {self.stats['events_received']}")
        print(f"   🎯 Con GPS: {self.stats['events_with_gps']} ({gps_percentage:.1f}%)")
        print(f"   🌐 IPs únicas: {len(self.stats['unique_ips'])}")
        print(f"   ⚡ Rate: {events_per_sec:.1f} eventos/seg")
        print("=" * 60)

    def listen(self):
        """Bucle principal de escucha"""
        self.running = True
        last_stats_time = time.time()

        print("⚡ Iniciando escucha... (Ctrl+C para detener)")
        print("🔍 Esperando eventos del agente promiscuo...")

        try:
            while self.running:
                try:
                    # Recibir mensaje multipart
                    topic, data = self.socket.recv_multipart(zmq.NOBLOCK)

                    # Parsear evento
                    event = self.parse_event(data)
                    if event:
                        self.stats['events_received'] += 1
                        self.display_event(event)

                        # Mostrar stats cada 30 segundos o cada 50 eventos
                        if (time.time() - last_stats_time > 30 or
                                self.stats['events_received'] % 50 == 0):
                            self.show_stats()
                            last_stats_time = time.time()

                except zmq.Again:
                    # Timeout - no hay mensajes
                    time.sleep(0.1)
                    continue

                except KeyboardInterrupt:
                    break

        except Exception as e:
            print(f"❌ Error en bucle de escucha: {e}")
        finally:
            self.stop()

    def stop(self):
        """Detener subscriber"""
        print("\n🛑 Deteniendo subscriber...")
        self.running = False

        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()

        # Mostrar estadísticas finales
        self.show_stats()
        print("✅ Subscriber detenido")


def main():
    """Función principal"""
    import signal

    print("🧪 Test Subscriber para Enhanced Promiscuous Agent")
    print("================================================")

    if not PROTOBUF_AVAILABLE:
        print("❌ Protobuf no disponible - no se pueden parsear eventos")
        return 1

    # Obtener puerto de argumentos
    port = 5559
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("❌ Puerto debe ser un número")
            return 1

    subscriber = None

    def signal_handler(signum, frame):
        print(f"\n📡 Señal {signum} recibida")
        if subscriber:
            subscriber.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        subscriber = EventSubscriber(port)
        subscriber.connect()
        subscriber.listen()

    except Exception as e:
        print(f"❌ Error fatal: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())