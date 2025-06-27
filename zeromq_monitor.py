#!/usr/bin/env python3
"""
Monitor del broker ZeroMQ - Ve exactamente qué está enviando tu agente
"""

import zmq
import sys
import os
import time
from collections import Counter

# Agregar path para importar protobuf
sys.path.insert(0, os.getcwd())

try:
    from src.protocols.protobuf import network_event_pb2

    print("✅ Protobuf importado exitosamente")
except ImportError as e:
    print(f"❌ Error importando protobuf: {e}")
    sys.exit(1)


class ZeroMQMonitor:
    def __init__(self, broker_address="tcp://localhost:5555"):
        self.broker_address = broker_address
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.SUB)

        # Suscribirse a todos los mensajes
        self.socket.setsockopt(zmq.SUBSCRIBE, b"")

        # Contadores
        self.event_count = 0
        self.start_time = time.time()
        self.protocols = Counter()
        self.ports = Counter()
        self.ips = Counter()

        print(f"🔍 MONITOR DEL BROKER ZEROMQ")
        print(f"📡 Conectando a: {broker_address}")
        print(f"🕒 Inicio: {time.strftime('%H:%M:%S')}")
        print("=" * 60)

    def connect(self):
        """Conectar al broker"""
        try:
            self.socket.connect(self.broker_address)
            print("✅ Conectado al broker ZeroMQ")
            return True
        except Exception as e:
            print(f"❌ Error conectando: {e}")
            return False

    def monitor_events(self, duration=60):
        """Monitorear eventos por un tiempo determinado"""
        print(f"🚀 Monitoreando eventos por {duration} segundos...")
        print("📊 Presiona Ctrl+C para detener antes")
        print("-" * 60)

        end_time = time.time() + duration

        try:
            while time.time() < end_time:
                try:
                    # Recibir mensaje con timeout
                    message = self.socket.recv(zmq.NOBLOCK)
                    self.process_event(message)

                except zmq.Again:
                    # No hay mensajes, esperar un poco
                    time.sleep(0.1)
                    continue

        except KeyboardInterrupt:
            print(f"\n🛑 Monitoreo detenido por usuario")

        self.show_summary()

    def process_event(self, message):
        """Procesar un evento recibido"""
        try:
            # Deserializar evento protobuf
            event = network_event_pb2.NetworkEvent()
            event.ParseFromString(message)

            self.event_count += 1

            # Determinar protocolo basado en puertos
            protocol = "OTHER"
            if event.dest_port > 0 or event.src_port > 0:
                # Puertos conocidos
                ports_to_check = [event.dest_port, event.src_port]

                for port in ports_to_check:
                    if port == 80:
                        protocol = "HTTP"
                        break
                    elif port == 443:
                        protocol = "HTTPS"
                        break
                    elif port == 53:
                        protocol = "DNS"
                        break
                    elif port == 22:
                        protocol = "SSH"
                        break
                    elif port == 25:
                        protocol = "SMTP"
                        break
                    elif port == 21:
                        protocol = "FTP"
                        break
                    elif port in [993, 995]:
                        protocol = "EMAIL-SSL"
                        break
                    elif port in [1900, 5353]:
                        protocol = "mDNS/SSDP"
                        break
                    elif port == 123:
                        protocol = "NTP"
                        break
                    elif port > 1024:
                        protocol = "HIGH-PORT"
                        break

            # Contar estadísticas
            self.protocols[protocol] += 1

            if event.dest_port > 0:
                self.ports[f":{event.dest_port}"] += 1
            if event.src_port > 0 and event.src_port != event.dest_port:
                self.ports[f":{event.src_port}"] += 1

            # IPs (solo las más comunes)
            self.ips[event.source_ip] += 1
            self.ips[event.target_ip] += 1

            # Mostrar evento cada 50 eventos
            if self.event_count % 50 == 0:
                elapsed = time.time() - self.start_time
                rate = self.event_count / elapsed
                print(f"📊 Eventos: {self.event_count:,} | Velocidad: {rate:.1f} evt/s")

            # Mostrar detalle de los primeros 10 eventos
            elif self.event_count <= 10:
                print(
                    f"[{self.event_count:2d}] {protocol:<12} | {event.source_ip}:{event.src_port} → {event.target_ip}:{event.dest_port} | {event.packet_size} bytes")

        except Exception as e:
            print(f"❌ Error procesando evento: {e}")

    def show_summary(self):
        """Mostrar resumen de la actividad"""
        elapsed = time.time() - self.start_time
        rate = self.event_count / elapsed if elapsed > 0 else 0

        print("\n" + "=" * 60)
        print(f"📊 RESUMEN DEL MONITOREO ZEROMQ")
        print("=" * 60)
        print(f"⏱️  Tiempo total: {elapsed:.1f} segundos")
        print(f"📦 Total eventos: {self.event_count:,}")
        print(f"🚀 Velocidad promedio: {rate:.1f} eventos/segundo")

        if self.protocols:
            print(f"\n🔍 PROTOCOLOS CAPTURADOS:")
            print("-" * 30)
            for protocol, count in self.protocols.most_common():
                percentage = (count / self.event_count) * 100
                print(f"{protocol:<15} | {count:>6,} ({percentage:>5.1f}%)")

        if self.ports:
            print(f"\n🚪 PUERTOS MÁS ACTIVOS:")
            print("-" * 30)
            for port, count in self.ports.most_common(10):
                percentage = (count / self.event_count) * 100 if self.event_count > 0 else 0
                print(f"{port:<10} | {count:>6,} ({percentage:>5.1f}%)")

        if self.ips:
            print(f"\n🌐 IPs MÁS ACTIVAS:")
            print("-" * 40)
            for ip, count in self.ips.most_common(10):
                percentage = (count / self.event_count) * 100 if self.event_count > 0 else 0
                print(f"{ip:<20} | {count:>6,} ({percentage:>5.1f}%)")

    def cleanup(self):
        """Limpiar recursos"""
        self.socket.close()
        self.context.term()


def main():
    """Función principal"""
    import argparse

    parser = argparse.ArgumentParser(description="Monitor del broker ZeroMQ")
    parser.add_argument("-b", "--broker", default="tcp://localhost:5555", help="Dirección del broker")
    parser.add_argument("-t", "--time", type=int, default=60, help="Tiempo de monitoreo en segundos")

    args = parser.parse_args()

    monitor = ZeroMQMonitor(args.broker)

    if monitor.connect():
        try:
            monitor.monitor_events(args.time)
        finally:
            monitor.cleanup()
    else:
        print("❌ No se pudo conectar al broker")
        print("💡 Asegúrate de que el broker esté corriendo: ./scripts/run_broker.sh")


if __name__ == "__main__":
    main()