#!/usr/bin/env python3
"""
ZMQ Consumer Test - Para recibir datos del promiscuous_agent
PATRÓN: PULL CONNECT (cliente) → recibe de PUSH BIND (servidor)
"""

import zmq
import time
import sys


def main():
    print("🔍 ZMQ CONSUMER TEST - PULL CONNECT")
    print("=" * 50)

    # Configurar ZMQ context
    context = zmq.Context()

    # Crear socket PULL (cliente)
    socket = context.socket(zmq.PULL)

    # CONNECT al promiscuous agent (servidor)
    address = "tcp://localhost:5559"
    socket.connect(address)

    # Configurar timeout
    socket.setsockopt(zmq.RCVTIMEO, 5000)  # 5 segundos

    print(f"📡 Conectado a {address}")
    print("🎯 Esperando datos del promiscuous_agent...")
    print("   (Presiona Ctrl+C para detener)")
    print()

    events_received = 0
    bytes_received = 0
    start_time = time.time()

    try:
        while True:
            try:
                # Recibir datos
                data = socket.recv()
                events_received += 1
                bytes_received += len(data)

                # Mostrar info cada 10 eventos
                if events_received % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = events_received / elapsed if elapsed > 0 else 0

                    print(f"📊 Eventos: {events_received:4d} | "
                          f"Bytes: {bytes_received:6d} | "
                          f"Rate: {rate:5.1f} eventos/s | "
                          f"Último: {len(data):3d} bytes")

                # Mostrar primeros eventos en detalle
                elif events_received <= 5:
                    print(f"📦 Evento {events_received}: {len(data)} bytes")
                    print(f"   Hex: {data[:32].hex()}")

                    # Intentar decodificar protobuf si es posible
                    try:
                        # Verificar si es protobuf válido (comienza con field tags típicos)
                        if data and data[0] in [0x08, 0x0a, 0x10, 0x12]:
                            print(f"   ✅ Posible protobuf válido")
                        else:
                            print(f"   ⚠️ No parece protobuf estándar")
                    except:
                        pass
                    print()

            except zmq.Again:
                print("⏱️ Timeout - no hay datos (5s)")
                continue

    except KeyboardInterrupt:
        print("\n🛑 Deteniendo consumer...")

    finally:
        # Estadísticas finales
        elapsed = time.time() - start_time
        rate = events_received / elapsed if elapsed > 0 else 0

        print(f"\n📊 ESTADÍSTICAS FINALES:")
        print(f"   ⏱️ Tiempo: {elapsed:.1f}s")
        print(f"   📦 Eventos: {events_received}")
        print(f"   📊 Bytes: {bytes_received}")
        print(f"   ⚡ Rate promedio: {rate:.1f} eventos/s")
        print(f"   📏 Tamaño promedio: {bytes_received / max(events_received, 1):.1f} bytes/evento")

        # Limpiar
        socket.close()
        context.term()
        print("✅ Consumer ZMQ cerrado")


if __name__ == "__main__":
    main()