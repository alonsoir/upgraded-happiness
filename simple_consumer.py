#!/usr/bin/env python3
"""
simple_consumer.py - Consumer temporal para drenar el puerto 5570
🔧 EMERGENCY CONSUMER para evitar que el ML detector se ahogue
- Conecta al puerto 5570 del ML detector
- Recibe y cuenta eventos sin procesar
- Evita que se llene el buffer ZMQ
- Muestra estadísticas simples
"""

import zmq
import time
import sys


def main():
    print("🔧 EMERGENCY CONSUMER - Drenando puerto 5570")
    print("=" * 50)
    print("📡 Conectando al ML detector puerto 5570...")

    # Setup ZMQ básico
    context = zmq.Context()
    socket = context.socket(zmq.PULL)
    socket.connect("tcp://localhost:5570")
    socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 segundo timeout

    print("✅ Conectado - drenando eventos...")
    print("🛑 Presiona Ctrl+C para detener")
    print()

    events_received = 0
    start_time = time.time()
    last_stats_time = time.time()

    try:
        while True:
            try:
                # Recibir evento
                message = socket.recv()
                events_received += 1

                # Stats cada 10 segundos
                now = time.time()
                if now - last_stats_time >= 10:
                    elapsed = now - start_time
                    rate = events_received / elapsed if elapsed > 0 else 0

                    print(f"📊 Eventos recibidos: {events_received} | Rate: {rate:.1f}/s | Runtime: {elapsed:.1f}s")
                    last_stats_time = now

            except zmq.Again:
                # No hay eventos - continuar
                continue

    except KeyboardInterrupt:
        print("\n🛑 Deteniendo consumer...")

    finally:
        elapsed = time.time() - start_time
        rate = events_received / elapsed if elapsed > 0 else 0

        print(f"\n📊 STATS FINALES:")
        print(f"   Total eventos: {events_received}")
        print(f"   Runtime: {elapsed:.1f}s")
        print(f"   Rate promedio: {rate:.1f} eventos/s")

        socket.close()
        context.term()
        print("✅ Consumer cerrado")


if __name__ == "__main__":
    main()