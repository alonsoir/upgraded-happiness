#!/usr/bin/env python3
"""
simple_consumer_v31.py - Consumidor para testing del pipeline tricapa v3.1
🎯 Conecta al puerto 5580 del ML Detector y drena eventos para evitar backpressure
📊 Mantiene métricas simples para verificar el flujo del pipeline

Autor: Alonso Isidoro, Claude
Fecha: Agosto 10, 2025
"""

import zmq
import time
import signal
import sys
import json
from datetime import datetime
from pathlib import Path


class SimpleTricapaConsumer:
    """Consumidor simple para drenar eventos del ML Detector Tricapa v3.1"""

    def __init__(self, port=5580):
        self.port = port
        self.context = zmq.Context()
        self.socket = None
        self.running = True

        # Métricas simples
        self.stats = {
            'total_events': 0,
            'start_time': time.time(),
            'last_log_time': time.time(),
            'events_since_last_log': 0
        }

        # Setup signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Graceful shutdown"""
        print(f"\n🛑 Señal recibida ({signum}), cerrando consumidor...")
        self.running = False

    def setup_socket(self):
        """Configurar socket ZMQ"""
        try:
            self.socket = self.context.socket(zmq.PULL)

            # Configuración conservadora pero eficiente
            self.socket.setsockopt(zmq.RCVHWM, 1000)
            self.socket.setsockopt(zmq.RCVTIMEO, 100)  # 100ms timeout
            self.socket.setsockopt(zmq.LINGER, 0)

            self.socket.connect(f"tcp://localhost:{self.port}")
            print(f"✅ Consumidor conectado a ML Detector Tricapa (puerto {self.port})")
            return True

        except Exception as e:
            print(f"❌ Error configurando socket: {e}")
            return False

    def log_stats(self, force=False):
        """Log estadísticas cada cierto tiempo"""
        current_time = time.time()

        # Log cada 10 segundos o si es forzado
        if force or (current_time - self.stats['last_log_time']) >= 10:
            elapsed_total = current_time - self.stats['start_time']
            elapsed_period = current_time - self.stats['last_log_time']

            # Rate calculations
            total_rate = self.stats['total_events'] / elapsed_total if elapsed_total > 0 else 0
            period_rate = self.stats['events_since_last_log'] / elapsed_period if elapsed_period > 0 else 0

            print(f"📊 Eventos drenados: {self.stats['total_events']} "
                  f"(total: {total_rate:.1f}/s, período: {period_rate:.1f}/s)")

            # Reset period stats
            self.stats['last_log_time'] = current_time
            self.stats['events_since_last_log'] = 0

    def consume_events(self):
        """Loop principal de consumo"""
        print("🔄 Iniciando drenado de eventos tricapa...")
        print("💡 Presiona Ctrl+C para detener")

        consecutive_timeouts = 0
        max_consecutive_timeouts = 50  # ~5 segundos sin eventos

        while self.running:
            try:
                # Intentar recibir evento
                protobuf_data = self.socket.recv(zmq.NOBLOCK)

                # Evento recibido exitosamente
                self.stats['total_events'] += 1
                self.stats['events_since_last_log'] += 1
                consecutive_timeouts = 0

                # Log periódico
                self.log_stats()

                # Opcional: analizar el evento (solo para debugging)
                if len(sys.argv) > 1 and sys.argv[1] == "--debug":
                    self.debug_event(protobuf_data)

            except zmq.Again:
                # No hay eventos disponibles
                consecutive_timeouts += 1

                # Si no hay eventos por un tiempo, log de estado
                if consecutive_timeouts >= max_consecutive_timeouts:
                    print("⏳ Esperando eventos del ML Detector...")
                    consecutive_timeouts = 0

                time.sleep(0.1)  # 100ms sleep
                continue

            except Exception as e:
                print(f"❌ Error procesando evento: {e}")
                time.sleep(0.1)
                continue

    def debug_event(self, protobuf_data):
        """Debug opcional del evento (solo si --debug)"""
        try:
            # Información básica sin deserializar completamente
            size = len(protobuf_data)

            # Log cada 50 eventos en modo debug
            if self.stats['total_events'] % 50 == 0:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"🔍 [{timestamp}] Evento #{self.stats['total_events']}: {size} bytes")

        except Exception as e:
            print(f"⚠️ Error en debug: {e}")

    def run(self):
        """Ejecutar consumidor"""
        print("🚀 SIMPLE TRICAPA CONSUMER v3.1")
        print("=" * 50)

        if not self.setup_socket():
            return 1

        try:
            self.consume_events()
        except Exception as e:
            print(f"❌ Error fatal: {e}")
            return 1
        finally:
            self.shutdown()

        return 0

    def shutdown(self):
        """Cierre graceful"""
        elapsed = time.time() - self.stats['start_time']
        rate = self.stats['total_events'] / elapsed if elapsed > 0 else 0

        print(f"\n📊 RESUMEN FINAL:")
        print(f"   🎯 Total eventos: {self.stats['total_events']}")
        print(f"   ⏱️ Tiempo total: {elapsed:.1f}s")
        print(f"   📈 Rate promedio: {rate:.1f} eventos/s")

        if self.socket:
            self.socket.close()
        self.context.term()

        print("✅ Consumidor cerrado correctamente")


def main():
    """Función principal"""

    # Help
    if len(sys.argv) > 1 and sys.argv[1] in ["-h", "--help"]:
        print("🎯 SIMPLE TRICAPA CONSUMER v3.1")
        print("=" * 40)
        print("Uso:")
        print("  python simple_consumer_v31.py           # Modo normal")
        print("  python simple_consumer_v31.py --debug   # Modo debug")
        print()
        print("Descripción:")
        print("  Drena eventos del ML Detector Tricapa (puerto 5580)")
        print("  para evitar backpressure durante testing")
        return 0

    # Puerto personalizable via variable de entorno
    import os
    port = int(os.environ.get('ML_DETECTOR_PORT', 5580))

    try:
        consumer = SimpleTricapaConsumer(port=port)
        return consumer.run()
    except KeyboardInterrupt:
        print("\n🛑 Interrupción por usuario")
        return 0
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())