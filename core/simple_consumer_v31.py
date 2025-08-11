#!/usr/bin/env python3
"""
simple_consumer_v31_fixed.py - Consumer SIMPLE Y EFICAZ para tricapa v3.1
🎯 Se conecta como SUB al ml_detector PUB/SUB
📊 Drena eventos eficientemente sin auto-detección problemática
🚀 Optimizado para el nuevo patrón PUB/SUB

CARACTERÍSTICAS:
- 📡 SUB socket optimizado para PUB/SUB
- 📊 Métricas en tiempo real
- 🛡️ Manejo robusto de errores
- ⚡ Sin lógica de auto-detección problemática
- 🔧 Simple pero efectivo

Autor: Alonso Isidoro, Claude
Fecha: Agosto 11, 2025
Versión: 3.1.2-fixed-simple
"""

import zmq
import time
import signal
import sys
import os
from datetime import datetime


class SimpleTricapaConsumerFixed:
    """Consumer simple y eficaz para drenar eventos del ml_detector PUB/SUB"""

    def __init__(self, port=5580):
        self.port = port
        self.context = zmq.Context()
        self.socket = None
        self.running = True

        # Métricas simples pero útiles
        self.stats = {
            'total_events': 0,
            'start_time': time.time(),
            'last_log_time': time.time(),
            'events_since_last_log': 0,
            'errors': 0
        }

        # Setup signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Graceful shutdown"""
        print(f"\n🛑 Señal recibida ({signum}), cerrando consumer...")
        self.running = False

    def setup_socket(self):
        """Configurar socket SUB optimizado"""
        try:
            print(f"🔌 Configurando consumer SUB para puerto {self.port}...")

            # Crear socket SUB
            self.socket = self.context.socket(zmq.SUB)

            # 📡 CRUCIAL: Suscribirse a TODOS los eventos
            self.socket.setsockopt(zmq.SUBSCRIBE, b"")
            print("📡 Suscrito a TODOS los eventos del ml_detector")

            # Configuración optimizada
            self.socket.setsockopt(zmq.RCVHWM, 1000)
            self.socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 segundo timeout
            self.socket.setsockopt(zmq.LINGER, 0)
            self.socket.setsockopt(zmq.RCVBUF, 131072)  # 128KB buffer

            # Conectar al ml_detector
            address = f"tcp://localhost:{self.port}"
            self.socket.connect(address)

            print(f"✅ Consumer SUB conectado a: {address}")
            print("🔄 Esperando eventos del ml_detector...")
            return True

        except Exception as e:
            print(f"❌ Error configurando socket: {e}")
            return False

    def log_stats(self, force=False):
        """Log estadísticas cada 10 segundos"""
        current_time = time.time()

        if force or (current_time - self.stats['last_log_time']) >= 10:
            elapsed_total = current_time - self.stats['start_time']
            elapsed_period = current_time - self.stats['last_log_time']

            # Calcular rates
            total_rate = self.stats['total_events'] / elapsed_total if elapsed_total > 0 else 0
            period_rate = self.stats['events_since_last_log'] / elapsed_period if elapsed_period > 0 else 0

            print(f"📊 [SUB] Eventos drenados: {self.stats['total_events']} "
                  f"(total: {total_rate:.1f}/s, período: {period_rate:.1f}/s)")

            if self.stats['errors'] > 0:
                print(f"⚠️ Errores: {self.stats['errors']}")

            # Reset period stats
            self.stats['last_log_time'] = current_time
            self.stats['events_since_last_log'] = 0

    def consume_events(self):
        """Loop principal optimizado para drenar eventos"""
        print("🔄 Iniciando drenado de eventos PUB/SUB...")
        print("💡 Presiona Ctrl+C para detener")

        consecutive_timeouts = 0
        max_consecutive_timeouts = 30  # ~30 segundos sin eventos

        while self.running:
            try:
                # Intentar recibir evento
                try:
                    protobuf_data = self.socket.recv(zmq.NOBLOCK)

                    # Evento recibido exitosamente
                    self.stats['total_events'] += 1
                    self.stats['events_since_last_log'] += 1
                    consecutive_timeouts = 0

                    # Debug opcional
                    if "--debug" in sys.argv:
                        self.debug_event(protobuf_data)

                except zmq.Again:
                    # No hay eventos disponibles - esto es normal
                    consecutive_timeouts += 1

                    # Log de estado cada cierto tiempo
                    if consecutive_timeouts >= max_consecutive_timeouts:
                        print("⏳ [SUB] Esperando eventos del ml_detector...")
                        consecutive_timeouts = 0

                    time.sleep(0.1)  # Sleep corto
                    continue

                # Log periódico
                self.log_stats()

            except Exception as e:
                print(f"❌ Error procesando evento: {e}")
                self.stats['errors'] += 1
                time.sleep(0.1)

    def debug_event(self, protobuf_data):
        """Debug opcional del evento"""
        try:
            size = len(protobuf_data)

            # Log cada 50 eventos en modo debug
            if self.stats['total_events'] % 50 == 0:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"🔍 [{timestamp}] [SUB] Evento #{self.stats['total_events']}: {size} bytes")

        except Exception as e:
            print(f"⚠️ Error en debug: {e}")

    def run(self):
        """Ejecutar consumer"""
        print("🚀 SIMPLE TRICAPA CONSUMER v3.1.2-FIXED")
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
        print(f"   ❌ Errores: {self.stats['errors']}")

        if self.socket:
            self.socket.close()
        self.context.term()

        print("✅ Consumer cerrado correctamente")


def main():
    """Función principal"""

    # Help
    if len(sys.argv) > 1 and sys.argv[1] in ["-h", "--help"]:
        print("🎯 SIMPLE TRICAPA CONSUMER v3.1.2-FIXED")
        print("=" * 40)
        print("Uso:")
        print("  python simple_consumer_v31_fixed.py           # Modo normal")
        print("  python simple_consumer_v31_fixed.py --debug   # Con logs debug")
        print("  python simple_consumer_v31_fixed.py --port 5581  # Puerto custom")
        print()
        print("Variables de entorno:")
        print("  ML_DETECTOR_PORT=5580    # Puerto del ml_detector")
        print()
        print("Descripción:")
        print("  Consumer SUB optimizado para drenar eventos del ml_detector PUB")
        return 0

    # Puerto configurable
    port = int(os.environ.get('ML_DETECTOR_PORT', 5580))

    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])

    try:
        consumer = SimpleTricapaConsumerFixed(port=port)
        return consumer.run()
    except KeyboardInterrupt:
        print("\n🛑 Interrupción por usuario")
        return 0
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())