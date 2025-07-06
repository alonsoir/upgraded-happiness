#!/usr/bin/env python3
"""
🔧 Simple ZeroMQ Broker - SCADA System
Recibe mensajes del agente promiscuo y los retransmite
"""

import zmq
import time
import threading
import signal
import sys
from datetime import datetime


class SimpleBroker:
    def __init__(self, input_port=5559, output_port=5560):
        self.input_port = input_port
        self.output_port = output_port
        self.running = True
        self.message_count = 0

        # Configurar ZeroMQ
        self.context = zmq.Context()

        # Socket SUB para recibir del agente
        self.subscriber = self.context.socket(zmq.SUB)
        self.subscriber.bind(f"tcp://*:{input_port}")
        self.subscriber.setsockopt(zmq.SUBSCRIBE, b"")  # Suscribirse a todos los mensajes

        # Socket PUB para retransmitir
        self.publisher = self.context.socket(zmq.PUB)
        self.publisher.bind(f"tcp://*:{output_port}")

        # Configurar manejo de señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        print("🔧 Broker Completo ZeroMQ - Sistema SCADA")
        print("=" * 56)
        print(f"Recibe del agente ({input_port}) y retransmite ({output_port})")
        print("=" * 56)

    def signal_handler(self, signum, frame):
        """Manejo limpio de señales"""
        print(f"\n🛑 Señal {signum} recibida. Cerrando broker...")
        self.running = False

    def start_stats_monitor(self):
        """Monitor de estadísticas en hilo separado"""

        def stats_loop():
            last_count = 0
            while self.running:
                time.sleep(10)
                if self.message_count > last_count:
                    print(f"📊 Estado: ✅ ACTIVO | Mensajes: {self.message_count}")
                    last_count = self.message_count
                elif self.message_count == 0:
                    print(f"📊 Estado: ⏳ Esperando primer mensaje | Mensajes: {self.message_count}")

        stats_thread = threading.Thread(target=stats_loop, daemon=True)
        stats_thread.start()

    def run(self):
        """Ejecutar el broker principal"""
        print("🔌 BROKER SIMPLE ZeroMQ - PUB/SUB CON RETRANSMISIÓN")
        print("=" * 56)
        print("Configurado para recibir del agente y retransmitir")
        print("=" * 56)
        print(f"📡 Broker SUB escuchando en puerto {self.input_port}")
        print("   Esperando datos del agente promiscuo...")
        print(f"📤 Broker PUB retransmitiendo en puerto {self.output_port}")
        print("   Listo para retransmitir mensajes recibidos")
        print("🚀 Broker iniciado correctamente")
        print("💡 El agente debería conectarse automáticamente")
        print("⚠️  Ctrl+C para detener")

        # Iniciar monitor de estadísticas
        self.start_stats_monitor()

        try:
            while self.running:
                try:
                    # Recibir mensaje del agente (no bloqueante)
                    message = self.subscriber.recv(zmq.NOBLOCK)
                    self.message_count += 1

                    # Retransmitir inmediatamente
                    self.publisher.send(message)

                    # Log del mensaje
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(
                        f"[{timestamp}] 📨 Mensaje #{self.message_count} recibido ({len(message)} bytes) → RETRANSMITIDO")

                except zmq.Again:
                    # No hay mensajes disponibles, continuar
                    time.sleep(0.1)
                    continue
                except Exception as e:
                    print(f"❌ Error procesando mensaje: {e}")
                    continue

        except KeyboardInterrupt:
            print("\n🛑 Broker detenido por usuario")
        except Exception as e:
            print(f"❌ Error fatal en broker: {e}")
        finally:
            self.cleanup()

    def cleanup(self):
        """Limpieza de recursos"""
        print("🧹 Cerrando broker...")
        self.running = False

        try:
            self.subscriber.close()
            self.publisher.close()
            self.context.term()
            print("✅ Broker cerrado correctamente")
        except Exception as e:
            print(f"⚠️ Error durante limpieza: {e}")


def main():
    """Función principal"""
    try:
        broker = SimpleBroker()
        broker.run()
    except Exception as e:
        print(f"❌ Error iniciando broker: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()