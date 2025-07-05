#!/usr/bin/env python3
"""
Broker ZeroMQ simple para recibir del agente promiscuo (PUB/SUB)
Compatible con la configuración actual del agente
"""

import zmq
import time
import threading
import signal
from datetime import datetime


class SimpleBroker:
    def __init__(self):
        self.running = True
        self.context = zmq.Context()
        self.messages_received = 0
        self.last_message_time = None

        # Configurar manejo de señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print("\n🛑 Deteniendo broker...")
        self.running = False

    def start_subscriber(self, port):
        """Iniciar subscriber para recibir del agente"""
        try:
            # Crear socket SUB para recibir del agente PUB
            sub_socket = self.context.socket(zmq.SUB)
            sub_socket.setsockopt(zmq.SUBSCRIBE, b"")  # Suscribirse a todo
            sub_socket.bind(f"tcp://*:{port}")

            print(f"📡 Broker SUB escuchando en puerto {port}")
            print("   Esperando datos del agente promiscuo...")

            while self.running:
                try:
                    # Recibir datos del agente con timeout
                    sub_socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 segundo
                    binary_data = sub_socket.recv()

                    self.messages_received += 1
                    self.last_message_time = time.time()

                    # RETRANSMITIR al puerto de salida
                    if hasattr(self, 'pub_socket'):
                        try:
                            self.pub_socket.send(binary_data, zmq.NOBLOCK)
                        except zmq.Again:
                            pass  # Si no se puede enviar inmediatamente, continuar

                    # Log cada mensaje recibido
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    size = len(binary_data)
                    print(f"[{timestamp}] 📨 Mensaje #{self.messages_received} recibido ({size} bytes) → RETRANSMITIDO")

                    # Mostrar estadísticas cada 50 mensajes
                    if self.messages_received % 50 == 0:
                        print(f"🔥 Total recibidos: {self.messages_received} mensajes")

                except zmq.Again:
                    # Timeout, continuar
                    pass
                except Exception as e:
                    print(f"❌ Error recibiendo: {e}")
                    break

        except Exception as e:
            print(f"❌ Error configurando subscriber: {e}")
        finally:
            sub_socket.close()

    def start_publisher(self, port):
        """Iniciar publisher para retransmitir a otros componentes"""
        try:
            # Crear socket PUB para retransmitir
            self.pub_socket = self.context.socket(zmq.PUB)
            self.pub_socket.bind(f"tcp://*:{port}")

            print(f"📤 Broker PUB retransmitiendo en puerto {port}")
            print("   Listo para retransmitir mensajes recibidos")

            # Mantener el socket activo
            while self.running:
                time.sleep(1)

        except Exception as e:
            print(f"❌ Error configurando publisher: {e}")
        finally:
            if hasattr(self, 'pub_socket'):
                self.pub_socket.close()

    def run(self):
        """Ejecutar broker completo"""
        print("🔌 BROKER SIMPLE ZeroMQ - PUB/SUB CON RETRANSMISIÓN")
        print("=" * 60)
        print("Configurado para recibir del agente y retransmitir")
        print("=" * 60)

        # Iniciar subscriber en hilo separado (recibir del agente)
        sub_thread = threading.Thread(
            target=self.start_subscriber,
            args=(5559,),  # Puerto donde el agente envía
            daemon=True
        )
        sub_thread.start()

        # Iniciar publisher en hilo separado (retransmitir)
        pub_thread = threading.Thread(
            target=self.start_publisher,
            args=(5560,),  # Puerto para retransmitir
            daemon=True
        )
        pub_thread.start()

        print("\n🚀 Broker iniciado correctamente")
        print("💡 El agente debería conectarse automáticamente")
        print("⚠️  Ctrl+C para detener\n")

        try:
            # Mostrar estadísticas en tiempo real
            while self.running:
                if self.last_message_time:
                    seconds_ago = time.time() - self.last_message_time
                    if seconds_ago < 10:
                        status = "✅ ACTIVO"
                    else:
                        status = f"⚠️ Inactivo ({seconds_ago:.1f}s)"
                else:
                    status = "⏳ Esperando primer mensaje"

                print(f"\r📊 Estado: {status} | Mensajes: {self.messages_received}", end="", flush=True)
                time.sleep(2)

        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            print(f"\n\n🏁 Broker detenido")
            print(f"📈 Total mensajes procesados: {self.messages_received}")

            # Esperar threads
            sub_thread.join(timeout=2)
            pub_thread.join(timeout=2)

            self.context.term()


def main():
    """Función principal"""
    print("🔧 Broker Completo ZeroMQ - Sistema SCADA")
    print("=" * 60)
    print("Recibe del agente (5559) y retransmite (5560)")
    print("=" * 60)

    broker = SimpleBroker()
    broker.run()


if __name__ == "__main__":
    main()