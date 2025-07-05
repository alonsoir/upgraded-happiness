#!/usr/bin/env python3
"""
🚀 Quick Bridge Fix
Conecta inmediatamente promiscuous_agent.py con el dashboard
"""

import zmq
import asyncio
import zmq.asyncio
import json
import signal
import time
from datetime import datetime


class QuickBridge:
    def __init__(self):
        self.context = zmq.asyncio.Context()
        self.running = True
        self.message_count = 0

        # Manejador de señales
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

    def stop(self, signum=None, frame=None):
        print(f"\n🛑 Deteniendo bridge...")
        self.running = False

    async def start_bridge(self):
        print("🚀 QUICK BRIDGE - Conectando Sistema SCADA")
        print("=" * 50)
        print("📥 Recibiendo de promiscuous_agent.py: tcp://localhost:5559")
        print("📤 Enviando al dashboard: tcp://*:5560")
        print("💡 Presiona Ctrl+C para detener")

        # Socket para recibir del agente promiscuo
        subscriber = self.context.socket(zmq.SUB)
        subscriber.connect("tcp://localhost:5559")
        subscriber.setsockopt(zmq.SUBSCRIBE, b"")  # Todos los mensajes

        # Socket para enviar al dashboard
        publisher = self.context.socket(zmq.PUB)
        publisher.bind("tcp://*:5560")

        # Dar tiempo para establecer conexiones
        await asyncio.sleep(1)
        print("✅ Bridge activo - Esperando eventos del agente...")

        last_stat_time = time.time()

        while self.running:
            try:
                # Intentar recibir mensaje (no bloqueante)
                message = await subscriber.recv_string(zmq.NOBLOCK)

                # Validar y procesar mensaje
                await self.process_and_forward(message, publisher)

                # Estadísticas cada 10 segundos
                if time.time() - last_stat_time > 10:
                    print(f"📊 {self.message_count} eventos procesados | {datetime.now().strftime('%H:%M:%S')}")
                    last_stat_time = time.time()

            except zmq.Again:
                # No hay mensajes, esperar un poco
                await asyncio.sleep(0.01)
            except Exception as e:
                print(f"❌ Error: {e}")
                await asyncio.sleep(0.1)

        # Cleanup
        print(f"\n📊 Bridge detenido - {self.message_count} eventos procesados")
        subscriber.close()
        publisher.close()
        self.context.term()

    async def process_and_forward(self, message: str, publisher):
        """Procesa y reenvía un mensaje"""
        self.message_count += 1

        try:
            # Intentar parsear como JSON para validar
            data = json.loads(message)

            # Reenviar mensaje original
            await publisher.send_string(message)

            # Log del primer mensaje para debug
            if self.message_count == 1:
                print(f"✅ Primer evento recibido:")
                print(f"   Tipo: JSON válido")
                print(f"   Tamaño: {len(message)} chars")
                if isinstance(data, dict) and 'src_ip' in data:
                    print(f"   IP origen: {data.get('src_ip', 'N/A')}")
                    print(f"   Protocolo: {data.get('protocol', 'N/A')}")

        except json.JSONDecodeError:
            # Mensaje no-JSON, pero aún así reenviarlo
            await publisher.send_string(message)
            if self.message_count == 1:
                print(f"⚠️ Primer evento no es JSON válido:")
                print(f"   Tamaño: {len(message)} chars")
                print(f"   Preview: {message[:100]}...")


async def main():
    bridge = QuickBridge()

    print("🔍 Verificando si el agente está enviando datos...")

    # Verificación rápida
    context = zmq.asyncio.Context()
    test_socket = context.socket(zmq.SUB)
    test_socket.connect("tcp://localhost:5559")
    test_socket.setsockopt(zmq.SUBSCRIBE, b"")
    test_socket.setsockopt(zmq.RCVTIMEO, 3000)  # 3 segundos

    try:
        message = await test_socket.recv_string()
        print("✅ ¡Agente detectado enviando datos!")
        test_socket.close()
        context.term()

        # Iniciar el bridge
        await bridge.start_bridge()

    except zmq.Again:
        print("❌ No se detectan datos del agente")
        print("💡 Verifica que esté ejecutándose: sudo python3 promiscuous_agent.py")
        test_socket.close()
        context.term()
    except Exception as e:
        print(f"❌ Error verificando agente: {e}")
        test_socket.close()
        context.term()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Bridge terminado")