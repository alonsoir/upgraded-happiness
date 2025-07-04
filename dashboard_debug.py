#!/usr/bin/env python3
"""
Dashboard GIS SCADA con DEBUG EXTENSIVO
Para diagnosticar por qué no aparecen eventos reales
"""

import asyncio
import json
import logging
import socket
import zmq
import zmq.asyncio
from datetime import datetime
import time

# Setup logging muy detallado
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('dashboard_debug.log', mode='w')  # Archivo nuevo cada vez
    ]
)
logger = logging.getLogger(__name__)


class SCADADebugger:
    """Debugger especializado para diagnóstico SCADA"""

    def __init__(self):
        self.context = zmq.asyncio.Context()
        self.subscriber = None
        self.message_count = 0
        self.start_time = time.time()
        self.last_message_time = None

    async def test_zmq_connection(self, port):
        """Test de conexión ZeroMQ con diagnóstico completo"""
        logger.info(f"🧪 Testing ZeroMQ connection to port {port}")

        try:
            # Crear subscriber con configuración debug
            self.subscriber = self.context.socket(zmq.SUB)

            # Configurar opciones de debug
            self.subscriber.setsockopt(zmq.SUBSCRIBE, b"")  # Sin filtros
            self.subscriber.setsockopt(zmq.RCVTIMEO, 2000)  # 2 segundo timeout
            self.subscriber.setsockopt(zmq.LINGER, 0)  # No linger

            logger.info(f"📡 Connecting to tcp://localhost:{port}")
            self.subscriber.connect(f"tcp://localhost:{port}")

            # Esperar un momento para establecer conexión
            await asyncio.sleep(1)

            logger.info(f"✅ Connected to port {port}, starting message loop")
            return True

        except Exception as e:
            logger.error(f"❌ Error connecting to port {port}: {e}")
            return False

    async def debug_message_loop(self, duration=30):
        """Loop de debug para capturar mensajes"""
        logger.info(f"🔄 Starting debug message loop for {duration} seconds")

        end_time = time.time() + duration
        check_interval = 5  # Mostrar estado cada 5 segundos
        last_status = time.time()

        while time.time() < end_time:
            try:
                # Check for messages
                if await self.subscriber.poll(1000, zmq.POLLIN):
                    # Hay mensaje disponible
                    try:
                        # Recibir mensaje raw
                        message_parts = await self.subscriber.recv_multipart(zmq.NOBLOCK)
                        self.message_count += 1
                        self.last_message_time = time.time()

                        logger.info(f"📨 MESSAGE #{self.message_count} RECEIVED!")
                        logger.info(f"   Parts: {len(message_parts)}")

                        for i, part in enumerate(message_parts):
                            logger.info(f"   Part {i}: {len(part)} bytes")

                            # Intentar decodificar
                            try:
                                if len(part) > 0:
                                    # Intentar JSON
                                    try:
                                        json_data = json.loads(part.decode('utf-8'))
                                        logger.info(f"   Part {i} JSON: {json_data}")
                                    except:
                                        # Intentar texto
                                        try:
                                            text_data = part.decode('utf-8')
                                            logger.info(f"   Part {i} TEXT: {text_data[:200]}...")
                                        except:
                                            # Mostrar hex
                                            logger.info(f"   Part {i} HEX: {part[:50].hex()}...")
                            except Exception as decode_error:
                                logger.error(f"   Error decoding part {i}: {decode_error}")

                        logger.info("📨 END OF MESSAGE")

                    except zmq.Again:
                        logger.debug("zmq.Again - no message available")
                    except Exception as recv_error:
                        logger.error(f"❌ Error receiving message: {recv_error}")
                else:
                    # No hay mensajes disponibles
                    logger.debug("No messages available (timeout)")

                # Mostrar estado periódicamente
                current_time = time.time()
                if current_time - last_status >= check_interval:
                    elapsed = current_time - self.start_time
                    rate = self.message_count / max(elapsed, 1)
                    logger.info(
                        f"📊 STATUS: {self.message_count} messages, {rate:.1f}/s, last: {self.last_message_time or 'never'}")
                    last_status = current_time

                # Pequeña pausa para no saturar
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"❌ Error in debug loop: {e}")
                await asyncio.sleep(1)

        logger.info(f"🏁 Debug loop completed")
        self.show_summary()

    def show_summary(self):
        """Mostrar resumen del debug"""
        elapsed = time.time() - self.start_time
        rate = self.message_count / max(elapsed, 1)

        logger.info("=" * 60)
        logger.info("📊 DEBUG SUMMARY")
        logger.info("=" * 60)
        logger.info(f"⏰ Duration: {elapsed:.1f} seconds")
        logger.info(f"📡 Messages received: {self.message_count}")
        logger.info(f"📈 Average rate: {rate:.1f} msg/s")
        logger.info(f"⏱️ Last message: {self.last_message_time or 'never'}")

        if self.message_count == 0:
            logger.warning("🚨 NO MESSAGES RECEIVED!")
            logger.info("🔍 DIAGNOSIS:")
            logger.info("   1. Verify promiscuous agent is sending to this port")
            logger.info("   2. Check if messages use specific topics/channels")
            logger.info("   3. Verify broker configuration")
            logger.info("   4. Check if messages are in different format")
        else:
            logger.info("✅ Messages were received successfully")

        logger.info("=" * 60)

    async def cleanup(self):
        """Cleanup resources"""
        if self.subscriber:
            self.subscriber.close()
        self.context.term()


async def debug_scada_integration():
    """Función principal de debug"""
    logger.info("🚀 SCADA GIS Integration Debugger")
    logger.info("=" * 50)

    # Detectar puertos activos
    ports_to_test = [5555, 5556, 5557, 5558, 5559, 5560]
    active_ports = []

    logger.info("🔍 Detecting active ZeroMQ ports...")
    for port in ports_to_test:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex(('localhost', port)) == 0:
                    active_ports.append(port)
                    logger.info(f"✅ Port {port} is ACTIVE")
                else:
                    logger.info(f"❌ Port {port} is INACTIVE")
        except:
            logger.info(f"❌ Port {port} is ERROR")

    if not active_ports:
        logger.error("❌ No active ZeroMQ ports found!")
        logger.info("💡 Make sure SCADA system is running: make run-daemon")
        return

    # Test cada puerto activo
    for port in active_ports:
        logger.info(f"\n🧪 TESTING PORT {port}")
        logger.info("-" * 30)

        debugger = SCADADebugger()

        if await debugger.test_zmq_connection(port):
            logger.info(f"🔄 Starting 15-second message capture on port {port}")
            await debugger.debug_message_loop(duration=15)
        else:
            logger.error(f"❌ Failed to connect to port {port}")

        await debugger.cleanup()

        # Pausa entre puertos
        logger.info(f"⏸️ Waiting 2 seconds before next port...")
        await asyncio.sleep(2)

    logger.info("\n🏁 All ports tested")
    logger.info(f"📋 Check dashboard_debug.log for detailed logs")


async def main():
    """Main function"""
    try:
        await debug_scada_integration()
    except KeyboardInterrupt:
        logger.info("🛑 Debug interrupted by user")
    except Exception as e:
        logger.error(f"❌ Debug error: {e}")


if __name__ == "__main__":
    print("🚀 SCADA GIS Integration Debugger")
    print("This will test ZeroMQ connections and capture messages")
    print("Check console and dashboard_debug.log for results")
    print("Press Ctrl+C to stop")
    print()

    asyncio.run(main())