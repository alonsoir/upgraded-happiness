#!/usr/bin/env python3
"""
🔗 Hybrid Dashboard Connector
Conecta promiscuous_agent.py específicamente con real_zmq_dashboard.py
"""

import zmq
import zmq.asyncio
import asyncio
import json
import re
import sys
import signal
import time
from datetime import datetime


class HybridDashboardConnector:
    def __init__(self):
        self.context = zmq.asyncio.Context()
        self.running = True
        self.message_count = 0
        self.agent_port = 5559  # Puerto por defecto del agente
        self.dashboard_port = None

        signal.signal(signal.SIGINT, self.stop)

    def stop(self, signum=None, frame=None):
        print(f"\n🛑 Deteniendo connector...")
        self.running = False

    def analyze_hybrid_dashboard(self):
        """Analiza la configuración del real_zmq_dashboard.py"""
        print("🔍 ANALIZANDO HYBRID_DASHBOARD.PY")
        print("-" * 40)

        try:
            with open('real_zmq_dashboard.py', 'r', encoding='utf-8') as f:
                content = f.read()

            # Buscar puerto ZMQ
            zmq_patterns = [
                r'tcp://[^:]*:(\d+)',
                r'ZMQ_PORT\s*=\s*(\d+)',
                r'zmq.*port.*?(\d+)',
                r'connect.*?(\d+)',
                r'bind.*?(\d+)'
            ]

            ports_found = []
            for pattern in zmq_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                ports_found.extend([int(p) for p in matches])

            # Buscar puerto HTTP
            http_patterns = [
                r'port\s*=\s*(\d+)',
                r'\.run.*port.*?(\d+)',
                r'HTTP_PORT\s*=\s*(\d+)',
                r'uvicorn.*port.*?(\d+)'
            ]

            http_ports = []
            for pattern in http_patterns:
                matches = re.findall(pattern, content)
                http_ports.extend([int(p) for p in matches])

            # Filtrar puertos comunes ZMQ vs HTTP
            zmq_ports = [p for p in ports_found if p in [5555, 5556, 5557, 5558, 5559, 5560]]
            http_ports = [p for p in http_ports if p >= 8000]

            print(f"✅ Archivo encontrado: real_zmq_dashboard.py")
            print(f"🔧 Puertos ZMQ detectados: {zmq_ports}")
            print(f"🌐 Puertos HTTP detectados: {http_ports}")

            # Determinar puerto ZMQ más probable
            if zmq_ports:
                self.dashboard_port = zmq_ports[0]
                print(f"📡 Puerto ZMQ seleccionado: {self.dashboard_port}")
            else:
                # Puerto por defecto si no se encuentra
                self.dashboard_port = 5560
                print(f"⚠️ No se detectó puerto ZMQ, usando por defecto: {self.dashboard_port}")

            return {
                'zmq_port': self.dashboard_port,
                'http_ports': http_ports,
                'file_exists': True
            }

        except FileNotFoundError:
            print("❌ real_zmq_dashboard.py no encontrado")
            return {'file_exists': False}
        except Exception as e:
            print(f"❌ Error analizando archivo: {e}")
            return {'file_exists': False}

    async def test_agent_connection(self):
        """Verifica si el agente está enviando datos"""
        print(f"\n🧪 PROBANDO CONEXIÓN CON PROMISCUOUS_AGENT")
        print(f"📡 Puerto del agente: {self.agent_port}")
        print("-" * 40)

        test_socket = self.context.socket(zmq.SUB)
        try:
            test_socket.connect(f"tcp://localhost:{self.agent_port}")
            test_socket.setsockopt(zmq.SUBSCRIBE, b"")
            test_socket.setsockopt(zmq.RCVTIMEO, 3000)  # 3 segundos

            print("🔗 Conectado al agente, esperando datos...")
            message = await test_socket.recv_string()

            print("✅ ¡AGENTE DETECTADO ENVIANDO DATOS!")
            print(f"   Tamaño del mensaje: {len(message)} chars")

            # Analizar el mensaje
            try:
                data = json.loads(message)
                print(f"   Formato: JSON válido")
                if isinstance(data, dict):
                    keys = list(data.keys())[:5]
                    print(f"   Campos: {keys}")
            except:
                print(f"   Formato: Texto/Binario")
                print(f"   Preview: {message[:100]}...")

            return True

        except zmq.Again:
            print("❌ TIMEOUT: El agente no está enviando datos")
            print("💡 Ejecutar: sudo python3 promiscuous_agent.py")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
        finally:
            test_socket.close()

    async def start_bridge(self):
        """Inicia el bridge entre agente y dashboard"""
        print(f"\n🌉 INICIANDO BRIDGE PARA HYBRID_DASHBOARD")
        print("=" * 50)
        print(f"📥 Agente (fuente): tcp://localhost:{self.agent_port}")
        print(f"📤 Dashboard (destino): tcp://*:{self.dashboard_port}")

        # Socket para recibir del agente
        subscriber = self.context.socket(zmq.SUB)
        subscriber.connect(f"tcp://localhost:{self.agent_port}")
        subscriber.setsockopt(zmq.SUBSCRIBE, b"")

        # Socket para enviar al dashboard
        publisher = self.context.socket(zmq.PUB)
        publisher.bind(f"tcp://*:{self.dashboard_port}")

        await asyncio.sleep(1)
        print("✅ Bridge iniciado - Conectando datos reales...")
        print("💡 Presiona Ctrl+C para detener")

        last_msg_time = time.time()
        stats_interval = 15  # Estadísticas cada 15 segundos

        while self.running:
            try:
                message = await subscriber.recv_string(zmq.NOBLOCK)

                # Reenviar al dashboard
                await publisher.send_string(message)
                self.message_count += 1
                last_msg_time = time.time()

                # Mostrar estadísticas periódicamente
                if self.message_count % 50 == 0:
                    print(f"📊 {self.message_count} eventos reenviados | {datetime.now().strftime('%H:%M:%S')}")

                # Log del primer mensaje para confirmación
                if self.message_count == 1:
                    print(f"🎉 ¡PRIMER EVENTO REENVIADO AL DASHBOARD!")
                    print(f"   Ahora deberías ver datos reales en real_zmq_dashboard.py")

            except zmq.Again:
                # Verificar si llevamos mucho tiempo sin mensajes
                if time.time() - last_msg_time > 30:
                    print(f"⏰ Sin mensajes por 30s - Verificar que el agente esté activo")
                    last_msg_time = time.time()
                await asyncio.sleep(0.01)
            except Exception as e:
                print(f"❌ Error en bridge: {e}")
                await asyncio.sleep(0.1)

        # Cleanup
        print(f"\n📊 Bridge detenido")
        print(f"   Total eventos procesados: {self.message_count}")
        subscriber.close()
        publisher.close()
        self.context.term()

    async def run_connection_process(self):
        """Ejecuta el proceso completo de conexión"""
        print("🚀 HYBRID DASHBOARD CONNECTOR")
        print("=" * 50)

        # 1. Analizar configuración del dashboard
        config = self.analyze_hybrid_dashboard()
        if not config['file_exists']:
            print("❌ No se puede proceder sin real_zmq_dashboard.py")
            return

        # 2. Verificar que el agente esté enviando datos
        agent_active = await self.test_agent_connection()
        if not agent_active:
            print("\n❌ AGENTE NO ESTÁ ACTIVO")
            print("📋 PASOS PARA ACTIVAR:")
            print("1. Terminal 1: sudo python3 promiscuous_agent.py")
            print("2. Terminal 2: python3 hybrid_dashboard_connector.py")
            print("3. Terminal 3: python3 real_zmq_dashboard.py")
            return

        # 3. Verificar si necesitamos bridge
        if self.agent_port == self.dashboard_port:
            print(f"\n✅ PUERTOS COINCIDEN ({self.agent_port})")
            print("💡 No necesitas bridge, conexión directa debería funcionar")
            print(f"   Ejecutar: python3 real_zmq_dashboard.py")
        else:
            print(f"\n🌉 PUERTOS DIFERENTES - Bridge necesario")
            print(f"   Agente: {self.agent_port} → Dashboard: {self.dashboard_port}")

            # 4. Iniciar bridge
            await self.start_bridge()


async def main():
    connector = HybridDashboardConnector()

    try:
        await connector.run_connection_process()
    except KeyboardInterrupt:
        print("\n👋 Connector detenido por usuario")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("🔗 CONECTANDO PROMISCUOUS_AGENT.PY ↔ HYBRID_DASHBOARD.PY")
    print("=" * 60)
    asyncio.run(main())