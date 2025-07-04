#!/usr/bin/env python3
"""
Test de integración entre el sistema SCADA y el dashboard GIS
"""

import asyncio
import json
import zmq
import zmq.asyncio
import time
import random
import socket
from datetime import datetime


class SCADAGISIntegrationTest:
    """Test de integración SCADA-GIS"""

    def __init__(self):
        self.context = zmq.asyncio.Context()
        self.publisher = None
        self.found_ports = []

    def find_scada_ports(self):
        """Buscar puertos activos del sistema SCADA"""
        print("🔍 Buscando puertos activos del sistema SCADA...")
        common_ports = [5555, 5556, 5557, 5558, 5559, 5560, 55565]
        active_ports = []

        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex(('localhost', port))
                    if result == 0:
                        active_ports.append(port)
                        print(f"  ✅ Puerto {port} activo")
                    else:
                        print(f"  ❌ Puerto {port} no activo")
            except Exception as e:
                print(f"  ❌ Error verificando puerto {port}: {e}")

        self.found_ports = active_ports
        return active_ports

    async def test_zmq_publisher(self, port):
        """Test de publicación ZeroMQ"""
        try:
            self.publisher = self.context.socket(zmq.PUB)
            self.publisher.connect(f"tcp://localhost:{port}")

            # Esperar un momento para establecer conexión
            await asyncio.sleep(1)

            print(f"📡 Enviando evento de test al puerto {port}...")

            test_event = {
                "timestamp": datetime.now().isoformat(),
                "type": "test_event",
                "source_ip": "192.168.1.123",
                "destination_ip": "8.8.8.8",
                "protocol": "HTTPS",
                "description": "Test event from SCADA GIS integration test",
                "port_src": 63494,
                "port_dst": 443,
                "bytes": 1024
            }

            await self.publisher.send_json(test_event)
            print(f"  ✅ Evento enviado: {test_event}")
            return True

        except Exception as e:
            print(f"  ❌ Error enviando al puerto {port}: {e}")
            return False

    async def test_multiple_events(self, port):
        """Enviar múltiples eventos de test"""
        if not self.publisher:
            return

        print(f"🚀 Enviando múltiples eventos al puerto {port}...")

        event_templates = [
            {
                "template": "Ethernet → IPv4 → TCP → HTTPS | {}:63494 → {}:443",
                "ips": [("192.168.1.123", "172.64.155.69"), ("192.168.1.100", "8.8.8.8")]
            },
            {
                "template": "Ethernet → IPv4 → UDP → QUIC → Raw-Data | {}:61989 → {}:443",
                "ips": [("192.168.1.123", "142.250.191.3"), ("192.168.1.150", "172.224.53.5")]
            },
            {
                "template": "Ethernet → ARP | {}:0 → {}:0",
                "ips": [("192.168.1.1", "192.168.1.123")]
            },
            {
                "template": "📊 STATS: {} eventos | {:.1f} evt/s | Network monitoring active",
                "ips": None
            }
        ]

        for i in range(10):
            template = random.choice(event_templates)

            if template["ips"] is None:
                # Evento de estadísticas
                event_str = template["template"].format(
                    random.randint(100, 1000),
                    random.uniform(10.0, 50.0)
                )
            else:
                # Evento de tráfico
                src_ip, dst_ip = random.choice(template["ips"])
                event_str = template["template"].format(src_ip, dst_ip)

            event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": f"scada_test_{i}",
                "raw_event": event_str,
                "source": "integration_test"
            }

            try:
                await self.publisher.send_json(event)
                print(f"  📤 Evento {i + 1}: {event_str}")
                await asyncio.sleep(0.5)  # Pausa entre eventos

            except Exception as e:
                print(f"  ❌ Error enviando evento {i + 1}: {e}")

        print("✅ Todos los eventos enviados")

    def check_dashboard_gis_running(self):
        """Verificar si el dashboard GIS está corriendo"""
        print("🔍 Verificando si el dashboard GIS está activo...")

        gis_ports = [8767, 8768, 8769, 8770]
        running_ports = []

        for port in gis_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex(('localhost', port))
                    if result == 0:
                        running_ports.append(port)
                        print(f"  ✅ Dashboard GIS encontrado en puerto {port}")
            except:
                pass

        if running_ports:
            print(f"🎯 Dashboard GIS activo en puertos: {running_ports}")
            for port in running_ports:
                print(f"   🌐 http://localhost:{port}")
        else:
            print("❌ No se encontró dashboard GIS activo")
            print("💡 Inicia el dashboard con: python dashboard_server_gis_scada.py")

        return running_ports

    async def run_integration_test(self):
        """Ejecutar test completo de integración"""
        print("🧪 SCADA GIS Integration Test")
        print("=" * 50)

        # 1. Verificar puertos SCADA
        scada_ports = self.find_scada_ports()
        if not scada_ports:
            print("❌ No se encontraron puertos SCADA activos")
            print("💡 Asegúrate de que el sistema SCADA esté corriendo:")
            print("   make run-daemon")
            return False

        print(f"✅ Sistema SCADA encontrado en puertos: {scada_ports}")

        # 2. Verificar dashboard GIS
        gis_ports = self.check_dashboard_gis_running()
        if not gis_ports:
            print("⚠️ Dashboard GIS no encontrado, pero continuando test...")

        # 3. Test de envío de eventos
        test_port = scada_ports[0]  # Usar el primer puerto encontrado
        success = await self.test_zmq_publisher(test_port)

        if success:
            print(f"✅ Conexión ZeroMQ exitosa al puerto {test_port}")

            # 4. Enviar múltiples eventos
            await self.test_multiple_events(test_port)

            print("\n🎯 Test completado!")
            print("💡 Verifica que los eventos aparezcan en el dashboard GIS")
            if gis_ports:
                print(f"🌐 Dashboard GIS: http://localhost:{gis_ports[0]}")

            return True
        else:
            print("❌ Error en test de integración")
            return False

    async def cleanup(self):
        """Limpiar recursos"""
        if self.publisher:
            self.publisher.close()
        self.context.term()


async def main():
    """Función principal"""
    test = SCADAGISIntegrationTest()

    try:
        success = await test.run_integration_test()

        if success:
            print("\n✅ Test de integración EXITOSO")
            print("📋 Próximos pasos:")
            print("   1. Abrir dashboard GIS en el navegador")
            print("   2. Verificar que aparezcan los eventos en el mapa")
            print("   3. Usar 'Test Event' para generar más eventos")
        else:
            print("\n❌ Test de integración FALLÓ")
            print("🔧 Soluciones:")
            print("   1. Verificar que el sistema SCADA esté corriendo")
            print("   2. Iniciar dashboard GIS: python dashboard_server_gis_scada.py")
            print("   3. Revisar logs para errores")

    except KeyboardInterrupt:
        print("\n🛑 Test interrumpido por el usuario")
    except Exception as e:
        print(f"\n❌ Error en test: {e}")
    finally:
        await test.cleanup()


if __name__ == "__main__":
    asyncio.run(main())