#!/usr/bin/env python3
"""
🔍 Advanced ZeroMQ Debugger - SCADA System
Diagnostica y arregla problemas de comunicación ZeroMQ
"""

import zmq
import zmq.asyncio
import asyncio
import json
import time
import subprocess
import psutil
import socket
import signal
import sys
from datetime import datetime
from typing import List, Dict, Optional


class AdvancedZMQDebugger:
    def __init__(self):
        self.context = zmq.asyncio.Context()
        self.results = {}
        self.running = True

        # Configurar manejador de señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print(f"\n🛑 Señal {signum} recibida - Deteniendo debugger...")
        self.running = False

    async def check_port_usage(self, ports: List[int]) -> Dict[int, Dict]:
        """Verifica qué puertos están en uso"""
        print("🔍 VERIFICANDO PUERTOS ZeroMQ")
        print("=" * 50)

        port_status = {}

        for port in ports:
            status = {
                'tcp_open': False,
                'zmq_responsive': False,
                'process': None,
                'pid': None,
                'messages_received': 0
            }

            # 1. Verificar si el puerto está abierto a nivel TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                result = sock.connect_ex(('localhost', port))
                if result == 0:
                    status['tcp_open'] = True
            except Exception:
                pass
            finally:
                sock.close()

            # 2. Verificar qué proceso usa el puerto
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    for conn in proc.connections():
                        if hasattr(conn, 'laddr') and conn.laddr.port == port:
                            status['process'] = proc.info['name']
                            status['pid'] = proc.info['pid']
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # 3. Probar comunicación ZMQ directa
            zmq_result = await self.test_zmq_communication(port)
            status['zmq_responsive'] = zmq_result['responsive']
            status['messages_received'] = zmq_result['messages']

            port_status[port] = status

            # Reporte del puerto
            if status['zmq_responsive']:
                print(
                    f"✅ Puerto {port}: ZMQ ACTIVO ({status['messages_received']} msgs) - {status['process']} (PID: {status['pid']})")
            elif status['tcp_open']:
                print(
                    f"🟡 Puerto {port}: TCP abierto pero ZMQ sin respuesta - {status['process']} (PID: {status['pid']})")
            else:
                print(f"❌ Puerto {port}: INACTIVO")

        return port_status

    async def test_zmq_communication(self, port: int, timeout: int = 2) -> Dict:
        """Prueba comunicación ZMQ real en un puerto"""
        result = {'responsive': False, 'messages': 0, 'sample_message': None}

        try:
            socket = self.context.socket(zmq.SUB)
            socket.connect(f"tcp://localhost:{port}")
            socket.setsockopt(zmq.SUBSCRIBE, b"")  # Suscribirse a todos
            socket.setsockopt(zmq.RCVTIMEO, timeout * 1000)  # timeout en ms

            # Intentar recibir mensajes durante el timeout
            start_time = time.time()
            while (time.time() - start_time) < timeout:
                try:
                    message = await socket.recv_string(zmq.NOBLOCK)
                    result['messages'] += 1
                    result['responsive'] = True

                    if not result['sample_message']:
                        result['sample_message'] = message[:100] + ("..." if len(message) > 100 else "")

                    # Solo necesitamos confirmar que hay comunicación
                    if result['messages'] >= 3:
                        break

                except zmq.Again:
                    await asyncio.sleep(0.1)
                    continue

            socket.close()

        except Exception as e:
            pass  # Es normal que falle si no hay nada escuchando

        return result

    async def find_dashboard_config(self) -> Dict[str, any]:
        """Busca la configuración del dashboard"""
        print("\n🔍 BUSCANDO CONFIGURACIÓN DEL DASHBOARD")
        print("-" * 50)

        config = {
            'zmq_port': None,
            'dashboard_file': None,
            'running': False,
            'http_port': None
        }

        # Buscar archivos del dashboard
        dashboard_files = [
            'enhanced_protobuf_gis_dashboard.py',
            'real_zmq_dashboard.py',
            'minimal_dashboard.py',
            'ultra_basic_dashboard.py'
        ]

        for filename in dashboard_files:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Buscar configuración ZMQ
                    import re

                    # Buscar puertos ZMQ
                    zmq_patterns = [
                        r'tcp://[^:]*:(\d+)',
                        r'ZMQ_PORT\s*=\s*(\d+)',
                        r'zmq.*port.*?(\d+)',
                    ]

                    for pattern in zmq_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            config['zmq_port'] = int(matches[0])
                            break

                    # Buscar puerto HTTP
                    http_patterns = [
                        r'port=(\d+)',
                        r'\.run.*port.*?(\d+)',
                        r'HTTP_PORT\s*=\s*(\d+)'
                    ]

                    for pattern in http_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            config['http_port'] = int(matches[0])
                            break

                    if config['zmq_port']:
                        config['dashboard_file'] = filename
                        print(f"✅ {filename}: ZMQ={config['zmq_port']}, HTTP={config.get('http_port', 'N/A')}")
                        break

            except FileNotFoundError:
                continue
            except Exception as e:
                print(f"⚠️ Error leyendo {filename}: {e}")

        if not config['dashboard_file']:
            print("❌ No se encontró configuración del dashboard")
        else:
            # Verificar si está ejecutándose
            config['running'] = await self.check_dashboard_running(config.get('http_port', 8000))

        return config

    async def check_dashboard_running(self, http_port: int) -> bool:
        """Verifica si el dashboard está ejecutándose"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://localhost:{http_port}/health', timeout=2) as resp:
                    return resp.status == 200
        except:
            return False

    async def create_smart_bridge(self, source_port: int, target_port: int) -> str:
        """Crea un bridge inteligente entre puertos"""
        print(f"\n🌉 CREANDO BRIDGE INTELIGENTE: {source_port} → {target_port}")
        print("-" * 50)

        bridge_code = f'''#!/usr/bin/env python3
"""
🌉 Smart ZMQ Bridge - Auto-generated
Conecta puerto {source_port} → {target_port}
Generado: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

import zmq
import zmq.asyncio
import asyncio
import json
import signal
import time
from datetime import datetime

class SmartBridge:
    def __init__(self):
        self.context = zmq.asyncio.Context()
        self.running = True
        self.stats = {{'messages': 0, 'errors': 0, 'start_time': time.time()}}

        signal.signal(signal.SIGINT, lambda s, f: setattr(self, 'running', False))

    async def bridge_messages(self):
        print("🌉 SMART BRIDGE INICIADO")
        print(f"📥 Fuente: tcp://localhost:{source_port}")
        print(f"📤 Destino: tcp://*:{target_port}")

        # Socket de entrada
        subscriber = self.context.socket(zmq.SUB)
        subscriber.connect("tcp://localhost:{source_port}")
        subscriber.setsockopt(zmq.SUBSCRIBE, b"")

        # Socket de salida
        publisher = self.context.socket(zmq.PUB)
        publisher.bind(f"tcp://*:{target_port}")

        await asyncio.sleep(1)  # Tiempo para conexiones
        print("✅ Bridge listo - Ctrl+C para detener")

        last_stat_time = time.time()

        while self.running:
            try:
                # Intentar recibir mensaje
                message = await subscriber.recv_string(zmq.NOBLOCK)

                # Procesar y validar
                try:
                    # Verificar si es JSON válido
                    json.loads(message)
                    await publisher.send_string(message)
                    self.stats['messages'] += 1

                except json.JSONDecodeError:
                    # Aún así reenviar mensaje no-JSON
                    await publisher.send_string(message)
                    self.stats['messages'] += 1

                # Estadísticas cada 30 segundos
                if time.time() - last_stat_time > 30:
                    elapsed = time.time() - self.stats['start_time']
                    rate = self.stats['messages'] / max(elapsed, 1)
                    print(f"📊 {{self.stats['messages']}} mensajes ({rate:.1f}/s)")
                    last_stat_time = time.time()

            except zmq.Again:
                await asyncio.sleep(0.01)
            except Exception as e:
                self.stats['errors'] += 1
                if self.stats['errors'] < 10:  # Evitar spam
                    print(f"⚠️ Error: {{e}}")

        # Cleanup
        subscriber.close()
        publisher.close()
        self.context.term()

        elapsed = time.time() - self.stats['start_time']
        print(f"\\n📊 ESTADÍSTICAS FINALES:")
        print(f"   Mensajes: {{self.stats['messages']}}")
        print(f"   Errores: {{self.stats['errors']}}")
        print(f"   Tiempo: {{elapsed:.1f}}s")
        print(f"   Rate: {{self.stats['messages']/max(elapsed,1):.1f}} msg/s")

if __name__ == "__main__":
    bridge = SmartBridge()
    asyncio.run(bridge.bridge_messages())
'''

        filename = f'smart_bridge_{source_port}_to_{target_port}.py'
        with open(filename, 'w') as f:
            f.write(bridge_code)

        print(f"✅ Bridge creado: {filename}")
        print(f"💡 Ejecutar con: python3 {filename}")
        return filename

    async def run_comprehensive_diagnosis(self):
        """Ejecuta diagnóstico completo del sistema"""
        print("🚀 DIAGNÓSTICO COMPLETO ZeroMQ - SISTEMA SCADA")
        print("=" * 60)

        # 1. Verificar puertos comunes
        common_ports = [5555, 5556, 5557, 5558, 5559, 5560, 8000, 8001]
        print(f"🔍 Verificando {len(common_ports)} puertos...")
        port_status = await self.check_port_usage(common_ports)

        # 2. Buscar configuración del dashboard
        dashboard_config = await self.find_dashboard_config()

        # 3. Analizar resultados y generar recomendaciones
        active_zmq_ports = [port for port, status in port_status.items() if status['zmq_responsive']]

        print(f"\\n📊 RESUMEN DEL ANÁLISIS:")
        print(f"✅ Puertos ZMQ activos: {active_zmq_ports}")
        print(f"📋 Dashboard detectado: {dashboard_config.get('dashboard_file', 'No encontrado')}")
        print(f"🔧 Puerto ZMQ del dashboard: {dashboard_config.get('zmq_port', 'No detectado')}")
        print(f"🌐 Dashboard ejecutándose: {'Sí' if dashboard_config.get('running') else 'No'}")

        # 4. Generar recomendaciones
        await self.generate_recommendations(active_zmq_ports, dashboard_config, port_status)

        # 5. Crear soluciones automáticas si es necesario
        if len(active_zmq_ports) > 0 and dashboard_config.get('zmq_port'):
            source_port = active_zmq_ports[0]  # Puerto con datos
            target_port = dashboard_config['zmq_port']  # Puerto que espera el dashboard

            if source_port != target_port:
                bridge_file = await self.create_smart_bridge(source_port, target_port)
                print(f"\\n🔧 SOLUCIÓN AUTOMÁTICA CREADA:")
                print(f"   Archivo: {bridge_file}")
                print(f"   Conecta: puerto {source_port} → puerto {target_port}")

    async def generate_recommendations(self, active_ports, dashboard_config, port_status):
        """Genera recomendaciones basadas en el análisis"""
        print(f"\\n💡 RECOMENDACIONES:")
        print("-" * 30)

        if not active_ports:
            print("❌ NO HAY PUERTOS ZMQ ACTIVOS")
            print("   1. Verificar que promiscuous_agent.py esté ejecutándose:")
            print("      sudo python3 promiscuous_agent.py")
            print("   2. Verificar que simple_broker.py esté ejecutándose:")
            print("      python3 simple_broker.py")
            print("   3. Revisar logs de errores del agente")

        elif not dashboard_config.get('dashboard_file'):
            print("❌ DASHBOARD NO DETECTADO")
            print("   1. Verificar que el archivo del dashboard existe")
            print("   2. Ejecutar dashboard manualmente:")
            print("      python3 minimal_dashboard.py")

        elif not dashboard_config.get('running'):
            print("❌ DASHBOARD NO ESTÁ EJECUTÁNDOSE")
            print(f"   1. Ejecutar: python3 {dashboard_config['dashboard_file']}")
            print(f"   2. Verificar puerto HTTP: {dashboard_config.get('http_port', 8000)}")

        else:
            source_port = active_ports[0]
            target_port = dashboard_config['zmq_port']

            if source_port == target_port:
                print("✅ CONFIGURACIÓN CORRECTA")
                print("   Los puertos coinciden, debería funcionar")
            else:
                print("⚠️ PUERTOS NO COINCIDEN")
                print(f"   Datos en: {source_port}")
                print(f"   Dashboard espera: {target_port}")
                print("   → Se creará un bridge automáticamente")

    async def cleanup(self):
        """Limpia recursos"""
        self.context.term()


async def main():
    debugger = AdvancedZMQDebugger()

    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--port":
            # Modo debug de puerto específico
            port = int(sys.argv[2])
            print(f"🔍 Debuggeando puerto específico: {port}")
            result = await debugger.test_zmq_communication(port, timeout=5)
            print(f"Resultado: {result}")
        else:
            # Diagnóstico completo
            await debugger.run_comprehensive_diagnosis()

    except KeyboardInterrupt:
        print("\\n👋 Debugger detenido por usuario")
    except Exception as e:
        print(f"\\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await debugger.cleanup()


if __name__ == "__main__":
    asyncio.run(main())