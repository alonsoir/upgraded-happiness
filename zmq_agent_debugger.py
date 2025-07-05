#!/usr/bin/env python3
"""
🔍 ZMQ Agent Debugger
Diagnostica por qué promiscuous_agent.py no está enviando datos a ZeroMQ
"""

import zmq
import zmq.asyncio
import asyncio
import socket
import psutil
import time
import json
import signal
import sys
from datetime import datetime


class ZMQAgentDebugger:
    def __init__(self):
        self.context = zmq.asyncio.Context()
        self.running = True
        signal.signal(signal.SIGINT, self.stop)

    def stop(self, signum=None, frame=None):
        self.running = False

    def check_agent_process(self):
        """Verifica el proceso del agente promiscuo"""
        print("🔍 VERIFICANDO PROCESO PROMISCUOUS_AGENT.PY")
        print("=" * 50)

        agent_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'status']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'promiscuous_agent.py' in cmdline:
                    agent_processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': cmdline,
                        'status': proc.info['status']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if agent_processes:
            for proc in agent_processes:
                print(f"✅ Proceso encontrado:")
                print(f"   PID: {proc['pid']}")
                print(f"   Status: {proc['status']}")
                print(f"   Comando: {proc['cmdline']}")
        else:
            print("❌ No se encontró proceso promiscuous_agent.py")
            return False

        return True

    async def scan_zmq_ports(self, port_range):
        """Escanea puertos ZMQ para encontrar actividad"""
        print(f"\n🔍 ESCANEANDO PUERTOS ZMQ ({port_range[0]}-{port_range[1]})")
        print("-" * 50)

        active_ports = []

        for port in range(port_range[0], port_range[1] + 1):
            try:
                # Probar conexión ZMQ
                test_socket = self.context.socket(zmq.SUB)
                test_socket.connect(f"tcp://localhost:{port}")
                test_socket.setsockopt(zmq.SUBSCRIBE, b"")
                test_socket.setsockopt(zmq.RCVTIMEO, 500)  # 500ms timeout

                try:
                    message = await test_socket.recv_string()
                    print(f"✅ Puerto {port}: ACTIVO - Datos detectados")
                    print(f"   Mensaje: {message[:100]}...")
                    active_ports.append(port)
                except zmq.Again:
                    # Puerto abierto pero sin datos inmediatos
                    # Verificar si está escuchando a nivel TCP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        result = sock.connect_ex(('localhost', port))
                        if result == 0:
                            print(f"🟡 Puerto {port}: TCP abierto, ZMQ sin datos inmediatos")
                        else:
                            print(f"❌ Puerto {port}: Inactivo")
                    except:
                        print(f"❌ Puerto {port}: Error de conexión")
                    finally:
                        sock.close()

                test_socket.close()

            except Exception as e:
                print(f"❌ Puerto {port}: Error - {e}")

        return active_ports

    async def deep_port_analysis(self, port):
        """Análisis profundo de un puerto específico"""
        print(f"\n🔬 ANÁLISIS PROFUNDO PUERTO {port}")
        print("-" * 40)

        stats = {
            'messages_received': 0,
            'total_bytes': 0,
            'message_types': {},
            'sample_messages': []
        }

        subscriber = self.context.socket(zmq.SUB)
        try:
            subscriber.connect(f"tcp://localhost:{port}")
            subscriber.setsockopt(zmq.SUBSCRIBE, b"")
            subscriber.setsockopt(zmq.RCVTIMEO, 1000)  # 1 segundo timeout

            print(f"🔗 Conectado al puerto {port}, analizando por 10 segundos...")

            start_time = time.time()
            while time.time() - start_time < 10 and self.running:
                try:
                    message = await subscriber.recv_string()
                    stats['messages_received'] += 1
                    stats['total_bytes'] += len(message)

                    # Analizar tipo de mensaje
                    try:
                        data = json.loads(message)
                        msg_type = 'JSON'
                        if isinstance(data, dict) and 'protocol' in data:
                            msg_type = f"JSON-{data.get('protocol', 'Unknown')}"
                    except:
                        msg_type = 'RAW'

                    stats['message_types'][msg_type] = stats['message_types'].get(msg_type, 0) + 1

                    # Guardar muestras
                    if len(stats['sample_messages']) < 3:
                        stats['sample_messages'].append(message[:200])

                    # Progreso cada 50 mensajes
                    if stats['messages_received'] % 50 == 0:
                        print(f"📊 {stats['messages_received']} mensajes analizados...")

                except zmq.Again:
                    await asyncio.sleep(0.1)
                    continue

        except Exception as e:
            print(f"❌ Error en análisis: {e}")
        finally:
            subscriber.close()

        # Mostrar resultados
        print(f"\n📊 RESULTADOS DEL ANÁLISIS:")
        print(f"   Mensajes recibidos: {stats['messages_received']}")
        print(f"   Bytes totales: {stats['total_bytes']}")
        print(f"   Rate promedio: {stats['messages_received'] / 10:.1f} msg/s")
        print(f"   Tipos de mensaje: {stats['message_types']}")

        if stats['sample_messages']:
            print(f"\n📄 MUESTRAS DE MENSAJES:")
            for i, sample in enumerate(stats['sample_messages'], 1):
                print(f"   {i}: {sample}...")

        return stats

    async def check_agent_configuration(self):
        """Verifica la configuración del agente"""
        print(f"\n🔧 VERIFICANDO CONFIGURACIÓN DEL AGENTE")
        print("-" * 50)

        try:
            with open('promiscuous_agent.py', 'r', encoding='utf-8') as f:
                content = f.read()

            # Buscar configuración ZMQ
            import re

            # Buscar puertos y configuraciones
            zmq_patterns = [
                r'tcp://[^:]*:(\d+)',
                r'ZMQ_PORT\s*=\s*(\d+)',
                r'port.*?(\d+)',
                r'bind.*?(\d+)',
                r'connect.*?(\d+)'
            ]

            ports_in_code = []
            for pattern in zmq_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                ports_in_code.extend([int(p) for p in matches if p.isdigit()])

            # Buscar keywords importantes
            zmq_keywords = ['zmq', 'ZeroMQ', 'publisher', 'socket', 'send', 'pub']
            found_keywords = []
            for keyword in zmq_keywords:
                if keyword.lower() in content.lower():
                    found_keywords.append(keyword)

            print(f"✅ Archivo del agente encontrado")
            print(f"🔧 Puertos en código: {list(set(ports_in_code))}")
            print(f"📡 Keywords ZMQ encontrados: {found_keywords}")

            # Verificar si está configurado para enviar
            if 'send' in content.lower() and 'zmq' in content.lower():
                print(f"✅ El agente parece estar configurado para enviar datos ZMQ")
            else:
                print(f"⚠️ El agente podría no estar configurado para envío ZMQ")

            return {
                'ports': list(set(ports_in_code)),
                'zmq_configured': len(found_keywords) > 2
            }

        except FileNotFoundError:
            print("❌ promiscuous_agent.py no encontrado en directorio actual")
            return {'ports': [], 'zmq_configured': False}
        except Exception as e:
            print(f"❌ Error analizando configuración: {e}")
            return {'ports': [], 'zmq_configured': False}

    async def generate_fix_recommendations(self, scan_results, config_analysis):
        """Genera recomendaciones para solucionar el problema"""
        print(f"\n💡 RECOMENDACIONES DE SOLUCIÓN")
        print("=" * 50)

        if not scan_results:
            print("❌ NO SE DETECTÓ ACTIVIDAD ZMQ")
            print("\n🔧 POSIBLES SOLUCIONES:")
            print("1. Verificar que el agente tenga permisos sudo:")
            print("   sudo python3 promiscuous_agent.py")

            print("\n2. Verificar logs del agente en otra terminal:")
            print("   tail -f /var/log/syslog | grep promiscuous")

            print("\n3. Forzar restart del agente:")
            print("   pkill -f promiscuous_agent.py")
            print("   sudo python3 promiscuous_agent.py")

            if config_analysis['ports']:
                print(f"\n4. Verificar puertos específicos del código: {config_analysis['ports']}")

        else:
            print(f"✅ ACTIVIDAD ZMQ DETECTADA EN PUERTOS: {scan_results}")
            print("\n🔧 CONFIGURAR BRIDGE:")
            for port in scan_results:
                print(f"   Puerto {port} → Dashboard (5560)")

        print(f"\n🚀 COMANDO DE BRIDGE AUTOMÁTICO:")
        if scan_results:
            source_port = scan_results[0]
            print(f"   python3 -c \"")
            print(f"import zmq, asyncio, zmq.asyncio")
            print(f"async def bridge():")
            print(f"    ctx = zmq.asyncio.Context()")
            print(f"    sub = ctx.socket(zmq.SUB)")
            print(f"    sub.connect('tcp://localhost:{source_port}')")
            print(f"    sub.setsockopt(zmq.SUBSCRIBE, b'')")
            print(f"    pub = ctx.socket(zmq.PUB)")
            print(f"    pub.bind('tcp://*:5560')")
            print(f"    print('Bridge {source_port}→5560 activo')")
            print(f"    while True:")
            print(f"        try:")
            print(f"            msg = await sub.recv_string(zmq.NOBLOCK)")
            print(f"            await pub.send_string(msg)")
            print(f"        except zmq.Again:")
            print(f"            await asyncio.sleep(0.01)")
            print(f"asyncio.run(bridge())\"")

    async def run_full_diagnosis(self):
        """Ejecuta diagnóstico completo"""
        print("🚀 DIAGNÓSTICO COMPLETO DEL AGENTE ZMQ")
        print("=" * 60)

        # 1. Verificar proceso
        process_ok = self.check_agent_process()

        # 2. Analizar configuración
        config = await self.check_agent_configuration()

        # 3. Escanear puertos ZMQ
        active_ports = await self.scan_zmq_ports((5555, 5565))

        # 4. Análisis profundo de puertos activos
        if active_ports:
            print(f"\n🔬 ANÁLISIS PROFUNDO DE PUERTOS ACTIVOS")
            for port in active_ports[:2]:  # Máximo 2 puertos para no saturar
                await self.deep_port_analysis(port)

        # 5. Generar recomendaciones
        await self.generate_fix_recommendations(active_ports, config)

        self.context.term()


async def main():
    debugger = ZMQAgentDebugger()

    try:
        await debugger.run_full_diagnosis()
    except KeyboardInterrupt:
        print("\n👋 Diagnóstico detenido")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("🔍 DIAGNOSTICANDO PROMISCUOUS_AGENT.PY")
    print("=" * 50)
    asyncio.run(main())