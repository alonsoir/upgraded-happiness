#!/usr/bin/env python3
"""
Herramienta de diagnóstico para el sistema SCADA upgraded-happiness
Identifica problemas en la cadena: Agente -> ZeroMQ -> ML Detector
"""

import zmq
import socket
import psutil
import subprocess
import time
import json
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional


class SCADADiagnostics:
    def __init__(self):
        self.results = {}
        self.zmq_context = None

    def print_header(self, title: str):
        print(f"\n{'=' * 60}")
        print(f"🔍 {title}")
        print(f"{'=' * 60}")

    def print_section(self, title: str):
        print(f"\n📋 {title}")
        print("-" * 40)

    def check_ports(self) -> Dict:
        """Verificar que los puertos ZeroMQ estén disponibles/en uso"""
        self.print_section("Verificación de Puertos ZeroMQ")

        ports_to_check = [5559, 5560, 55565]
        port_status = {}

        for port in ports_to_check:
            try:
                # Intentar conectar al puerto
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('localhost', port))

                if result == 0:
                    port_status[port] = "LISTENING"
                    print(f"✅ Puerto {port}: ACTIVO")
                else:
                    port_status[port] = "NOT_LISTENING"
                    print(f"❌ Puerto {port}: NO ACTIVO")

                sock.close()

            except Exception as e:
                port_status[port] = f"ERROR: {e}"
                print(f"⚠️  Puerto {port}: ERROR - {e}")

        return port_status

    def check_processes(self) -> Dict:
        """Verificar que los procesos del sistema estén ejecutándose"""
        self.print_section("Verificación de Procesos")

        target_processes = [
            "smart_broker",
            "lightweight_ml",
            "promiscuous_agent"
        ]

        process_status = {}

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''

                for target in target_processes:
                    if target in cmdline.lower():
                        process_status[target] = {
                            'pid': proc.info['pid'],
                            'status': 'RUNNING',
                            'cmdline': cmdline
                        }
                        print(f"✅ {target}: PID {proc.info['pid']} - ACTIVO")
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Verificar procesos faltantes
        for target in target_processes:
            if target not in process_status:
                process_status[target] = {'status': 'NOT_RUNNING'}
                print(f"❌ {target}: NO ENCONTRADO")

        return process_status

    def test_zmq_connection(self) -> Dict:
        """Probar conexión directa a ZeroMQ"""
        self.print_section("Test de Conexión ZeroMQ")

        connection_results = {}

        try:
            self.zmq_context = zmq.Context()

            # Test conexión al puerto principal (5559)
            socket_5559 = self.zmq_context.socket(zmq.SUB)
            socket_5559.setsockopt(zmq.SUBSCRIBE, b"")
            socket_5559.setsockopt(zmq.RCVTIMEO, 3000)  # 3 segundos timeout

            try:
                socket_5559.connect("tcp://localhost:5559")
                connection_results['5559'] = "CONNECTED"
                print("✅ Conexión a puerto 5559: EXITOSA")

                # Intentar recibir un mensaje
                try:
                    message = socket_5559.recv_string(zmq.NOBLOCK)
                    connection_results['5559_data'] = "RECEIVING_DATA"
                    print(f"📨 Datos recibidos en 5559: {message[:100]}...")
                except zmq.Again:
                    connection_results['5559_data'] = "NO_DATA"
                    print("⚠️  Puerto 5559 conectado pero sin datos")

            except Exception as e:
                connection_results['5559'] = f"ERROR: {e}"
                print(f"❌ Error conectando a 5559: {e}")
            finally:
                socket_5559.close()

            # Test conexión al puerto secundario (5560)
            socket_5560 = self.zmq_context.socket(zmq.SUB)
            socket_5560.setsockopt(zmq.SUBSCRIBE, b"")
            socket_5560.setsockopt(zmq.RCVTIMEO, 3000)

            try:
                socket_5560.connect("tcp://localhost:5560")
                connection_results['5560'] = "CONNECTED"
                print("✅ Conexión a puerto 5560: EXITOSA")

                try:
                    message = socket_5560.recv_string(zmq.NOBLOCK)
                    connection_results['5560_data'] = "RECEIVING_DATA"
                    print(f"📨 Datos recibidos en 5560: {message[:100]}...")
                except zmq.Again:
                    connection_results['5560_data'] = "NO_DATA"
                    print("⚠️  Puerto 5560 conectado pero sin datos")

            except Exception as e:
                connection_results['5560'] = f"ERROR: {e}"
                print(f"❌ Error conectando a 5560: {e}")
            finally:
                socket_5560.close()

        except Exception as e:
            connection_results['context_error'] = str(e)
            print(f"❌ Error creando contexto ZeroMQ: {e}")

        return connection_results

    def test_message_flow(self) -> Dict:
        """Enviar mensaje de prueba y verificar que llegue"""
        self.print_section("Test de Flujo de Mensajes")

        flow_results = {}

        try:
            if not self.zmq_context:
                self.zmq_context = zmq.Context()

            # Crear publisher para enviar mensaje de prueba
            pub_socket = self.zmq_context.socket(zmq.PUB)
            pub_socket.bind("tcp://*:55999")  # Puerto temporal

            # Crear subscriber para recibir
            sub_socket = self.zmq_context.socket(zmq.SUB)
            sub_socket.setsockopt(zmq.SUBSCRIBE, b"TEST")
            sub_socket.connect("tcp://localhost:55999")

            time.sleep(1)  # Dar tiempo para establecer conexión

            # Enviar mensaje de prueba
            test_message = f"TEST_MESSAGE_{int(time.time())}"
            pub_socket.send_string(test_message)
            print(f"📤 Mensaje enviado: {test_message}")

            # Intentar recibir
            try:
                sub_socket.setsockopt(zmq.RCVTIMEO, 5000)
                received = sub_socket.recv_string()

                if received == test_message:
                    flow_results['local_test'] = "SUCCESS"
                    print("✅ Test local ZeroMQ: EXITOSO")
                else:
                    flow_results['local_test'] = f"MISMATCH: sent={test_message}, received={received}"
                    print(f"⚠️  Mensaje no coincide: enviado={test_message}, recibido={received}")

            except zmq.Again:
                flow_results['local_test'] = "TIMEOUT"
                print("❌ Timeout esperando mensaje de prueba")

            pub_socket.close()
            sub_socket.close()

        except Exception as e:
            flow_results['local_test'] = f"ERROR: {e}"
            print(f"❌ Error en test de flujo: {e}")

        return flow_results

    def check_network_interfaces(self) -> Dict:
        """Verificar interfaces de red disponibles para captura"""
        self.print_section("Verificación de Interfaces de Red")

        interface_results = {}

        try:
            # Obtener interfaces de red
            interfaces = psutil.net_if_addrs()

            for interface, addresses in interfaces.items():
                interface_info = {
                    'addresses': [],
                    'status': 'unknown'
                }

                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        interface_info['addresses'].append(addr.address)

                # Verificar si la interfaz está activa
                stats = psutil.net_if_stats().get(interface)
                if stats:
                    interface_info['status'] = 'UP' if stats.isup else 'DOWN'

                interface_results[interface] = interface_info
                status_icon = "✅" if interface_info['status'] == 'UP' else "❌"
                print(f"{status_icon} {interface}: {interface_info['status']} - {interface_info['addresses']}")

        except Exception as e:
            interface_results['error'] = str(e)
            print(f"❌ Error obteniendo interfaces: {e}")

        return interface_results

    def generate_report(self) -> str:
        """Generar reporte completo de diagnóstico"""
        self.print_header("REPORTE DE DIAGNÓSTICO COMPLETO")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Ejecutar todas las verificaciones
        port_status = self.check_ports()
        process_status = self.check_processes()
        zmq_status = self.test_zmq_connection()
        flow_status = self.test_message_flow()
        network_status = self.check_network_interfaces()

        # Compilar resultados
        report = {
            'timestamp': timestamp,
            'ports': port_status,
            'processes': process_status,
            'zmq_connections': zmq_status,
            'message_flow': flow_status,
            'network_interfaces': network_status
        }

        # Análisis de problemas
        problems = []

        if port_status.get(5559) != "LISTENING":
            problems.append("🚨 Puerto principal ZeroMQ (5559) no está escuchando")

        if port_status.get(5560) != "LISTENING":
            problems.append("⚠️  Puerto secundario ZeroMQ (5560) no está escuchando")

        if process_status.get('smart_broker', {}).get('status') != 'RUNNING':
            problems.append("🚨 Broker ZeroMQ no está ejecutándose")

        if process_status.get('promiscuous_agent', {}).get('status') != 'RUNNING':
            problems.append("🚨 Agente promiscuo no está ejecutándose")

        if zmq_status.get('5555_data') == "NO_DATA":
            problems.append("⚠️  Broker ZeroMQ activo pero sin datos")

        print(f"\n🔍 PROBLEMAS IDENTIFICADOS:")
        if problems:
            for problem in problems:
                print(f"  {problem}")
        else:
            print("  ✅ No se detectaron problemas obvios")

        print(f"\n📊 RECOMENDACIONES:")
        if port_status.get(5559) != "LISTENING":
            print("  1. Ejecutar: make run-broker")
        if process_status.get('promiscuous_agent', {}).get('status') != 'RUNNING':
            print("  2. Ejecutar: sudo python promiscuous_agent.py")
        if zmq_status.get('5559_data') == "NO_DATA":
            print("  3. Verificar que el agente esté enviando datos al broker")
            print("  4. Revisar logs del agente promiscuo")

        # Limpiar contexto ZeroMQ
        if self.zmq_context:
            self.zmq_context.term()

        return json.dumps(report, indent=2)


def main():
    """Función principal"""
    diagnostics = SCADADiagnostics()

    print("🔧 Iniciando diagnóstico del sistema SCADA...")
    print("   Sistema: upgraded-happiness")
    print("   Componentes: ZeroMQ + Scapy + ML")

    try:
        report = diagnostics.generate_report()

        # Guardar reporte
        report_file = f"scada_diagnostic_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            f.write(report)

        print(f"\n💾 Reporte guardado en: {report_file}")

    except KeyboardInterrupt:
        print("\n\n⏹️  Diagnóstico interrumpido por el usuario")
    except Exception as e:
        print(f"\n❌ Error durante diagnóstico: {e}")
    finally:
        print("\n🏁 Diagnóstico completado")


if __name__ == "__main__":
    main()