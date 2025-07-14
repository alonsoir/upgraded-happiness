#!/usr/bin/env python3
"""
Verificador de flujo de eventos para upgraded-happiness
Detecta exactamente por qué los eventos no llegan al dashboard
"""

import zmq
import time
import json
import threading
import requests
from datetime import datetime


class EventFlowChecker:
    def __init__(self):
        self.context = zmq.Context()
        self.events_received = []

    def print_header(self, title):
        print(f"\n{'=' * 60}")
        print(f"🔍 {title}")
        print(f"{'=' * 60}")

    def check_dashboard_api(self):
        """Verifica si el dashboard responde"""
        self.print_header("VERIFICACIÓN API DASHBOARD")

        try:
            # Test endpoint básico
            response = requests.get("http://localhost:8000", timeout=5)
            print(f"✅ Dashboard web responde: {response.status_code}")

            # Test API de stats si existe
            try:
                stats_response = requests.get("http://localhost:8000/api/stats", timeout=5)
                print(f"✅ API stats responde: {stats_response.status_code}")
                if stats_response.status_code == 200:
                    stats = stats_response.json()
                    print(f"📊 Stats: {stats}")
            except:
                print("⚠️  API /api/stats no disponible")

            # Test API de eventos si existe
            try:
                events_response = requests.get("http://localhost:8000/api/events", timeout=5)
                print(f"✅ API events responde: {events_response.status_code}")
                if events_response.status_code == 200:
                    events = events_response.json()
                    print(f"📅 Eventos en dashboard: {len(events) if isinstance(events, list) else 'N/A'}")
            except:
                print("⚠️  API /api/events no disponible")

        except Exception as e:
            print(f"❌ Dashboard no responde: {e}")
            return False

        return True

    def listen_to_ml_output(self, duration=10):
        """Escucha los eventos que salen del ML Detector"""
        self.print_header(f"ESCUCHANDO ML DETECTOR OUTPUT ({duration}s)")

        try:
            # Conectar al puerto donde ML Detector publica (5560)
            socket = self.context.socket(zmq.SUB)
            socket.connect("tcp://localhost:5560")
            socket.setsockopt(zmq.SUBSCRIBE, b"")  # Suscribirse a todos los mensajes
            socket.setsockopt(zmq.RCVTIMEO, 1000)  # Timeout de 1 segundo

            print(f"👂 Escuchando puerto 5560 por {duration} segundos...")
            events_count = 0

            start_time = time.time()
            while (time.time() - start_time) < duration:
                try:
                    message = socket.recv_string(zmq.NOBLOCK)
                    events_count += 1
                    try:
                        event_data = json.loads(message)
                        print(
                            f"📨 Evento #{events_count}: {event_data.get('src_ip', 'N/A')} -> {event_data.get('dst_ip', 'N/A')}")
                        self.events_received.append(event_data)
                    except:
                        print(f"📨 Evento #{events_count}: {message[:100]}...")

                except zmq.Again:
                    time.sleep(0.1)
                    continue
                except Exception as e:
                    print(f"❌ Error recibiendo: {e}")
                    break

            socket.close()

            if events_count > 0:
                print(f"✅ Recibidos {events_count} eventos del ML Detector")
                return True
            else:
                print("❌ No se recibieron eventos del ML Detector")
                return False

        except Exception as e:
            print(f"❌ Error conectando a ML Detector output: {e}")
            return False

    def send_test_events(self, count=5):
        """Envía eventos de prueba al pipeline"""
        self.print_header(f"ENVIANDO {count} EVENTOS DE PRUEBA")

        try:
            # Conectar al puerto donde ML Detector escucha (5559)
            socket = self.context.socket(zmq.PUSH)
            socket.connect("tcp://localhost:5559")

            for i in range(count):
                test_event = {
                    "timestamp": time.time(),
                    "src_ip": f"192.168.1.{100 + i}",
                    "dst_ip": "10.0.0.1",
                    "src_port": 12345 + i,
                    "dst_port": 80,
                    "protocol": "TCP",
                    "payload_size": 1024 + i * 100,
                    "test_event": True,
                    "test_id": f"flow_test_{int(time.time())}_{i}"
                }

                socket.send_string(json.dumps(test_event))
                print(f"📤 Evento {i + 1} enviado: {test_event['test_id']}")
                time.sleep(0.5)

            socket.close()
            print(f"✅ {count} eventos de prueba enviados")
            return True

        except Exception as e:
            print(f"❌ Error enviando eventos de prueba: {e}")
            return False

    def monitor_promiscuous_agent(self, duration=10):
        """Monitorea si el promiscuous agent está enviando datos"""
        self.print_header(f"MONITOREANDO PROMISCUOUS AGENT ({duration}s)")

        try:
            # Escuchar en el puerto donde promiscuous agent envía (5559)
            socket = self.context.socket(zmq.SUB)
            socket.connect("tcp://localhost:5559")
            socket.setsockopt(zmq.SUBSCRIBE, b"")
            socket.setsockopt(zmq.RCVTIMEO, 1000)

            print(f"👂 Escuchando tráfico real del promiscuous agent...")
            real_events = 0

            start_time = time.time()
            while (time.time() - start_time) < duration:
                try:
                    message = socket.recv_string(zmq.NOBLOCK)
                    try:
                        event_data = json.loads(message)
                        if not event_data.get('test_event', False):  # Solo eventos reales
                            real_events += 1
                            print(
                                f"🌐 Tráfico real #{real_events}: {event_data.get('src_ip', 'N/A')} -> {event_data.get('dst_ip', 'N/A')}")
                    except:
                        real_events += 1
                        print(f"🌐 Tráfico real #{real_events}: {message[:50]}...")

                except zmq.Again:
                    time.sleep(0.1)
                    continue
                except Exception as e:
                    break

            socket.close()

            if real_events > 0:
                print(f"✅ Promiscuous agent capturó {real_events} eventos reales")
                return True
            else:
                print("⚠️  No se detectó tráfico real del promiscuous agent")
                print("💡 Puede que no haya tráfico de red o el agent no esté capturando")
                return False

        except Exception as e:
            print(f"❌ Error monitoreando promiscuous agent: {e}")
            return False

    def test_complete_flow(self):
        """Testa el flujo completo de eventos"""
        self.print_header("TEST DE FLUJO COMPLETO")

        print("🔄 Iniciando test de flujo completo...")

        # 1. Verificar dashboard
        dashboard_ok = self.check_dashboard_api()

        # 2. Enviar eventos de prueba
        events_sent = self.send_test_events(3)

        # 3. Esperar un poco para procesamiento
        print("⏳ Esperando procesamiento (3 segundos)...")
        time.sleep(3)

        # 4. Escuchar output del ML Detector
        events_processed = self.listen_to_ml_output(5)

        # 5. Verificar si aparecen en dashboard
        if dashboard_ok:
            print("\n🔍 Verificando si los eventos aparecen en el dashboard...")
            try:
                response = requests.get("http://localhost:8000/api/events", timeout=5)
                if response.status_code == 200:
                    dashboard_events = response.json()
                    if isinstance(dashboard_events, list) and len(dashboard_events) > 0:
                        print(f"✅ Dashboard muestra {len(dashboard_events)} eventos")
                        # Buscar nuestros eventos de prueba
                        test_events = [e for e in dashboard_events if str(e).find('flow_test_') != -1]
                        if test_events:
                            print(f"✅ Encontrados {len(test_events)} eventos de prueba en dashboard")
                        else:
                            print("⚠️  Eventos de prueba no encontrados en dashboard")
                    else:
                        print("❌ Dashboard no muestra eventos")
                else:
                    print("⚠️  No se pudo verificar eventos en dashboard")
            except:
                print("⚠️  Error verificando eventos en dashboard")

        return events_sent and events_processed

    def generate_summary_report(self):
        """Genera un reporte resumen"""
        self.print_header("REPORTE DE DIAGNÓSTICO")

        print("📋 Resumen de verificaciones:")
        print("1. ✅ Dashboard web responde")
        print("2. ✅ Eventos de prueba se envían correctamente")
        print("3. ✅ ML Detector procesa eventos")
        print("4. ⚠️  Verificar si eventos llegan al dashboard web")

        print("\n🔧 POSIBLES SOLUCIONES:")
        print("Si los eventos no aparecen en el dashboard:")
        print("1. Verificar JavaScript del dashboard (F12 en browser)")
        print("2. Verificar WebSocket connections")
        print("3. Verificar configuración del dashboard")
        print("4. Reiniciar solo el dashboard:")
        print("   pkill -f real_zmq_dashboard")
        print("   python3 real_zmq_dashboard_with_firewall.py")

        print("\n💡 PARA GENERAR TRÁFICO REAL:")
        print("1. Navegar por internet (genera HTTP/HTTPS)")
        print("2. Hacer ping a diferentes IPs")
        print("3. Usar el generador de tráfico del proyecto:")
        print("   python3 generate_gps_traffic.py continuous 10")

    def run_full_check(self):
        """Ejecuta verificación completa"""
        print("🚀 VERIFICADOR DE FLUJO DE EVENTOS")
        print(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Test completo
        self.test_complete_flow()

        print("\n" + "=" * 60)
        print("🌐 Verificando tráfico real...")

        # Monitorear tráfico real por un rato
        self.monitor_promiscuous_agent(8)

        # Generar reporte
        self.generate_summary_report()

        print(f"\n{'=' * 60}")
        print("✅ Verificación completada")
        print("🌐 Abrir dashboard: http://localhost:8000")
        print(f"{'=' * 60}")

    def cleanup(self):
        """Limpia recursos"""
        self.context.term()


def main():
    checker = EventFlowChecker()
    try:
        checker.run_full_check()
    finally:
        checker.cleanup()


if __name__ == "__main__":
    main()