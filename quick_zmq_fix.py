#!/usr/bin/env python3
"""
Fix rápido para problemas ZMQ comunes en upgraded-happiness
"""

import zmq
import json
import time
import threading
from datetime import datetime


class ZMQBridge:
    """Bridge temporal para conectar componentes que no se comunican"""

    def __init__(self):
        self.context = zmq.Context()
        self.running = False

    def ml_detector_bridge(self):
        """Bridge que simula el output del ML Detector si no está funcionando"""
        print("🌉 Iniciando bridge ML Detector...")

        # Input: Escuchar lo que llega al ML Detector
        input_socket = self.context.socket(zmq.SUB)
        input_socket.connect("tcp://localhost:5559")
        input_socket.setsockopt(zmq.SUBSCRIBE, b"")
        input_socket.setsockopt(zmq.RCVTIMEO, 1000)

        # Output: Enviar como lo haría el ML Detector
        output_socket = self.context.socket(zmq.PUSH)
        output_socket.bind("tcp://*:5560")

        self.running = True
        events_processed = 0

        print("✅ Bridge activo - procesando eventos...")

        while self.running:
            try:
                # Recibir evento original
                raw_event = input_socket.recv_string()
                event_data = json.loads(raw_event)

                # Simular procesamiento ML (agregar scores fake)
                enhanced_event = event_data.copy()
                enhanced_event.update({
                    'ml_processed': True,
                    'risk_score': 0.75,  # Score fake para testing
                    'anomaly_score': 0.65,
                    'ml_models_applied': ['IsolationForest', 'OneClassSVM'],
                    'bridge_processed': True,
                    'processing_timestamp': time.time()
                })

                # Enviar evento procesado
                output_socket.send_string(json.dumps(enhanced_event))
                events_processed += 1

                print(
                    f"🔄 Evento #{events_processed} procesado: {event_data.get('src_ip', 'N/A')} -> {event_data.get('dst_ip', 'N/A')}")

            except zmq.Again:
                continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ Error en bridge: {e}")
                time.sleep(1)

        input_socket.close()
        output_socket.close()
        print(f"🛑 Bridge detenido. Eventos procesados: {events_processed}")


class EventGenerator:
    """Generador de eventos para testing"""

    def __init__(self):
        self.context = zmq.Context()

    def generate_test_traffic(self, count=10, interval=2):
        """Genera tráfico de prueba"""
        print(f"📡 Generando {count} eventos de prueba...")

        socket = self.context.socket(zmq.PUSH)
        socket.connect("tcp://localhost:5559")

        for i in range(count):
            test_event = {
                'timestamp': time.time(),
                'src_ip': f'192.168.1.{100 + i}',
                'dst_ip': f'10.0.0.{1 + (i % 10)}',
                'src_port': 10000 + i,
                'dst_port': 80 if i % 2 == 0 else 443,
                'protocol': 'TCP',
                'payload_size': 512 + (i * 100),
                'generated_test': True,
                'test_id': f'fix_test_{int(time.time())}_{i}'
            }

            socket.send_string(json.dumps(test_event))
            print(f"📤 Evento {i + 1}/{count}: {test_event['src_ip']} -> {test_event['dst_ip']}")
            time.sleep(interval)

        socket.close()
        print("✅ Generación de eventos completada")


class DiagnosticListener:
    """Escucha en todos los puertos para diagnosticar flujo"""

    def __init__(self):
        self.context = zmq.Context()

    def listen_all_ports(self, duration=15):
        """Escucha en todos los puertos ZMQ"""
        print(f"👂 Escuchando en todos los puertos por {duration} segundos...")

        listeners = []
        ports = [
            (5559, "Promiscuous -> ML"),
            (5560, "ML -> Dashboard"),
            (5561, "Dashboard -> Firewall")
        ]

        def listen_port(port, description):
            events = 0
            try:
                # Probar SUB primero
                socket = self.context.socket(zmq.SUB)
                socket.connect(f"tcp://localhost:{port}")
                socket.setsockopt(zmq.SUBSCRIBE, b"")
                socket.setsockopt(zmq.RCVTIMEO, 1000)

                start_time = time.time()
                while (time.time() - start_time) < duration:
                    try:
                        message = socket.recv_string()
                        events += 1
                        event_data = json.loads(message)
                        print(f"📨 Puerto {port} ({description}): {event_data.get('src_ip', 'N/A')} [SUB]")
                    except zmq.Again:
                        continue
                    except:
                        break

                socket.close()

            except Exception as e:
                # Si SUB falla, probar PULL
                try:
                    socket = self.context.socket(zmq.PULL)
                    socket.connect(f"tcp://localhost:{port}")
                    socket.setsockopt(zmq.RCVTIMEO, 1000)

                    start_time = time.time()
                    while (time.time() - start_time) < duration:
                        try:
                            message = socket.recv_string()
                            events += 1
                            event_data = json.loads(message)
                            print(f"📨 Puerto {port} ({description}): {event_data.get('src_ip', 'N/A')} [PULL]")
                        except zmq.Again:
                            continue
                        except:
                            break

                    socket.close()

                except Exception as e2:
                    print(f"❌ Puerto {port} ({description}): No accesible ({e2})")

            print(f"📊 Puerto {port}: {events} eventos recibidos")

        # Crear threads para cada puerto
        threads = []
        for port, description in ports:
            thread = threading.Thread(target=listen_port, args=(port, description))
            thread.start()
            threads.append(thread)

        # Esperar a que terminen
        for thread in threads:
            thread.join()

        print("✅ Diagnóstico de puertos completado")


def show_menu():
    """Muestra menú de opciones"""
    print("\n🔧 MENU DE FIXES ZMQ")
    print("===================")
    print("1. 🌉 Bridge ML Detector (si no envía output)")
    print("2. 📡 Generar tráfico de prueba")
    print("3. 👂 Escuchar todos los puertos")
    print("4. 🔄 Test de conectividad completo")
    print("5. 🚪 Salir")
    print()


def test_connectivity():
    """Test rápido de conectividad"""
    print("🔄 Test de conectividad...")

    context = zmq.Context()

    ports_to_test = [
        (5559, zmq.PUSH, "ML Input"),
        (5560, zmq.PUSH, "Dashboard Input"),
        (5561, zmq.PUSH, "Firewall Input")
    ]

    for port, socket_type, description in ports_to_test:
        try:
            socket = context.socket(socket_type)
            socket.connect(f"tcp://localhost:{port}")

            test_msg = json.dumps({
                'test': True,
                'timestamp': time.time(),
                'connectivity_test': description
            })

            socket.send_string(test_msg, zmq.NOBLOCK)
            print(f"✅ {description} (puerto {port}): Conectado")
            socket.close()

        except Exception as e:
            print(f"❌ {description} (puerto {port}): Error - {e}")

    context.term()


def main():
    print("🚀 FIX RÁPIDO ZMQ - upgraded-happiness")
    print(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    while True:
        show_menu()
        choice = input("Selecciona una opción (1-5): ").strip()

        if choice == '1':
            bridge = ZMQBridge()
            try:
                bridge.ml_detector_bridge()
            except KeyboardInterrupt:
                bridge.running = False
                print("\n🛑 Bridge detenido por usuario")

        elif choice == '2':
            generator = EventGenerator()
            count = int(input("Número de eventos (default 10): ") or "10")
            interval = float(input("Intervalo en segundos (default 2): ") or "2")
            generator.generate_test_traffic(count, interval)

        elif choice == '3':
            listener = DiagnosticListener()
            duration = int(input("Duración en segundos (default 15): ") or "15")
            listener.listen_all_ports(duration)

        elif choice == '4':
            test_connectivity()

        elif choice == '5':
            print("👋 ¡Hasta luego!")
            break

        else:
            print("❌ Opción inválida")


if __name__ == "__main__":
    main()