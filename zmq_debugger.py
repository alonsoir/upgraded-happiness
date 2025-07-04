#!/usr/bin/env python3
"""
ZeroMQ Debugger - Capturar y analizar mensajes del sistema SCADA
"""

import zmq
import json
import time
from datetime import datetime
import sys
import threading
import signal


class ZMQDebugger:
    def __init__(self):
        self.context = zmq.Context()
        self.should_stop = False
        self.message_count = 0
        self.start_time = time.time()

        # Setup signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signum, frame):
        print("\n🛑 Deteniendo debugger...")
        self.should_stop = True

    def debug_port(self, port, debug_name):
        """Debug específico para un puerto"""
        print(f"\n🔍 Iniciando debug para {debug_name} en puerto {port}")

        try:
            # Crear subscriber
            subscriber = self.context.socket(zmq.SUB)
            subscriber.connect(f"tcp://localhost:{port}")

            # Suscribirse a TODOS los mensajes (sin filtros)
            subscriber.setsockopt(zmq.SUBSCRIBE, b"")

            # Configurar timeout
            subscriber.setsockopt(zmq.RCVTIMEO, 1000)  # 1 segundo timeout

            print(f"✅ Conectado a puerto {port}, escuchando mensajes...")

            message_count = 0
            while not self.should_stop:
                try:
                    # Intentar recibir mensaje
                    if subscriber.poll(1000, zmq.POLLIN):
                        # Recibir mensaje raw
                        message = subscriber.recv(zmq.NOBLOCK)
                        message_count += 1
                        self.message_count += 1

                        print(f"\n📡 [{debug_name}] Mensaje #{message_count}")
                        print(f"⏰ Timestamp: {datetime.now().strftime('%H:%M:%S.%f')}")
                        print(f"📏 Tamaño: {len(message)} bytes")

                        # Intentar decodificar como diferentes formatos
                        self.analyze_message(message)

                        # Mostrar raw (primeros 200 caracteres)
                        try:
                            raw_str = message.decode('utf-8', errors='ignore')
                            if len(raw_str) > 200:
                                raw_str = raw_str[:200] + "..."
                            print(f"📄 Raw: {raw_str}")
                        except:
                            print(f"📄 Raw (hex): {message[:50].hex()}...")

                        print("-" * 60)

                    else:
                        # No hay mensajes, mostrar estado cada 5 segundos
                        if int(time.time()) % 5 == 0:
                            elapsed = time.time() - self.start_time
                            rate = message_count / max(elapsed, 1)
                            print(f"⏳ [{debug_name}] Esperando mensajes... ({message_count} recibidos, {rate:.1f}/s)")
                            time.sleep(1)

                except zmq.Again:
                    # Timeout - normal
                    continue
                except Exception as e:
                    print(f"❌ Error recibiendo mensaje: {e}")
                    break

            subscriber.close()
            print(f"\n✅ Debug de puerto {port} terminado. Mensajes: {message_count}")

        except Exception as e:
            print(f"❌ Error conectando al puerto {port}: {e}")

    def analyze_message(self, message):
        """Analizar formato del mensaje"""
        try:
            # Intentar JSON
            try:
                json_data = json.loads(message.decode('utf-8'))
                print(f"📋 Formato: JSON")
                print(
                    f"🔧 Estructura: {list(json_data.keys()) if isinstance(json_data, dict) else type(json_data).__name__}")
                if isinstance(json_data, dict):
                    for key, value in list(json_data.items())[:5]:  # Primeros 5 campos
                        value_str = str(value)[:50]
                        print(f"   • {key}: {value_str}")
                return
            except:
                pass

            # Intentar texto plano
            try:
                text = message.decode('utf-8')
                print(f"📋 Formato: Texto plano")
                lines = text.split('\n')[:3]  # Primeras 3 líneas
                for i, line in enumerate(lines):
                    if line.strip():
                        print(f"   {i + 1}: {line.strip()[:80]}")
                return
            except:
                pass

            # Intentar protobuf o binario
            print(f"📋 Formato: Binario/Protobuf")
            print(f"🔧 Primeros bytes: {message[:20].hex()}")

        except Exception as e:
            print(f"❌ Error analizando mensaje: {e}")

    def debug_all_ports(self):
        """Debug todos los puertos conocidos del sistema SCADA"""
        print("🚀 ZeroMQ SCADA Debugger")
        print("=" * 50)

        # Puertos conocidos del sistema SCADA
        ports_to_debug = [
            (5555, "Primary Broker"),
            (5556, "Secondary Broker"),
            (5557, "Broker Alt 1"),
            (5558, "Broker Alt 2"),
            (5559, "Broker Alt 3"),
            (5560, "Broker Alt 4")
        ]

        # Verificar qué puertos están activos
        active_ports = []
        for port, name in ports_to_debug:
            try:
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex(('localhost', port)) == 0:
                        active_ports.append((port, name))
                        print(f"✅ Puerto {port} ({name}) - ACTIVO")
                    else:
                        print(f"❌ Puerto {port} ({name}) - INACTIVO")
            except:
                print(f"❌ Puerto {port} ({name}) - ERROR")

        if not active_ports:
            print("\n❌ No se encontraron puertos ZeroMQ activos")
            print("💡 Asegúrate de que el sistema SCADA esté corriendo")
            return

        print(f"\n🎯 Debuggeando {len(active_ports)} puertos activos...")
        print("💡 Presiona Ctrl+C para detener")

        # Crear thread para cada puerto activo
        threads = []
        for port, name in active_ports:
            thread = threading.Thread(
                target=self.debug_port,
                args=(port, name),
                daemon=True
            )
            threads.append(thread)
            thread.start()

        # Esperar hasta que se detenga
        try:
            while not self.should_stop:
                time.sleep(1)
        except KeyboardInterrupt:
            self.should_stop = True

        # Esperar que terminen los threads
        print("\n⏳ Esperando que terminen los threads...")
        for thread in threads:
            thread.join(timeout=2)

        # Mostrar resumen
        elapsed = time.time() - self.start_time
        print(f"\n📊 RESUMEN:")
        print(f"⏰ Tiempo total: {elapsed:.1f} segundos")
        print(f"📡 Mensajes totales: {self.message_count}")
        print(f"📈 Rate promedio: {self.message_count / max(elapsed, 1):.1f} msg/s")

        if self.message_count == 0:
            print("\n🤔 DIAGNÓSTICO: NO SE RECIBIERON MENSAJES")
            print("Posibles causas:")
            print("1. El agente promiscuo no está enviando mensajes al broker")
            print("2. Los mensajes se envían a un topic específico")
            print("3. El broker está configurado de forma diferente")
            print("4. Los mensajes no pasan por ZeroMQ")

            print("\n💡 SOLUCIONES:")
            print("1. Verificar logs del agente promiscuo")
            print("2. Verificar configuración del broker")
            print("3. Usar network sniffer (tcpdump)")
            print("4. Revisar código del agente promiscuo")

    def debug_single_port(self, port):
        """Debug un puerto específico"""
        print(f"🚀 ZeroMQ Debugger - Puerto {port}")
        print("=" * 40)
        self.debug_port(port, f"Port-{port}")

        # Mostrar resumen
        elapsed = time.time() - self.start_time
        print(f"\n📊 RESUMEN:")
        print(f"⏰ Tiempo: {elapsed:.1f} segundos")
        print(f"📡 Mensajes: {self.message_count}")

    def cleanup(self):
        """Limpiar recursos"""
        self.context.term()


def main():
    debugger = ZMQDebugger()

    try:
        if len(sys.argv) > 1:
            # Debug puerto específico
            port = int(sys.argv[1])
            debugger.debug_single_port(port)
        else:
            # Debug todos los puertos
            debugger.debug_all_ports()
    except ValueError:
        print("❌ Puerto inválido. Uso: python zmq_debugger.py [puerto]")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        debugger.cleanup()


if __name__ == "__main__":
    main()