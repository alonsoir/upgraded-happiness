#!/usr/bin/env python3
"""
Agente de debug para verificar que se envían eventos
"""

import os
import sys
import time
import traceback

import zmq
from scapy.all import ARP, IP, TCP, UDP, IPv6, sniff

# Agregar el directorio raíz al path
sys.path.insert(0, os.getcwd())

try:
    from src.protocols.protobuf import network_event_pb2

    print("✅ Protobuf importado exitosamente")
except ImportError as e:
    print(f"❌ Error importando protobuf: {e}")
    sys.exit(1)


class DebugAgent:
    def __init__(self, broker_address="tcp://localhost:5555", interface="en0"):
        self.broker_address = broker_address
        self.interface = interface
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUB)
        self.packet_count = 0
        self.sent_count = 0
        self.start_time = time.time()

        print(f"🔧 AGENTE DE DEBUG")
        print(f"📡 Broker: {broker_address}")
        print(f"🌐 Interfaz: {interface}")
        print("=" * 50)

        try:
            self.socket.connect(broker_address)
            print("✅ Conectado al broker ZeroMQ")
        except Exception as e:
            print(f"❌ Error conectando: {e}")
            raise

    def capture_traffic(self, pkt):
        """Procesar paquetes con debug detallado"""
        try:
            self.packet_count += 1

            # Solo procesar IPv4 para mantener consistencia con el agente original
            if pkt.haslayer(IP):
                # Crear evento
                event = network_event_pb2.NetworkEvent()
                event.event_id = f"debug_{int(time.time() * 1000)}_{self.packet_count}"
                event.timestamp = int(pkt.time * 1e9)
                event.source_ip = pkt["IP"].src
                event.target_ip = pkt["IP"].dst
                event.packet_size = len(pkt)
                event.agent_id = "debug-agent"

                # Detectar puertos
                if pkt.haslayer(TCP):
                    event.dest_port = pkt["TCP"].dport
                    event.src_port = pkt["TCP"].sport
                    protocol = "TCP"
                elif pkt.haslayer(UDP):
                    event.dest_port = pkt["UDP"].dport
                    event.src_port = pkt["UDP"].sport
                    protocol = "UDP"
                else:
                    event.dest_port = 0
                    event.src_port = 0
                    protocol = "OTHER"

                # ENVIAR AL BROKER
                try:
                    self.socket.send(event.SerializeToString())
                    self.sent_count += 1

                    # Debug detallado para los primeros 20 eventos
                    if self.sent_count <= 20:
                        print(
                            f"[{self.sent_count:2d}] ✅ ENVIADO: {protocol} {event.source_ip}:{event.src_port} → {event.target_ip}:{event.dest_port}"
                        )
                    elif self.sent_count % 50 == 0:
                        elapsed = time.time() - self.start_time
                        rate = self.sent_count / elapsed
                        print(
                            f"📊 Eventos enviados: {self.sent_count} | Rate: {rate:.1f} evt/s | Paquetes procesados: {self.packet_count}"
                        )

                except Exception as e:
                    print(f"❌ Error enviando evento {self.sent_count}: {e}")

            else:
                # Contar paquetes no-IPv4 pero no enviar
                if self.packet_count <= 10:
                    if pkt.haslayer(IPv6):
                        print(f"[SKIP] IPv6: {pkt[IPv6].src} → {pkt[IPv6].dst}")
                    elif pkt.haslayer(ARP):
                        print(f"[SKIP] ARP")
                    else:
                        print(f"[SKIP] Otro protocolo")

        except Exception as e:
            print(f"❌ Error procesando paquete {self.packet_count}: {e}")
            traceback.print_exc()

    def start_capture(self, duration=60):
        """Iniciar captura por tiempo limitado"""
        print(f"🚀 Iniciando captura por {duration} segundos...")
        print("📝 Solo IPv4 será enviado al broker (como el agente original)")
        print("Ctrl+C para detener\n")

        try:

            def stop_filter(pkt):
                return time.time() - self.start_time > duration

            sniff(
                iface=self.interface,
                prn=self.capture_traffic,
                timeout=duration + 5,
                store=0,
            )

        except KeyboardInterrupt:
            print(f"\n🛑 Captura detenida por usuario")
        except Exception as e:
            print(f"❌ Error durante captura: {e}")
            traceback.print_exc()
        finally:
            self.show_summary()
            self.cleanup()

    def show_summary(self):
        """Mostrar resumen"""
        elapsed = time.time() - self.start_time

        print("\n" + "=" * 50)
        print("📊 RESUMEN DEBUG")
        print("=" * 50)
        print(f"⏱️  Tiempo: {elapsed:.1f}s")
        print(f"📦 Paquetes capturados: {self.packet_count}")
        print(f"📤 Eventos enviados: {self.sent_count}")
        print(f"📈 Rate de envío: {self.sent_count / elapsed:.1f} eventos/s")

        if self.sent_count == 0:
            print("\n❌ NO SE ENVIÓ NINGÚN EVENTO")
            print("Posibles problemas:")
            print("  - Broker no está corriendo")
            print("  - Problemas de conexión ZeroMQ")
            print("  - Solo hay tráfico no-IPv4")
        else:
            print(f"\n✅ {self.sent_count} eventos enviados correctamente")

    def cleanup(self):
        """Limpiar recursos"""
        self.socket.close()
        self.context.term()


if __name__ == "__main__":
    print("🔧 AGENTE DE DEBUG PARA ZEROMQ")

    try:
        agent = DebugAgent()
        agent.start_capture(duration=30)  # 30 segundos

    except PermissionError:
        print("❌ Error de permisos. Ejecuta con sudo:")
        print("sudo python agent_debug.py")
    except Exception as e:
        print(f"❌ Error: {e}")
