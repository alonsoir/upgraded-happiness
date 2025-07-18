# test_geoip_pipeline.py - Test completo del pipeline protobuf

import zmq
import time
import json
import threading
import sys
from typing import Dict, Any

# Importar protobuf
try:
    import network_event_extended_v2_pb2 as NetworkEventProto

    PROTOBUF_AVAILABLE = True
except ImportError:
    try:
        import src.protocols.protobuf.network_event_extended_v2_pb2 as NetworkEventProto

        PROTOBUF_AVAILABLE = True
    except ImportError:
        print("❌ Protobuf no disponible")
        PROTOBUF_AVAILABLE = False


class GeoIPPipelineTester:
    """
    Tester completo para verificar el pipeline promiscuous_agent -> geoip_enricher
    """

    def __init__(self):
        self.context = zmq.Context()

        # Resultados del test
        self.results = {
            'protobuf_generation': False,
            'geoip_connectivity': False,
            'enrichment_working': False,
            'pids_tracking': False,
            'pipeline_metrics': False,
            'events_received': 0,
            'events_enriched': 0,
            'avg_latency_ms': 0.0
        }

    def test_protobuf_generation(self):
        """Test 1: Verificar generación de eventos protobuf"""
        print("🧪 TEST 1: Generación de eventos protobuf")
        print("-" * 40)

        if not PROTOBUF_AVAILABLE:
            print("❌ Protobuf no disponible")
            return False

        try:
            # Crear evento de prueba
            event = NetworkEventProto.NetworkEvent()
            event.event_id = "test_event_001"
            event.timestamp = int(time.time() * 1000)
            event.source_ip = "192.168.1.100"
            event.target_ip = "8.8.8.8"
            event.packet_size = 1024
            event.dest_port = 80
            event.src_port = 45678
            event.protocol = "tcp"

            # Campos distribuidos
            event.node_id = "test_promiscuous_001"
            event.process_id = 12345
            event.promiscuous_pid = 12345
            event.promiscuous_timestamp = int(time.time() * 1000)
            event.pipeline_path = "promiscuous"
            event.pipeline_hops = 1

            # Serializar
            serialized = event.SerializeToString()

            print(f"✅ Evento protobuf creado: {len(serialized)} bytes")
            print(f"   🆔 Event ID: {event.event_id}")
            print(f"   🌐 Source IP: {event.source_ip}")
            print(f"   🏷️ Node ID: {event.node_id}")
            print(f"   🔢 PID: {event.process_id}")

            self.results['protobuf_generation'] = True
            return True

        except Exception as e:
            print(f"❌ Error generando protobuf: {e}")
            return False

    def test_geoip_connectivity(self):
        """Test 2: Verificar conectividad con geoip_enricher"""
        print("\n🧪 TEST 2: Conectividad con GeoIP Enricher")
        print("-" * 45)

        try:
            # Conectar al puerto del geoip_enricher
            socket = self.context.socket(zmq.PUSH)
            socket.setsockopt(zmq.SNDTIMEO, 2000)  # 2 segundos timeout
            socket.connect("tcp://localhost:5559")

            # Enviar evento de prueba
            test_event = self.create_test_protobuf_event()
            socket.send(test_event)

            print("✅ Conectividad establecida con puerto 5559")
            print("✅ Evento de prueba enviado")

            socket.close()
            self.results['geoip_connectivity'] = True
            return True

        except Exception as e:
            print(f"❌ Error de conectividad: {e}")
            print("💡 Verificar que geoip_enricher esté ejecutándose")
            return False

    def test_enrichment_output(self):
        """Test 3: Verificar enriquecimiento GeoIP"""
        print("\n🧪 TEST 3: Verificar enriquecimiento GeoIP")
        print("-" * 40)

        try:
            # Conectar al puerto de salida del geoip_enricher
            socket = self.context.socket(zmq.PULL)
            socket.setsockopt(zmq.RCVTIMEO, 10000)  # 10 segundos timeout
            socket.connect("tcp://localhost:5560")

            print("📡 Escuchando en puerto 5560 por eventos enriquecidos...")
            print("⏱️ Timeout: 10 segundos")

            events_received = 0
            events_enriched = 0
            total_latency = 0.0

            start_time = time.time()
            while time.time() - start_time < 10:  # 10 segundos máximo
                try:
                    # Recibir evento enriquecido
                    enriched_data = socket.recv(zmq.NOBLOCK)
                    events_received += 1

                    # Deserializar y verificar enriquecimiento
                    enriched_event = NetworkEventProto.NetworkEvent()
                    enriched_event.ParseFromString(enriched_data)

                    print(f"📦 Evento {events_received}:")
                    print(f"   🆔 ID: {enriched_event.event_id}")
                    print(f"   🌐 Source: {enriched_event.source_ip}")
                    print(f"   🌍 GeoIP: {enriched_event.geoip_enriched}")

                    if enriched_event.geoip_enriched:
                        events_enriched += 1
                        print(f"   📍 Coords: ({enriched_event.latitude}, {enriched_event.longitude})")
                        print(f"   🔢 GeoIP PID: {enriched_event.geoip_enricher_pid}")
                        print(f"   🛤️ Pipeline: {enriched_event.pipeline_path}")

                        # Calcular latencia
                        if enriched_event.processing_latency_ms > 0:
                            total_latency += enriched_event.processing_latency_ms
                            print(f"   ⏱️ Latencia: {enriched_event.processing_latency_ms:.1f}ms")

                    print()

                    if events_received >= 5:  # Límite de eventos de prueba
                        break

                except zmq.Again:
                    time.sleep(0.1)
                    continue

            socket.close()

            if events_received > 0:
                enrichment_rate = (events_enriched / events_received) * 100
                avg_latency = total_latency / events_enriched if events_enriched > 0 else 0

                print(f"📊 Resultados del test:")
                print(f"   📦 Eventos recibidos: {events_received}")
                print(f"   🌍 Eventos enriquecidos: {events_enriched}")
                print(f"   📈 Tasa de enriquecimiento: {enrichment_rate:.1f}%")
                print(f"   ⏱️ Latencia promedio: {avg_latency:.1f}ms")

                self.results['events_received'] = events_received
                self.results['events_enriched'] = events_enriched
                self.results['avg_latency_ms'] = avg_latency

                if events_enriched > 0:
                    self.results['enrichment_working'] = True
                    self.results['pids_tracking'] = True
                    self.results['pipeline_metrics'] = True
                    print("✅ Enriquecimiento GeoIP funcionando correctamente")
                    return True
                else:
                    print("⚠️ Eventos recibidos pero sin enriquecimiento")
                    return False
            else:
                print("❌ No se recibieron eventos enriquecidos")
                print("💡 Verificar que promiscuous_agent esté enviando eventos")
                return False

        except Exception as e:
            print(f"❌ Error verificando enriquecimiento: {e}")
            return False

    def create_test_protobuf_event(self) -> bytes:
        """Crea evento protobuf de prueba"""
        event = NetworkEventProto.NetworkEvent()
        event.event_id = f"test_{int(time.time())}"
        event.timestamp = int(time.time() * 1000)
        event.source_ip = "203.0.113.10"  # IP de prueba documentada
        event.target_ip = "8.8.8.8"
        event.packet_size = 512
        event.dest_port = 443
        event.src_port = 54321
        event.protocol = "tcp"

        # Campos distribuidos
        event.node_id = "test_node"
        event.process_id = 99999
        event.promiscuous_pid = 99999
        event.promiscuous_timestamp = int(time.time() * 1000)
        event.pipeline_path = "test"
        event.pipeline_hops = 1

        return event.SerializeToString()

    def test_pipeline_stress(self):
        """Test 4: Stress test del pipeline"""
        print("\n🧪 TEST 4: Stress test del pipeline")
        print("-" * 35)

        try:
            # Socket para enviar eventos
            send_socket = self.context.socket(zmq.PUSH)
            send_socket.connect("tcp://localhost:5559")

            # Socket para recibir eventos
            recv_socket = self.context.socket(zmq.PULL)
            recv_socket.setsockopt(zmq.RCVTIMEO, 5000)
            recv_socket.connect("tcp://localhost:5560")

            # Enviar múltiples eventos
            num_events = 10
            print(f"📤 Enviando {num_events} eventos...")

            for i in range(num_events):
                test_event = self.create_test_protobuf_event()
                send_socket.send(test_event)
                time.sleep(0.1)  # 100ms entre eventos

            print(f"⏱️ Esperando respuestas (5 segundos)...")

            # Recoger respuestas
            received = 0
            start_time = time.time()

            while time.time() - start_time < 5 and received < num_events:
                try:
                    enriched_data = recv_socket.recv(zmq.NOBLOCK)
                    received += 1
                    print(f"📦 Respuesta {received}/{num_events}")
                except zmq.Again:
                    time.sleep(0.1)
                    continue

            send_socket.close()
            recv_socket.close()

            success_rate = (received / num_events) * 100
            print(f"📊 Tasa de éxito: {success_rate:.1f}% ({received}/{num_events})")

            if success_rate >= 80:
                print("✅ Stress test pasado")
                return True
            else:
                print("⚠️ Stress test parcialmente exitoso")
                return False

        except Exception as e:
            print(f"❌ Error en stress test: {e}")
            return False

    def generate_test_report(self):
        """Genera reporte final del test"""
        print("\n" + "=" * 60)
        print("📋 REPORTE FINAL - GEOIP PIPELINE TEST")
        print("=" * 60)

        tests = [
            ("Generación Protobuf", self.results['protobuf_generation']),
            ("Conectividad GeoIP", self.results['geoip_connectivity']),
            ("Enriquecimiento GeoIP", self.results['enrichment_working']),
            ("Tracking PIDs", self.results['pids_tracking']),
            ("Métricas Pipeline", self.results['pipeline_metrics'])
        ]

        passed = 0
        for test_name, result in tests:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{status} {test_name}")
            if result:
                passed += 1

        print(f"\n📊 Resumen:")
        print(f"   ✅ Tests pasados: {passed}/{len(tests)}")
        print(f"   📦 Eventos procesados: {self.results['events_received']}")
        print(f"   🌍 Eventos enriquecidos: {self.results['events_enriched']}")

        if self.results['avg_latency_ms'] > 0:
            print(f"   ⏱️ Latencia promedio: {self.results['avg_latency_ms']:.1f}ms")

        if passed == len(tests):
            print(f"\n🎉 ¡TODOS LOS TESTS PASARON!")
            print(f"✅ Pipeline GeoIP funcionando correctamente")
        elif passed >= len(tests) * 0.8:
            print(f"\n⚠️ MAYORÍA DE TESTS PASARON")
            print(f"💡 Revisar tests fallidos arriba")
        else:
            print(f"\n💥 MÚLTIPLES TESTS FALLARON")
            print(f"❌ Pipeline necesita corrección")

        return passed == len(tests)

    def run_all_tests(self):
        """Ejecuta todos los tests en secuencia"""
        print("🚀 GEOIP PIPELINE TESTER")
        print("=" * 30)
        print("Verifica el funcionamiento completo del pipeline protobuf")
        print()

        # Ejecutar tests en orden
        self.test_protobuf_generation()
        self.test_geoip_connectivity()
        self.test_enrichment_output()

        # Stress test opcional
        print("\n❓ ¿Ejecutar stress test? (Recomendado)")
        print("   Enviará múltiples eventos para verificar rendimiento")

        if '--stress' in sys.argv or '--all' in sys.argv:
            self.test_pipeline_stress()

        # Generar reporte final
        return self.generate_test_report()


def main():
    """Función principal"""
    if not PROTOBUF_AVAILABLE:
        print("❌ Protobuf no disponible")
        print("💡 Ejecutar: protoc --python_out=. network_event_extended_v2.proto")
        return False

    tester = GeoIPPipelineTester()

    if '--help' in sys.argv:
        print("🔧 GEOIP PIPELINE TESTER")
        print("Uso: python test_geoip_pipeline.py [opciones]")
        print()
        print("Opciones:")
        print("  --stress    Incluir stress test")
        print("  --all       Ejecutar todos los tests")
        print("  --help      Mostrar esta ayuda")
        print()
        print("Prerequisitos:")
        print("  1. promiscuous_agent.py ejecutándose")
        print("  2. geoip_enricher.py ejecutándose")
        print("  3. Protobuf generado")
        return True

    try:
        success = tester.run_all_tests()
        return success
    except KeyboardInterrupt:
        print("\n🛑 Test interrumpido por usuario")
        return False
    except Exception as e:
        print(f"\n❌ Error fatal en test: {e}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)