#!/usr/bin/env python3
"""
🔧 Test de Conexión ZeroMQ 5559
Verifica que el Enhanced Promiscuous Agent esté enviando eventos
"""

import zmq
import time
import logging
from datetime import datetime

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Intentar importar protobuf
PROTOBUF_AVAILABLE = False
try:
    from src.protocols.protobuf import network_event_pb2

    PROTOBUF_AVAILABLE = True
    logger.info("✅ Protobuf disponible: src.protocols.protobuf.network_event_pb2")
except ImportError:
    try:
        import network_event_pb2

        PROTOBUF_AVAILABLE = True
        logger.info("✅ Protobuf disponible: directorio local")
    except ImportError:
        logger.warning("⚠️ Protobuf NO disponible - eventos se mostrarán como raw bytes")


def test_zmq_connection():
    """Test de conexión a ZeroMQ 5559"""
    print("🔧 TEST DE CONEXIÓN ZeroMQ 5559")
    print("=" * 40)
    print(f"📦 Protobuf disponible: {PROTOBUF_AVAILABLE}")
    print("🎯 Conectando a tcp://localhost:5559...")
    print("⏱️ Esperando eventos por 30 segundos...")
    print("🛑 Presiona Ctrl+C para detener")
    print("")

    context = None
    socket = None
    events_received = 0
    events_with_gps = 0

    try:
        # Configurar ZeroMQ
        context = zmq.Context()
        socket = context.socket(zmq.SUB)
        socket.connect("tcp://localhost:5559")
        socket.setsockopt(zmq.SUBSCRIBE, b"")
        socket.setsockopt(zmq.RCVTIMEO, 1000)  # Timeout 1 segundo

        print("✅ Conectado a ZeroMQ puerto 5559")

        start_time = time.time()
        last_event_time = None

        while time.time() - start_time < 30:  # 30 segundos máximo
            try:
                # Recibir mensaje
                message = socket.recv(zmq.NOBLOCK)
                events_received += 1
                last_event_time = datetime.now()

                if PROTOBUF_AVAILABLE:
                    # Decodificar protobuf
                    event = network_event_pb2.NetworkEvent()
                    event.ParseFromString(message)

                    has_gps = event.latitude != 0 and event.longitude != 0
                    if has_gps:
                        events_with_gps += 1

                    print(f"📡 Evento #{events_received}: {event.source_ip} → {event.target_ip}")
                    print(f"   🎯 Puerto: {event.dest_port} | Agente: {event.agent_id}")
                    print(f"   📊 Anomalía: {event.anomaly_score:.3f} | Riesgo: {event.risk_score:.3f}")
                    if has_gps:
                        print(f"   🗺️ GPS: {event.latitude:.6f}, {event.longitude:.6f}")
                    print(f"   ⏰ {last_event_time.strftime('%H:%M:%S')}")
                    print("")
                else:
                    # Mostrar bytes raw
                    print(f"📡 Evento #{events_received}: {len(message)} bytes")
                    print(f"   Raw: {message[:50]}{'...' if len(message) > 50 else ''}")
                    print(f"   ⏰ {last_event_time.strftime('%H:%M:%S')}")
                    print("")

            except zmq.Again:
                # No hay mensajes, continuar
                time.sleep(0.1)
                continue

        # Resumen final
        print("📊 RESUMEN DEL TEST:")
        print(f"   ✅ Eventos recibidos: {events_received}")
        if PROTOBUF_AVAILABLE:
            print(f"   🗺️ Eventos con GPS: {events_with_gps}")
            print(f"   📍 Porcentaje GPS: {(events_with_gps / max(1, events_received)) * 100:.1f}%")
        print(f"   ⏰ Último evento: {last_event_time if last_event_time else 'Ninguno'}")

        if events_received > 0:
            print("\n✅ CONEXIÓN EXITOSA - El dashboard funcionará correctamente")
        else:
            print("\n⚠️ NO SE RECIBIERON EVENTOS")
            print("   Verifica que el Enhanced Promiscuous Agent esté:")
            print("   - Ejecutándose correctamente")
            print("   - Enviando eventos al puerto ZeroMQ 5559")
            print("   - Capturando tráfico de red")

    except KeyboardInterrupt:
        print(f"\n🛑 Test interrumpido por usuario")
        print(f"📊 Eventos recibidos hasta ahora: {events_received}")

    except Exception as e:
        print(f"\n❌ ERROR DE CONEXIÓN: {e}")
        print("🔧 Posibles soluciones:")
        print("   1. Verifica que el Enhanced Promiscuous Agent esté ejecutándose")
        print("   2. Confirma que usa el puerto ZeroMQ 5559")
        print("   3. Verifica que no hay firewall bloqueando localhost:5559")

    finally:
        if socket:
            socket.close()
        if context:
            context.term()


if __name__ == "__main__":
    test_zmq_connection()