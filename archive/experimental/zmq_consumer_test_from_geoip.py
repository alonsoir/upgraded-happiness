#!/usr/bin/env python3
"""
ZMQ Consumer Test - Para recibir datos del geoip_enricher
PATRÓN: PULL CONNECT (cliente) → recibe de PUSH BIND (servidor geoip_enricher)
"""

import zmq
import time
import sys

# Importar protobuf para decodificar si está disponible
PROTOBUF_AVAILABLE = False
try:
    from src.protocols.protobuf import network_event_extended_fixed_pb2

    PROTOBUF_AVAILABLE = True
    print("✅ Protobuf disponible para decodificación")
except ImportError:
    try:
        import network_event_extended_fixed_pb2

        PROTOBUF_AVAILABLE = True
        print("✅ Protobuf disponible para decodificación")
    except ImportError:
        print("ℹ️ Protobuf no disponible - solo hex dump")


def decode_protobuf_event(data):
    """Intentar decodificar evento protobuf"""
    if not PROTOBUF_AVAILABLE:
        return None

    try:
        event = network_event_extended_fixed_pb2.NetworkEvent()
        event.ParseFromString(data)
        return {
            'event_id': event.event_id,
            'source_ip': event.source_ip,
            'target_ip': event.target_ip,
            'latitude': event.latitude,
            'longitude': event.longitude,
            'packet_size': event.packet_size,
            'agent_id': event.agent_id,
            'description': event.description,
            'is_handshake': event.is_initial_handshake
        }
    except Exception as e:
        print(f"❌ Error decodificando protobuf: {e}")
        return None


def main():
    print("🌍 ZMQ CONSUMER TEST - GeoIP Enricher Output")
    print("=" * 60)
    print("Recibe eventos ENRIQUECIDOS con coordenadas geográficas")
    print()

    # Configurar ZMQ context
    context = zmq.Context()

    # Crear socket PULL (cliente)
    socket = context.socket(zmq.PULL)

    # CONNECT al geoip_enricher (servidor)
    address = "tcp://localhost:5560"
    socket.connect(address)

    # Configurar timeout
    socket.setsockopt(zmq.RCVTIMEO, 5000)  # 5 segundos

    print(f"📡 Conectado a {address}")
    print("🎯 Esperando datos ENRIQUECIDOS del geoip_enricher...")
    print("   (Presiona Ctrl+C para detener)")
    print()

    events_received = 0
    bytes_received = 0
    start_time = time.time()
    geo_enriched_count = 0
    handshake_count = 0

    try:
        while True:
            try:
                # Recibir datos
                data = socket.recv()
                events_received += 1
                bytes_received += len(data)

                # Intentar decodificar protobuf
                decoded = decode_protobuf_event(data)

                # Mostrar info detallada para primeros eventos
                if events_received <= 10:
                    print(f"📦 Evento {events_received}: {len(data)} bytes")
                    print(f"   Hex: {data[:32].hex()}")

                    if decoded:
                        print(f"   🆔 Event ID: {decoded['event_id']}")
                        print(f"   📡 Source IP: {decoded['source_ip']}")
                        print(f"   🎯 Target IP: {decoded['target_ip']}")
                        print(f"   🌍 Coordinates: {decoded['latitude']:.4f}, {decoded['longitude']:.4f}")
                        print(f"   📦 Packet Size: {decoded['packet_size']}")
                        print(f"   🤖 Agent: {decoded['agent_id']}")
                        print(f"   🤝 Handshake: {decoded['is_handshake']}")
                        if decoded['description']:
                            print(f"   📝 Description: {decoded['description'][:100]}")

                        # Contar enriquecimientos
                        if decoded['latitude'] != 0.0 or decoded['longitude'] != 0.0:
                            geo_enriched_count += 1
                            print(f"   ✅ GeoIP enriquecido")

                        if decoded['is_handshake']:
                            handshake_count += 1
                            print(f"   🤝 Handshake procesado")

                    print()

                # Estadísticas cada 10 eventos
                elif events_received % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = events_received / elapsed if elapsed > 0 else 0
                    geo_rate = (geo_enriched_count / events_received) * 100 if events_received > 0 else 0

                    print(f"📊 Eventos: {events_received:4d} | "
                          f"Bytes: {bytes_received:6d} | "
                          f"Rate: {rate:5.1f} eventos/s | "
                          f"GeoIP: {geo_rate:4.1f}% | "
                          f"Handshakes: {handshake_count}")

                # Validar que los eventos tienen coordenadas
                if decoded and not decoded['is_handshake']:
                    if decoded['latitude'] == 0.0 and decoded['longitude'] == 0.0:
                        print(f"⚠️ Evento sin coordenadas: {decoded['event_id']}")

            except zmq.Again:
                print("⏱️ Timeout - no hay datos (5s)")
                continue

    except KeyboardInterrupt:
        print("\n🛑 Deteniendo consumer...")

    finally:
        # Estadísticas finales
        elapsed = time.time() - start_time
        rate = events_received / elapsed if elapsed > 0 else 0
        geo_rate = (geo_enriched_count / events_received) * 100 if events_received > 0 else 0

        print(f"\n📊 ESTADÍSTICAS FINALES:")
        print(f"   ⏱️ Tiempo: {elapsed:.1f}s")
        print(f"   📦 Eventos: {events_received}")
        print(f"   📊 Bytes: {bytes_received}")
        print(f"   ⚡ Rate promedio: {rate:.1f} eventos/s")
        print(f"   📏 Tamaño promedio: {bytes_received / max(events_received, 1):.1f} bytes/evento")
        print(f"   🌍 Eventos geo-enriquecidos: {geo_enriched_count} ({geo_rate:.1f}%)")
        print(f"   🤝 Handshakes: {handshake_count}")

        # Validar pipeline
        if events_received > 0:
            print(f"\n✅ VALIDACIÓN DEL PIPELINE:")
            if geo_enriched_count > 0:
                print(f"   ✅ GeoIP enrichment funcionando")
            else:
                print(f"   ⚠️ No se detectó enrichment GeoIP")

            if decoded:
                print(f"   ✅ Protobuf decodificación funcionando")
            else:
                print(f"   ⚠️ Protobuf no disponible o eventos corruptos")

        # Limpiar
        socket.close()
        context.term()
        print("✅ Consumer ZMQ cerrado")


if __name__ == "__main__":
    main()