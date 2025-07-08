#!/usr/bin/env python3
import sys
import time
import uuid
from asyncio.log import logger

try:
    from src.protocols.protobuf import network_event_extended_fixed_pb2 as network_event_extended_pb2

    print("✅ Protobuf extendido (corregido) importado exitosamente")
    PROTOBUF_AVAILABLE = True
    EXTENDED_PROTOBUF = True
except ImportError as e:
    print(f"⚠️  Protobuf extendido no disponible: {e}")
    try:
        # Fallback al protobuf original
        from src.protocols.protobuf import network_event_pb2

        print("✅ Protobuf original importado exitosamente")
        PROTOBUF_AVAILABLE = True
        EXTENDED_PROTOBUF = False
    except ImportError as e:
        print(f"❌ Error importando protobuf: {e}")
        sys.exit(1)


# ====== FUNCIÓN create_enhanced_network_event CORREGIDA ======

def create_enhanced_network_event(self, packet):
    """
    Función corregida para crear eventos sin conflictos de protobuf
    """

    if EXTENDED_PROTOBUF:
        # Usar protobuf extendido (namespace corregido)
        event = network_event_extended_pb2.NetworkEvent()
    else:
        # Fallback al protobuf original
        event = network_event_pb2.NetworkEvent()

    # Campos básicos (disponibles en ambos protobuf)
    event.event_id = str(uuid.uuid4())
    event.timestamp = int(time.time())  # Timestamp corregido en segundos
    event.agent_id = self.agent_id

    # Información de red
    if IP in packet:
        event.source_ip = packet[IP].src
        event.target_ip = packet[IP].dst

        # Geolocalización
        src_lat, src_lon, src_source = self.get_geolocation(packet, packet[IP].src)
        event.latitude = src_lat
        event.longitude = src_lon

    # Puertos
    if TCP in packet:
        event.src_port = packet[TCP].sport
        event.dest_port = packet[TCP].dport
    elif UDP in packet:
        event.src_port = packet[UDP].sport
        event.dest_port = packet[UDP].dport

    # Información adicional
    event.packet_size = len(packet)
    event.event_type = "network_capture"
    event.anomaly_score = 0.0
    event.risk_score = 0.0
    event.description = f"Packet captured from {event.source_ip} to {event.target_ip}"

    # CAMPOS EXTENDIDOS (solo si está disponible el protobuf extendido)
    if EXTENDED_PROTOBUF:
        event.so_identifier = self.system_detector.get_so_identifier()

        # Handshake solo en el primer evento
        if self.system_detector.is_first_event():
            node_info = self.system_detector.get_node_info_for_handshake()
            event.is_initial_handshake = True
            event.node_hostname = node_info['node_hostname']
            event.os_version = node_info['os_version']
            event.firewall_status = node_info['firewall_status']
            event.agent_version = node_info['agent_version']

            print(f"📤 Handshake inicial: SO={event.so_identifier}, Host={event.node_hostname}")
        else:
            event.is_initial_handshake = False
            event.node_hostname = ""
            event.os_version = ""
            event.firewall_status = ""
            event.agent_version = ""
    else:
        print("⚠️  Protobuf extendido no disponible - usando básico")

    self.stats['packets_captured'] += 1
    return event


# ====== TAMBIÉN ACTUALIZAR EL MÉTODO packet_handler ======

def packet_handler(self, packet):
    """Handler principal para procesar paquetes capturados - CORREGIDO"""
    try:
        # Crear evento usando función corregida
        event = self.create_enhanced_network_event(packet)

        # Enviar via ZeroMQ
        self.send_event(event)

        # Log periódico de estadísticas
        if self.stats['packets_captured'] % 100 == 0:
            self._log_stats()

    except Exception as e:
        logger.error(f"❌ Error procesando paquete: {e}")
        self.stats['errors'] += 1


# ====== INSTRUCCIONES DE APLICACIÓN ======

print("""
📋 INSTRUCCIONES PARA APLICAR EL FIX:

1. Ejecutar el script de corrección:
   chmod +x fix_protobuf_conflict.sh
   ./fix_protobuf_conflict.sh

2. En tu promiscuous_agent.py, reemplazar:

   ❌ Línea ~27:
   from protobuf import network_event_extended_pb2

   ✅ Por estas líneas:
   try:
       from src.protocols.protobuf import network_event_extended_fixed_pb2 as network_event_extended_pb2
       EXTENDED_PROTOBUF = True
   except ImportError:
       from src.protocols.protobuf import network_event_pb2
       EXTENDED_PROTOBUF = False

3. Actualizar el método create_enhanced_network_event con el código de arriba

4. Probar:
   sudo python promiscuous_agent.py enhanced_agent_config.json

✅ Esto resolverá el conflicto de símbolos de protobuf
""")