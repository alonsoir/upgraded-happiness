import zmq
from src.protocols.protobuff import network_event_pb2  # Importación corregida
from scapy.all import sniff, IP, TCP
import os

# Configura el broker
broker_address = "tcp://localhost:5555"
context = zmq.Context()
socket = context.socket(zmq.PUB)
socket.connect(broker_address)

# Ajusta la interfaz de red (usa 'ifconfig' para verificar, normalmente 'en0' en Wi-Fi)
interface = "en0"

def capture_traffic(pkt):
    if pkt.haslayer(IP):
        event = network_event_pb2.NetworkEvent()
        event.event_id = "evt_" + str(pkt.time)
        event.timestamp = int(pkt.time * 1e9)  # nanosegundos
        event.source_ip = pkt['IP'].src
        event.target_ip = pkt['IP'].dst
        event.packet_size = len(pkt)
        event.dest_port = pkt['TCP'].dport if pkt.haslayer(TCP) else 0
        event.src_port = pkt['TCP'].sport if pkt.haslayer(TCP) else 0
        event.agent_id = "macos-agent"
        socket.send(event.SerializeToString())

# Ajusta permisos de red en macOS
os.system("sudo chmod 644 /dev/bpf*")
sniff(iface=interface, prn=capture_traffic, filter="ip", store=0)