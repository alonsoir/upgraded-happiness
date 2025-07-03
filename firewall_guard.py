import zmq
from src.protocols.protobuf import network_event_pb2
import subprocess

context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect("tcp://localhost:5555")
socket.setsockopt_string(zmq.SUBSCRIBE, '')  # Suscribirse a todos los eventos

def block_ip(ip):
    print(f"[!] Bloqueando IP sospechosa: {ip}")
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

print("firewall_guard.py escuchando eventos...")

while True:
    raw = socket.recv()
    event = network_event_pb2.NetworkEvent()
    event.ParseFromString(raw)

    if event.event_type == "TOR_EXFIL_RISK" and event.risk_score >= 0.8:
        print(f"Evento de alto riesgo detectado: {event.description}")
        block_ip(event.source_ip)
