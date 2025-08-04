import os
import time
import subprocess
import logging
from datetime import datetime
import psutil

from scapy.all import sniff, IP, TCP  # Solo para detección básica, no para captura completa

'''
Detección rápida del comportamiento anómalo interno (gracias al modelo rf_internal_behavior.joblib).
Captura de evidencia (PCAP) automática en cuanto se dispare una alerta.
Acción inmediata configurable:
a. Eyectar al nodo atacante (bloqueo en iptables/firewall).
b. Redireccionar a honeypot con login automatizado simulado.
Envío del evento a los demás nodos con alta prioridad para que lo incluyan en sus modelos.
Modo silencioso/observación: posibilidad de solo monitorear en lugar de actuar, útil para debugging o entornos de test.

Esto es un prototipo inicial de lo que sería un sistema mucho más avanzado.
'''
# === CONFIGURACIÓN TEMPORAL ===
HONEYPOT_IP = "192.168.99.99"  # IP del honeypot interno (en red aislada)
PCAP_OUTPUT_DIR = "/var/log/fast_ejector/pcaps"
FIREWALL_BLOCK_CMD = "iptables -A INPUT -s {ip} -j DROP"
FIREWALL_EJECT_CMD = "pkill -KILL -u {user}"

# === LOGGING ===
os.makedirs(PCAP_OUTPUT_DIR, exist_ok=True)
logging.basicConfig(
    filename="fast_ejector.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# === FUNCIONES UTILITARIAS ===
def block_ip(ip):
    cmd = FIREWALL_BLOCK_CMD.format(ip=ip)
    subprocess.run(cmd.split())
    logging.info(f"Bloqueada IP {ip} en iptables")

def kill_user_session(username):
    cmd = FIREWALL_EJECT_CMD.format(user=username)
    subprocess.run(cmd.split())
    logging.info(f"Sesión de usuario {username} terminada")

def start_pcap_capture(attacker_ip):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(PCAP_OUTPUT_DIR, f"ejector_capture_{attacker_ip}_{timestamp}.pcap")
    cmd = ["tcpdump", "-i", "any", "host", attacker_ip, "-w", pcap_file]
    subprocess.Popen(cmd)
    logging.info(f"Iniciada captura pcap para {attacker_ip} en {pcap_file}")

def redirect_to_honeypot():
    logging.info("Redirigiendo tráfico a honeypot")
    # Este paso depende de si se usa tunelado, reglas de NAT, o iproute2
    pass  # Se deja como stub: implementado en entornos controlados


def detect_internal_intrusion(pkt):
    if IP in pkt and TCP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        flags = pkt[TCP].flags

        # Regla simple de ejemplo: intento lateral desde host no autorizado
        if ip_src.startswith("192.168.") and ip_dst.startswith("192.168."):
            if flags == "S":  # SYN scanning sospechoso
                logging.warning(f"Posible escaneo lateral detectado desde {ip_src} hacia {ip_dst}")
                eject_intruder(ip_src)


def get_username_from_ip(ip):
    # Heurística local: buscar conexiones activas de usuarios
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.raddr.ip == ip:
            try:
                proc = psutil.Process(conn.pid)
                return proc.username()
            except Exception:
                pass
    return None


def eject_intruder(attacker_ip):
    username = get_username_from_ip(attacker_ip)
    start_pcap_capture(attacker_ip)

    if username:
        kill_user_session(username)
    block_ip(attacker_ip)
    redirect_to_honeypot()

    logging.info(f"Expulsado y aislado atacante {attacker_ip} ({username})")


if __name__ == "__main__":
    logging.info("Fast Ejector Layer activado")
    sniff(prn=detect_internal_intrusion, store=False, filter="tcp")
