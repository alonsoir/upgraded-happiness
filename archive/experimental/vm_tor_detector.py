import os
import psutil
import time
from datetime import datetime
from pathlib import Path
import socket
import zmq
from src.protocols.protobuf import network_event_pb2

# Config
video_extensions = [".mp4", ".mkv", ".avi"]
scan_path = "/home/usuario/Videos"  # ajusta según entorno
video_recent_seconds = 300  # 5 min
check_interval = 30
agent_id = "vm-tor-detector"

# ZeroMQ
context = zmq.Context()
pub_socket = context.socket(zmq.PUB)
pub_socket.connect("tcp://localhost:5555")

def detect_vm_processes():
    vm_keywords = ["vmware", "VBox", "qemu", "kvm", "virtualbox"]
    found = []
    for proc in psutil.process_iter(attrs=["name"]):
        try:
            name = proc.info["name"].lower()
            if any(k.lower() in name for k in vm_keywords):
                found.append(name)
        except Exception:
            continue
    return found

def detect_tor_process():
    for proc in psutil.process_iter(attrs=["name"]):
        try:
            name = proc.info["name"].lower()
            if "tor" in name:
                return True
        except Exception:
            continue
    return False

def detect_virtual_interfaces():
    suspicious = []
    for iface in psutil.net_if_addrs().keys():
        if iface.startswith(("tun", "tap", "vbox", "virbr", "vmnet")):
            suspicious.append(iface)
    return suspicious

def find_recent_videos():
    now = time.time()
    recent = []
    for path in Path(scan_path).rglob("*"):
        if path.suffix.lower() in video_extensions:
            try:
                if now - path.stat().st_mtime < video_recent_seconds:
                    recent.append(str(path))
            except Exception:
                continue
    return recent

def compute_risk_score(vm_procs, tor_active, ifaces, videos):
    score = 0
    if vm_procs:
        score += 0.3
    if tor_active:
        score += 0.4
    if ifaces:
        score += 0.2
    if videos:
        score += 0.1
    return min(score, 1.0)

def publish_alert(event_id_suffix, risk, description, event_type="GENERIC_ALERT"):
    event = network_event_pb2.NetworkEvent()
    event.event_id = f"{event_type.lower()}_{int(time.time())}_{event_id_suffix}"
    event.timestamp = int(time.time() * 1e9)
    event.source_ip = socket.gethostbyname(socket.gethostname())
    event.agent_id = agent_id
    event.event_type = event_type
    event.risk_score = risk
    event.description = description

    pub_socket.send(event.SerializeToString())


if __name__ == "__main__":
    print("Iniciando vm_tor_detector...")
    while True:
        try:
            vm_procs = detect_vm_processes()
            tor_active = detect_tor_process()
            ifaces = detect_virtual_interfaces()
            videos = find_recent_videos()

            risk = compute_risk_score(vm_procs, tor_active, ifaces, videos)

            if risk > 0.4:
                desc = f"[!] Posible exfiltración vía VM+Tor detectada:\n" \
                       f"VMs: {vm_procs}, Tor: {tor_active}, Ifaces: {ifaces}, Videos: {len(videos)}"
                print(desc)
                publish_alert("tor_exfil", risk, desc, event_type="TOR_EXFIL_RISK")
            else:
                print(f"Estado normal. Risk: {risk:.2f}")

            time.sleep(check_interval)

        except KeyboardInterrupt:
            print("Interrumpido por el usuario.")
            break
