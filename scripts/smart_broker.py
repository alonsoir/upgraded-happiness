#!/usr/bin/env python3
import zmq
import socket
import time
import signal
import sys

def find_available_port(start_port=5555):
    for port in range(start_port, start_port + 10):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    return start_port

def start_smart_broker():
    frontend_port = find_available_port(5555)
    backend_port = frontend_port + 1

    print(f"🔌 Iniciando broker en puertos {frontend_port}/{backend_port}")

    context = zmq.Context()

    # Frontend socket (clientes se conectan aquí)
    frontend = context.socket(zmq.ROUTER)
    frontend.bind(f"tcp://*:{frontend_port}")

    # Backend socket (workers se conectan aquí)  
    backend = context.socket(zmq.DEALER)
    backend.bind(f"tcp://*:{backend_port}")

    print(f"✅ Broker ZeroMQ iniciado en {frontend_port}/{backend_port}")

    def signal_handler(signum, frame):
        print("\n🛑 Deteniendo broker...")
        frontend.close()
        backend.close()
        context.term()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Proxy entre frontend y backend
        zmq.proxy(frontend, backend)
    except KeyboardInterrupt:
        pass
    finally:
        frontend.close()
        backend.close()
        context.term()

if __name__ == "__main__":
    start_smart_broker()
