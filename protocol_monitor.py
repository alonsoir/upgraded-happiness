#!/usr/bin/env python3
"""
Monitor de protocolos en tiempo real
Muestra exactamente qué protocolos se están capturando
"""

import os
import sys
import time
import traceback
from collections import Counter, defaultdict

import zmq
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6, sniff
from scapy.layers.http import HTTP

# Agregar el directorio raíz al path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)


class ProtocolMonitor:
    def __init__(self, interface="en0", monitor_time=60):
        self.interface = interface
        self.monitor_time = monitor_time
        self.start_time = time.time()

        # Contadores
        self.protocol_counts = Counter()
        self.port_counts = Counter()
        self.ip_pairs = Counter()
        self.packet_count = 0

        print(f"🔍 MONITOR DE PROTOCOLOS")
        print(f"📡 Interfaz: {interface}")
        print(f"⏱️  Duración: {monitor_time} segundos")
        print(f"🕒 Inicio: {time.strftime('%H:%M:%S')}")
        print("=" * 60)

    def analyze_packet(self, pkt):
        """Analizar cada paquete y clasificar protocolos"""
        try:
            self.packet_count += 1
            protocols = []
            src_ip = "unknown"
            dst_ip = "unknown"
            src_port = 0
            dst_port = 0

            # Analizar capas del paquete
            if pkt.haslayer(ARP):
                protocols.append("ARP")
                src_ip = pkt[ARP].psrc if hasattr(pkt[ARP], "psrc") else "unknown"
                dst_ip = pkt[ARP].pdst if hasattr(pkt[ARP], "pdst") else "unknown"

            elif pkt.haslayer(IPv6):
                protocols.append("IPv6")
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            elif pkt.haslayer(IP):
                protocols.append("IPv4")
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                # Analizar protocolos de transporte
                if pkt.haslayer(TCP):
                    protocols.append("TCP")
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport

                    # Protocolos de aplicación sobre TCP
                    if dst_port == 80 or src_port == 80:
                        protocols.append("HTTP")
                    elif dst_port == 443 or src_port == 443:
                        protocols.append("HTTPS")
                    elif dst_port == 22 or src_port == 22:
                        protocols.append("SSH")
                    elif dst_port == 25 or src_port == 25:
                        protocols.append("SMTP")
                    elif dst_port == 21 or src_port == 21:
                        protocols.append("FTP")
                    elif dst_port == 993 or src_port == 993:
                        protocols.append("IMAPS")
                    elif dst_port == 995 or src_port == 995:
                        protocols.append("POP3S")
                    elif dst_port in [8080, 8443] or src_port in [8080, 8443]:
                        protocols.append("HTTP-ALT")

                elif pkt.haslayer(UDP):
                    protocols.append("UDP")
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport

                    # Protocolos de aplicación sobre UDP
                    if dst_port == 53 or src_port == 53:
                        protocols.append("DNS")
                    elif (
                        dst_port == 67
                        or src_port == 67
                        or dst_port == 68
                        or src_port == 68
                    ):
                        protocols.append("DHCP")
                    elif dst_port == 123 or src_port == 123:
                        protocols.append("NTP")
                    elif dst_port == 161 or src_port == 161:
                        protocols.append("SNMP")
                    elif dst_port in [1900, 5353] or src_port in [1900, 5353]:
                        protocols.append("mDNS/SSDP")

                elif pkt.haslayer(ICMP):
                    protocols.append("ICMP")

                # Verificar si hay DNS específicamente
                if pkt.haslayer(DNS):
                    protocols.append("DNS-QUERY")

            # Contar protocolos
            protocol_stack = " → ".join(protocols)
            self.protocol_counts[protocol_stack] += 1

            # Contar puertos si existen
            if src_port > 0 or dst_port > 0:
                if dst_port in [80, 443, 22, 53, 25, 21]:  # Puertos conocidos
                    self.port_counts[f":{dst_port}"] += 1
                elif src_port in [80, 443, 22, 53, 25, 21]:
                    self.port_counts[f":{src_port}"] += 1

            # Contar pares IP (solo los más comunes)
            if src_ip != "unknown" and dst_ip != "unknown":
                self.ip_pairs[f"{src_ip} → {dst_ip}"] += 1

            # Mostrar progreso cada 100 paquetes
            if self.packet_count % 100 == 0:
                elapsed = time.time() - self.start_time
                rate = self.packet_count / elapsed
                print(
                    f"📊 Paquetes: {self.packet_count:,} | Velocidad: {rate:.1f} pkt/s | Tiempo: {elapsed:.1f}s"
                )

        except Exception as e:
            print(f"❌ Error analizando paquete: {e}")

    def start_monitoring(self):
        """Iniciar monitoreo"""
        print(f"🚀 Iniciando captura... (Ctrl+C para detener)")

        try:
            # Capturar por tiempo limitado
            def stop_filter(pkt):
                return time.time() - self.start_time > self.monitor_time

            sniff(
                iface=self.interface,
                prn=self.analyze_packet,
                timeout=self.monitor_time + 5,  # Un poco más de tiempo por seguridad
                store=0,
            )

        except KeyboardInterrupt:
            print(f"\n🛑 Monitoreo detenido por usuario")
        except Exception as e:
            print(f"❌ Error durante captura: {e}")
            traceback.print_exc()
        finally:
            self.show_results()

    def show_results(self):
        """Mostrar resultados del análisis"""
        elapsed = time.time() - self.start_time
        rate = self.packet_count / elapsed if elapsed > 0 else 0

        print("\n" + "=" * 60)
        print(f"📊 RESUMEN DEL ANÁLISIS")
        print("=" * 60)
        print(f"⏱️  Tiempo total: {elapsed:.1f} segundos")
        print(f"📦 Total paquetes: {self.packet_count:,}")
        print(f"🚀 Velocidad promedio: {rate:.1f} paquetes/segundo")

        print(f"\n🔍 PROTOCOLOS DETECTADOS:")
        print("-" * 40)
        for protocol, count in self.protocol_counts.most_common(15):
            percentage = (count / self.packet_count) * 100
            print(f"{protocol:<25} | {count:>6,} ({percentage:>5.1f}%)")

        if self.port_counts:
            print(f"\n🚪 PUERTOS MÁS ACTIVOS:")
            print("-" * 30)
            for port, count in self.port_counts.most_common(10):
                percentage = (count / self.packet_count) * 100
                print(f"{port:<15} | {count:>6,} ({percentage:>5.1f}%)")

        if self.ip_pairs:
            print(f"\n🌐 COMUNICACIONES MÁS FRECUENTES:")
            print("-" * 50)
            for pair, count in self.ip_pairs.most_common(10):
                percentage = (count / self.packet_count) * 100
                print(f"{pair:<35} | {count:>4,} ({percentage:>4.1f}%)")


def main():
    """Función principal"""
    import argparse

    parser = argparse.ArgumentParser(description="Monitor de protocolos de red")
    parser.add_argument(
        "-i", "--interface", default="en0", help="Interfaz de red (default: en0)"
    )
    parser.add_argument(
        "-t",
        "--time",
        type=int,
        default=60,
        help="Tiempo de monitoreo en segundos (default: 60)",
    )
    parser.add_argument(
        "--list-interfaces", action="store_true", help="Listar interfaces disponibles"
    )

    args = parser.parse_args()

    if args.list_interfaces:
        print("📡 Interfaces disponibles:")
        os.system("ifconfig -l")
        return

    try:
        monitor = ProtocolMonitor(args.interface, args.time)
        monitor.start_monitoring()
    except PermissionError:
        print("❌ Error de permisos. Ejecuta con sudo:")
        print(f"sudo python {sys.argv[0]} -i {args.interface} -t {args.time}")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
