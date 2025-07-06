#!/usr/bin/env python3
"""
Generador de tráfico de red con coordenadas GPS
Para probar la detección del Enhanced Promiscuous Agent
"""

import time
import json
import random
import socket
import threading
from datetime import datetime


class GPSTrafficGenerator:
    def __init__(self):
        self.running = False
        self.locations = [
            {"name": "New York", "lat": 40.7128, "lng": -74.0060},
            {"name": "Madrid", "lat": 40.4168, "lng": -3.7038},
            {"name": "Tokyo", "lat": 35.6762, "lng": 139.6503},
            {"name": "London", "lat": 51.5074, "lng": -0.1278},
            {"name": "Sydney", "lat": -33.8688, "lng": 151.2093},
            {"name": "São Paulo", "lat": -23.5505, "lng": -46.6333},
        ]

    def generate_mqtt_like_message(self):
        """Generar mensaje tipo MQTT con coordenadas GPS"""
        location = random.choice(self.locations)

        # Añadir algo de ruido a las coordenadas
        lat = location["lat"] + random.uniform(-0.01, 0.01)
        lng = location["lng"] + random.uniform(-0.01, 0.01)

        message = {
            "device_id": f"sensor_{random.randint(1, 100):03d}",
            "timestamp": datetime.utcnow().isoformat(),
            "location": {
                "latitude": lat,
                "longitude": lng,
                "accuracy": random.uniform(5.0, 50.0)
            },
            "data": {
                "temperature": random.uniform(15.0, 35.0),
                "humidity": random.uniform(30.0, 80.0),
                "battery": random.uniform(20.0, 100.0)
            },
            "city": location["name"]
        }

        return json.dumps(message).encode('utf-8')

    def generate_api_response(self):
        """Generar respuesta tipo API REST con coordenadas"""
        location = random.choice(self.locations)

        response = {
            "status": "success",
            "data": {
                "user_id": random.randint(1000, 9999),
                "lat": location["lat"],
                "lon": location["lng"],
                "timestamp": int(time.time()),
                "address": f"Street {random.randint(1, 999)}, {location['name']}"
            }
        }

        return json.dumps(response).encode('utf-8')

    def generate_simple_coordinates(self):
        """Generar coordenadas simples en texto"""
        location = random.choice(self.locations)

        formats = [
            f"latitude={location['lat']}&longitude={location['lng']}",
            f"GPS: {location['lat']}, {location['lng']}",
            f"coordinates: [{location['lat']}, {location['lng']}]",
            f'"lat": {location["lat"]}, "lng": {location["lng"]}',
        ]

        return random.choice(formats).encode('utf-8')

    def send_udp_message(self, message, port=12345):
        """Enviar mensaje UDP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message, ('127.0.0.1', port))
            sock.close()
            return True
        except Exception as e:
            print(f"Error enviando UDP: {e}")
            return False

    def send_tcp_message(self, message, port=8080):
        """Enviar mensaje TCP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', port))

            # Simular HTTP request con GPS data
            http_request = f"""POST /api/location HTTP/1.1\r
Host: localhost:{port}\r
Content-Type: application/json\r
Content-Length: {len(message)}\r
\r
{message.decode('utf-8')}\r
\r
"""

            sock.send(http_request.encode())
            sock.close()
            return True
        except Exception as e:
            # Es normal que falle si no hay servidor escuchando
            return False

    def generate_traffic_burst(self):
        """Generar una ráfaga de tráfico con GPS"""
        print(f"📡 Generando ráfaga de tráfico con GPS...")

        messages_sent = 0

        # Enviar varios tipos de mensajes
        for i in range(5):
            # MQTT-like UDP
            mqtt_msg = self.generate_mqtt_like_message()
            if self.send_udp_message(mqtt_msg, 1883):  # Puerto MQTT
                messages_sent += 1
                print(f"   📤 MQTT-like UDP enviado: {len(mqtt_msg)} bytes")

            # API REST-like TCP
            api_msg = self.generate_api_response()
            if self.send_tcp_message(api_msg, 8080):  # Puerto HTTP
                messages_sent += 1
                print(f"   📤 API REST-like TCP enviado: {len(api_msg)} bytes")

            # Coordenadas simples UDP
            simple_msg = self.generate_simple_coordinates()
            if self.send_udp_message(simple_msg, 5683):  # Puerto CoAP
                messages_sent += 1
                print(f"   📤 Coordenadas simples UDP enviado: {len(simple_msg)} bytes")

            time.sleep(0.5)

        print(f"✅ Ráfaga completada: {messages_sent} mensajes enviados\n")
        return messages_sent

    def start_continuous_generation(self, interval=10):
        """Iniciar generación continua de tráfico"""
        self.running = True
        total_sent = 0

        print("🚀 Iniciando generación continua de tráfico GPS")
        print(f"🔄 Ráfaga cada {interval} segundos")
        print("⚡ Presiona Ctrl+C para detener\n")

        try:
            while self.running:
                sent = self.generate_traffic_burst()
                total_sent += sent

                print(f"📊 Total enviado: {total_sent} mensajes")
                print(f"⏰ Próxima ráfaga en {interval}s...")
                print("-" * 50)

                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n🛑 Deteniendo generación...")
            self.running = False

        print(f"✅ Generación detenida. Total: {total_sent} mensajes")


def main():
    import sys

    print("🌍 Generador de Tráfico GPS para Enhanced Promiscuous Agent")
    print("==========================================================")

    generator = GPSTrafficGenerator()

    # Determinar modo
    if len(sys.argv) > 1 and sys.argv[1] == "continuous":
        # Modo continuo
        interval = 10
        if len(sys.argv) > 2:
            try:
                interval = int(sys.argv[2])
            except ValueError:
                print("❌ Intervalo debe ser un número")
                return 1

        generator.start_continuous_generation(interval)

    else:
        # Modo ráfaga única
        print("🎯 Modo ráfaga única")
        print("💡 Para modo continuo: python3 generate_gps_traffic.py continuous [intervalo]\n")

        sent = generator.generate_traffic_burst()
        print(f"✅ Ráfaga completada: {sent} mensajes con coordenadas GPS")
        print("\n📋 Para probar:")
        print("1. Ejecutar el agente promiscuo en una terminal")
        print("2. Ejecutar el subscriber en otra terminal")
        print("3. Ejecutar este generador para ver detección GPS")


if __name__ == "__main__":
    main()