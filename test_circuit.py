#!/usr/bin/env python3
"""
Script de Prueba del Circuito Completo
Verifica la comunicación end-to-end: promiscuous_agent → geoip_enricher → ml_detector → dashboard → firewall_agent
"""

import zmq
import json
import time
import threading
import logging
import sys
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import random

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('circuit_test')


@dataclass
class TestEvent:
    id: str
    source_ip: str
    target_ip: str
    risk_score: float
    timestamp: str
    attack_type: str
    protocol: str
    port: int
    test_marker: str = "CIRCUIT_TEST"


@dataclass
class TestCommand:
    action: str
    target_ip: str
    duration: str
    reason: str
    risk_score: float
    timestamp: str
    event_id: str
    rule_type: str = "test"
    test_marker: str = "CIRCUIT_TEST"


class CircuitTester:
    """Probador del circuito completo de la arquitectura"""

    def __init__(self):
        self.context = zmq.Context()
        self.running = True
        self.test_results = []

        # Contadores
        self.events_sent = 0
        self.events_received = 0
        self.commands_received = 0
        self.responses_sent = 0

        # Configurar sockets
        self.setup_sockets()

    def setup_sockets(self):
        """Configurar todos los sockets necesarios"""
        logger.info("🔧 Configurando sockets para prueba del circuito...")

        # Socket para enviar eventos al geoip_enricher (simula promiscuous_agent)
        self.event_sender = self.context.socket(zmq.PUSH)
        self.event_sender.connect("tcp://localhost:5559")
        logger.info("📡 Event sender conectado a puerto 5559 (geoip_enricher)")

        # Socket para recibir comandos del dashboard (simula firewall_agent)
        self.command_receiver = self.context.socket(zmq.SUB)
        self.command_receiver.connect("tcp://localhost:5580")
        self.command_receiver.setsockopt(zmq.SUBSCRIBE, b"")  # Suscribirse a todos los mensajes
        self.command_receiver.setsockopt(zmq.RCVTIMEO, 1000)  # Timeout de 1 segundo
        logger.info("🛡️ Command receiver conectado a puerto 5580 (dashboard)")

        # Socket para enviar respuestas al dashboard (simula firewall_agent)
        self.response_sender = self.context.socket(zmq.PUSH)
        self.response_sender.connect("tcp://localhost:5581")
        logger.info("📥 Response sender conectado a puerto 5581 (dashboard)")

        time.sleep(2)  # Dar tiempo para que las conexiones se establezcan

    def generate_test_event(self, test_id: int) -> TestEvent:
        """Generar evento de prueba"""
        return TestEvent(
            id=f"test_event_{test_id}_{int(time.time())}",
            source_ip=f"192.168.1.{100 + (test_id % 50)}",
            target_ip=f"10.0.0.{1 + (test_id % 50)}",
            risk_score=0.7 + (test_id % 3) * 0.1,  # 0.7, 0.8, 0.9 para activar respuesta
            timestamp=datetime.now().isoformat(),
            attack_type=["port_scan", "ddos", "intrusion_attempt"][test_id % 3],
            protocol="TCP",
            port=80 + (test_id % 1000)
        )

    def send_test_events(self, count: int = 5):
        """Enviar eventos de prueba"""
        logger.info(f"📤 Enviando {count} eventos de prueba...")

        for i in range(count):
            event = self.generate_test_event(i)
            event_json = json.dumps(asdict(event))

            try:
                self.event_sender.send_string(event_json)
                self.events_sent += 1
                logger.info(
                    f"✅ Evento {i + 1}/{count} enviado: {event.source_ip} -> {event.target_ip} (riesgo: {event.risk_score})")
                time.sleep(0.5)  # Pausa entre eventos

            except Exception as e:
                logger.error(f"❌ Error enviando evento {i + 1}: {e}")

        logger.info(f"📊 Total eventos enviados: {self.events_sent}")

    def listen_for_commands(self, timeout_seconds: int = 30):
        """Escuchar comandos del dashboard"""
        logger.info(f"👂 Escuchando comandos del dashboard (timeout: {timeout_seconds}s)...")

        start_time = time.time()

        while time.time() - start_time < timeout_seconds:
            try:
                # Intentar recibir comando
                command_json = self.command_receiver.recv_string(zmq.NOBLOCK)
                command_data = json.loads(command_json)

                self.commands_received += 1
                logger.info(
                    f"🛡️ Comando recibido: {command_data.get('action', 'unknown')} para {command_data.get('target_ip', 'unknown')}")

                # Simular procesamiento del comando
                time.sleep(0.1)

                # Enviar respuesta de confirmación
                response = {
                    "status": "applied" if random.random() > 0.1 else "failed",  # 90% éxito
                    "target_ip": command_data.get('target_ip'),
                    "action": command_data.get('action'),
                    "timestamp": datetime.now().isoformat(),
                    "node_id": "test_firewall_agent",
                    "rule_id": f"rule_{int(time.time())}",
                    "test_marker": "CIRCUIT_TEST_RESPONSE"
                }

                self.response_sender.send_string(json.dumps(response))
                self.responses_sent += 1
                logger.info(f"📨 Respuesta enviada: {response['status']} para {response['target_ip']}")

            except zmq.Again:
                # Timeout, continuar
                time.sleep(0.1)
                continue
            except Exception as e:
                logger.error(f"❌ Error procesando comando: {e}")

        logger.info(f"📊 Comandos recibidos: {self.commands_received}, Respuestas enviadas: {self.responses_sent}")

    def test_dashboard_api(self):
        """Probar API del dashboard"""
        logger.info("🌐 Probando API del dashboard...")

        try:
            import requests

            # Probar métricas
            response = requests.get("http://localhost:8080/api/metrics", timeout=5)
            if response.status_code == 200:
                logger.info("✅ API /api/metrics accesible")
                metrics = response.json()
                logger.info(f"📊 Eventos en dashboard: {metrics.get('basic_stats', {}).get('events_received', 0)}")
            else:
                logger.warning(f"⚠️ API métricas devolvió status {response.status_code}")

            # Probar test de firewall
            response = requests.get("http://localhost:8080/api/test-firewall", timeout=5)
            if response.status_code == 200:
                logger.info("✅ API /api/test-firewall accesible")
                result = response.json()
                logger.info(f"🧪 Test firewall: {result.get('message', 'No message')}")
            else:
                logger.warning(f"⚠️ API test-firewall devolvió status {response.status_code}")

        except ImportError:
            logger.warning("⚠️ requests no disponible, saltando pruebas de API")
        except Exception as e:
            logger.error(f"❌ Error probando API del dashboard: {e}")

    def run_full_circuit_test(self):
        """Ejecutar prueba completa del circuito"""
        logger.info("🚀 Iniciando prueba completa del circuito...")
        logger.info("=" * 60)

        # Paso 1: Enviar eventos de prueba
        logger.info("📋 PASO 1: Enviando eventos de prueba")
        self.send_test_events(3)

        # Paso 2: Dar tiempo para que los eventos se procesen
        logger.info("📋 PASO 2: Esperando procesamiento (10s)")
        time.sleep(10)

        # Paso 3: Probar API del dashboard
        logger.info("📋 PASO 3: Probando API del dashboard")
        self.test_dashboard_api()

        # Paso 4: Escuchar comandos de firewall
        logger.info("📋 PASO 4: Escuchando comandos del dashboard")
        self.listen_for_commands(20)

        # Paso 5: Mostrar resumen
        logger.info("📋 PASO 5: Resumen de la prueba")
        self.show_test_summary()

    def show_test_summary(self):
        """Mostrar resumen de la prueba"""
        logger.info("=" * 60)
        logger.info("📊 RESUMEN DE LA PRUEBA DEL CIRCUITO")
        logger.info("=" * 60)

        logger.info(f"📤 Eventos enviados: {self.events_sent}")
        logger.info(f"🛡️ Comandos recibidos: {self.commands_received}")
        logger.info(f"📨 Respuestas enviadas: {self.responses_sent}")

        # Calcular métricas
        if self.events_sent > 0:
            command_rate = (self.commands_received / self.events_sent) * 100
            logger.info(f"📈 Tasa de conversión evento→comando: {command_rate:.1f}%")

        if self.commands_received > 0:
            response_rate = (self.responses_sent / self.commands_received) * 100
            logger.info(f"📈 Tasa de respuesta comando→respuesta: {response_rate:.1f}%")

        # Evaluación general
        if self.commands_received > 0 and self.responses_sent > 0:
            logger.info("✅ CIRCUITO FUNCIONANDO: Los eventos generan comandos y respuestas")
        elif self.commands_received > 0:
            logger.info("⚠️ PARCIAL: Los eventos generan comandos pero no hay respuestas")
        else:
            logger.info("❌ FALLO: No se recibieron comandos del dashboard")

        logger.info("=" * 60)

        # Recomendaciones
        logger.info("💡 RECOMENDACIONES:")
        if self.commands_received == 0:
            logger.info("   • Verificar que el ml_detector esté funcionando")
            logger.info("   • Verificar que el dashboard esté recibiendo eventos")
            logger.info("   • Comprobar configuración de puertos")
        if self.responses_sent == 0 and self.commands_received > 0:
            logger.info("   • Verificar conexión del puerto 5581 (responses)")
        if self.events_sent > 0 and self.commands_received > 0:
            logger.info("   • ✅ El circuito principal funciona correctamente")

    def cleanup(self):
        """Limpiar recursos"""
        logger.info("🧹 Limpiando recursos...")

        try:
            self.event_sender.close()
            self.command_receiver.close()
            self.response_sender.close()
            self.context.term()
            logger.info("✅ Recursos limpiados correctamente")
        except Exception as e:
            logger.error(f"⚠️ Error limpiando recursos: {e}")


def main():
    """Función principal"""
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("Script de Prueba del Circuito Completo")
        print("=====================================")
        print("Este script verifica la comunicación end-to-end:")
        print("  promiscuous_agent → geoip_enricher → ml_detector → dashboard → firewall_agent")
        print()
        print("Requisitos:")
        print("  • Todos los componentes deben estar ejecutándose")
        print("  • Puertos 5559, 5570, 5580, 5581, 8080 deben estar libres")
        print()
        print("Uso:")
        print("  python test_circuit.py")
        return

    logger.info("🎯 Script de Prueba del Circuito Completo")
    logger.info(
        "Verificando comunicación: promiscuous_agent → geoip_enricher → ml_detector → dashboard → firewall_agent")

    tester = None
    try:
        tester = CircuitTester()
        tester.run_full_circuit_test()

    except KeyboardInterrupt:
        logger.info("\n🛑 Prueba interrumpida por el usuario")
    except Exception as e:
        logger.error(f"💥 Error durante la prueba: {e}")
    finally:
        if tester:
            tester.cleanup()

    logger.info("🏁 Prueba del circuito completada")


if __name__ == "__main__":
    main()