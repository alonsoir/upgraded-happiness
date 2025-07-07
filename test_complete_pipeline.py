#!/usr/bin/env python3
"""
🔍 Test del Pipeline Completo ML
Verifica que todos los componentes estén funcionando correctamente
"""

import zmq
import time
import json
import os
from datetime import datetime

# Intentar importar protobuf
try:
    from src.protocols.protobuf import network_event_pb2

    PROTOBUF_AVAILABLE = True
except ImportError:
    try:
        import network_event_pb2

        PROTOBUF_AVAILABLE = True
    except ImportError:
        PROTOBUF_AVAILABLE = False


def test_zmq_port(port, description, timeout=5):
    """Test de conexión a un puerto ZeroMQ específico"""
    print(f"🔍 Testeando {description} (puerto {port})...")

    context = zmq.Context()
    socket = context.socket(zmq.SUB)

    try:
        socket.connect(f"tcp://localhost:{port}")
        socket.setsockopt(zmq.SUBSCRIBE, b"")
        socket.setsockopt(zmq.RCVTIMEO, timeout * 1000)

        events_received = 0
        ml_enriched_events = 0
        gps_events = 0
        bytes_received = 0

        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                message = socket.recv(zmq.NOBLOCK)
                events_received += 1
                bytes_received += len(message)

                # Para puerto 5559 (raw), solo verificar que hay mensajes
                # NO intentar parsear protobuf porque tiene timestamps incorrectos
                if port == 5559:
                    if events_received <= 3:
                        print(f"   📡 Evento #{events_received}: {len(message)} bytes (raw)")

                # Para puerto 5560 (enriquecido), sí parsear protobuf
                elif port == 5560 and PROTOBUF_AVAILABLE:
                    try:
                        event = network_event_pb2.NetworkEvent()
                        event.ParseFromString(message)

                        # Verificar si tiene ML scores
                        has_ml_scores = (event.anomaly_score > 0 or event.risk_score > 0)
                        if has_ml_scores:
                            ml_enriched_events += 1

                        # Verificar GPS
                        has_gps = (event.latitude != 0 and event.longitude != 0)
                        if has_gps:
                            gps_events += 1

                        if events_received <= 3:
                            print(f"   📡 Evento #{events_received}:")
                            print(f"      {event.source_ip} → {event.target_ip}:{event.dest_port}")
                            print(f"      Anomaly: {event.anomaly_score:.3f} | Risk: {event.risk_score:.3f}")
                            if has_gps:
                                print(f"      GPS: {event.latitude:.6f}, {event.longitude:.6f}")
                            if event.description:
                                print(f"      Desc: {event.description}")
                    except Exception as parse_error:
                        # En puerto 5560 también puede haber algunos errores residuales
                        if events_received <= 3:
                            print(f"   📡 Evento #{events_received}: {len(message)} bytes (parse error)")

                # Para otros puertos, mostrar info básica
                else:
                    if events_received <= 3:
                        print(f"   📡 Evento #{events_received}: {len(message)} bytes")

            except zmq.Again:
                time.sleep(0.1)
                continue

        # Resultados
        if events_received > 0:
            print(f"   ✅ {events_received} eventos recibidos ({bytes_received} bytes)")

            if port == 5560 and PROTOBUF_AVAILABLE:
                print(f"   🤖 {ml_enriched_events} eventos con ML scores")
                print(f"   🗺️ {gps_events} eventos con GPS")
                ml_percentage = (ml_enriched_events / events_received) * 100 if events_received > 0 else 0
                gps_percentage = (gps_events / events_received) * 100 if events_received > 0 else 0
                print(f"   📊 ML: {ml_percentage:.1f}% | GPS: {gps_percentage:.1f}%")
            elif port == 5559:
                print(f"   📡 Puerto raw funcionando (Enhanced Promiscuous Agent)")

            return True
        else:
            print(f"   ❌ No se recibieron eventos")
            return False

    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

    finally:
        socket.close()
        context.term()


def test_complete_pipeline():
    """Test completo del pipeline"""
    print("🧪 TEST DEL PIPELINE COMPLETO ML")
    print("=" * 50)
    print(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Protobuf disponible: {PROTOBUF_AVAILABLE}")
    print("")

    # Test 1: Puerto 5559 (eventos raw)
    print("🔸 PASO 1: Enhanced Promiscuous Agent (puerto 5559)")
    port_5559_ok = test_zmq_port(5559, "Enhanced Promiscuous Agent", 10)
    print("")

    # Test 2: Puerto 5560 (eventos enriquecidos)
    print("🔸 PASO 2: Complete ML Detector (puerto 5560)")
    port_5560_ok = test_zmq_port(5560, "Complete ML Detector Output", 10)
    print("")

    # Test 3: Dashboard
    print("🔸 PASO 3: Dashboard")
    try:
        import urllib.request
        response = urllib.request.urlopen("http://127.0.0.1:8000/api/stats", timeout=5)
        stats = json.loads(response.read().decode())

        print("   ✅ Dashboard respondiendo")
        print(f"   📊 Total eventos: {stats.get('total_events', 0)}")
        print(f"   🤖 ML activos: {stats.get('ml_models_active', [])}")
        print(f"   🗺️ Eventos GPS: {stats.get('events_with_gps', 0)}")
        dashboard_ok = True

    except Exception as e:
        print(f"   ❌ Dashboard no responde: {e}")
        dashboard_ok = False

    print("")

    # Resumen final
    print("📋 RESUMEN DEL TEST")
    print("-" * 30)
    status_5559 = "✅" if port_5559_ok else "❌"
    status_5560 = "✅" if port_5560_ok else "❌"
    status_dashboard = "✅" if dashboard_ok else "❌"

    print(f"{status_5559} Enhanced Promiscuous Agent (5559): {'Funcionando' if port_5559_ok else 'No disponible'}")
    print(f"{status_5560} Complete ML Detector (5560): {'Funcionando' if port_5560_ok else 'No disponible'}")
    print(f"{status_dashboard} Dashboard Real: {'Funcionando' if dashboard_ok else 'No disponible'}")

    print("")

    # Diagnóstico
    if port_5559_ok and port_5560_ok and dashboard_ok:
        print("🎉 ¡PIPELINE COMPLETO FUNCIONANDO!")
        print("   🚀 Sistema de ML en tiempo real operativo")
        print("   📊 Dashboard: http://127.0.0.1:8000")

    elif port_5559_ok and not port_5560_ok:
        print("⚠️ ENHANCED PROMISCUOUS AGENT OK, pero falta ML DETECTOR")
        print("   🔧 Ejecuta: python complete_ml_detector.py")

    elif port_5560_ok and not port_5559_ok:
        print("⚠️ ML DETECTOR OK, pero falta ENHANCED PROMISCUOUS AGENT")
        print("   🔧 Ejecuta: python promiscous_agent.py")

    elif not dashboard_ok:
        print("⚠️ ZEROMQ OK, pero falta DASHBOARD")
        print("   🔧 Ejecuta: python real_zmq_dashboard.py")

    else:
        print("❌ PIPELINE NO FUNCIONANDO")
        print("   🔧 Ejecuta los componentes en orden:")
        print("      1. python promiscous_agent.py")
        print("      2. python complete_ml_detector.py")
        print("      3. python real_zmq_dashboard.py")

    print("")
    print("📖 Consulta complete_pipeline_guide.md para instrucciones detalladas")


def verify_dashboard_port():
    """Verificar que el dashboard esté configurado para puerto 5560"""
    print("🔍 VERIFICANDO CONFIGURACIÓN DEL DASHBOARD")
    print("-" * 45)

    # Verificar que el dashboard esté conectado al puerto 5560
    dashboard_port_correct = False

    try:
        # Leer el archivo del dashboard para verificar puerto
        dashboard_files = ['real_zmq_dashboard.py', 'hybrid_dashboard.py']

        for filename in dashboard_files:
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    content = f.read()

                if 'tcp://localhost:5560' in content:
                    print(f"   ✅ {filename} configurado para puerto 5560 (correcto)")
                    dashboard_port_correct = True
                elif 'tcp://localhost:5559' in content:
                    print(f"   ⚠️ {filename} configurado para puerto 5559 (debe ser 5560)")
                    print(f"      El dashboard debe leer eventos ENRIQUECIDOS del puerto 5560")
                else:
                    print(f"   ❓ {filename} - configuración de puerto no clara")

        if not dashboard_port_correct:
            print("   ❌ Dashboard no configurado correctamente")
            print("   🔧 El dashboard debe conectarse a puerto 5560 para eventos enriquecidos")

    except Exception as e:
        print(f"   ❌ Error verificando dashboard: {e}")

    return dashboard_port_correct
    """Test específico de estadísticas del ML detector"""
    print("\n🤖 TEST ESPECÍFICO: ML DETECTOR")
    print("-" * 40)

    try:
        # Verificar archivos de modelos
        from pathlib import Path
        models_dir = Path("ml_models")

        if models_dir.exists():
            versions = list(models_dir.glob("versions/*"))
            best_models = list(models_dir.glob("best/*"))

            print(f"📁 Directorio de modelos: {'✅' if models_dir.exists() else '❌'}")
            print(f"📂 Versiones guardadas: {len(versions)}")
            print(f"🏆 Mejores modelos: {len(best_models)}")

            if versions:
                latest = sorted(versions)[-1]
                print(f"🕐 Última versión: {latest.name}")
        else:
            print("📁 No hay directorio de modelos (se creará automáticamente)")

    except Exception as e:
        print(f"❌ Error verificando modelos: {e}")


if __name__ == "__main__":
    test_complete_pipeline()
    # test_ml_detector_stats()