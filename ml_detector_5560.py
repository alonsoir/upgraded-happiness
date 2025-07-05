#!/usr/bin/env python3
"""
ML Detector con puerto corregido (5560)
Versión simple que instancia el detector original con puerto correcto
"""

import sys
import numpy as np

# Importar el detector original
try:
    from lightweight_ml_detector import LightweightThreatDetector

    print("✅ ML Detector original importado exitosamente")
except ImportError as e:
    print(f"❌ Error importando ML detector: {e}")
    print("💡 Asegúrate de que lightweight_ml_detector.py esté en el directorio")
    sys.exit(1)


def main():
    """Función principal con puerto corregido"""
    print("🤖 ML DETECTOR CORREGIDO - PUERTO 5560")
    print("=" * 50)
    print("Conectando al broker simple que retransmite eventos")
    print("Configurado para recibir datos protobuf del agente")
    print("=" * 50)

    # Crear detector con puerto correcto
    detector = LightweightThreatDetector(broker_address="tcp://localhost:5560")

    print(f"🔌 Configurado para conectar a: tcp://localhost:5560")
    print("📡 Esperando eventos protobuf del broker simple...")

    if detector.connect():
        # Entrenamiento inicial con datos sintéticos
        print("\n📚 Generando datos de entrenamiento inicial...")
        X_initial = np.random.rand(1000, 15)  # 1000 muestras, 15 features
        y_initial = np.random.choice([0, 1], 1000)  # Etiquetas aleatorias

        print("🧠 Entrenando modelos ligeros...")
        detector.train_lightweight_models(X_initial, y_initial)

        print("\n🚀 Iniciando monitoreo en tiempo real...")
        print("💡 Debería empezar a procesar eventos inmediatamente")
        print("⚠️  Ctrl+C para detener\n")

        try:
            detector.start_monitoring()
        except KeyboardInterrupt:
            print("\n🛑 Detector detenido por el usuario")
        except Exception as e:
            print(f"\n❌ Error durante monitoreo: {e}")
            import traceback
            traceback.print_exc()
        finally:
            print("🧹 Cerrando conexiones...")
            detector.socket.close()
            detector.context.term()
            print("🏁 ML Detector cerrado correctamente")
    else:
        print("❌ No se pudo conectar al broker en puerto 5560")
        print("💡 Verificaciones:")
        print("   1. ¿Está ejecutándose simple_broker.py?")
        print("   2. ¿Está el broker retransmitiendo en puerto 5560?")
        print("   3. ¿Hay eventos llegando al monitor binario?")


if __name__ == "__main__":
    main()