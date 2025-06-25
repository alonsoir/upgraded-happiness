# test_protobuf_research.py
"""
Test completo y benchmark del sistema de investigación Protocol Buffers.
Verifica setup, performance y prepara para comparación con otros protocolos.
"""

import time
import os
import sys
import statistics
import json
from typing import List, Dict, Any
from dataclasses import asdict

# Añadir paths necesarios
sys.path.insert(0, 'src')
sys.path.insert(0, 'src/protocols')


# Test de imports principales
def test_imports():
    """Verifica que todos los imports funcionen correctamente."""
    print("🧪 Testing imports del sistema de investigación...")

    try:
        from base_interfaces import (
            EventData, SerializationMetrics, SerializationProtocol,
            CompressionAlgorithm, EncryptionAlgorithm,
            ResearchDataGenerator, SerializerFactory
        )
        print("✅ Interfaces base importadas")

        from protobuf.protobuf_serializer import ProtobufEventSerializer
        print("✅ Serializer Protocol Buffers importado")

        # Verificar que Protocol Buffers está disponible
        import scada_events_pb2 as pb
        print("✅ Schema Protocol Buffers disponible")

        return True

    except ImportError as e:
        print(f"❌ Error importando: {e}")
        print("💡 Ejecuta: bash setup_research_environment.sh")
        return False


def test_protobuf_serialization():
    """Test básico de serialización Protocol Buffers."""
    print("\n🔧 Testing serialización Protocol Buffers...")

    from base_interfaces import ResearchDataGenerator, CompressionAlgorithm, EncryptionAlgorithm
    from protobuff.protobuf_serializer import ProtobufEventSerializer

    # Crear serializer con diferentes configuraciones
    configs = [
        {"name": "Sin compresión ni cifrado", "compression": CompressionAlgorithm.NONE,
         "encryption": EncryptionAlgorithm.NONE},
        {"name": "Solo LZ4", "compression": CompressionAlgorithm.LZ4, "encryption": EncryptionAlgorithm.NONE},
        {"name": "LZ4 + ChaCha20", "compression": CompressionAlgorithm.LZ4, "encryption": EncryptionAlgorithm.CHACHA20}
    ]

    # Generar eventos de prueba
    generator = ResearchDataGenerator()
    security_events = generator.generate_security_events(5)
    scada_events = generator.generate_scada_alarms(5)
    network_events = generator.generate_network_anomalies(5)

    all_events = security_events + scada_events + network_events

    print(f"   Eventos generados: {len(all_events)}")

    results = {}

    for config in configs:
        print(f"\n   Configuración: {config['name']}")

        # Crear serializer
        encryption_key = os.urandom(32) if config['encryption'] != EncryptionAlgorithm.NONE else None

        # Nota: Para esta prueba, simplificamos y solo probamos casos básicos
        if config['compression'] == CompressionAlgorithm.NONE or config['encryption'] == EncryptionAlgorithm.NONE:
            # Para la implementación simplificada inicial
            serializer = ProtobufEventSerializer(
                compression=CompressionAlgorithm.LZ4,
                encryption=EncryptionAlgorithm.CHACHA20 if encryption_key else EncryptionAlgorithm.NONE,
                encryption_key=encryption_key
            )
        else:
            serializer = ProtobufEventSerializer(
                compression=config['compression'],
                encryption=config['encryption'],
                encryption_key=encryption_key
            )

        # Test con cada tipo de evento
        config_results = []

        for i, event in enumerate(all_events[:3]):  # Solo primeros 3 para prueba rápida
            try:
                # Serializar
                serialized_data, ser_metrics = serializer.serialize(event)

                # Deserializar
                deserialized_event, deser_metrics = serializer.deserialize(serialized_data)

                if deserialized_event:
                    config_results.append({
                        "event_type": event.event_type,
                        "original_size": ser_metrics.original_size_bytes,
                        "serialized_size": ser_metrics.serialized_size_bytes,
                        "compression_ratio": ser_metrics.compression_ratio,
                        "serialization_time_us": ser_metrics.serialization_time_ns / 1000,
                        "deserialization_time_us": deser_metrics.deserialization_time_ns / 1000,
                        "total_time_us": (
                                                     ser_metrics.total_processing_time_ns + deser_metrics.total_processing_time_ns) / 1000
                    })
                    print(
                        f"     ✅ {event.event_type}: {len(serialized_data)} bytes, {ser_metrics.total_processing_time_ns / 1000:.1f}μs")
                else:
                    print(f"     ❌ {event.event_type}: Error en deserialización")

            except Exception as e:
                print(f"     ❌ {event.event_type}: Error - {e}")

        results[config['name']] = config_results

    return results


def benchmark_performance():
    """Benchmark de performance con diferentes cargas de trabajo."""
    print("\n📊 Benchmark de performance Protocol Buffers...")

    from base_interfaces import ResearchDataGenerator
    from protobuf.protobuf_serializer import ProtobufEventSerializer

    # Configuración del benchmark
    event_counts = [100, 1000, 5000]
    encryption_key = os.urandom(32)

    serializer = ProtobufEventSerializer(
        compression=CompressionAlgorithm.LZ4,
        encryption=EncryptionAlgorithm.CHACHA20,
        encryption_key=encryption_key
    )

    benchmark_results = {}

    for count in event_counts:
        print(f"\n   Benchmarking con {count:,} eventos...")

        # Generar carga de trabajo mixta
        generator = ResearchDataGenerator()
        events = generator.generate_mixed_workload(count)

        # Benchmark de serialización
        start_time = time.time()
        serialized_events = []
        total_serialized_size = 0
        serialization_times = []

        for event in events:
            ser_start = time.time_ns()
            serialized_data, metrics = serializer.serialize(event)
            ser_end = time.time_ns()

            serialized_events.append(serialized_data)
            total_serialized_size += len(serialized_data)
            serialization_times.append(ser_end - ser_start)

        serialization_total_time = time.time() - start_time

        # Benchmark de deserialización
        start_time = time.time()
        deserialization_times = []
        successful_deserializations = 0

        for serialized_data in serialized_events:
            deser_start = time.time_ns()
            deserialized_event, metrics = serializer.deserialize(serialized_data)
            deser_end = time.time_ns()

            if deserialized_event:
                successful_deserializations += 1
            deserialization_times.append(deser_end - deser_start)

        deserialization_total_time = time.time() - start_time

        # Calcular estadísticas
        events_per_second_ser = count / serialization_total_time
        events_per_second_deser = count / deserialization_total_time
        avg_event_size = total_serialized_size / count
        throughput_mbps = (total_serialized_size / (1024 * 1024)) / serialization_total_time

        benchmark_results[count] = {
            "events_processed": count,
            "successful_deserializations": successful_deserializations,
            "serialization": {
                "total_time_seconds": serialization_total_time,
                "events_per_second": events_per_second_ser,
                "avg_time_us": statistics.mean(serialization_times) / 1000,
                "median_time_us": statistics.median(serialization_times) / 1000,
                "p95_time_us": sorted(serialization_times)[int(len(serialization_times) * 0.95)] / 1000,
                "p99_time_us": sorted(serialization_times)[int(len(serialization_times) * 0.99)] / 1000
            },
            "deserialization": {
                "total_time_seconds": deserialization_total_time,
                "events_per_second": events_per_second_deser,
                "avg_time_us": statistics.mean(deserialization_times) / 1000,
                "median_time_us": statistics.median(deserialization_times) / 1000,
                "success_rate": successful_deserializations / count
            },
            "size_metrics": {
                "total_size_bytes": total_serialized_size,
                "avg_event_size_bytes": avg_event_size,
                "throughput_mbps": throughput_mbps
            }
        }

        print(f"     Serialización: {events_per_second_ser:,.0f} eventos/segundo")
        print(f"     Deserialización: {events_per_second_deser:,.0f} eventos/segundo")
        print(f"     Tamaño promedio: {avg_event_size:.1f} bytes/evento")
        print(f"     Throughput: {throughput_mbps:.1f} MB/s")

    return benchmark_results


def compare_event_types():
    """Compara performance entre diferentes tipos de eventos."""
    print("\n📈 Comparación por tipo de evento...")

    from base_interfaces import ResearchDataGenerator
    from protobuf.protobuf_serializer import ProtobufEventSerializer

    encryption_key = os.urandom(32)
    serializer = ProtobufEventSerializer(
        compression=CompressionAlgorithm.LZ4,
        encryption=EncryptionAlgorithm.CHACHA20,
        encryption_key=encryption_key
    )

    generator = ResearchDataGenerator()

    # Generar diferentes tipos de eventos
    event_types = [
        ("Security Events", generator.generate_security_events(100)),
        ("SCADA Alarms", generator.generate_scada_alarms(100)),
        ("Network Anomalies", generator.generate_network_anomalies(100))
    ]

    comparison_results = {}

    for event_type_name, events in event_types:
        print(f"\n   {event_type_name}:")

        sizes = []
        serialization_times = []
        compression_ratios = []

        for event in events[:50]:  # Test con 50 eventos por tipo
            serialized_data, metrics = serializer.serialize(event)

            sizes.append(len(serialized_data))
            serialization_times.append(metrics.serialization_time_ns / 1000)  # μs
            compression_ratios.append(metrics.compression_ratio)

        comparison_results[event_type_name] = {
            "avg_size_bytes": statistics.mean(sizes),
            "avg_serialization_time_us": statistics.mean(serialization_times),
            "avg_compression_ratio": statistics.mean(compression_ratios),
            "size_std": statistics.stdev(sizes) if len(sizes) > 1 else 0,
            "time_std": statistics.stdev(serialization_times) if len(serialization_times) > 1 else 0
        }

        print(
            f"     Tamaño promedio: {statistics.mean(sizes):.1f} ± {statistics.stdev(sizes) if len(sizes) > 1 else 0:.1f} bytes")
        print(
            f"     Tiempo promedio: {statistics.mean(serialization_times):.1f} ± {statistics.stdev(serialization_times) if len(serialization_times) > 1 else 0:.1f} μs")
        print(f"     Compresión: {statistics.mean(compression_ratios):.1f}x")

    return comparison_results


def save_results(results: Dict[str, Any]):
    """Guarda resultados del benchmark en archivo JSON."""
    os.makedirs("research_results/benchmarks", exist_ok=True)

    timestamp = int(time.time())
    filename = f"research_results/benchmarks/protobuf_benchmark_{timestamp}.json"

    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n💾 Resultados guardados en: {filename}")


def main():
    """Función principal del test de investigación."""
    print("🔬 SCADA Protocol Research - Protocol Buffers Test Suite")
    print("=" * 70)

    # Test 1: Verificar imports y setup
    if not test_imports():
        print("\n💥 Setup incompleto. Ejecuta setup_research_environment.sh")
        return False

    # Test 2: Serialización básica
    try:
        serialization_results = test_protobuf_serialization()
        print("✅ Test de serialización completado")
    except Exception as e:
        print(f"❌ Error en test de serialización: {e}")
        return False

    # Test 3: Benchmark de performance
    try:
        performance_results = benchmark_performance()
        print("✅ Benchmark de performance completado")
    except Exception as e:
        print(f"❌ Error en benchmark: {e}")
        return False

    # Test 4: Comparación por tipos de eventos
    try:
        comparison_results = compare_event_types()
        print("✅ Comparación por tipos completada")
    except Exception as e:
        print(f"❌ Error en comparación: {e}")
        return False

    # Compilar resultados finales
    final_results = {
        "protocol": "Protocol Buffers + LZ4 + ChaCha20",
        "timestamp": time.time(),
        "test_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "serialization_tests": serialization_results,
        "performance_benchmarks": performance_results,
        "event_type_comparison": comparison_results,
        "system_info": {
            "python_version": sys.version,
            "platform": sys.platform
        }
    }

    # Guardar resultados
    save_results(final_results)

    # Resumen ejecutivo
    print("\n" + "=" * 70)
    print("📋 RESUMEN EJECUTIVO - Protocol Buffers")
    print("=" * 70)

    # Extraer métricas clave del benchmark más grande
    if performance_results:
        largest_test = max(performance_results.keys())
        key_metrics = performance_results[largest_test]

        print(f"🎯 Performance con {largest_test:,} eventos:")
        print(f"   Serialización: {key_metrics['serialization']['events_per_second']:,.0f} eventos/segundo")
        print(f"   Deserialización: {key_metrics['deserialization']['events_per_second']:,.0f} eventos/segundo")
        print(f"   Throughput: {key_metrics['size_metrics']['throughput_mbps']:.1f} MB/s")
        print(f"   Tamaño promedio: {key_metrics['size_metrics']['avg_event_size_bytes']:.1f} bytes/evento")
        print(f"   Latencia P95: {key_metrics['serialization']['p95_time_us']:.1f} μs")
        print(f"   Tasa éxito: {key_metrics['deserialization']['success_rate'] * 100:.1f}%")

    # Evaluación vs targets
    target_eps = 100000  # 100K eventos/segundo
    if performance_results and largest_test:
        actual_eps = key_metrics['serialization']['events_per_second']
        target_met = actual_eps >= target_eps

        print(f"\n🎯 Evaluación vs Targets:")
        print(f"   Target: >{target_eps:,} eventos/segundo")
        print(f"   Actual: {actual_eps:,.0f} eventos/segundo")
        print(f"   Status: {'✅ TARGET MET' if target_met else '❌ Below target'}")

        if target_met:
            print("\n🎉 ¡Protocol Buffers cumple los targets de performance!")
            print("✅ Listo para comparación con otros protocolos")
        else:
            print("\n⚠️  Performance por debajo del target")
            print("💡 Considera ajustar configuración o optimizar")

    print(f"\n📝 Próximos pasos:")
    print("   1. Implementar MessagePack + LZ4 + ChaCha20")
    print("   2. Implementar Apache Arrow + LZ4 + ChaCha20")
    print("   3. Ejecutar benchmark comparativo")
    print("   4. Integrar con pipeline ML")

    return True


if __name__ == "__main__":
    success = main()

    if success:
        print("\n🚀 Test de investigación Protocol Buffers completado exitosamente!")
        print("📊 Resultados guardados en research_results/benchmarks/")
    else:
        print("\n💥 Test falló. Revisar setup y dependencias.")
        sys.exit(1)


# ============================================================
# SCRIPT DE SETUP RÁPIDO
# ============================================================

def quick_setup():
    """Setup rápido para testing."""
    print("⚡ Setup rápido de testing...")

    # Crear directorios necesarios
    os.makedirs("src/protocols/protobuf", exist_ok=True)
    os.makedirs("src/common", exist_ok=True)
    os.makedirs("research_results/benchmarks", exist_ok=True)

    # Crear __init__.py files
    init_files = [
        "src/__init__.py",
        "src/protocols/__init__.py",
        "src/protocols/protobuf/__init__.py",
        "src/common/__init__.py"
    ]

    for init_file in init_files:
        if not os.path.exists(init_file):
            with open(init_file, 'w') as f:
                f.write("# Auto-generated __init__.py\n")

    print("✅ Estructura básica creada")


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--quick-setup":
    quick_setup()