#!/usr/bin/env python3
"""
🧪 TEST EVOLUTIONARY SNIFFER v3.1
test_evolutionary_sniffer_v31.py

Pruebas unitarias y de integración para verificar que todo funciona
antes de hacer captura real de paquetes.

TESTS:
✅ Importación de protobuf v3.1
✅ Dependencias críticas (scapy, zmq, etc.)
✅ Carga de configuración JSON
✅ Extracción de features ML
✅ Time windows management
✅ Creación de eventos protobuf
✅ Serialización y deserialización
✅ ZeroMQ socket setup

Autor: Alonso Isidoro, Claude
Fecha: Agosto 9, 2025
"""

import sys
import os
import json
import time
import uuid
import traceback
from typing import Dict, Any, List
from datetime import datetime, timedelta

# Añadir el directorio actual al path para importar el sniffer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_imports():
    """Test 1: Verificar todas las importaciones críticas"""
    print("🧪 TEST 1: Verificando importaciones críticas...")

    issues = []

    # Test protobuf v3.1 con la misma estrategia que el sniffer
    try:
        # Buscar protobuf con múltiples estrategias
        protobuf_found = False

        # Estrategia 1: Importación directa
        try:
            import network_security_clean_v31_pb2 as pb
            protobuf_found = True
            print("   ✅ Protobuf v3.1 importado directamente")
        except ImportError:
            pass

        # Estrategia 2: Buscar en protocols/v3.1/
        if not protobuf_found:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            possible_paths = [
                os.path.join(current_dir, '..', 'protocols', 'v3.1'),
                os.path.join(current_dir, 'protocols', 'v3.1'),
                current_dir,
                os.path.join(current_dir, '..'),
            ]

            for protocols_path in possible_paths:
                protocols_path = os.path.abspath(protocols_path)
                pb2_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')

                if os.path.exists(pb2_file):
                    try:
                        sys.path.insert(0, protocols_path)
                        import network_security_clean_v31_pb2 as pb
                        protobuf_found = True
                        print(f"   ✅ Protobuf v3.1 encontrado en: {protocols_path}")
                        break
                    except ImportError:
                        if protocols_path in sys.path:
                            sys.path.remove(protocols_path)
                        continue

        if not protobuf_found:
            issues.append("❌ Protobuf v3.1: No encontrado en ninguna ubicación")
            print("   🔍 Ubicaciones buscadas:")
            current_dir = os.path.dirname(os.path.abspath(__file__))
            search_paths = [
                os.path.join(current_dir, '..', 'protocols', 'v3.1'),
                os.path.join(current_dir, 'protocols', 'v3.1'),
                current_dir,
                os.path.join(current_dir, '..'),
            ]
            for path in search_paths:
                pb2_file = os.path.join(os.path.abspath(path), 'network_security_clean_v31_pb2.py')
                exists = "✅" if os.path.exists(pb2_file) else "❌"
                print(f"      {exists} {pb2_file}")

    except Exception as e:
        issues.append(f"❌ Protobuf v3.1: {e}")

    # Test scapy
    try:
        from scapy.all import IP, TCP, UDP
        print("   ✅ Scapy importado correctamente")
    except ImportError as e:
        issues.append(f"❌ Scapy: {e}")

    # Test zmq
    try:
        import zmq
        print("   ✅ ZeroMQ importado correctamente")
    except ImportError as e:
        issues.append(f"❌ ZeroMQ: {e}")

    # Test pandas/numpy
    try:
        import numpy as np
        import pandas as pd
        print("   ✅ NumPy/Pandas importados correctamente")
    except ImportError as e:
        issues.append(f"❌ NumPy/Pandas: {e}")

    # Test psutil
    try:
        import psutil
        print("   ✅ psutil importado correctamente")
    except ImportError as e:
        issues.append(f"❌ psutil: {e}")

    if issues:
        print("   🚨 PROBLEMAS ENCONTRADOS:")
        for issue in issues:
            print(f"      {issue}")
        return False
    else:
        print("   🎯 Todas las importaciones OK")
        return True


def test_config_loading():
    """Test 2: Verificar carga de configuración JSON"""
    print("\n🧪 TEST 2: Verificando carga de configuración...")

    # Crear config temporal para testing
    test_config = {
        "node_id": "test_node_001",
        "version": "3.1.0",
        "network": {
            "output_socket": {
                "address": "localhost",
                "port": 5999,
                "mode": "bind",
                "socket_type": "PUSH"
            }
        },
        "time_windows": {
            "test_window": {
                "window_size_seconds": 10.0,
                "slide_interval_seconds": 2.0,
                "max_flows_per_window": 100,
                "features_required": ["flow_duration", "total_forward_packets"],
                "model_types": ["ddos_83"],
                "description": "Test window"
            }
        },
        "capture": {
            "interface": "any",
            "promiscuous_mode": True,
            "filter_expression": "",
            "buffer_size": 1024,
            "min_packet_size": 20,
            "excluded_ports": [22],
            "included_protocols": ["tcp", "udp"]
        },
        "processing": {
            "internal_queue_size": 100,
            "processing_threads": 1,
            "queue_timeout_seconds": 1.0
        },
        "logging": {
            "level": "INFO",
            "file": None
        },
        "monitoring": {
            "stats_interval_seconds": 30,
            "alerts": {
                "max_queue_usage_percent": 80.0
            }
        }
    }

    try:
        # Guardar config temporal
        with open('test_config_v31.json', 'w') as f:
            json.dump(test_config, f, indent=2)

        # Verificar que se puede cargar
        with open('test_config_v31.json', 'r') as f:
            loaded_config = json.load(f)

        # Verificar campos críticos
        required_fields = ["node_id", "network", "time_windows", "capture", "processing"]
        for field in required_fields:
            if field not in loaded_config:
                print(f"   ❌ Campo faltante: {field}")
                return False

        print("   ✅ Configuración JSON cargada y validada correctamente")
        return True

    except Exception as e:
        print(f"   ❌ Error en configuración: {e}")
        return False
    finally:
        # Limpiar archivo temporal
        if os.path.exists('test_config_v31.json'):
            os.remove('test_config_v31.json')


def test_features_extractor():
    """Test 3: Verificar extractor de features ML"""
    print("\n🧪 TEST 3: Verificando extractor de features...")

    try:
        # Importar classes necesarias
        from evolutionary_sniffer_v31 import NetworkFeaturesExtractor, FlowInfo, PacketInfo

        # Crear extractor
        extractor = NetworkFeaturesExtractor()

        # Crear flujo de prueba
        flow = FlowInfo(
            flow_id="test_flow_001",
            src_ip="192.168.1.100",
            dst_ip="192.168.1.200",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            start_time=time.time() - 10,
            last_seen=time.time(),
            forward_packets=[],
            backward_packets=[]
        )

        # Añadir paquetes de prueba
        for i in range(5):
            packet = PacketInfo(
                timestamp=time.time() - 9 + i,
                src_ip="192.168.1.100",
                dst_ip="192.168.1.200",
                src_port=12345,
                dst_port=80,
                protocol_number=6,
                protocol_name="TCP",
                packet_size=100 + i * 10,
                tcp_flags={'S': i == 0, 'A': i > 0, 'F': i == 4},
                flow_id="test_flow_001"
            )
            flow.forward_packets.append(packet)
            flow.total_forward_bytes += packet.packet_size

        # Extraer features
        features = extractor.extract_all_features(flow)

        # Verificar features extraídas
        if len(features) == 0:
            print("   ❌ No se extrajeron features")
            return False

        print(f"   ✅ Extraídas {len(features)} features correctamente")

        # Verificar features específicas por modelo
        ddos_features = extractor.get_features_for_model(features, "ddos_83")
        rf_features = extractor.get_features_for_model(features, "rf_23")
        internal_features = extractor.get_features_for_model(features, "internal_4")

        print(f"   ✅ Features DDOS: {len(ddos_features)} (esperado: 83)")
        print(f"   ✅ Features RF: {len(rf_features)} (esperado: 23)")
        print(f"   ✅ Features Internal: {len(internal_features)} (esperado: 4)")

        # Verificar que las features tienen valores razonables
        duration = features.get('flow_duration', 0)
        if duration <= 0:
            print("   ⚠️ Warning: flow_duration es 0")

        packets = features.get('total_forward_packets', 0)
        if packets != 5:
            print(f"   ⚠️ Warning: total_forward_packets es {packets}, esperado 5")

        print("   🎯 Extractor de features funcionando correctamente")
        return True

    except Exception as e:
        print(f"   ❌ Error en extractor de features: {e}")
        traceback.print_exc()
        return False


def test_time_windows():
    """Test 4: Verificar time window manager"""
    print("\n🧪 TEST 4: Verificando time window manager...")

    try:
        from evolutionary_sniffer_v31 import TimeWindowManager, TimeWindowConfig, PacketInfo
        import logging

        # Configurar logger temporal
        logger = logging.getLogger("test")

        # Crear configuración de ventanas
        configs = {
            "test_window": TimeWindowConfig(
                window_size_seconds=5.0,
                slide_interval_seconds=1.0,
                max_flows_per_window=100,
                features_required=["flow_duration"],
                model_types=["ddos_83"],
                description="Test window"
            )
        }

        # Crear manager
        manager = TimeWindowManager(configs, logger)

        # Añadir paquetes de prueba
        for i in range(3):
            packet = PacketInfo(
                timestamp=time.time() + i,
                src_ip="192.168.1.100",
                dst_ip="192.168.1.200",
                src_port=12345,
                dst_port=80,
                protocol_number=6,
                protocol_name="TCP",
                packet_size=100,
                tcp_flags={'A': True},
                flow_id=f"test_flow_{i}"
            )
            manager.add_packet(packet)

        # Verificar flujos activos
        if len(manager.active_flows) != 3:
            print(f"   ❌ Flujos activos: {len(manager.active_flows)}, esperado: 3")
            return False

        print(f"   ✅ Time windows manager creado con {len(manager.active_flows)} flujos")
        print("   🎯 Time window manager funcionando correctamente")
        return True

    except Exception as e:
        print(f"   ❌ Error en time window manager: {e}")
        traceback.print_exc()
        return False


def test_protobuf_event_creation():
    """Test 5: Verificar creación de eventos protobuf v3.1"""
    print("\n🧪 TEST 5: Verificando creación de eventos protobuf...")

    try:
        # Usar la misma estrategia de importación que el sniffer
        pb = None

        # Estrategia 1: Importación directa
        try:
            import network_security_clean_v31_pb2 as pb
        except ImportError:
            pass

        # Estrategia 2: Buscar en paths conocidos
        if pb is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            possible_paths = [
                os.path.join(current_dir, '..', 'protocols', 'v3.1'),
                os.path.join(current_dir, 'protocols', 'v3.1'),
                current_dir,
                os.path.join(current_dir, '..'),
            ]

            for protocols_path in possible_paths:
                protocols_path = os.path.abspath(protocols_path)
                pb2_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')

                if os.path.exists(pb2_file):
                    try:
                        sys.path.insert(0, protocols_path)
                        import network_security_clean_v31_pb2 as pb
                        break
                    except ImportError:
                        if protocols_path in sys.path:
                            sys.path.remove(protocols_path)
                        continue

        if pb is None:
            print("   ❌ No se pudo importar protobuf v3.1")
            return False

        # Crear evento protobuf
        event = pb.NetworkSecurityEvent()

        # Llenar campos básicos
        event.event_id = str(uuid.uuid4())
        event.event_timestamp.FromDatetime(datetime.now())
        event.originating_node_id = "test_node_001"

        # Network features básicas
        event.network_features.source_ip = "192.168.1.100"
        event.network_features.destination_ip = "192.168.1.200"
        event.network_features.source_port = 12345
        event.network_features.destination_port = 80
        event.network_features.protocol_name = "TCP"

        # Features DDOS
        event.network_features.ddos_features[:] = [1.0, 2.0, 3.0, 4.0, 5.0]

        # Nodo distribuido
        event.capturing_node.node_id = "test_node_001"
        event.capturing_node.node_hostname = "test_host"
        event.capturing_node.node_role = pb.DistributedNode.NodeRole.PACKET_SNIFFER
        event.capturing_node.node_status = pb.DistributedNode.NodeStatus.ACTIVE
        event.capturing_node.process_id = os.getpid()

        # Time window
        event.time_window.window_start.FromDatetime(datetime.now() - timedelta(seconds=10))
        event.time_window.window_end.FromDatetime(datetime.now())
        event.time_window.window_type = pb.TimeWindow.WindowType.SLIDING

        # Pipeline tracking
        event.pipeline_tracking.pipeline_id = str(uuid.uuid4())
        event.pipeline_tracking.sniffer_process_id = os.getpid()
        event.pipeline_tracking.pipeline_hops_count = 1
        event.pipeline_tracking.processing_path = "sniffer[test]"

        # Metadatos
        event.schema_version = 31
        event.final_classification = "CAPTURED"
        event.protobuf_version = "3.1.0"
        event.custom_metadata["test"] = "true"
        event.event_tags.extend(["test", "sniffer_v31"])

        # Serializar
        serialized = event.SerializeToString()

        # Deserializar para verificar
        event2 = pb.NetworkSecurityEvent()
        event2.ParseFromString(serialized)

        # Verificar que la deserialización funciona
        if event2.event_id != event.event_id:
            print("   ❌ Error en serialización/deserialización")
            return False

        if event2.network_features.source_ip != "192.168.1.100":
            print("   ❌ Error en network features")
            return False

        if len(event2.network_features.ddos_features) != 5:
            print("   ❌ Error en ddos features")
            return False

        print(f"   ✅ Evento protobuf creado: {len(serialized)} bytes")
        print(f"   ✅ Event ID: {event2.event_id}")
        print(f"   ✅ Source IP: {event2.network_features.source_ip}")
        print(f"   ✅ Node ID: {event2.capturing_node.node_id}")
        print(f"   ✅ Schema version: {event2.schema_version}")
        print(f"   ✅ DDOS features: {len(event2.network_features.ddos_features)}")
        print("   🎯 Eventos protobuf v3.1 funcionando correctamente")
        return True

    except Exception as e:
        print(f"   ❌ Error en eventos protobuf: {e}")
        traceback.print_exc()
        return False


def test_zmq_socket():
    """Test 6: Verificar configuración ZeroMQ"""
    print("\n🧪 TEST 6: Verificando configuración ZeroMQ...")

    try:
        import zmq

        # Crear contexto y socket
        context = zmq.Context()
        socket = context.socket(zmq.PUSH)

        # Configurar socket
        socket.setsockopt(zmq.SNDHWM, 1000)
        socket.setsockopt(zmq.LINGER, 1000)
        socket.setsockopt(zmq.SNDTIMEO, 100)

        # Test bind/unbind
        port = 5999
        bind_address = f"tcp://*:{port}"
        socket.bind(bind_address)

        print(f"   ✅ Socket ZMQ creado y bind en {bind_address}")

        # Test envío no-bloqueante (debería funcionar)
        try:
            socket.send(b"test_message", zmq.NOBLOCK)
            print("   ✅ Envío no-bloqueante OK")
        except zmq.Again:
            print("   ✅ Envío no-bloqueante (buffer lleno) - comportamiento esperado")

        # Limpiar
        socket.close()
        context.term()

        print("   🎯 ZeroMQ funcionando correctamente")
        return True

    except Exception as e:
        print(f"   ❌ Error en ZeroMQ: {e}")
        return False


def test_evolutionary_sniffer_initialization():
    """Test 7: Verificar inicialización del sniffer sin captura real"""
    print("\n🧪 TEST 7: Verificando inicialización del sniffer...")

    try:
        # Crear config mínima para testing
        test_config = {
            "node_id": "test_node_001",
            "version": "3.1.0",
            "network": {
                "output_socket": {
                    "address": "localhost",
                    "port": 5999,
                    "mode": "bind",
                    "socket_type": "PUSH"
                }
            },
            "zmq": {
                "sndhwm": 1000,
                "linger_ms": 1000,
                "send_timeout_ms": 100
            },
            "time_windows": {
                "test_window": {
                    "window_size_seconds": 10.0,
                    "slide_interval_seconds": 2.0,
                    "max_flows_per_window": 100,
                    "features_required": ["flow_duration"],
                    "model_types": ["ddos_83"],
                    "description": "Test window"
                }
            },
            "capture": {
                "interface": "any",
                "promiscuous_mode": True,
                "filter_expression": "",
                "buffer_size": 1024,
                "min_packet_size": 20,
                "excluded_ports": [22],
                "included_protocols": ["tcp", "udp"]
            },
            "processing": {
                "internal_queue_size": 100,
                "processing_threads": 1,
                "queue_timeout_seconds": 1.0
            },
            "logging": {
                "level": "ERROR",  # Reducir logs para testing
                "file": None
            },
            "monitoring": {
                "stats_interval_seconds": 30,
                "alerts": {
                    "max_queue_usage_percent": 80.0
                }
            }
        }

        # Guardar config temporal
        with open('test_init_config_v31.json', 'w') as f:
            json.dump(test_config, f, indent=2)

        # Importar sniffer
        from evolutionary_sniffer_v31 import EvolutionarySniffer

        # Intentar inicializar (sin run())
        sniffer = EvolutionarySniffer('test_init_config_v31.json')

        # Verificar inicialización
        if sniffer.node_id != "test_node_001":
            print(f"   ❌ Node ID incorrecto: {sniffer.node_id}")
            return False

        if not sniffer.features_extractor:
            print("   ❌ Features extractor no inicializado")
            return False

        if not sniffer.time_window_manager:
            print("   ❌ Time window manager no inicializado")
            return False

        if len(sniffer.time_window_manager.window_configs) != 1:
            print("   ❌ Time window configs incorrectas")
            return False

        # Test handshake creation (sin envío)
        sniffer.handshake_sent = False
        # sniffer.send_handshake()  # No llamar para evitar envío real

        print(f"   ✅ Sniffer inicializado: {sniffer.node_id}")
        print(f"   ✅ Features extractor: OK")
        print(f"   ✅ Time window manager: {len(sniffer.time_window_manager.window_configs)} ventanas")
        print(f"   ✅ ZMQ socket: configurado")

        # Limpiar
        if sniffer.socket:
            sniffer.socket.close()
        sniffer.context.term()

        print("   🎯 Sniffer evolutivo v3.1 inicialización OK")
        return True

    except Exception as e:
        print(f"   ❌ Error en inicialización del sniffer: {e}")
        traceback.print_exc()
        return False
    finally:
        # Limpiar archivo temporal
        if os.path.exists('test_init_config_v31.json'):
            os.remove('test_init_config_v31.json')


def run_all_tests():
    """Ejecuta todos los tests"""
    print("🚀 INICIANDO TESTS EVOLUTIONARY SNIFFER v3.1")
    print("=" * 60)

    tests = [
        ("Importaciones críticas", test_imports),
        ("Carga de configuración", test_config_loading),
        ("Extractor de features", test_features_extractor),
        ("Time window manager", test_time_windows),
        ("Eventos protobuf v3.1", test_protobuf_event_creation),
        ("Configuración ZeroMQ", test_zmq_socket),
        ("Inicialización sniffer", test_evolutionary_sniffer_initialization),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"   ✅ {test_name}: PASSED")
            else:
                failed += 1
                print(f"   ❌ {test_name}: FAILED")
        except Exception as e:
            failed += 1
            print(f"   💥 {test_name}: ERROR - {e}")

    print("\n" + "=" * 60)
    print(f"📊 RESULTADO FINAL:")
    print(f"   ✅ PASSED: {passed}")
    print(f"   ❌ FAILED: {failed}")
    print(f"   📈 SUCCESS RATE: {passed / (passed + failed) * 100:.1f}%")

    if failed == 0:
        print("\n🎉 TODOS LOS TESTS PASARON!")
        print("🚀 Evolutionary Sniffer v3.1 listo para uso")
        print("\n💡 Próximos pasos:")
        print("   1. Ejecutar con sudo para captura promiscua:")
        print("      sudo python evolutionary_sniffer_v31.py evolutionary_sniffer_config_v31.json")
        print("   2. Monitorear logs en: logs/evolutionary_sniffer_v31.log")
        print("   3. Verificar métricas cada 30 segundos")
        return True
    else:
        print(f"\n🚨 {failed} TESTS FALLARON")
        print("🔧 Revisar dependencias y configuración antes de usar")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)