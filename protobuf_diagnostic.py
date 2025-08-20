#!/usr/bin/env python3
"""
🔍 PROTOBUF DIAGNOSTIC TOOL v3.1
protobuf_diagnostic.py

Script para diagnosticar problemas con protobuf v3.1 y enums
"""

import os
import sys
import importlib
from typing import Optional, Any


def test_protobuf_import() -> tuple[bool, Optional[Any], str]:
    """Test protobuf module import"""
    print("🔍 Testing protobuf v3.1 import...")

    # Estrategias de importación
    import_strategies = [
        ("protocols.v3_1.network_security_clean_v31_pb2", "Paquete protocols.v3_1"),
        ("protocols.network_security_clean_v31_pb2", "Paquete protocols"),
        ("network_security_clean_v31_pb2", "Importación directa"),
    ]

    for import_path, description in import_strategies:
        try:
            module = importlib.import_module(import_path)
            print(f"✅ {description}: {import_path}")
            return True, module, import_path
        except ImportError as e:
            print(f"❌ {description}: {e}")

    # Estrategia con path dinámico
    current_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [
        os.path.join(current_dir, '..', 'protocols', 'v3_1'),
        os.path.join(current_dir, 'protocols', 'v3_1'),
        os.path.join(os.getcwd(), 'protocols', 'v3_1'),
    ]

    for protocols_path in possible_paths:
        protocols_path = os.path.abspath(protocols_path)
        pb2_file = os.path.join(protocols_path, 'network_security_clean_v31_pb2.py')

        if os.path.exists(pb2_file):
            try:
                sys.path.insert(0, protocols_path)
                import network_security_clean_v31_pb2 as module
                print(f"✅ Path dinámico: {protocols_path}")
                return True, module, "network_security_clean_v31_pb2"
            except ImportError as e:
                print(f"❌ Path dinámico {protocols_path}: {e}")
                if protocols_path in sys.path:
                    sys.path.remove(protocols_path)

    return False, None, ""


def test_enum_values(module: Any) -> None:
    """Test enum values"""
    print("\n🔢 Testing enum values...")

    try:
        # Test TimeWindow.WindowType
        print("⏰ TimeWindow.WindowType:")
        window_type_enum = module.TimeWindow.WindowType

        test_enums = ['SLIDING', 'TUMBLING', 'SESSION_BASED', 'ADAPTIVE']
        for enum_name in test_enums:
            try:
                value = getattr(window_type_enum, enum_name)
                print(f"   ✅ {enum_name} = {value} (type: {type(value)})")
            except AttributeError:
                print(f"   ❌ {enum_name} not found")

        # Test DistributedNode.NodeRole
        print("\n🖥️ DistributedNode.NodeRole:")
        node_role_enum = module.DistributedNode.NodeRole

        test_roles = ['PACKET_SNIFFER', 'FEATURE_PROCESSOR', 'ML_ANALYZER']
        for role_name in test_roles:
            try:
                value = getattr(node_role_enum, role_name)
                print(f"   ✅ {role_name} = {value} (type: {type(value)})")
            except AttributeError:
                print(f"   ❌ {role_name} not found")

        # Test DistributedNode.NodeStatus
        print("\n📊 DistributedNode.NodeStatus:")
        node_status_enum = module.DistributedNode.NodeStatus

        test_statuses = ['ACTIVE', 'STARTING', 'STOPPING', 'ERROR']
        for status_name in test_statuses:
            try:
                value = getattr(node_status_enum, status_name)
                print(f"   ✅ {status_name} = {value} (type: {type(value)})")
            except AttributeError:
                print(f"   ❌ {status_name} not found")

    except Exception as e:
        print(f"❌ Error testing enums: {e}")


def test_event_creation(module: Any) -> None:
    """Test creating a basic event"""
    print("\n📦 Testing event creation...")

    try:
        # Create basic event
        event = module.NetworkSecurityEvent()
        print("✅ NetworkSecurityEvent created")

        # Test basic fields
        event.event_id = "test-123"
        event.originating_node_id = "test-node"
        event.schema_version = 31
        event.protobuf_version = "3.1.0"
        print("✅ Basic fields set")

        # Test enum assignment (correct way)
        capturing_node = event.capturing_node
        capturing_node.node_id = "test-node"
        capturing_node.node_hostname = "test-host"

        # Use enum values correctly
        capturing_node.node_role = module.DistributedNode.NodeRole.PACKET_SNIFFER
        capturing_node.node_status = module.DistributedNode.NodeStatus.ACTIVE
        print("✅ Enum fields set correctly")

        # Test time window
        time_window = event.time_window
        time_window.sequence_number = 1
        time_window.window_type = module.TimeWindow.WindowType.SLIDING
        print("✅ TimeWindow enum set correctly")

        # Test serialization
        serialized = event.SerializeToString()
        print(f"✅ Event serialized: {len(serialized)} bytes")

        # Test deserialization
        event2 = module.NetworkSecurityEvent()
        event2.ParseFromString(serialized)
        print("✅ Event deserialized successfully")

        return True

    except Exception as e:
        print(f"❌ Error creating event: {e}")
        import traceback
        print(f"❌ Traceback: {traceback.format_exc()}")
        return False


def test_enum_helper_simulation(module: Any) -> None:
    """Test enum helper logic"""
    print("\n🔧 Testing enum helper simulation...")

    def get_window_type_enum(window_type_str: str) -> int:
        """Simulate enum helper"""
        try:
            window_type_mapping = {
                "SLIDING": module.TimeWindow.WindowType.SLIDING,
                "TUMBLING": module.TimeWindow.WindowType.TUMBLING,
                "SESSION_BASED": module.TimeWindow.WindowType.SESSION_BASED,
                "ADAPTIVE": module.TimeWindow.WindowType.ADAPTIVE,
            }
            return window_type_mapping.get(window_type_str.upper(), 0)
        except AttributeError:
            return 0

    # Test conversions
    test_cases = ["SLIDING", "tumbling", "SESSION_BASED", "invalid"]
    for test_case in test_cases:
        result = get_window_type_enum(test_case)
        print(f"   '{test_case}' -> {result}")


def main():
    """Main diagnostic function"""
    print("🚀 PROTOBUF DIAGNOSTIC TOOL v3.1")
    print("=" * 50)

    # Test import
    success, module, import_path = test_protobuf_import()

    if not success:
        print("\n❌ PROTOBUF MODULE NOT FOUND")
        print("💡 Posibles soluciones:")
        print("   1. Generar protobuf: protoc --python_out=. network_security_clean_v31.proto")
        print("   2. Verificar ruta de protobuf en sys.path")
        print("   3. Instalar protobuf: pip install protobuf")
        return

    print(f"\n✅ PROTOBUF MODULE LOADED: {import_path}")

    # Test enum values
    test_enum_values(module)

    # Test event creation
    success = test_event_creation(module)

    if success:
        print("\n✅ ALL TESTS PASSED")
        print("🎯 Tu protobuf está funcionando correctamente!")
    else:
        print("\n❌ SOME TESTS FAILED")
        print("💡 Revisa los errores arriba")

    # Test enum helper
    test_enum_helper_simulation(module)

    print("\n" + "=" * 50)
    print("🏁 DIAGNOSTIC COMPLETED")


if __name__ == "__main__":
    main()