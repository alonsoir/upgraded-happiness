#!/usr/bin/env python3
"""
CRYPTO PROTOBUF ANALYZER - Con crypto wrapping para descifrar datos
"""
import json
import time
import zmq
import sys
import os

# Add protocols path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'protocols', 'current'))

# 🔐 CRYPTO V31
try:
    from crypto.crypto_zmq_v31 import CryptoZMQV31

    CRYPTO_V31_AVAILABLE = True
    print("✅ CryptoZMQV31 disponible")
except ImportError as e:
    print(f"❌ CryptoZMQV31 NO disponible: {e}")
    CRYPTO_V31_AVAILABLE = False

# 📦 Protobuf imports - USANDO PATHS REALES
PROTOBUF_MODULES = {}


def import_all_protobuf_modules():
    """Importar todos los módulos protobuf encontrados"""

    # Modules que SÍ existen según tu ls
    modules_to_try = [
        ("firewall_commands_v31_pb2", "V3.1 current"),
        ("firewall_commands_pb2", "Legacy current"),
        ("network_security_clean_v31_pb2", "Network V3.1"),
    ]

    for module_name, description in modules_to_try:
        try:
            module = __import__(module_name, fromlist=[''])
            PROTOBUF_MODULES[description] = module
            print(f"✅ {description}: {module_name}")

            # Verificar qué classes tiene
            classes = [attr for attr in dir(module) if not attr.startswith('_')]
            print(f"   Classes: {classes}")

        except ImportError as e:
            print(f"❌ {description}: {e}")


def analyze_decrypted_protobuf(data: bytes):
    """Analizar protobuf después de descifrar"""
    print(f"\n🔬 ANALYZING DECRYPTED PROTOBUF:")
    print(f"   Size: {len(data)} bytes")
    print(f"   First 50 bytes (hex): {data[:50].hex()}")

    # Verificar si ahora SÍ parece protobuf
    if len(data) > 0:
        first_byte = data[0]
        wire_type = first_byte & 0x07
        field_number = (first_byte >> 3)

        print(f"   First byte: 0x{first_byte:02x}")
        print(f"   Wire type: {wire_type}")
        print(f"   Field number: {field_number}")

        if wire_type in [0, 1, 2, 5] and field_number > 0:
            print(f"✅ NOW LOOKS LIKE VALID PROTOBUF!")
            return True
        else:
            print(f"❌ Still not valid protobuf after decryption")
            return False

    return False


def try_parse_with_all_modules(data: bytes):
    """Probar parsing con todos los módulos disponibles"""
    print(f"\n🧪 TRYING ALL AVAILABLE MODULES:")

    for description, module in PROTOBUF_MODULES.items():
        print(f"\n🔬 Trying {description}...")

        # Buscar FirewallCommand
        if hasattr(module, 'FirewallCommand'):
            try:
                pb_command = module.FirewallCommand()
                pb_command.ParseFromString(data)

                print(f"✅ SUCCESS with {description}!")
                print(f"   Command ID: {getattr(pb_command, 'command_id', 'N/A')}")
                print(f"   Action: {getattr(pb_command, 'action', 'N/A')}")
                print(f"   Target IP: {getattr(pb_command, 'target_ip', 'N/A')}")

                # Verificar campos V3.1
                if hasattr(pb_command, 'node_id'):
                    print(f"   Node ID: {pb_command.node_id}")
                if hasattr(pb_command, 'timestamp'):
                    print(f"   Timestamp: {pb_command.timestamp}")

                # Mostrar TODOS los campos
                print(f"   All fields:")
                for field_desc in pb_command.DESCRIPTOR.fields:
                    field_value = getattr(pb_command, field_desc.name, 'NOT_SET')
                    print(f"     {field_desc.name}: {field_value}")

                return pb_command, description, module.__name__

            except Exception as e:
                print(f"❌ Parsing failed: {e}")

        else:
            print(f"❌ No FirewallCommand class found")
            # Mostrar qué classes SÍ tiene
            classes = [attr for attr in dir(module) if not attr.startswith('_') and attr[0].isupper()]
            print(f"   Available classes: {classes}")

    return None, None, None


def main_crypto_analyzer():
    """Analizador principal CON crypto"""
    print("🔐 CRYPTO PROTOBUF ANALYZER")
    print("=" * 50)

    # 1. Import protobuf modules
    import_all_protobuf_modules()

    if not PROTOBUF_MODULES:
        print("❌ No protobuf modules available")
        return

    # 2. Setup crypto
    if not CRYPTO_V31_AVAILABLE:
        print("❌ Crypto V31 not available")
        return

    try:
        crypto_wrapper = CryptoZMQV31(
            "simple_firewall_agent_001",
            "config/crypto/crypto_config_v31.json"
        )
        print("✅ Crypto wrapper initialized")
    except Exception as e:
        print(f"❌ Crypto initialization failed: {e}")
        return

    # 3. Setup socket
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.setsockopt(zmq.SUBSCRIBE, b"")

    # 4. Wrap socket with crypto
    try:
        socket = crypto_wrapper.wrap_socket_recv(socket)
        print("✅ Socket wrapped with crypto")
    except Exception as e:
        print(f"❌ Socket wrapping failed: {e}")
        return

    # 5. Connect
    socket.connect("tcp://localhost:5580")
    print("🔌 Connected to scheduler-firewall on port 5580")
    print("⏳ Waiting for encrypted protobuf message...")

    try:
        # Receive - should be auto-decrypted
        decrypted_data = socket.recv()
        print(f"📨 Received {len(decrypted_data)} bytes (should be decrypted)")

        # Analyze decrypted data
        is_valid_protobuf = analyze_decrypted_protobuf(decrypted_data)

        if is_valid_protobuf:
            # Try parsing with all available modules
            parsed_pb, successful_description, module_name = try_parse_with_all_modules(decrypted_data)

            if parsed_pb:
                print(f"\n🎉 SOLUTION FOUND!")
                print(f"   ✅ Crypto wrapping: WORKING")
                print(f"   ✅ Protobuf module: {module_name}")
                print(f"   ✅ Description: {successful_description}")
                print(f"\n🔧 TO FIX YOUR AGENT:")
                print(f"   1. Use: import {module_name}")
                print(f"   2. Ensure crypto wrapper is working")
                print(f"   3. Use {module_name}.FirewallCommand()")
            else:
                print(f"\n❌ No module could parse the decrypted data")
                print("   The protobuf schema is still incompatible")
        else:
            print(f"\n❌ Data is still not valid protobuf after decryption")
            print("   Possible crypto key mismatch")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Cleanup
        try:
            crypto_wrapper.close()
        except:
            pass
        socket.close()
        context.term()


if __name__ == "__main__":
    main_crypto_analyzer()