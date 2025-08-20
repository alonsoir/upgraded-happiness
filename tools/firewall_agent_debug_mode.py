#!/usr/bin/env python3
"""
FIREWALL AGENT DEBUG MODE - Para identificar QUÉ CARAJO está pasando
"""
import json
import time
import zmq
import logging
import os
import sys

# 🔐 CRYPTO V31
try:
    from crypto.crypto_zmq_v31 import CryptoZMQV31

    CRYPTO_V31_AVAILABLE = True
    print("✅ CryptoZMQV31 disponible")
except ImportError as e:
    print(f"❌ CryptoZMQV31 NO disponible: {e}")
    CRYPTO_V31_AVAILABLE = False

# 📦 Protobuf - MÚLTIPLES INTENTOS
PROTOBUF_MODULES = {}


def try_import_protobuf():
    """Intentar importar todos los protobuf posibles"""
    strategies = [
        ("firewall_commands_v31_pb2", "Directo V3.1"),
        ("protocols.v3_1.firewall_commands_v31_pb2", "Package V3.1"),
        ("firewall_commands_pb2", "Directo legacy"),
        ("protocols.firewall_commands_pb2", "Package legacy"),
    ]

    for import_path, description in strategies:
        try:
            module = __import__(import_path, fromlist=[''])
            PROTOBUF_MODULES[description] = module
            print(f"✅ {description}: {import_path}")
        except ImportError as e:
            print(f"❌ {description}: {e}")

    return len(PROTOBUF_MODULES) > 0


try_import_protobuf()


def debug_raw_data(data: bytes, source: str):
    """Debug completo de datos raw"""
    print(f"\n🔍 === DEBUG RAW DATA FROM {source} ===")
    print(f"📏 Size: {len(data)} bytes")
    print(f"🔤 First 100 bytes (hex): {data[:100].hex()}")
    print(f"📝 First 100 bytes (ascii): {data[:100].decode('ascii', errors='ignore')}")

    # Verificar si parece JSON
    try:
        if data.strip().startswith(b'{'):
            json_data = json.loads(data.decode('utf-8'))
            print(f"✅ LOOKS LIKE JSON: {json_data}")
            return "JSON", json_data
    except:
        pass

    # Verificar si parece protobuf
    if len(data) > 0:
        first_byte = data[0]
        wire_type = first_byte & 0x07
        field_number = (first_byte >> 3)
        print(f"🔬 Protobuf analysis:")
        print(f"   First byte: 0x{first_byte:02x}")
        print(f"   Wire type: {wire_type}")
        print(f"   Field number: {field_number}")

        if wire_type in [0, 1, 2, 5] and field_number > 0:
            print(f"✅ LOOKS LIKE PROTOBUF")
            return "PROTOBUF", None
        else:
            print(f"❌ NOT PROTOBUF FORMAT")

    print(f"❓ UNKNOWN FORMAT")
    return "UNKNOWN", None


def try_parse_with_all_protobuf(data: bytes):
    """Intentar parsear con todos los módulos protobuf disponibles"""
    print(f"\n🧪 === TRYING ALL PROTOBUF MODULES ===")

    for description, module in PROTOBUF_MODULES.items():
        try:
            print(f"\n🔬 Trying {description}...")

            # Verificar si tiene FirewallCommand
            if hasattr(module, 'FirewallCommand'):
                pb_command = module.FirewallCommand()
                pb_command.ParseFromString(data)
                print(f"✅ SUCCESS with {description}!")
                print(f"   Command ID: {pb_command.command_id}")
                print(f"   Action: {pb_command.action}")
                print(f"   Target IP: {pb_command.target_ip}")
                return pb_command, description
            else:
                print(f"❌ No FirewallCommand in {description}")

        except Exception as e:
            print(f"❌ Failed with {description}: {e}")

    print(f"💥 ALL PROTOBUF MODULES FAILED")
    return None, None


def debug_crypto_setup(config_file: str, component_id: str):
    """Debug de configuración crypto"""
    print(f"\n🔐 === CRYPTO DEBUG ===")

    if not CRYPTO_V31_AVAILABLE:
        print(f"❌ CRYPTO NOT AVAILABLE")
        return None

    try:
        crypto_wrapper = CryptoZMQV31(component_id, config_file)
        print(f"✅ Crypto wrapper created successfully")
        print(f"   Component ID: {component_id}")
        print(f"   Config file: {config_file}")
        return crypto_wrapper
    except Exception as e:
        print(f"❌ Crypto wrapper failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def main_debug():
    """Main debug - simplified single socket test"""

    # Configuración básica
    config_file = "simple_firewall_agent_v31_config.json"
    crypto_config_file = "config/crypto/crypto_config_v31.json"
    component_id = "simple_firewall_agent_001"

    print("🚀 FIREWALL AGENT DEBUG MODE")
    print("=" * 50)

    # 1. Setup crypto
    crypto_wrapper = debug_crypto_setup(crypto_config_file, component_id)

    # 2. Setup ZMQ - SOLO DASHBOARD para simplificar
    context = zmq.Context()
    dashboard_socket = context.socket(zmq.SUB)
    dashboard_socket.setsockopt(zmq.SUBSCRIBE, b"")

    # 3. Crypto wrapping si está disponible
    if crypto_wrapper:
        print("🔐 Wrapping dashboard socket...")
        try:
            dashboard_socket = crypto_wrapper.wrap_socket_recv(dashboard_socket)
            print("✅ Dashboard socket wrapped successfully")
        except Exception as e:
            print(f"❌ Socket wrapping failed: {e}")
            return

    # 4. Connect
    dashboard_socket.connect("tcp://localhost:5580")
    print("🔌 Connected to dashboard on port 5580")

    print("\n⏳ Waiting for messages...")
    print("=" * 50)

    message_count = 0

    while True:
        try:
            # Receive with timeout
            raw_data = dashboard_socket.recv(zmq.NOBLOCK)
            message_count += 1

            print(f"\n📨 MESSAGE #{message_count} RECEIVED")
            print("=" * 30)

            # Debug raw data
            data_type, parsed_data = debug_raw_data(raw_data, "DASHBOARD")

            if data_type == "JSON":
                print("🎯 DATA IS JSON - Dashboard might be sending JSON instead of protobuf!")

            elif data_type == "PROTOBUF":
                # Try parsing with all protobuf modules
                parsed_pb, successful_module = try_parse_with_all_protobuf(raw_data)

                if parsed_pb:
                    print(f"🎉 PROTOBUF PARSING SUCCESS with {successful_module}!")
                else:
                    print("💥 ALL PROTOBUF PARSING FAILED")
                    print("🤔 Possible issues:")
                    print("   1. Wrong protobuf version")
                    print("   2. Data corruption during decryption")
                    print("   3. Sender using different protobuf schema")

            else:
                print("❓ UNKNOWN DATA FORMAT")
                print("🤔 Possible issues:")
                print("   1. Encryption/decryption problem")
                print("   2. Data corruption")
                print("   3. Wrong socket/port")

            # Espaciado para siguiente mensaje
            print("\n" + "=" * 50)

        except zmq.Again:
            time.sleep(0.1)
            continue
        except KeyboardInterrupt:
            print("\n🛑 Debug interrupted by user")
            break
        except Exception as e:
            print(f"\n💥 UNEXPECTED ERROR: {e}")
            import traceback
            traceback.print_exc()
            break

    # Cleanup
    if crypto_wrapper:
        crypto_wrapper.close()
    dashboard_socket.close()
    context.term()

    print(f"\n📊 DEBUG SUMMARY:")
    print(f"   Messages received: {message_count}")
    print(f"   Protobuf modules available: {len(PROTOBUF_MODULES)}")
    print(f"   Crypto available: {CRYPTO_V31_AVAILABLE}")


if __name__ == "__main__":
    main_debug()