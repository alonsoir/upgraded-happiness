#!/usr/bin/env python3
"""
PROTOBUF SCHEMA ANALYZER - Encontrar exactamente qué schema usa scheduler-firewall
"""
import json
import time
import zmq
import struct
from typing import Dict, List, Tuple, Any


def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decodificar varint protobuf"""
    result = 0
    shift = 0
    pos = offset

    while pos < len(data):
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
        if shift >= 64:
            raise ValueError("Varint too long")

    return result, pos


def decode_protobuf_raw(data: bytes) -> Dict[str, Any]:
    """Decodificar protobuf raw y mostrar estructura"""
    fields = {}
    pos = 0

    print(f"🔬 ANALYZING PROTOBUF STRUCTURE:")
    print(f"   Total size: {len(data)} bytes")
    print(f"   Raw hex: {data[:50].hex()}...")

    while pos < len(data):
        try:
            # Leer tag (field_number + wire_type)
            tag, pos = decode_varint(data, pos)
            field_number = tag >> 3
            wire_type = tag & 0x07

            print(f"\n📋 Field {field_number} (wire_type {wire_type}):")

            if wire_type == 0:  # Varint
                value, pos = decode_varint(data, pos)
                fields[field_number] = {"type": "varint", "value": value}
                print(f"   VARINT: {value}")

            elif wire_type == 1:  # 64-bit
                if pos + 8 <= len(data):
                    value = struct.unpack('<Q', data[pos:pos + 8])[0]
                    fields[field_number] = {"type": "fixed64", "value": value}
                    print(f"   FIXED64: {value}")
                    pos += 8
                else:
                    break

            elif wire_type == 2:  # Length-delimited (string, bytes, embedded message)
                length, pos = decode_varint(data, pos)
                if pos + length <= len(data):
                    value = data[pos:pos + length]
                    fields[field_number] = {"type": "length_delimited", "length": length, "value": value}

                    # Intentar decodificar como string
                    try:
                        str_value = value.decode('utf-8')
                        print(f"   STRING: '{str_value}'")
                        fields[field_number]["string_value"] = str_value
                    except:
                        print(f"   BYTES: {value[:20].hex()}{'...' if len(value) > 20 else ''}")

                    pos += length
                else:
                    break

            elif wire_type == 5:  # 32-bit
                if pos + 4 <= len(data):
                    value = struct.unpack('<I', data[pos:pos + 4])[0]
                    fields[field_number] = {"type": "fixed32", "value": value}
                    print(f"   FIXED32: {value}")
                    pos += 4
                else:
                    break
            else:
                print(f"   UNKNOWN WIRE TYPE: {wire_type}")
                break

        except Exception as e:
            print(f"❌ Error at position {pos}: {e}")
            break

    return fields


def compare_with_known_schemas(fields: Dict[str, Any]):
    """Comparar con schemas conocidos"""
    print(f"\n🎯 SCHEMA COMPARISON:")

    # Schema esperado para FirewallCommand V3.1
    v31_schema = {
        1: "command_id (string)",
        2: "action (enum)",
        3: "target_ip (string)",
        4: "target_port (int32)",
        5: "duration_seconds (int32)",
        6: "dry_run (bool)",
        7: "node_id (string)",  # Nuevo en V3.1
        8: "timestamp (int64)",  # Nuevo en V3.1
    }

    # Schema legacy
    legacy_schema = {
        1: "command_id (string)",
        2: "action (enum)",
        3: "target_ip (string)",
        4: "target_port (int32)",
        5: "duration_seconds (int32)",
        6: "dry_run (bool)",
    }

    print(f"📊 Fields found in message: {list(fields.keys())}")
    print(f"📊 V3.1 expected fields: {list(v31_schema.keys())}")
    print(f"📊 Legacy expected fields: {list(legacy_schema.keys())}")

    # Analizar compatibilidad
    v31_match = all(f in v31_schema for f in fields.keys())
    legacy_match = all(f in legacy_schema for f in fields.keys())

    print(f"\n🎯 COMPATIBILITY ANALYSIS:")
    print(f"   V3.1 compatible: {'✅' if v31_match else '❌'}")
    print(f"   Legacy compatible: {'✅' if legacy_match else '❌'}")

    # Mostrar campos específicos
    for field_num, field_data in fields.items():
        expected_v31 = v31_schema.get(field_num, "UNKNOWN")
        expected_legacy = legacy_schema.get(field_num, "UNKNOWN")

        print(f"\n📋 Field {field_num}:")
        print(f"   Found: {field_data}")
        print(f"   V3.1 expects: {expected_v31}")
        print(f"   Legacy expects: {expected_legacy}")


def try_parse_with_corrected_import(data: bytes, fields: Dict[str, Any]):
    """Intentar importar el protobuf correcto basado en el análisis"""
    print(f"\n🔧 TRYING CORRECTED IMPORTS:")

    # Determinar qué versión usar basado en campos encontrados
    has_node_id = 7 in fields
    has_timestamp = 8 in fields

    if has_node_id and has_timestamp:
        print("🎯 Data has V3.1 fields (node_id + timestamp)")
        proto_versions = ["v31", "v3.1", "v3_1"]
    else:
        print("🎯 Data appears to be legacy version (no node_id/timestamp)")
        proto_versions = ["legacy", "v3", "v30", "v3_0"]

    # Intentar diferentes imports
    import_attempts = [
        "firewall_commands_v31_pb2",
        "firewall_commands_pb2",
        "firewall_command_pb2",
        "protocols.firewall_commands_v31_pb2",
        "protocols.firewall_commands_pb2",
        "protocols.v3.1.firewall_commands_v31_pb2",
        "protocols.v3.firewall_commands_pb2",
    ]

    for import_path in import_attempts:
        try:
            print(f"\n🧪 Trying: {import_path}")
            module = __import__(import_path, fromlist=[''])

            if hasattr(module, 'FirewallCommand'):
                pb_command = module.FirewallCommand()
                pb_command.ParseFromString(data)

                print(f"✅ SUCCESS with {import_path}!")
                print(f"   Command ID: {getattr(pb_command, 'command_id', 'N/A')}")
                print(f"   Action: {getattr(pb_command, 'action', 'N/A')}")
                print(f"   Target IP: {getattr(pb_command, 'target_ip', 'N/A')}")
                print(f"   Node ID: {getattr(pb_command, 'node_id', 'N/A')}")
                print(f"   Timestamp: {getattr(pb_command, 'timestamp', 'N/A')}")

                return pb_command, import_path
            else:
                print(f"❌ No FirewallCommand class found")

        except ImportError as e:
            print(f"❌ Import failed: {e}")
        except Exception as e:
            print(f"❌ Parsing failed: {e}")

    return None, None


def main_schema_analyzer():
    """Analizador principal de schema"""
    print("🔬 PROTOBUF SCHEMA ANALYZER")
    print("=" * 50)

    # Setup socket simple
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.setsockopt(zmq.SUBSCRIBE, b"")

    # Connect to scheduler-firewall
    socket.connect("tcp://localhost:5580")  # Dashboard port
    print("🔌 Connected to scheduler-firewall on port 5580")
    print("⏳ Waiting for protobuf message...")

    try:
        # Recibir mensaje SIN crypto wrapping
        raw_data = socket.recv()
        print(f"📨 Received {len(raw_data)} bytes")

        # Analizar estructura raw
        fields = decode_protobuf_raw(raw_data)

        # Comparar con schemas conocidos
        compare_with_known_schemas(fields)

        # Intentar parsing con import correcto
        parsed_pb, successful_import = try_parse_with_corrected_import(raw_data, fields)

        if parsed_pb:
            print(f"\n🎉 SOLUTION FOUND!")
            print(f"   Use import: {successful_import}")
            print(f"   This is the correct protobuf module for your scheduler-firewall")
        else:
            print(f"\n💥 NO COMPATIBLE PROTOBUF FOUND")
            print(f"   scheduler-firewall might be using a custom/modified protobuf")
            print(f"   You need to get the correct .proto file from scheduler-firewall")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        socket.close()
        context.term()


if __name__ == "__main__":
    main_schema_analyzer()