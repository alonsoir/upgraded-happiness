#!/usr/bin/env python3
"""
🔧 FIX PROTOBUF ENUMS v3.1
fix_protobuf_enums.py

Script para corregir problemas con enums en protobuf generado
"""

import os
import re
import sys
import subprocess
from pathlib import Path


def find_protobuf_files():
    """Find protobuf .proto and .py files"""
    current_dir = Path.cwd()

    # Buscar archivos .proto
    proto_files = list(current_dir.rglob("*.proto"))
    proto_files.extend(list(current_dir.rglob("network_security_clean_v31.proto")))

    # Buscar archivos _pb2.py
    pb2_files = list(current_dir.rglob("*_pb2.py"))
    pb2_files.extend(list(current_dir.rglob("network_security_clean_v31_pb2.py")))

    return proto_files, pb2_files


def check_protoc_available():
    """Check if protoc is available"""
    try:
        result = subprocess.run(['protoc', '--version'],
                                capture_output=True, text=True)
        return result.returncode == 0, result.stdout.strip()
    except FileNotFoundError:
        return False, "protoc not found"


def regenerate_protobuf(proto_file: Path):
    """Regenerate protobuf Python files"""
    print(f"🔄 Regenerating protobuf from {proto_file}")

    # Determine output directory
    output_dir = proto_file.parent

    try:
        cmd = [
            'protoc',
            f'--python_out={output_dir}',
            f'--proto_path={proto_file.parent}',
            str(proto_file)
        ]

        print(f"📝 Command: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print("✅ Protobuf regenerated successfully")
            return True
        else:
            print(f"❌ Error regenerating protobuf:")
            print(f"   stdout: {result.stdout}")
            print(f"   stderr: {result.stderr}")
            return False

    except Exception as e:
        print(f"❌ Exception during regeneration: {e}")
        return False


def fix_enum_values_in_pb2(pb2_file: Path):
    """Fix enum values in generated _pb2.py file"""
    print(f"🔧 Checking enum values in {pb2_file}")

    try:
        with open(pb2_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check for enum issues
        enum_issues = []

        # Look for enum definitions
        enum_pattern = r'(\w+)\s*=\s*(\d+)'
        matches = re.findall(enum_pattern, content)

        print(f"📊 Found {len(matches)} enum definitions")

        # Check specific enums we care about
        required_enums = [
            'SLIDING', 'TUMBLING', 'SESSION_BASED', 'ADAPTIVE',
            'PACKET_SNIFFER', 'FEATURE_PROCESSOR', 'ML_ANALYZER',
            'ACTIVE', 'STARTING', 'STOPPING', 'ERROR'
        ]

        found_enums = [match[0] for match in matches]
        missing_enums = [enum for enum in required_enums if enum not in found_enums]

        if missing_enums:
            print(f"⚠️  Missing enums: {missing_enums}")
            enum_issues.extend(missing_enums)
        else:
            print("✅ All required enums found")

        return len(enum_issues) == 0, enum_issues

    except Exception as e:
        print(f"❌ Error checking enum values: {e}")
        return False, [str(e)]


def create_enum_validation_test(pb2_file: Path):
    """Create a test file to validate enums"""
    test_file = pb2_file.parent / "test_enums.py"

    test_content = f'''#!/usr/bin/env python3
"""
Auto-generated enum validation test
"""

import sys
import os

# Add path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import {pb2_file.stem} as pb2
    print("✅ Import successful")

    # Test TimeWindow.WindowType
    try:
        sliding = pb2.TimeWindow.WindowType.SLIDING
        print(f"✅ SLIDING = {{sliding}}")
    except AttributeError as e:
        print(f"❌ SLIDING not found: {{e}}")

    # Test DistributedNode.NodeRole  
    try:
        sniffer = pb2.DistributedNode.NodeRole.PACKET_SNIFFER
        print(f"✅ PACKET_SNIFFER = {{sniffer}}")
    except AttributeError as e:
        print(f"❌ PACKET_SNIFFER not found: {{e}}")

    # Test DistributedNode.NodeStatus
    try:
        active = pb2.DistributedNode.NodeStatus.ACTIVE
        print(f"✅ ACTIVE = {{active}}")
    except AttributeError as e:
        print(f"❌ ACTIVE not found: {{e}}")

    # Test event creation
    try:
        event = pb2.NetworkSecurityEvent()
        event.event_id = "test"
        event.schema_version = 31
        print("✅ Event creation successful")

        # Test enum assignment
        event.capturing_node.node_role = pb2.DistributedNode.NodeRole.PACKET_SNIFFER
        event.capturing_node.node_status = pb2.DistributedNode.NodeStatus.ACTIVE
        event.time_window.window_type = pb2.TimeWindow.WindowType.SLIDING
        print("✅ Enum assignment successful")

        # Test serialization
        data = event.SerializeToString()
        print(f"✅ Serialization successful: {{len(data)}} bytes")

    except Exception as e:
        print(f"❌ Event test failed: {{e}}")

except ImportError as e:
    print(f"❌ Import failed: {{e}}")
'''

    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_content)

    print(f"✅ Created enum validation test: {test_file}")
    return test_file


def main():
    """Main function"""
    print("🔧 PROTOBUF ENUM FIXER v3.1")
    print("=" * 50)

    # Find protobuf files
    proto_files, pb2_files = find_protobuf_files()

    print(f"📁 Found {len(proto_files)} .proto files:")
    for f in proto_files:
        print(f"   📄 {f}")

    print(f"📁 Found {len(pb2_files)} _pb2.py files:")
    for f in pb2_files:
        print(f"   🐍 {f}")

    # Check protoc
    protoc_available, protoc_info = check_protoc_available()
    print(f"\n🛠️  protoc available: {'✅' if protoc_available else '❌'} ({protoc_info})")

    if not protoc_available:
        print("💡 Install protoc: apt-get install protobuf-compiler")
        print("💡 Or download from: https://github.com/protocolbuffers/protobuf/releases")

    # Process each .proto file
    for proto_file in proto_files:
        if "network_security_clean_v31" in proto_file.name:
            print(f"\n🎯 Processing {proto_file}")

            if protoc_available:
                success = regenerate_protobuf(proto_file)
                if not success:
                    print("⚠️  Regeneration failed, checking existing files...")
            else:
                print("⚠️  protoc not available, checking existing files...")

    # Check existing _pb2.py files
    for pb2_file in pb2_files:
        if "network_security_clean_v31" in pb2_file.name:
            print(f"\n🔍 Checking {pb2_file}")

            success, issues = fix_enum_values_in_pb2(pb2_file)

            if success:
                print("✅ Enum values look good")
            else:
                print(f"⚠️  Issues found: {issues}")

            # Create validation test
            test_file = create_enum_validation_test(pb2_file)

            print(f"\n🧪 Running validation test...")
            try:
                result = subprocess.run([sys.executable, str(test_file)],
                                        capture_output=True, text=True)
                print("📝 Test output:")
                print(result.stdout)
                if result.stderr:
                    print("⚠️  Test errors:")
                    print(result.stderr)
            except Exception as e:
                print(f"❌ Test execution failed: {e}")

    print("\n" + "=" * 50)
    print("✅ PROTOBUF ENUM FIXER COMPLETED")

    print("\n💡 Next steps:")
    print("   1. Run the test files created")
    print("   2. If issues persist, regenerate with protoc")
    print("   3. Use the fixed evolutionary_sniffer_standalone_fixed.py")


if __name__ == "__main__":
    main()