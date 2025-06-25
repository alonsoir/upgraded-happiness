#!/usr/bin/env python3
"""
Quick fix and test script to ensure everything is working
"""

import os
import sys


def create_directory_structure():
    """Create the necessary directory structure"""
    print("🏗️  Creating directory structure...")

    directories = [
        "src/protocols/protobuff",
        "tests/unit"
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"   ✅ {directory}")


def create_init_files():
    """Create necessary __init__.py files"""
    print("📁 Creating __init__.py files...")

    # src/__init__.py
    with open("src/__init__.py", "w") as f:
        f.write('"""Upgraded Happiness - Main package"""\n__version__ = "0.1.0"\n')
    print("   ✅ src/__init__.py")

    # src/common/__init__.py
    init_common = '''"""Common package - Shared interfaces and utilities"""

from .base_interfaces import (
    CompressionAlgorithm,
    EncryptionAlgorithm,
    ResearchDataGenerator,
    EventSerializer,
    EventData,
    SerializationMetrics,
    EventType,
    Severity
)

__all__ = [
    'CompressionAlgorithm',
    'EncryptionAlgorithm', 
    'ResearchDataGenerator',
    'EventSerializer',
    'EventData', 
    'SerializationMetrics',
    'EventType',
    'Severity'
]
'''
    with open("src/common/__init__.py", "w") as f:
        f.write(init_common)
    print("   ✅ src/common/__init__.py")

    # src/protocols/__init__.py
    init_protocols = '''"""Protocols package - Serialization implementations"""

from .protobuff.protobuf_serializer import ProtobufEventSerializer

__all__ = [
    'ProtobufEventSerializer',
]
'''
    with open("src/protocols/__init__.py", "w") as f:
        f.write(init_protocols)
    print("   ✅ src/protocols/__init__.py")

    # src/protocols/protobuff/__init__.py
    init_protobuff = '''"""Protobuf serialization implementation"""

from .protobuf_serializer import ProtobufEventSerializer

__all__ = [
    'ProtobufEventSerializer',
]
'''
    with open("src/protocols/protobuff/__init__.py", "w") as f:
        f.write(init_protobuff)
    print("   ✅ src/protocols/protobuff/__init__.py")

    # tests/__init__.py
    with open("tests/__init__.py", "w") as f:
        f.write('"""Tests package"""\n')
    print("   ✅ tests/__init__.py")

    # tests/unit/__init__.py
    with open("tests/unit/__init__.py", "w") as f:
        f.write('"""Unit tests package"""\n')
    print("   ✅ tests/unit/__init__.py")


def test_imports():
    """Test that imports work correctly"""
    print("🧪 Testing imports...")

    # Add src to path
    sys.path.insert(0, 'src')

    try:
        # Test basic imports
        from common.base_interfaces import CompressionAlgorithm, EncryptionAlgorithm
        print("   ✅ base_interfaces imports")

        from protocols.protobuff.protobuf_serializer import ProtobufEventSerializer
        print("   ✅ protobuf_serializer imports")

        # Test serializer creation
        serializer = ProtobufEventSerializer()
        print("   ✅ ProtobufEventSerializer creation")

        return True

    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def main():
    """Main function"""
    print("🔧 Quick Fix and Test Script")
    print("=" * 40)

    # Step 1: Create directories
    create_directory_structure()
    print()

    # Step 2: Create __init__.py files
    create_init_files()
    print()

    # Step 3: Test imports
    success = test_imports()
    print()

    if success:
        print("🎉 All checks passed!")
        print()
        print("📋 Next steps:")
        print("   1. Copy base_interfaces.py to src/common/")
        print("   2. Copy protobuf_serializer.py to src/protocols/protobuff/")
        print("   3. Run: python test_setup.py")
        print("   4. Run: pytest tests/unit/test_protobuf_research.py -v")
        return 0
    else:
        print("❌ Some checks failed")
        print("💡 Make sure all files are in the correct locations")
        return 1


if __name__ == "__main__":
    exit(main())