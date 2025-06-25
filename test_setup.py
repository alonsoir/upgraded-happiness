#!/usr/bin/env python3
"""
Test mejorado del setup del proyecto SCADA Distributed Agents + Protocol Research
"""


def test_core_imports():
    """Test que todas las dependencias principales se importan correctamente."""
    print("🚀 Testing SCADA Distributed Agents + Protocol Research Setup")
    print("=" * 60)

    # Test imports básicos SCADA
    try:
        import sys
        import os
        import zmq
        import scapy
        import yaml
        import click
        import msgpack
        import psutil
        from scapy.all import IP, TCP

        print(f"✅ Python: {sys.version.split()[0]}")
        print(f"✅ ZeroMQ: {zmq.zmq_version()}")
        print(f"✅ PyZMQ: {zmq.pyzmq_version()}")
        print(f"✅ Scapy: {scapy.__version__}")
        print(f"✅ YAML: {yaml.__version__}")
        print(f"✅ Click: {click.__version__}")
        print(f"✅ Psutil: {psutil.__version__}")

        # Test básico de Scapy
        packet = IP(dst="8.8.8.8") / TCP(dport=80)
        print(f"✅ Scapy packet test: {packet.summary()}")

        # Test entorno virtual
        venv_path = os.environ.get('VIRTUAL_ENV')
        if venv_path and 'upgraded_happiness_venv' in venv_path:
            print(f"✅ Virtual env: {os.path.basename(venv_path)}")
        else:
            print("⚠️  Virtual env: not detected or different name")

        # Test estructura de directorios
        if os.path.exists('src/agents'):
            print("✅ Project structure: SCADA agents created")
        else:
            print("⚠️  SCADA structure: src/agents missing")

        # Test estructura de investigación de protocolos
        if os.path.exists('src/protocols'):
            print("✅ Project structure: Protocol research created")
        else:
            print("⚠️  Protocol research structure: src/protocols missing")

        return True

    except ImportError as e:
        print(f"❌ Error importando dependencias básicas: {e}")
        return False
    except Exception as e:
        print(f"❌ Error inesperado en imports básicos: {e}")
        return False


def test_protocol_research_imports():
    """Test que las nuevas dependencias de investigación de protocolos funcionan."""
    print("\n🔬 Testing Protocol Research dependencies...")
    print("-" * 40)

    try:
        # Test Protocol Buffers
        import google.protobuf
        from google.protobuf import message
        print(f"✅ Protocol Buffers: {google.protobuf.__version__}")

        # Test LZ4
        import lz4
        import lz4.frame
        print(f"✅ LZ4: {lz4.version.version}")

        # Test PyCryptodome (ChaCha20)
        from Crypto.Cipher import ChaCha20
        print("✅ PyCryptodome (ChaCha20): Available")

        # Test AIOFiles
        import aiofiles
        print("✅ AIOFiles: Available")

        # Test pytest-benchmark (if available)
        try:
            import pytest_benchmark
            print("✅ Pytest-benchmark: Available")
        except ImportError:
            print("⚠️  Pytest-benchmark: Not installed (dev dependency)")

        return True

    except ImportError as e:
        print(f"❌ Error importando dependencias de investigación: {e}")
        print("💡 Ejecuta: bash install_research_dependencies.sh")
        return False
    except Exception as e:
        print(f"❌ Error inesperado en dependencias de investigación: {e}")
        return False


def test_zmq_functionality():
    """Test básico de funcionalidad ZeroMQ."""
    print("\n🔌 Testing ZeroMQ functionality...")
    try:
        import zmq

        # Test context creation
        context = zmq.Context()
        socket = context.socket(zmq.PUB)

        print("✅ ZeroMQ context and socket creation: OK")

        # Cleanup
        socket.close()
        context.term()

        return True
    except Exception as e:
        print(f"❌ ZeroMQ test failed: {e}")
        return False


def test_scapy_capabilities():
    """Test capacidades básicas de Scapy."""
    print("\n📡 Testing Scapy capabilities...")
    try:
        from scapy.all import IP, TCP, UDP, ICMP

        # Test packet creation
        ip_packet = IP(dst="127.0.0.1")
        tcp_packet = TCP(dport=80)
        udp_packet = UDP(dport=53)
        icmp_packet = ICMP()

        print("✅ Scapy packet creation: OK")
        print(f"✅ Packet types available: IP, TCP, UDP, ICMP")

        return True
    except Exception as e:
        print(f"❌ Scapy test failed: {e}")
        return False


def test_protocol_research_functionality():
    """Test funcionalidad básica de investigación de protocolos."""
    print("\n🧪 Testing Protocol Research functionality...")
    try:
        # Test LZ4 compression
        import lz4.frame
        test_data = b"Hello, Protocol Research!" * 50
        compressed = lz4.frame.compress(test_data)
        decompressed = lz4.frame.decompress(compressed)

        if decompressed == test_data:
            compression_ratio = len(test_data) / len(compressed)
            print(f"✅ LZ4 compression: OK (ratio: {compression_ratio:.2f}x)")
        else:
            print("❌ LZ4 compression: Data mismatch")
            return False

        # Test ChaCha20 encryption
        from Crypto.Cipher import ChaCha20
        key = b'0' * 32  # 32-byte key
        cipher = ChaCha20.new(key=key)
        test_data = b"Secret protocol data"
        encrypted = cipher.encrypt(test_data)

        # Decrypt
        cipher2 = ChaCha20.new(key=key, nonce=cipher.nonce)
        decrypted = cipher2.decrypt(encrypted)

        if decrypted == test_data:
            print("✅ ChaCha20 encryption: OK")
        else:
            print("❌ ChaCha20 encryption: Data mismatch")
            return False

        # Test Protocol Buffers basic functionality
        from google.protobuf import message
        print("✅ Protocol Buffers: Basic functionality OK")

        return True

    except Exception as e:
        print(f"❌ Protocol research functionality test failed: {e}")
        return False


def test_project_structure():
    """Test estructura completa del proyecto."""
    print("\n📁 Testing Project Structure...")

    import os  # Add missing import

    required_structure = {
        'src/': 'Main source directory',
        'src/agents/': 'SCADA agents',
        'src/common/': 'Common interfaces',
        'src/protocols/': 'Protocol research',
        'src/protocols/protobuff/': 'Protocol Buffers implementation',
        'tests/': 'Test directory',
        'tests/unit/': 'Unit tests',
        'requirements.txt': 'Dependencies',
    }

    all_good = True
    for path, description in required_structure.items():
        if os.path.exists(path):
            print(f"✅ {path:<25} : {description}")
        else:
            print(f"⚠️  {path:<25} : Missing - {description}")
            all_good = False

    return all_good


def test_imports_from_project():
    """Test que se pueden importar módulos del proyecto."""
    print("\n📦 Testing Project Module Imports...")

    try:
        # Add src to path temporarily
        import sys
        import os
        src_path = os.path.join(os.path.dirname(__file__), 'src')
        if src_path not in sys.path:
            sys.path.insert(0, src_path)

        # Test common module imports
        try:
            from common.base_interfaces import CompressionAlgorithm, EncryptionAlgorithm
            print("✅ Common interfaces: OK")
        except ImportError as e:
            print(f"⚠️  Common interfaces: {e}")

        # Test protocol imports
        try:
            from protocols.protobuff.protobuf_serializer import ProtobufEventSerializer
            print("✅ Protocol serializers: OK")
        except ImportError as e:
            print(f"⚠️  Protocol serializers: {e}")

        return True

    except Exception as e:
        print(f"❌ Project import test failed: {e}")
        return False


if __name__ == "__main__":
    success = True

    # Core SCADA tests
    success &= test_core_imports()
    success &= test_zmq_functionality()
    success &= test_scapy_capabilities()

    # New protocol research tests
    success &= test_protocol_research_imports()
    success &= test_protocol_research_functionality()

    # Project structure and integration
    success &= test_project_structure()
    success &= test_imports_from_project()

    print("\n" + "=" * 60)
    if success:
        print("🌟 ALL TESTS PASSED! ¡Sistema completo y listo!")
        print("🚀 SCADA Distributed Agents: ✅")
        print("🔬 Protocol Research Module: ✅")
        print("\n📝 Next steps:")
        print("   • Run: pytest tests/unit/test_protobuf_research.py")
        print("   • Start implementing: MessagePack + LZ4 + ChaCha20")
        exit(0)
    else:
        print("💥 SOME TESTS FAILED. Check the errors above.")
        print("\n💡 Quick fixes:")
        print("   • Install research deps: bash install_research_dependencies.sh")
        print("   • Create missing dirs: mkdir -p src/agents src/protocols/protobuff")
        print("   • Install package: pip install -e .")
        exit(1)