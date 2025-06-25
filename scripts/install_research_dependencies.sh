#!/bin/bash

# Clean version with individual pip install commands to avoid any linter warnings
# Script simplificado para instalar solo las dependencias de investigación

echo "🔬 Instalando dependencias de Protocol Research..."

# Check if virtual environment is activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "⚠️  Warning: No virtual environment detected."
    echo "Recommended: activate your virtual environment first:"
    echo "  source upgraded_happiness_venv/bin/activate    # Linux/macOS"
    echo "  upgraded_happiness_venv\\Scripts\\activate      # Windows"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

echo "📦 Installing core research dependencies..."

# Core protocol research dependencies (one per line for maximum clarity)
echo "  → Protocol Buffers..."
pip install "protobuf>=4.21.0"

echo "  → LZ4 compression..."
pip install "lz4>=4.0.0"

echo "  → Encryption library..."
pip install "pycryptodome>=3.15.0"

echo "  → Async file operations..."
pip install "aiofiles>=0.8.0"

echo "  → Testing framework..."
pip install "pytest>=7.0.0"

echo "  → Async testing..."
pip install "pytest-asyncio>=0.21.0"

echo "  → Performance benchmarking..."
pip install "pytest-benchmark>=4.0.0"

echo "  → MessagePack (for next research phase)..."
pip install "msgpack>=1.0.5"

echo "✅ Core research dependencies installed!"

# Quick verification
echo ""
echo "🧪 Quick verification test..."
python3 -c "
try:
    import lz4
    import google.protobuf
    from Crypto.Cipher import ChaCha20
    import aiofiles
    import msgpack
    print('✅ All core imports successful!')

    # Quick functionality test
    import lz4.frame
    test_data = b'Hello, Research!'
    compressed = lz4.frame.compress(test_data)
    decompressed = lz4.frame.decompress(compressed)
    assert decompressed == test_data
    print('✅ LZ4 compression working!')

    # ChaCha20 test
    key = b'0' * 32
    cipher = ChaCha20.new(key=key)
    encrypted = cipher.encrypt(test_data)
    cipher2 = ChaCha20.new(key=key, nonce=cipher.nonce)
    decrypted = cipher2.decrypt(encrypted)
    assert decrypted == test_data
    print('✅ ChaCha20 encryption working!')

except ImportError as e:
    print(f'❌ Import failed: {e}')
    exit(1)
except Exception as e:
    print(f'❌ Test failed: {e}')
    exit(1)
"

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Installation successful!"
    echo ""
    echo "Next steps:"
    echo "  1. bash scripts/setup_research_environment.sh  # Full setup if needed"
    echo "  2. python test_setup.py                        # Verify everything"
    echo "  3. pytest tests/unit/test_protobuf_research.py # Run tests"
    echo ""
    echo "Ready for Protocol Research! 🚀"
else
    echo "❌ Installation verification failed"
    echo "Please check the error messages above"
    exit 1
fi