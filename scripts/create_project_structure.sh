#!/bin/bash

# Script para crear la estructura de proyecto completa
echo "🏗️  Creating project structure..."

# Create directories
mkdir -p src/protocols/protobuff
mkdir -p tests/unit

# Create __init__.py files
echo "📁 Creating __init__.py files..."

# src/__init__.py
cat > src/__init__.py << 'EOF'
"""
Upgraded Happiness - Performance Research Framework
Main source package initialization
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"
EOF

# src/common/__init__.py
cat > src/common/__init__.py << 'EOF'
"""
Common package - Shared interfaces and utilities
"""

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
EOF

# src/protocols/__init__.py
cat > src/protocols/__init__.py << 'EOF'
"""
Protocols package - Serialization implementations
"""

from .protobuff.protobuf_serializer import ProtobufEventSerializer

__all__ = [
    'ProtobufEventSerializer',
]
EOF

# src/protocols/protobuff/__init__.py
cat > src/protocols/protobuff/__init__.py << 'EOF'
"""
Protobuf serialization implementation
"""

from .protobuf_serializer import ProtobufEventSerializer

__all__ = [
    'ProtobufEventSerializer',
]
EOF

echo "✅ Project structure created successfully!"
echo ""
echo "📋 Created:"
echo "   src/__init__.py"
echo "   src/common/__init__.py"
echo "   src/protocols/__init__.py"
echo "   src/protocols/protobuff/__init__.py"
echo ""
echo "📦 Next step: Copy the base_interfaces.py and protobuf_serializer.py files"