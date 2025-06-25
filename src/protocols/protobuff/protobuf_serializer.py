"""
Protocol Buffers serializer implementation with LZ4 compression and ChaCha20 encryption.

This module implements high-performance serialization using Protocol Buffers as the base
serialization format, with optional LZ4 compression and ChaCha20 encryption.
"""

import asyncio
import json
import os
import time
from typing import Any, Dict, Optional, Union, Tuple

# Protocol Buffers
try:
    from google.protobuf.message import Message
    from google.protobuf import json_format
    from google.protobuf.struct_pb2 import Struct
except ImportError:
    raise ImportError("protobuf library not found. Install with: pip install protobuf>=4.21.0")

# Compression
try:
    import lz4.frame
except ImportError:
    lz4 = None

# Encryption
try:
    from Crypto.Cipher import ChaCha20
    from Crypto.Random import get_random_bytes
except ImportError:
    ChaCha20 = None

# Async file operations
try:
    import aiofiles
except ImportError:
    aiofiles = None

# Base interfaces
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from common.base_interfaces import (
    EventSerializer,
    EventData,
    SerializationMetrics,
    CompressionAlgorithm,
    EncryptionAlgorithm,
    measure_time_ns
)


class ProtobufEventSerializer(EventSerializer):
    """
    High-performance Protocol Buffers serializer with compression and encryption.

    Features:
    - Protocol Buffers for efficient binary serialization
    - Optional LZ4 compression for size reduction
    - Optional ChaCha20 encryption for security
    - Async operations for non-blocking I/O
    - Comprehensive performance metrics
    """

    def __init__(self,
                 compression: Optional[CompressionAlgorithm] = None,
                 encryption: Optional[EncryptionAlgorithm] = None,
                 encryption_key: Optional[bytes] = None):
        """
        Initialize the Protocol Buffers serializer.

        Args:
            compression: Compression algorithm to use (default: None)
            encryption: Encryption algorithm to use (default: None)
            encryption_key: 32-byte key for encryption (generated if None)
        """
        super().__init__(compression, encryption, encryption_key)

        # Generate encryption key if not provided
        if self.encryption != EncryptionAlgorithm.NONE and not self.encryption_key:
            self.encryption_key = get_random_bytes(32) if ChaCha20 else b'0' * 32

        # Validate dependencies
        self._validate_dependencies()

        # Initialize metrics
        self._last_metrics = SerializationMetrics()

    def _validate_dependencies(self):
        """Validate that required dependencies are available"""

        if self.compression == CompressionAlgorithm.LZ4 and lz4 is None:
            raise ImportError("LZ4 compression requested but lz4 library not found. Install with: pip install lz4>=4.0.0")

        if self.encryption == EncryptionAlgorithm.CHACHA20 and ChaCha20 is None:
            raise ImportError("ChaCha20 encryption requested but pycryptodome library not found. Install with: pip install pycryptodome>=3.15.0")

    async def serialize(self,
                       event: Union[EventData, Dict[str, Any]],
                       compression: Optional[CompressionAlgorithm] = None,
                       encryption: Optional[EncryptionAlgorithm] = None) -> bytes:
        """
        Serialize an event to bytes using Protocol Buffers.

        Args:
            event: Event data to serialize
            compression: Override default compression (optional)
            encryption: Override default encryption (optional)

        Returns:
            Serialized bytes
        """
        start_time = measure_time_ns()

        # Use provided algorithms or fall back to instance defaults
        compression = compression or self.compression
        encryption = encryption or self.encryption

        try:
            # Step 1: Convert to Protocol Buffers format
            protobuf_data = await self._to_protobuf(event)
            original_size = len(protobuf_data)

            # Step 2: Apply compression if requested
            compressed_data, compression_ratio = await self._apply_compression(protobuf_data, compression)
            compressed_size = len(compressed_data)

            # Step 3: Apply encryption if requested
            final_data = await self._apply_encryption(compressed_data, encryption)
            final_size = len(final_data)

            # Record metrics
            end_time = measure_time_ns()
            self._last_metrics = SerializationMetrics(
                serialization_time_ns=end_time - start_time,
                original_size_bytes=original_size,
                compressed_size_bytes=compressed_size,
                final_size_bytes=final_size,
                compression_ratio=compression_ratio
            )

            return final_data

        except Exception as e:
            raise RuntimeError(f"Serialization failed: {e}")

    async def deserialize(self,
                         data: bytes,
                         compression: Optional[CompressionAlgorithm] = None,
                         encryption: Optional[EncryptionAlgorithm] = None) -> Union[EventData, Dict[str, Any]]:
        """
        Deserialize bytes back to an event.

        Args:
            data: Serialized bytes
            compression: Compression algorithm used (optional)
            encryption: Encryption algorithm used (optional)

        Returns:
            Deserialized event data
        """
        start_time = measure_time_ns()

        # Use provided algorithms or fall back to instance defaults
        compression = compression or self.compression
        encryption = encryption or self.encryption

        try:
            # Step 1: Decrypt if necessary
            decrypted_data = await self._remove_encryption(data, encryption)

            # Step 2: Decompress if necessary
            decompressed_data = await self._remove_compression(decrypted_data, compression)

            # Step 3: Parse Protocol Buffers
            event = await self._from_protobuf(decompressed_data)

            # Update metrics
            end_time = measure_time_ns()
            self._last_metrics.deserialization_time_ns = end_time - start_time

            return event

        except Exception as e:
            raise RuntimeError(f"Deserialization failed: {e}")

    async def _to_protobuf(self, event: Union[EventData, Dict[str, Any]]) -> bytes:
        """Convert event to Protocol Buffers bytes"""

        # Convert EventData to dict if necessary
        if isinstance(event, EventData):
            event_dict = {
                'event_id': event.event_id,
                'timestamp': event.timestamp,
                'event_type': event.event_type.value,
                'severity': event.severity.value,
                'source_ip': event.source_ip,
                'target_ip': event.target_ip,
                'properties': event.properties,
                'metadata': event.metadata
            }
        else:
            event_dict = event

        # Convert to Protocol Buffers Struct (generic message type)
        struct = Struct()

        # Recursively populate the struct
        await self._populate_struct(struct, event_dict)

        # Serialize to bytes
        return struct.SerializeToString()

    async def _populate_struct(self, struct: Struct, data: Dict[str, Any]):
        """Recursively populate a Protocol Buffers Struct"""

        for key, value in data.items():
            if value is None:
                struct.fields[key].null_value = 0
            elif isinstance(value, bool):
                struct.fields[key].bool_value = value
            elif isinstance(value, int):
                struct.fields[key].number_value = float(value)
            elif isinstance(value, float):
                struct.fields[key].number_value = value
            elif isinstance(value, str):
                struct.fields[key].string_value = value
            elif isinstance(value, list):
                list_value = struct.fields[key].list_value
                for item in value:
                    if isinstance(item, dict):
                        nested_struct = list_value.values.add().struct_value
                        await self._populate_struct(nested_struct, item)
                    else:
                        # Handle primitive types in lists
                        list_item = list_value.values.add()
                        if isinstance(item, str):
                            list_item.string_value = item
                        elif isinstance(item, (int, float)):
                            list_item.number_value = float(item)
                        elif isinstance(item, bool):
                            list_item.bool_value = item
            elif isinstance(value, dict):
                nested_struct = struct.fields[key].struct_value
                await self._populate_struct(nested_struct, value)
            else:
                # Convert other types to string
                struct.fields[key].string_value = str(value)

    async def _from_protobuf(self, data: bytes) -> Dict[str, Any]:
        """Convert Protocol Buffers bytes back to dict"""

        # Parse Protocol Buffers Struct
        struct = Struct()
        struct.ParseFromString(data)

        # Convert to dict using json_format (easiest way)
        json_string = json_format.MessageToJson(struct)
        return json.loads(json_string)

    async def _apply_compression(self, data: bytes, compression: CompressionAlgorithm) -> Tuple[bytes, float]:
        """Apply compression to data"""

        if compression == CompressionAlgorithm.NONE:
            return data, 1.0

        elif compression == CompressionAlgorithm.LZ4:
            if lz4 is None:
                raise RuntimeError("LZ4 compression requested but library not available")

            compressed = lz4.frame.compress(data)
            ratio = len(data) / len(compressed) if len(compressed) > 0 else 1.0
            return compressed, ratio

        else:
            raise ValueError(f"Unsupported compression algorithm: {compression}")

    async def _remove_compression(self, data: bytes, compression: CompressionAlgorithm) -> bytes:
        """Remove compression from data"""

        if compression == CompressionAlgorithm.NONE:
            return data

        elif compression == CompressionAlgorithm.LZ4:
            if lz4 is None:
                raise RuntimeError("LZ4 decompression requested but library not available")

            return lz4.frame.decompress(data)

        else:
            raise ValueError(f"Unsupported compression algorithm: {compression}")

    async def _apply_encryption(self, data: bytes, encryption: EncryptionAlgorithm) -> bytes:
        """Apply encryption to data"""

        if encryption == EncryptionAlgorithm.NONE:
            return data

        elif encryption == EncryptionAlgorithm.CHACHA20:
            if ChaCha20 is None:
                raise RuntimeError("ChaCha20 encryption requested but library not available")

            # Create cipher
            cipher = ChaCha20.new(key=self.encryption_key)

            # Encrypt data
            ciphertext = cipher.encrypt(data)

            # Prepend nonce to ciphertext
            return cipher.nonce + ciphertext

        else:
            raise ValueError(f"Unsupported encryption algorithm: {encryption}")

    async def _remove_encryption(self, data: bytes, encryption: EncryptionAlgorithm) -> bytes:
        """Remove encryption from data"""

        if encryption == EncryptionAlgorithm.NONE:
            return data

        elif encryption == EncryptionAlgorithm.CHACHA20:
            if ChaCha20 is None:
                raise RuntimeError("ChaCha20 decryption requested but library not available")

            # Extract nonce and ciphertext
            nonce = data[:8]  # ChaCha20 nonce is 8 bytes
            ciphertext = data[8:]

            # Create cipher with same key and nonce
            cipher = ChaCha20.new(key=self.encryption_key, nonce=nonce)

            # Decrypt
            return cipher.decrypt(ciphertext)

        else:
            raise ValueError(f"Unsupported encryption algorithm: {encryption}")

    def get_metrics(self) -> SerializationMetrics:
        """Get the latest serialization metrics"""
        return self._last_metrics

    async def serialize_to_file(self,
                               event: Union[EventData, Dict[str, Any]],
                               filepath: str,
                               compression: Optional[CompressionAlgorithm] = None,
                               encryption: Optional[EncryptionAlgorithm] = None):
        """Serialize event and save to file"""

        if aiofiles is None:
            raise ImportError("aiofiles library required for file operations. Install with: pip install aiofiles")

        serialized_data = await self.serialize(event, compression, encryption)

        async with aiofiles.open(filepath, 'wb') as f:
            await f.write(serialized_data)

    async def deserialize_from_file(self,
                                   filepath: str,
                                   compression: Optional[CompressionAlgorithm] = None,
                                   encryption: Optional[EncryptionAlgorithm] = None) -> Union[EventData, Dict[str, Any]]:
        """Load and deserialize event from file"""

        if aiofiles is None:
            raise ImportError("aiofiles library required for file operations. Install with: pip install aiofiles")

        async with aiofiles.open(filepath, 'rb') as f:
            serialized_data = await f.read()

        return await self.deserialize(serialized_data, compression, encryption)

    def __repr__(self) -> str:
        return (f"ProtobufEventSerializer("
                f"compression={self.compression.value}, "
                f"encryption={self.encryption.value})")


# Convenience functions
async def quick_serialize(event: Union[EventData, Dict[str, Any]],
                         compression: CompressionAlgorithm = CompressionAlgorithm.NONE,
                         encryption: EncryptionAlgorithm = EncryptionAlgorithm.NONE) -> bytes:
    """Quick serialization function for simple use cases"""

    serializer = ProtobufEventSerializer(compression=compression, encryption=encryption)
    return await serializer.serialize(event)


async def quick_deserialize(data: bytes,
                           compression: CompressionAlgorithm = CompressionAlgorithm.NONE,
                           encryption: EncryptionAlgorithm = EncryptionAlgorithm.NONE) -> Dict[str, Any]:
    """Quick deserialization function for simple use cases"""

    serializer = ProtobufEventSerializer(compression=compression, encryption=encryption)
    return await serializer.deserialize(data)


# Export main classes
__all__ = [
    'ProtobufEventSerializer',
    'quick_serialize',
    'quick_deserialize'
]