"""Protocols package - Serialization implementations"""

from .protobuff.protobuf_serializer import ProtobufEventSerializer

__all__ = [
    'ProtobufEventSerializer',
]
