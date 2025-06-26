"""Protocols package - Serialization implementations"""

from .protobuff.protobuf_serializer import ProtobufEventSerializer
from .protobuff import network_event_pb2


__all__ = [
    'ProtobufEventSerializer',
]
