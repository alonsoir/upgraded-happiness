# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: network_event.proto
# Protobuf Python Version: 5.29.3
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    3,
    '',
    'network_event.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13network_event.proto\x12\x0enetwork.events\"\x9e\x02\n\x0cNetworkEvent\x12\x10\n\x08\x65vent_id\x18\x01 \x01(\t\x12\x11\n\ttimestamp\x18\x02 \x01(\x03\x12\x11\n\tsource_ip\x18\x03 \x01(\t\x12\x11\n\ttarget_ip\x18\x04 \x01(\t\x12\x13\n\x0bpacket_size\x18\x05 \x01(\x05\x12\x11\n\tdest_port\x18\x06 \x01(\x05\x12\x10\n\x08src_port\x18\x07 \x01(\x05\x12\x10\n\x08\x61gent_id\x18\x08 \x01(\t\x12\x15\n\ranomaly_score\x18\t \x01(\x02\x12\x10\n\x08latitude\x18\n \x01(\x01\x12\x11\n\tlongitude\x18\x0b \x01(\x01\x12\x12\n\nevent_type\x18\x0c \x01(\t\x12\x12\n\nrisk_score\x18\r \x01(\x02\x12\x13\n\x0b\x64\x65scription\x18\x0e \x01(\tb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'network_event_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_NETWORKEVENT']._serialized_start=40
  _globals['_NETWORKEVENT']._serialized_end=326
# @@protoc_insertion_point(module_scope)
