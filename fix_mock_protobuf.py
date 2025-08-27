#!/usr/bin/env python3
"""
fix_mock_protobuf.py
🔧 Fix para el mock protobuf en evolutionary_sniffer_standalone.py
"""


def fix_mock_protobuf():
    """Fix the mock protobuf implementation"""

    file_path = "core/evolutionary_sniffer_standalone.py"

    print(f"🔧 Fixing mock protobuf in {file_path}...")

    # Read the file
    with open(file_path, 'r') as f:
        content = f.read()

    # Find the create_mock_protobuf function and replace it
    start_marker = "def create_mock_protobuf():"
    end_marker = "    PROTOBUF_VERSION = \"v3.1.0-mock\""

    start_idx = content.find(start_marker)
    if start_idx == -1:
        print("❌ create_mock_protobuf function not found")
        return False

    end_idx = content.find(end_marker, start_idx)
    if end_idx == -1:
        print("❌ End of create_mock_protobuf function not found")
        return False

    # Include the end marker line
    end_idx = content.find('\n', end_idx) + 1

    # New mock protobuf implementation
    new_mock_implementation = '''def create_mock_protobuf():
    """Create mock protobuf for development"""
    global NetworkSecurityEventProto, PROTOBUF_AVAILABLE, PROTOBUF_VERSION

    class MockTimestamp:
        def FromDatetime(self, dt):
            pass

    class MockDuration:
        def FromTimedelta(self, td):
            pass

    class MockDistributedNode:
        def __init__(self):
            self.node_id = ""
            self.node_hostname = ""
            self.node_ip_address = ""
            self.physical_location = ""
            self.node_role = "PACKET_SNIFFER"
            self.node_status = "ACTIVE"
            self.last_heartbeat = MockTimestamp()
            self.operating_system = ""
            self.os_version = ""
            self.agent_version = ""
            self.process_id = 0
            self.container_id = ""
            self.cluster_name = ""
            self.cpu_usage_percent = 0.0
            self.memory_usage_mb = 0.0
            self.queue_depth = 0
            self.uptime = MockDuration()

        class NodeRole:
            PACKET_SNIFFER = "PACKET_SNIFFER"

        class NodeStatus:
            ACTIVE = "ACTIVE"
            STARTING = "STARTING"

    class MockNetworkFeatures:
        def __init__(self):
            self.source_ip = ""
            self.destination_ip = ""
            self.source_port = 0
            self.destination_port = 0
            self.protocol_number = 0
            self.protocol_name = ""
            self.flow_start_time = MockTimestamp()
            self.flow_duration = MockDuration()
            self.flow_duration_microseconds = 0
            self.total_forward_packets = 0
            self.total_backward_packets = 0
            self.total_forward_bytes = 0
            self.total_backward_bytes = 0
            self.ddos_features = []
            self.general_attack_features = []
            self.internal_traffic_features = []
            self.custom_features = {}

    class MockTimeWindow:
        def __init__(self):
            self.window_start = MockTimestamp()
            self.window_end = MockTimestamp()
            self.window_duration = MockDuration()
            self.sequence_number = 0
            self.window_type = "SLIDING"

        class WindowType:
            SLIDING = "SLIDING"

    class MockPipelineTracking:
        def __init__(self):
            self.pipeline_id = ""
            self.pipeline_start = MockTimestamp()
            self.sniffer_process_id = 0
            self.packet_captured_at = MockTimestamp()
            self.total_processing_latency = MockDuration()
            self.pipeline_hops_count = 0
            self.processing_path = ""
            self.retry_attempts = 0
            self.requires_reprocessing = False
            self.component_metadata = {}
            self.processing_tags = []

    class MockNetworkSecurityEvent:
        def __init__(self):
            self.event_id = ""
            self.originating_node_id = ""
            self.final_classification = ""
            self.schema_version = 31
            self.network_features = MockNetworkFeatures()
            self.capturing_node = MockDistributedNode()
            self.time_window = MockTimeWindow()
            self.pipeline_tracking = MockPipelineTracking()
            self.overall_threat_score = 0.0
            self.threat_category = ""
            self.correlation_id = ""
            self.event_chain_id = ""
            self.custom_metadata = {}
            self.event_tags = []
            self.protobuf_version = "3.1.0-mock"
            self.event_timestamp = MockTimestamp()

        def SerializeToString(self):
            return b"mock_protobuf_data_v2"

    class MockProtobuf:
        NetworkSecurityEvent = MockNetworkSecurityEvent
        DistributedNode = MockDistributedNode  # Add this at module level
        TimeWindow = MockTimeWindow
        PipelineTracking = MockPipelineTracking

    NetworkSecurityEventProto = MockProtobuf()
    # Also set the classes directly for access
    NetworkSecurityEventProto.DistributedNode = MockDistributedNode
    NetworkSecurityEventProto.TimeWindow = MockTimeWindow

    PROTOBUF_AVAILABLE = True
    PROTOBUF_VERSION = "v3.1.0-mock"'''

    # Replace the function
    new_content = content[:start_idx] + new_mock_implementation + content[end_idx:]

    # Write back
    with open(file_path, 'w') as f:
        f.write(new_content)

    print("✅ Mock protobuf implementation fixed")
    return True


def main():
    print("🔧 MOCK PROTOBUF FIXER")
    print("=" * 30)

    success = fix_mock_protobuf()

    if success:
        print("\n🎉 MOCK PROTOBUF FIXED!")
        print("\nThe sniffer should now run without DistributedNode errors.")
        print("\n🚀 Restart the sniffer:")
        print(
            "sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/sniffer_config.json")
    else:
        print("\n❌ Failed to fix mock protobuf")

    return success


if __name__ == "__main__":
    main()