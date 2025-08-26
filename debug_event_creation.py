#!/usr/bin/env python3
"""
debug_event_creation.py
🔍 Debug específico para event creation pipeline en el sniffer real
"""

import os
import sys


def patch_sniffer_for_debug():
    """Patch the sniffer to add detailed debugging to event creation"""

    sniffer_file = "core/evolutionary_sniffer_standalone.py"

    if not os.path.exists(sniffer_file):
        print(f"❌ Sniffer file not found: {sniffer_file}")
        return False

    print(f"🔧 Patching {sniffer_file} for event creation debugging...")

    with open(sniffer_file, 'r') as f:
        content = f.read()

    # Find the _create_network_security_event method
    method_start = "def _create_network_security_event(self, flow: FlowInfo, all_features: Dict[str, float],"

    if method_start not in content:
        print("❌ _create_network_security_event method not found")
        return False

    # Create the improved version with extensive debugging
    new_method = '''    def _create_network_security_event(self, flow: FlowInfo, all_features: Dict[str, float],
                                       window_data: Dict[str, Any], model_type: str) -> Optional[bytes]:
        """Create NetworkSecurityEvent with extensive debugging"""
        try:
            self.logger.debug(f"🔄 Creating event for flow {flow.flow_id}, model {model_type}")

            from datetime import datetime, timedelta

            # Step 1: Create protobuf event
            self.logger.debug("📦 Step 1: Creating protobuf event...")
            try:
                event = NetworkSecurityEventProto.NetworkSecurityEvent()
                self.logger.debug("✅ Event instance created")
            except Exception as e:
                self.logger.error(f"❌ Failed to create event instance: {e}")
                return None

            # Step 2: Basic identification
            self.logger.debug("🆔 Step 2: Setting basic identification...")
            try:
                event.event_id = str(uuid.uuid4())
                event.event_timestamp.FromDatetime(datetime.fromtimestamp(time.time()))
                event.originating_node_id = self.node_id
                self.logger.debug("✅ Basic identification set")
            except Exception as e:
                self.logger.error(f"❌ Failed to set basic identification: {e}")
                return None

            # Step 3: Network features
            self.logger.debug("🌐 Step 3: Setting network features...")
            try:
                network_features = event.network_features
                network_features.source_ip = flow.src_ip
                network_features.destination_ip = flow.dst_ip
                network_features.source_port = flow.src_port
                network_features.destination_port = flow.dst_port
                network_features.protocol_number = flow.forward_packets[0].protocol_number if flow.forward_packets else 0
                network_features.protocol_name = flow.protocol
                self.logger.debug("✅ Network features set")
            except Exception as e:
                self.logger.error(f"❌ Failed to set network features: {e}")
                return None

            # Step 4: Timing features
            self.logger.debug("⏰ Step 4: Setting timing features...")
            try:
                network_features.flow_start_time.FromDatetime(datetime.fromtimestamp(flow.start_time))
                duration_seconds = flow.last_seen - flow.start_time
                network_features.flow_duration.FromTimedelta(timedelta(seconds=duration_seconds))
                network_features.flow_duration_microseconds = int(duration_seconds * 1_000_000)
                self.logger.debug("✅ Timing features set")
            except Exception as e:
                self.logger.error(f"❌ Failed to set timing features: {e}")
                return None

            # Step 5: Basic packet/byte counts
            self.logger.debug("📊 Step 5: Setting packet/byte counts...")
            try:
                network_features.total_forward_packets = len(flow.forward_packets)
                network_features.total_backward_packets = len(flow.backward_packets)
                network_features.total_forward_bytes = flow.total_forward_bytes
                network_features.total_backward_bytes = flow.total_backward_bytes
                self.logger.debug("✅ Packet/byte counts set")
            except Exception as e:
                self.logger.error(f"❌ Failed to set packet/byte counts: {e}")
                return None

            # Step 6: Model-specific features
            self.logger.debug(f"🎯 Step 6: Setting model-specific features for {model_type}...")
            try:
                model_features = self.features_extractor.get_features_for_model(all_features, model_type)
                self.logger.debug(f"📊 Got {len(model_features)} features for {model_type}")

                if model_type == "ddos_83":
                    network_features.ddos_features[:] = model_features
                    self.logger.debug("✅ DDOS features set")
                elif model_type == "rf_23":
                    network_features.general_attack_features[:] = model_features
                    self.logger.debug("✅ RF features set")
                elif model_type == "internal_4":
                    network_features.internal_traffic_features[:] = model_features
                    self.logger.debug("✅ Internal features set")
                else:
                    for i, feature_value in enumerate(model_features[:10]):
                        network_features.custom_features[f"feature_{i}"] = feature_value
                    self.logger.debug("✅ Custom features set")
            except Exception as e:
                self.logger.error(f"❌ Failed to set model features: {e}")
                return None

            # Step 7: Capturing node info (simplified for debugging)
            self.logger.debug("🖥️ Step 7: Setting capturing node info...")
            try:
                capturing_node = event.capturing_node
                capturing_node.node_id = self.node_id
                capturing_node.node_hostname = self.system_info.get('hostname', 'unknown')
                capturing_node.node_role = "PACKET_SNIFFER"
                capturing_node.node_status = "ACTIVE"
                capturing_node.agent_version = self.config.get("version", "3.1.0")
                capturing_node.process_id = self.process_id
                self.logger.debug("✅ Capturing node info set")
            except Exception as e:
                self.logger.error(f"❌ Failed to set capturing node: {e}")
                return None

            # Step 8: Time window (simplified)
            self.logger.debug("⏰ Step 8: Setting time window...")
            try:
                time_window = event.time_window
                time_window.window_start.FromDatetime(datetime.fromtimestamp(window_data['start_time']))
                time_window.window_end.FromDatetime(datetime.fromtimestamp(window_data['end_time']))
                time_window.sequence_number = int(time.time())
                time_window.window_type = "SLIDING"
                self.logger.debug("✅ Time window set")
            except Exception as e:
                self.logger.error(f"❌ Failed to set time window: {e}")
                return None

            # Step 9: Pipeline tracking (simplified)
            self.logger.debug("🔄 Step 9: Setting pipeline tracking...")
            try:
                pipeline_tracking = event.pipeline_tracking
                pipeline_tracking.pipeline_id = str(uuid.uuid4())
                pipeline_tracking.sniffer_process_id = self.process_id
                pipeline_tracking.pipeline_hops_count = 1
                pipeline_tracking.processing_path = f"sniffer[{self.node_id}]"
                pipeline_tracking.retry_attempts = 0
                pipeline_tracking.requires_reprocessing = False
                self.logger.debug("✅ Pipeline tracking set")
            except Exception as e:
                self.logger.error(f"❌ Failed to set pipeline tracking: {e}")
                return None

            # Step 10: Final event metadata
            self.logger.debug("📋 Step 10: Setting final metadata...")
            try:
                event.overall_threat_score = 0.0
                event.final_classification = "CAPTURED"
                event.threat_category = "UNKNOWN"
                event.correlation_id = flow.flow_id
                event.event_chain_id = f"chain_{flow.flow_id}_{int(time.time())}"
                event.schema_version = 31
                event.protobuf_version = "3.1.0"
                self.logger.debug("✅ Final metadata set")
            except Exception as e:
                self.logger.error(f"❌ Failed to set final metadata: {e}")
                return None

            # Step 11: Serialize
            self.logger.debug("📦 Step 11: Serializing event...")
            try:
                serialized_data = event.SerializeToString()
                self.logger.debug(f"✅ Event serialized successfully: {len(serialized_data)} bytes")
                return serialized_data
            except Exception as e:
                self.logger.error(f"❌ Failed to serialize event: {e}")
                import traceback
                self.logger.error(f"❌ Serialization traceback: {traceback.format_exc()}")
                return None

        except Exception as e:
            self.logger.error(f"❌ Top-level event creation error: {e}")
            import traceback
            self.logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            return None'''

    # Replace the method
    start_idx = content.find(method_start)
    if start_idx == -1:
        print("❌ Could not find method start")
        return False

    # Find the end of the method (next method or class definition)
    lines = content[start_idx:].split('\n')
    method_lines = []
    indent_level = None

    for i, line in enumerate(lines):
        if i == 0:  # First line (def statement)
            indent_level = len(line) - len(line.lstrip())
            method_lines.append(line)
        elif line.strip() == '' or line.startswith(' ' * (indent_level + 1)) or line.startswith('\t'):
            # Empty line or indented more than method definition
            method_lines.append(line)
        else:
            # Found next method or class - stop here
            break

    end_idx = start_idx + len('\n'.join(method_lines))

    # Replace the method
    new_content = content[:start_idx] + new_method + content[end_idx:]

    # Write back
    with open(sniffer_file, 'w') as f:
        f.write(new_content)

    print("✅ Sniffer patched with detailed event creation debugging")
    return True


def patch_send_method():
    """Also patch _send_event for more debugging"""

    sniffer_file = "core/evolutionary_sniffer_standalone.py"

    with open(sniffer_file, 'r') as f:
        content = f.read()

    # Find current send method
    send_method_start = "def _send_event(self, event_data: bytes) -> bool:"

    if send_method_start not in content:
        print("❌ _send_event method not found")
        return False

    new_send_method = '''    def _send_event(self, event_data: bytes) -> bool:
        """Send event via ZMQ with detailed debugging"""
        try:
            self.logger.debug(f"📤 Attempting to send event: {len(event_data)} bytes")

            # Check socket state
            if not self.socket:
                self.logger.error("❌ Socket is None - cannot send")
                return False

            # Try to send
            self.socket.send(event_data, zmq.NOBLOCK)
            self.logger.debug(f"✅ Event sent successfully: {len(event_data)} bytes")
            return True

        except zmq.Again:
            self.logger.warning("⚠️  ZMQ buffer full - event dropped")
            return False
        except zmq.ZMQError as e:
            self.logger.error(f"❌ ZMQ error sending event: {e}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Unexpected error sending event: {e}")
            import traceback
            self.logger.error(f"❌ Send traceback: {traceback.format_exc()}")
            return False'''

    # Replace send method
    start_idx = content.find(send_method_start)
    lines = content[start_idx:].split('\n')
    method_lines = []
    indent_level = None

    for i, line in enumerate(lines):
        if i == 0:
            indent_level = len(line) - len(line.lstrip())
            method_lines.append(line)
        elif line.strip() == '' or line.startswith(' ' * (indent_level + 1)):
            method_lines.append(line)
        else:
            break

    end_idx = start_idx + len('\n'.join(method_lines))
    new_content = content[:start_idx] + new_send_method + content[end_idx:]

    with open(sniffer_file, 'w') as f:
        f.write(new_content)

    print("✅ Send method also patched with debugging")
    return True


def main():
    print("🔍 EVENT CREATION DEBUG PATCHER")
    print("=" * 40)

    # Patch the event creation method
    success1 = patch_sniffer_for_debug()
    success2 = patch_send_method()

    if success1 and success2:
        print("\n🎉 DEBUGGING PATCHES APPLIED!")
        print("\n🚀 Now run the sniffer and watch for detailed event creation logs:")
        print(
            "sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json")
        print("\n🔍 Look for logs starting with:")
        print("   🔄 Creating event for flow...")
        print("   📦 Step X: ...")
        print("   ❌ Failed to... (if there are errors)")
    else:
        print("\n❌ Failed to apply patches")

    return success1 and success2


if __name__ == "__main__":
    main()