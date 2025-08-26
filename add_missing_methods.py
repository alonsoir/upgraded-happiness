#!/usr/bin/env python3
"""
add_missing_methods.py
🔧 Añade TODOS los métodos faltantes al EvolutionarySnifferStandalone
"""


def add_all_missing_methods():
    """Add all missing methods to the sniffer class"""

    sniffer_file = "core/evolutionary_sniffer_standalone.py"

    print(f"🔧 Adding all missing methods to {sniffer_file}...")

    with open(sniffer_file, 'r') as f:
        content = f.read()

    # All the missing methods as one block
    missing_methods = '''
    def send_handshake(self):
        """Send initial handshake"""
        if self.handshake_sent:
            return

        try:
            from datetime import datetime

            event = NetworkSecurityEventProto.NetworkSecurityEvent()

            event.event_id = str(uuid.uuid4())
            event.event_timestamp.FromDatetime(datetime.now())
            event.originating_node_id = self.node_id

            capturing_node = event.capturing_node
            capturing_node.node_id = self.node_id
            capturing_node.node_hostname = self.system_info['hostname']
            capturing_node.node_role = "PACKET_SNIFFER"
            capturing_node.node_status = "STARTING"
            capturing_node.agent_version = self.config.get("version", "3.1.0")
            capturing_node.process_id = self.process_id

            event.final_classification = "HANDSHAKE"
            event.threat_category = "SYSTEM"
            event.schema_version = 31
            event.protobuf_version = "3.1.0"
            event.custom_metadata["handshake"] = "initial"
            event.custom_metadata["capabilities"] = "packet_capture,feature_extraction,time_windows"
            event.event_tags.extend(["handshake", "sniffer_v31", "startup"])

            event_data = event.SerializeToString()
            success = self._send_event(event_data)

            if success:
                self.handshake_sent = True
                self.logger.info("🤝 Handshake sent successfully")
            else:
                self.logger.warning("⚠️ Error sending handshake")

        except Exception as e:
            self.logger.error(f"❌ Handshake error: {e}")

    def monitor_performance(self):
        """Monitor performance"""
        monitoring_config = self.config["monitoring"]
        interval = monitoring_config["stats_interval_seconds"]

        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            self._log_performance_stats()

    def _log_performance_stats(self):
        """Log performance statistics"""
        now = time.time()
        interval = now - self.stats['last_stats_time']

        if interval > 0:
            packet_rate = self.stats['packets_captured'] / interval
            event_rate = self.stats['events_sent'] / interval
        else:
            packet_rate = 0
            event_rate = 0

        self.logger.info(f"📊 Performance Stats v3.1:")
        self.logger.info(f"   📦 Packets: {self.stats['packets_captured']} ({packet_rate:.1f}/s)")
        self.logger.info(f"   📊 Features: {self.stats['features_extracted']}")
        self.logger.info(f"   ⏰ Windows: {self.stats['windows_completed']}")
        self.logger.info(f"   📤 Events: {self.stats['events_sent']} ({event_rate:.1f}/s)")
        self.logger.info(f"   🗑️ Drops: {self.stats['drops']}")
        self.logger.info(f"   ❌ Errors: {self.stats['errors']}")
        self.logger.info(f"   📋 Queue: {self.packet_queue.qsize()}")
        self.logger.info(f"   🏃 Flows: {len(self.time_window_manager.active_flows)}")

        # Reset stats
        for key in ['packets_captured', 'features_extracted', 'windows_completed',
                    'events_sent', 'drops', 'errors']:
            self.stats[key] = 0

        self.stats['last_stats_time'] = now

    def run(self):
        """Run the sniffer"""
        self.logger.info("🚀 Starting Evolutionary Sniffer Standalone")

        try:
            # Send handshake
            self.send_handshake()

            # Start threads
            threads = []

            # Packet processing thread
            packet_thread = threading.Thread(target=self.process_packets)
            packet_thread.start()
            threads.append(packet_thread)

            # Window processing thread  
            window_thread = threading.Thread(target=self.process_time_windows)
            window_thread.start()
            threads.append(window_thread)

            # Performance monitoring thread
            monitor_thread = threading.Thread(target=self.monitor_performance)
            monitor_thread.start()
            threads.append(monitor_thread)

            # Start packet capture (blocking)
            self.start_packet_capture()

        except KeyboardInterrupt:
            self.logger.info("🛑 Shutting down...")
        except Exception as e:
            self.logger.error(f"❌ Fatal error: {e}")
        finally:
            self.shutdown(threads)

    def shutdown(self, threads):
        """Shutdown gracefully"""
        self.running = False

        # Close crypto wrapper
        if self.crypto_wrapper:
            try:
                self.crypto_wrapper.close()
                self.logger.info("🔐 Crypto wrapper closed")
            except Exception as e:
                self.logger.error(f"❌ Error closing crypto wrapper: {e}")

        # Final stats
        runtime = time.time() - self.stats['start_time']
        self.logger.info(f"📊 Final stats - Runtime: {runtime:.1f}s")

        # Wait for threads
        for thread in threads:
            thread.join(timeout=5)

        # Close socket
        if self.socket:
            self.socket.close()
        self.context.term()

        self.logger.info("✅ Sniffer shut down")

'''

    # Find the end of the class to add methods
    # Look for the last method or the end of the class
    class_end_patterns = [
        "if __name__ == \"__main__\":",
        "# ✅ MAIN ASYNC",
        "async def main():",
        "def main():"
    ]

    insertion_point = -1
    for pattern in class_end_patterns:
        pos = content.find(pattern)
        if pos != -1:
            insertion_point = pos
            break

    if insertion_point == -1:
        # If no clear pattern, append to end of file
        insertion_point = len(content)
        print("⚠️ No clear insertion point found, appending to end of file")

    # Insert the methods
    new_content = content[:insertion_point] + missing_methods + "\n\n" + content[insertion_point:]

    # Write back
    with open(sniffer_file, 'w') as f:
        f.write(new_content)

    print("✅ All missing methods added")
    return True


def add_required_imports():
    """Add required imports that might be missing"""

    sniffer_file = "core/evolutionary_sniffer_standalone.py"

    with open(sniffer_file, 'r') as f:
        content = f.read()

    # Required imports
    required_imports = [
        "import threading",
        "from queue import Queue, Empty",
        "from typing import Dict, Any, Optional",
        "from datetime import datetime",
        "import uuid"
    ]

    # Check and add missing imports
    for import_stmt in required_imports:
        if import_stmt not in content:
            # Find a good place to insert (after existing imports)
            if "import time" in content:
                content = content.replace("import time", f"import time\n{import_stmt}")
                print(f"✅ Added: {import_stmt}")

    # Write back
    with open(sniffer_file, 'w') as f:
        f.write(content)


def verify_all_methods():
    """Verify all required methods exist now"""

    sniffer_file = "core/evolutionary_sniffer_standalone.py"

    with open(sniffer_file, 'r') as f:
        content = f.read()

    required_methods = [
        "def run(self):",
        "def process_packets(self):",
        "def process_time_windows(self):",
        "def monitor_performance(self):",
        "def start_packet_capture(self):",
        "def send_handshake(self):",
        "def shutdown(self, threads):",
        "def _log_performance_stats(self):",
        "def _send_event(self, event_data: bytes) -> bool:"
    ]

    print("\n🔍 Verifying all methods:")
    missing = []

    for method in required_methods:
        if method in content:
            print(f"   ✅ {method}")
        else:
            print(f"   ❌ {method}")
            missing.append(method)

    return len(missing) == 0


def main():
    print("🔧 ADDING ALL MISSING METHODS")
    print("=" * 40)

    # Add required imports
    add_required_imports()

    # Add all missing methods
    success = add_all_missing_methods()

    # Verify everything is there
    all_methods_exist = verify_all_methods()

    if success and all_methods_exist:
        print("\n🎉 ALL METHODS ADDED SUCCESSFULLY!")
        print("\n🚀 Now run the sniffer:")
        print(
            "sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json")
        print("\n🔍 Expected to see:")
        print("   🚀 Starting Evolutionary Sniffer Standalone")
        print("   🤝 Handshake sent successfully")
        print("   🎯 Starting packet capture")
        print("   📊 Performance Stats with Events > 0")
    else:
        print("\n❌ Some issues remain")
        if not success:
            print("   - Failed to add methods")
        if not all_methods_exist:
            print("   - Some methods still missing")

    return success and all_methods_exist


if __name__ == "__main__":
    main()