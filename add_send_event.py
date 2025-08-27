#!/usr/bin/env python3
"""
add_send_event.py
🔧 Añade el método _send_event faltante
"""


def add_send_event_method():
    """Add the missing _send_event method"""

    sniffer_file = "core/evolutionary_sniffer_standalone.py"

    print(f"🔧 Adding _send_event method to {sniffer_file}...")

    with open(sniffer_file, 'r') as f:
        content = f.read()

    # Check if method already exists
    if "def _send_event(self, event_data: bytes) -> bool:" in content:
        print("✅ _send_event method already exists")
        return True

    # The _send_event method
    send_event_method = '''
    def _send_event(self, event_data: bytes) -> bool:
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
            return False

'''

    # Find a good place to insert it (before send_handshake)
    send_handshake_pos = content.find("def send_handshake(self):")

    if send_handshake_pos != -1:
        # Insert before send_handshake
        new_content = content[:send_handshake_pos] + send_event_method + "\n" + content[send_handshake_pos:]
    else:
        # Find shutdown method instead
        shutdown_pos = content.find("def shutdown(self, threads):")
        if shutdown_pos != -1:
            new_content = content[:shutdown_pos] + send_event_method + "\n" + content[shutdown_pos:]
        else:
            # Just append before the end
            main_pos = content.find("if __name__ == \"__main__\":")
            if main_pos != -1:
                new_content = content[:main_pos] + send_event_method + "\n\n" + content[main_pos:]
            else:
                new_content = content + send_event_method

    # Write back
    with open(sniffer_file, 'w') as f:
        f.write(new_content)

    print("✅ _send_event method added")
    return True


def verify_final_check():
    """Final verification of all methods"""

    sniffer_file = "core/evolutionary_sniffer_standalone.py"

    with open(sniffer_file, 'r') as f:
        content = f.read()

    required_methods = [
        "def run(self):",
        "def _send_event(self, event_data: bytes) -> bool:",
        "def send_handshake(self):",
        "def monitor_performance(self):",
        "def shutdown(self, threads):"
    ]

    print("\n🔍 Final verification:")
    all_present = True

    for method in required_methods:
        if method in content:
            print(f"   ✅ {method}")
        else:
            print(f"   ❌ {method}")
            all_present = False

    return all_present


def main():
    print("🔧 ADDING _send_event METHOD")
    print("=" * 30)

    # Add the send event method
    success = add_send_event_method()

    # Final verification
    all_present = verify_final_check()

    if success and all_present:
        print("\n🎉 ALL METHODS COMPLETE!")
        print("\n🚀 READY TO RUN SNIFFER:")
        print(
            "sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/sniffer_config.json")
        print("\n📊 Expected output:")
        print("   🚀 Starting Evolutionary Sniffer Standalone")
        print("   🤝 Handshake sent successfully")
        print("   🎯 Starting packet capture")
        print("   📊 Performance Stats with Events > 0")
        print("   🔄 Creating event for flow... (debug logs)")
    else:
        print("\n❌ Issues remain")

    return success and all_present


if __name__ == "__main__":
    main()