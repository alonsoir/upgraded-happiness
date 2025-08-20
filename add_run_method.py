#!/usr/bin/env python3
"""
add_run_method.py
🔧 Añade el método run() faltante al EvolutionarySnifferStandalone
"""


def add_run_method():
    """Add the missing run() method to the sniffer class"""

    sniffer_file = "core/evolutionary_sniffer_standalone.py"

    print(f"🔧 Adding run() method to {sniffer_file}...")

    with open(sniffer_file, 'r') as f:
        content = f.read()

    # Check if run method already exists
    if "def run(self):" in content:
        print("✅ run() method already exists")
        return True

    # Find the shutdown method to insert run() before it
    shutdown_method = "    def shutdown(self, threads):"

    if shutdown_method not in content:
        print("❌ Cannot find shutdown method to insert run() before")
        return False

    # The run method to add
    run_method = '''    def run(self):
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

'''

    # Insert the run method before shutdown
    insertion_point = content.find(shutdown_method)
    new_content = content[:insertion_point] + run_method + "\n" + content[insertion_point:]

    # Write back
    with open(sniffer_file, 'w') as f:
        f.write(new_content)

    print("✅ run() method added successfully")
    return True


def add_missing_imports():
    """Add any missing imports that might be needed"""

    sniffer_file = "core/evolutionary_sniffer_standalone.py"

    with open(sniffer_file, 'r') as f:
        content = f.read()

    # Check for threading import
    if "import threading" not in content:
        # Add threading import after other imports
        import_insertion = "import time"
        if import_insertion in content:
            content = content.replace(import_insertion, import_insertion + "\nimport threading")
            print("✅ Added threading import")

    # Check for Queue import
    if "from queue import Queue, Empty" not in content:
        # Add at the end of imports section
        insertion_point = content.find("# ✅ IMPORTS ETCD CRYPTO FIJO")
        if insertion_point != -1:
            content = content[:insertion_point] + "from queue import Queue, Empty\n" + content[insertion_point:]
            print("✅ Added Queue import")

    # Write back if modified
    with open(sniffer_file, 'w') as f:
        f.write(content)


def verify_required_methods():
    """Verify all required methods exist"""

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
        "def shutdown(self, threads):"
    ]

    print("\n🔍 Checking required methods:")
    missing = []

    for method in required_methods:
        if method in content:
            print(f"   ✅ {method}")
        else:
            print(f"   ❌ {method}")
            missing.append(method)

    return len(missing) == 0


def main():
    print("🔧 ADDING MISSING RUN METHOD")
    print("=" * 40)

    # Add missing imports first
    add_missing_imports()

    # Add run method
    success = add_run_method()

    # Verify all methods exist
    all_methods_exist = verify_required_methods()

    if success and all_methods_exist:
        print("\n🎉 ALL FIXES APPLIED!")
        print("\n🚀 Now run the sniffer:")
        print(
            "sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json")
    else:
        print("\n❌ Some issues remain")
        if not success:
            print("   - Failed to add run() method")
        if not all_methods_exist:
            print("   - Some required methods are missing")

    return success and all_methods_exist


if __name__ == "__main__":
    main()