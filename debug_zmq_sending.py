#!/usr/bin/env python3
"""
debug_zmq_sending.py
🔍 Debug específico para el problema de ZMQ sending
"""

import zmq
import os
import time


def check_port_usage():
    """Check what's using port 5570"""
    print("🔍 CHECKING PORT 5570 USAGE:")

    try:
        import subprocess
        result = subprocess.run(['lsof', '-i', ':5570'], capture_output=True, text=True)
        if result.stdout:
            print("📋 Port 5570 is in use:")
            print(result.stdout)
        else:
            print("✅ Port 5570 appears free")
    except Exception as e:
        print(f"⚠️  Cannot check port usage: {e}")


def test_zmq_bind_connect():
    """Test ZMQ bind vs connect modes"""
    print("\n🔌 TESTING ZMQ BIND/CONNECT:")

    # Test bind mode (current sniffer config)
    print("📤 Testing BIND mode (current config)...")
    context = zmq.Context()

    try:
        socket = context.socket(zmq.PUSH)
        socket.setsockopt(zmq.LINGER, 0)
        socket.bind("tcp://*:5570")
        print("✅ BIND successful on port 5570")
        socket.close()
    except zmq.ZMQError as e:
        print(f"❌ BIND failed: {e}")
        print("💡 This is why the test failed - port is occupied")

        # Try alternative port
        try:
            socket = context.socket(zmq.PUSH)
            socket.bind("tcp://*:5571")
            print("✅ BIND successful on alternative port 5571")
            socket.close()
        except Exception as e2:
            print(f"❌ Alternative port also failed: {e2}")

    # Test connect mode
    print("\n📥 Testing CONNECT mode...")
    try:
        socket = context.socket(zmq.PUSH)
        socket.setsockopt(zmq.LINGER, 0)
        socket.connect("tcp://localhost:5570")
        print("✅ CONNECT successful to localhost:5570")

        # Try to send a test message
        socket.send(b"test_message", zmq.NOBLOCK)
        print("✅ Test message sent successfully")
        socket.close()
    except zmq.ZMQError as e:
        print(f"❌ CONNECT failed: {e}")

    context.term()


def analyze_sniffer_send_method():
    """Analyze the current _send_event method"""
    print("\n📤 ANALYZING _send_event METHOD:")

    sniffer_file = "core/evolutionary_sniffer_standalone.py"

    if not os.path.exists(sniffer_file):
        print("❌ Sniffer file not found")
        return

    with open(sniffer_file, 'r') as f:
        content = f.read()

    # Find _send_event method
    send_method_start = content.find("def _send_event(self, event_data: bytes)")
    if send_method_start == -1:
        print("❌ _send_event method not found")
        return

    # Extract the method
    method_lines = []
    lines = content[send_method_start:].split('\n')
    indent_level = None

    for line in lines:
        if line.strip().startswith('def _send_event'):
            indent_level = len(line) - len(line.lstrip())
            method_lines.append(line)
        elif method_lines and line.strip() == '':
            method_lines.append(line)
        elif method_lines and (len(line) - len(line.lstrip())) > indent_level:
            method_lines.append(line)
        elif method_lines:
            break

    print("🔍 Current _send_event implementation:")
    for line in method_lines:
        print(f"   {line}")

    # Check for common issues
    method_text = '\n'.join(method_lines)

    issues = []
    if "zmq.NOBLOCK" not in method_text:
        issues.append("❌ Not using zmq.NOBLOCK - may block")

    if "zmq.Again" not in method_text:
        issues.append("❌ Not handling zmq.Again exception properly")

    if "self.socket.send" not in method_text:
        issues.append("❌ Not using self.socket.send")

    if issues:
        print("\n🚨 POTENTIAL ISSUES FOUND:")
        for issue in issues:
            print(f"   {issue}")
    else:
        print("\n✅ _send_event method looks correct")


def create_improved_send_method():
    """Create an improved _send_event method"""

    improved_method = '''    def _send_event(self, event_data: bytes) -> bool:
        """Send event via ZMQ with improved error handling and diagnostics"""
        try:
            # Add debug logging
            if hasattr(self, 'logger'):
                self.logger.debug(f"Attempting to send event: {len(event_data)} bytes")

            # Check socket state
            if not self.socket:
                if hasattr(self, 'logger'):
                    self.logger.error("Socket is None - cannot send")
                return False

            # Try to send with timeout
            self.socket.send(event_data, zmq.NOBLOCK)

            # Success
            if hasattr(self, 'logger'):
                self.logger.debug(f"Event sent successfully: {len(event_data)} bytes")
            return True

        except zmq.Again:
            # Buffer full - this is expected sometimes
            if hasattr(self, 'logger'):
                self.logger.warning("ZMQ buffer full - event dropped")
            return False

        except zmq.ZMQError as e:
            # ZMQ specific error
            if hasattr(self, 'logger'):
                self.logger.error(f"ZMQ error sending event: {e}")
            return False

        except Exception as e:
            # Any other error
            if hasattr(self, 'logger'):
                self.logger.error(f"Unexpected error sending event: {e}")
            return False'''

    print("\n🔧 IMPROVED _send_event METHOD:")
    print(improved_method)

    return improved_method


def suggest_config_fixes():
    """Suggest configuration fixes"""
    print("\n💡 SUGGESTED FIXES:")

    print("\n1. 🔄 CHANGE SNIFFER TO CONNECT MODE:")
    print("   Instead of binding to port 5570, connect to existing receiver")
    print("   Change in config: mode: 'bind' → mode: 'connect'")

    print("\n2. 🔌 USE DIFFERENT PORT:")
    print("   Change port from 5570 to 5571 to avoid conflict")

    print("\n3. 🛑 KILL EXISTING SNIFFER:")
    print("   Find and kill the process using port 5570:")
    print("   lsof -i :5570")
    print("   kill -9 <PID>")

    print("\n4. 📤 ADD DEBUG LOGGING TO SEND:")
    print("   Add more detailed logging to _send_event method")

    print("\n5. 🔄 RESTART WITH CLEAN STATE:")
    print("   export UPGRADED_HAPPINESS_DEV_MODE=true")
    print("   sudo -E python3 core/evolutionary_sniffer_standalone.py config/...")


def create_quick_fix_script():
    """Create a script to fix the sending issue"""

    fix_script = '''#!/usr/bin/env python3
"""
quick_fix_sending.py
🔧 Quick fix for ZMQ sending issues
"""

import os
import subprocess
import sys

def kill_existing_sniffer():
    """Kill existing sniffer process"""
    print("🔄 Killing existing sniffer processes...")

    try:
        # Find processes using port 5570
        result = subprocess.run(['lsof', '-t', '-i', ':5570'], capture_output=True, text=True)
        if result.stdout.strip():
            pids = result.stdout.strip().split('\\n')
            for pid in pids:
                try:
                    subprocess.run(['kill', '-9', pid], check=True)
                    print(f"✅ Killed process {pid}")
                except:
                    print(f"⚠️  Could not kill process {pid}")
        else:
            print("✅ No processes found using port 5570")
    except Exception as e:
        print(f"⚠️  Error checking processes: {e}")

def fix_config_port():
    """Change config to use different port"""
    config_file = "config/json/evolutionary_sniffer_config_v31_etcd.json"

    if not os.path.exists(config_file):
        print(f"❌ Config file not found: {config_file}")
        return False

    print(f"🔧 Updating config port from 5570 to 5571...")

    with open(config_file, 'r') as f:
        content = f.read()

    # Replace port
    new_content = content.replace('"port": 5570', '"port": 5571')

    if new_content != content:
        with open(config_file, 'w') as f:
            f.write(new_content)
        print("✅ Port updated to 5571")
        return True
    else:
        print("⚠️  Port not found in config")
        return False

def main():
    print("🔧 QUICK FIX - ZMQ SENDING ISSUES")
    print("=" * 40)

    # Option 1: Kill existing processes
    kill_existing_sniffer()

    # Option 2: Change port in config
    fix_config_port()

    print("\\n🚀 NOW TRY RUNNING SNIFFER AGAIN:")
    print("sudo -E python3 core/evolutionary_sniffer_standalone.py config/json/evolutionary_sniffer_config_v31_etcd.json")

if __name__ == "__main__":
    main()
'''

    with open("quick_fix_sending.py", "w") as f:
        f.write(fix_script)

    print("\n📝 Created quick_fix_sending.py")


def main():
    print("🔍 ZMQ SENDING DEBUG TOOL")
    print("=" * 40)

    # 1. Check port usage
    check_port_usage()

    # 2. Test ZMQ modes
    test_zmq_bind_connect()

    # 3. Analyze current send method
    analyze_sniffer_send_method()

    # 4. Create improved method
    create_improved_send_method()

    # 5. Suggest fixes
    suggest_config_fixes()

    # 6. Create fix script
    create_quick_fix_script()

    print("\n" + "=" * 40)
    print("🎯 NEXT ACTIONS:")
    print("1. Run: python3 quick_fix_sending.py")
    print("2. Then run sniffer again")
    print("3. Watch for Events sent: >0")


if __name__ == "__main__":
    main()