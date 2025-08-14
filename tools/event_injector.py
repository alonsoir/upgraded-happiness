#!/usr/bin/env python3
"""
event_injector.py - INYECTOR DE EVENTOS DE PRUEBA
🚀 Simula eventos del ml_detector para probar scheduler directamente
"""
import zmq
import json
import time
import sys
import os
from datetime import datetime

# Add protocols path for protobuf imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'protocols', 'current'))

# Try to import protobuf
PROTOBUF_AVAILABLE = False
try:
    import enriched_event_v31_pb2 as EventProto

    PROTOBUF_AVAILABLE = True
    print("✅ Protobuf V3.1 loaded for event injection")
except ImportError:
    print("⚠️ Protobuf not available, will use JSON events")


class EventInjector:
    def __init__(self):
        self.context = zmq.Context()
        self.socket = None

    def setup_publisher(self):
        """Setup publisher socket to simulate ml_detector"""
        try:
            self.socket = self.context.socket(zmq.PUB)
            self.socket.setsockopt(zmq.LINGER, 0)

            # Bind to port 5584 to avoid conflict with real ml_detector
            endpoint = "tcp://localhost:5584"
            self.socket.bind(endpoint)

            print(f"🔌 Event injector bound to {endpoint}")
            print("📋 Note: You'll need to temporarily change scheduler config to connect to 5584")
            print("   Or stop ml_detector and bind to 5580 directly")

            time.sleep(1)  # Allow socket to establish
            return True

        except Exception as e:
            print(f"❌ Error setting up publisher: {e}")
            return False

    def create_test_event_protobuf(self, event_id=1):
        """Create a test event using protobuf V3.1"""
        if not PROTOBUF_AVAILABLE:
            return None

        try:
            event = EventProto.EnrichedEvent()

            # Basic event info
            event.event_id = f"test_event_{event_id}"
            event.timestamp = int(time.time() * 1000)
            event.node_id = "event_injector_001"

            # Network info
            event.src_ip = "192.168.1.100"
            event.dst_ip = "10.0.0.50"
            event.src_port = 12345
            event.dst_port = 443
            event.protocol = "TCP"

            # ML scores to trigger scheduler decisions
            event.ml_risk_score = 0.85  # High risk to trigger action
            event.attack_probability = 0.80
            event.ddos_probability = 0.75
            event.ransomware_probability = 0.20

            # Additional context
            event.reason = f"Test injection #{event_id} - High risk simulated event"

            return event.SerializeToString()

        except Exception as e:
            print(f"❌ Error creating protobuf event: {e}")
            return None

    def create_test_event_json(self, event_id=1):
        """Create a test event using JSON"""
        return json.dumps({
            "event_id": f"test_event_{event_id}",
            "timestamp": int(time.time() * 1000),
            "node_id": "event_injector_001",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.50",
            "src_port": 12345,
            "dst_port": 443,
            "protocol": "TCP",
            "ml_risk_score": 0.85,
            "attack_probability": 0.80,
            "ddos_probability": 0.75,
            "ransomware_probability": 0.20,
            "reason": f"Test injection #{event_id} - High risk simulated event",
            "event_type": "json_test"
        }).encode('utf-8')

    def inject_single_event(self, event_id=1, use_protobuf=True):
        """Inject a single test event"""
        if use_protobuf and PROTOBUF_AVAILABLE:
            event_data = self.create_test_event_protobuf(event_id)
            event_type = "protobuf"
        else:
            event_data = self.create_test_event_json(event_id)
            event_type = "json"

        if event_data:
            try:
                self.socket.send(event_data, zmq.NOBLOCK)
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                print(f"🚀 [{timestamp}] Injected test event #{event_id} ({event_type}, {len(event_data)} bytes)")
                return True
            except Exception as e:
                print(f"❌ Error sending event #{event_id}: {e}")
                return False
        else:
            print(f"❌ Failed to create event #{event_id}")
            return False

    def inject_burst(self, count=5, interval=2.0, use_protobuf=True):
        """Inject a burst of test events"""
        print(f"🎯 Injecting {count} test events (interval: {interval}s)")

        successful = 0
        for i in range(1, count + 1):
            if self.inject_single_event(i, use_protobuf):
                successful += 1

            if i < count:  # Don't sleep after last event
                time.sleep(interval)

        print(f"✅ Injection complete: {successful}/{count} events sent")
        return successful

    def inject_continuous(self, interval=5.0, use_protobuf=True):
        """Inject events continuously"""
        print(f"🔄 Continuous injection started (interval: {interval}s)")
        print("⏹️ Press Ctrl+C to stop")

        event_id = 1
        try:
            while True:
                self.inject_single_event(event_id, use_protobuf)
                event_id += 1
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n🛑 Continuous injection stopped after {event_id - 1} events")

    def test_scheduler_connectivity(self):
        """Test if scheduler is likely to receive our events"""
        print("🔍 Testing scheduler connectivity...")

        # Try to connect to scheduler's expected port
        try:
            test_socket = self.context.socket(zmq.REQ)
            test_socket.setsockopt(zmq.RCVTIMEO, 2000)
            test_socket.setsockopt(zmq.SNDTIMEO, 2000)

            # This won't work for SUB socket, but let's see if port is open
            test_socket.connect("tcp://localhost:5580")
            print("✅ Connected to port 5580")

            test_socket.close()

        except Exception as e:
            print(f"⚠️ Could not test connectivity: {e}")

    def cleanup(self):
        """Cleanup resources"""
        if self.socket:
            self.socket.close()
        self.context.term()


def main():
    print("🚀 EVENT INJECTOR FOR TROUBLESHOOTING")
    print("=" * 50)
    print("📋 This tool simulates ml_detector events to test scheduler")
    print()

    injector = EventInjector()

    if not injector.setup_publisher():
        print("💥 Failed to setup publisher")
        return

    print("\n🎯 INJECTION OPTIONS:")
    print("1. Single event")
    print("2. Burst of 5 events")
    print("3. Continuous injection")
    print("4. Bind to port 5580 (if ml_detector is stopped)")
    print()

    try:
        choice = input("Choose option (1-4): ").strip()

        if choice == "1":
            print("\n🚀 Injecting single event...")
            injector.inject_single_event(1, True)

        elif choice == "2":
            print("\n🚀 Injecting burst...")
            injector.inject_burst(5, 2.0, True)

        elif choice == "3":
            print("\n🚀 Starting continuous injection...")
            injector.inject_continuous(5.0, True)

        elif choice == "4":
            print("\n🔧 Attempting to bind to port 5580...")
            injector.cleanup()

            # Try to bind to real ml_detector port
            injector = EventInjector()
            injector.socket = injector.context.socket(zmq.PUB)
            injector.socket.setsockopt(zmq.LINGER, 0)

            try:
                injector.socket.bind("tcp://localhost:5580")
                print("✅ Bound to port 5580 (ml_detector port)")
                print("🎯 Scheduler should now receive these events directly")

                time.sleep(1)
                injector.inject_burst(3, 3.0, True)

            except Exception as e:
                print(f"❌ Could not bind to 5580: {e}")
                print("   Make sure ml_detector is stopped first")

        else:
            print("❌ Invalid choice")

    except KeyboardInterrupt:
        print("\n🛑 Interrupted")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        injector.cleanup()
        print("✅ Cleanup complete")


if __name__ == "__main__":
    main()