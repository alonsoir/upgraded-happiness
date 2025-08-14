#!/usr/bin/env python3
"""
flow_monitor.py - MONITOR EN TIEMPO REAL DEL FLUJO
🔍 Escucha en todos los puertos simultáneamente para ver dónde se corta el flujo
"""
import zmq
import threading
import time
import json
from datetime import datetime
import signal
import sys


class FlowMonitor:
    def __init__(self):
        self.running = True
        self.stats = {
            'ml_detector_messages': 0,
            'scheduler_commands': 0,
            'consumer_responses': 0,
            'start_time': time.time()
        }

    def monitor_ml_detector(self):
        """Monitor ML Detector output (port 5580)"""
        try:
            context = zmq.Context()
            socket = context.socket(zmq.SUB)
            socket.setsockopt(zmq.SUBSCRIBE, b"")  # Subscribe to all
            socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 second timeout
            socket.connect("tcp://localhost:5580")

            print("🎯 [ML DETECTOR MONITOR] Listening on port 5580...")

            while self.running:
                try:
                    message = socket.recv(zmq.NOBLOCK)
                    self.stats['ml_detector_messages'] += 1

                    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    print(f"📨 [{timestamp}] ML DETECTOR → {len(message)} bytes")

                    # Try to identify message type
                    if len(message) > 10:
                        try:
                            # Check if it's text/JSON
                            text_preview = message[:50].decode('utf-8', errors='ignore')
                            if text_preview.isprintable():
                                print(f"   📄 Text/JSON: {text_preview}...")
                            else:
                                print(f"   📦 Binary (likely protobuf)")
                        except:
                            print(f"   📦 Binary data")

                except zmq.Again:
                    time.sleep(0.1)
                except Exception as e:
                    print(f"❌ [ML DETECTOR MONITOR] Error: {e}")
                    break

            socket.close()
            context.term()

        except Exception as e:
            print(f"❌ [ML DETECTOR MONITOR] Failed to start: {e}")

    def monitor_scheduler_commands(self):
        """Monitor Scheduler commands output (port 5582)"""
        try:
            context = zmq.Context()
            socket = context.socket(zmq.PULL)
            socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 second timeout

            # Bind to port 5582 to intercept messages meant for consumer
            socket.bind("tcp://localhost:5583")  # Use different port to avoid conflict
            print("🎯 [SCHEDULER COMMANDS MONITOR] Note: Cannot directly monitor 5582 (consumer is bound)")
            print("   This monitor would need to be a proxy, skipping direct command monitoring")

            socket.close()
            context.term()

        except Exception as e:
            print(f"❌ [SCHEDULER COMMANDS MONITOR] Failed: {e}")

    def monitor_consumer_responses(self):
        """Monitor Consumer responses (port 5581)"""
        try:
            context = zmq.Context()
            socket = context.socket(zmq.SUB)
            socket.setsockopt(zmq.SUBSCRIBE, b"")
            socket.setsockopt(zmq.RCVTIMEO, 1000)

            # This won't work directly since consumer PUSH to scheduler PULL
            # We'd need to proxy, but let's try connecting as SUB anyway
            socket.connect("tcp://localhost:5581")

            print("🎯 [CONSUMER RESPONSES MONITOR] Attempting to monitor port 5581...")

            while self.running:
                try:
                    message = socket.recv(zmq.NOBLOCK)
                    self.stats['consumer_responses'] += 1

                    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    print(f"📤 [{timestamp}] CONSUMER RESPONSE → {len(message)} bytes")

                    # Try to parse response
                    try:
                        text = message.decode('utf-8')
                        data = json.loads(text)
                        print(f"   ✅ Response: {data.get('message', 'unknown')}")
                    except:
                        print(f"   📦 Binary response")

                except zmq.Again:
                    time.sleep(0.1)
                except Exception as e:
                    print(f"❌ [CONSUMER RESPONSES MONITOR] Error: {e}")
                    break

            socket.close()
            context.term()

        except Exception as e:
            print(f"❌ [CONSUMER RESPONSES MONITOR] Failed to start: {e}")

    def stats_reporter(self):
        """Report statistics every 10 seconds"""
        while self.running:
            time.sleep(10)
            if not self.running:
                break

            uptime = time.time() - self.stats['start_time']
            print(f"\n📊 FLOW STATISTICS (uptime: {uptime:.1f}s)")
            print(f"   📨 ML Detector messages: {self.stats['ml_detector_messages']}")
            print(f"   🔥 Scheduler commands: {self.stats['scheduler_commands']}")
            print(f"   📤 Consumer responses: {self.stats['consumer_responses']}")

            if self.stats['ml_detector_messages'] > 0:
                print(f"   ✅ ML Detector is active")
            else:
                print(f"   ❌ No messages from ML Detector")

            print()

    def start(self):
        """Start all monitors"""
        print("🔍 FLOW MONITOR STARTING")
        print("=" * 50)
        print("📋 This tool monitors the message flow between components")
        print("⏹️ Press Ctrl+C to stop")
        print()

        # Start monitor threads
        threads = [
            threading.Thread(target=self.monitor_ml_detector, daemon=True),
            threading.Thread(target=self.monitor_scheduler_commands, daemon=True),
            threading.Thread(target=self.monitor_consumer_responses, daemon=True),
            threading.Thread(target=self.stats_reporter, daemon=True)
        ]

        for thread in threads:
            thread.start()

        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping monitor...")
            self.running = False
            time.sleep(2)


def signal_handler(sig, frame):
    print("\n🛑 Signal received")
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    monitor = FlowMonitor()
    monitor.start()


if __name__ == "__main__":
    main()