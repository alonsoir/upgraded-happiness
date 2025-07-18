# test_pipeline_complete.py - End-to-End Pipeline Testing
import json
import time
import threading
import zmq
import sys
import os
import logging
from typing import Dict, List
import uuid
from datetime import datetime

# Add src to path for protobuf imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.protocols.protobuf import network_event_extended_v2_pb2 as network_event_pb2
    from src.protocols.protobuf import firewall_commands_pb2

    print("✅ Protobuf imports successful")
except ImportError as e:
    print(f"❌ Protobuf import failed: {e}")
    print("📁 Please ensure protobuf files are generated")
    sys.exit(1)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MLDetectorSimulator:
    """Simulates ML detector sending events to dashboard"""

    def __init__(self, dashboard_port: int = 5570):
        self.dashboard_port = dashboard_port
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUSH)
        self.socket.connect(f"tcp://localhost:{dashboard_port}")
        self.running = False
        self.events_sent = 0

        logger.info(f"ML Detector Simulator connected to dashboard port {dashboard_port}")

    def create_test_event(self, anomaly_score: float, risk_level: str) -> network_event_pb2.NetworkEvent:
        """Create a test network event"""
        event = network_event_pb2.NetworkEvent()

        event.event_id = str(uuid.uuid4())
        event.timestamp = time.time()
        event.src_ip = f"192.168.1.{100 + self.events_sent % 50}"
        event.dst_ip = "10.0.0.100"
        event.dst_port = 80
        event.protocol = "TCP"
        event.packet_size = 1024
        event.src_country = "CN" if anomaly_score > 0.7 else "US"
        event.dst_country = "US"
        event.anomaly_score = anomaly_score
        event.risk_level = risk_level
        event.ml_prediction = "MALICIOUS" if anomaly_score > 0.8 else "SUSPICIOUS" if anomaly_score > 0.6 else "NORMAL"
        event.pipeline_latency = 15.5
        event.component_path.extend(["promiscuous_001", "geoip_001", "ml_001"])

        return event

    def send_test_events(self, count: int = 10, interval: float = 2.0):
        """Send test events to dashboard"""
        logger.info(f"Sending {count} test events with {interval}s interval")

        # Send events with varying risk levels
        for i in range(count):
            if i % 4 == 0:
                # High risk event (should trigger auto-block)
                event = self.create_test_event(0.95, "HIGH")
                logger.info(f"📡 Sending HIGH risk event: {event.src_ip} (score: {event.anomaly_score})")
            elif i % 4 == 1:
                # Medium risk event (should trigger rate limiting)
                event = self.create_test_event(0.75, "MEDIUM")
                logger.info(f"📡 Sending MEDIUM risk event: {event.src_ip} (score: {event.anomaly_score})")
            else:
                # Low risk event (should be logged only)
                event = self.create_test_event(0.3, "LOW")
                logger.info(f"📡 Sending LOW risk event: {event.src_ip} (score: {event.anomaly_score})")

            # Serialize and send
            serialized = event.SerializeToString()
            self.socket.send(serialized, zmq.NOBLOCK)

            self.events_sent += 1
            time.sleep(interval)

        logger.info(f"✅ Sent {self.events_sent} test events")

    def cleanup(self):
        """Cleanup resources"""
        self.socket.close()
        self.context.term()


class FirewallAgentSimulator:
    """Simulates firewall agent receiving commands and sending responses"""

    def __init__(self, commands_port: int = 5580, responses_port: int = 5581):
        self.commands_port = commands_port
        self.responses_port = responses_port
        self.context = zmq.Context()

        # Commands socket (receive from dashboard)
        self.commands_socket = self.context.socket(zmq.PULL)
        self.commands_socket.connect(f"tcp://localhost:{commands_port}")

        # Responses socket (send to dashboard)
        self.responses_socket = self.context.socket(zmq.PUSH)
        self.responses_socket.connect(f"tcp://localhost:{responses_port}")

        self.running = False
        self.commands_received = 0
        self.responses_sent = 0

        logger.info(f"Firewall Agent Simulator connected - Commands: {commands_port}, Responses: {responses_port}")

    def listen_for_commands(self):
        """Listen for firewall commands from dashboard"""
        logger.info("🛡️ Firewall Agent Simulator listening for commands...")

        self.running = True

        while self.running:
            try:
                # Receive command
                raw_data = self.commands_socket.recv(zmq.NOBLOCK)

                # Parse protobuf
                pb_command = firewall_commands_pb2.FirewallCommand()
                pb_command.ParseFromString(raw_data)

                self.commands_received += 1

                logger.info(
                    f"🔥 Received firewall command: {pb_command.command_id} - {pb_command.action} {pb_command.target_ip}")

                # Simulate processing delay
                time.sleep(0.1)

                # Send response
                self._send_response(pb_command, success=True, message="Rule applied successfully")

            except zmq.Again:
                # No message available
                time.sleep(0.01)
            except Exception as e:
                logger.error(f"Error processing command: {e}")
                time.sleep(0.1)

    def _send_response(self, pb_command, success: bool, message: str):
        """Send response to dashboard"""
        try:
            # Create response
            pb_response = firewall_commands_pb2.FirewallResponse()
            pb_response.command_id = pb_command.command_id
            pb_response.agent_id = "test_firewall_agent_001"
            pb_response.success = success
            pb_response.message = message
            pb_response.timestamp = time.time()

            # Serialize and send
            serialized = pb_response.SerializeToString()
            self.responses_socket.send(serialized, zmq.NOBLOCK)

            self.responses_sent += 1

            logger.info(f"📤 Sent response: {pb_command.command_id} - Success: {success}")

        except Exception as e:
            logger.error(f"Error sending response: {e}")

    def stop(self):
        """Stop listening for commands"""
        self.running = False

    def cleanup(self):
        """Cleanup resources"""
        self.commands_socket.close()
        self.responses_socket.close()
        self.context.term()


class DashboardTester:
    """Tests dashboard API endpoints"""

    def __init__(self, dashboard_host: str = "localhost", dashboard_port: int = 8080):
        self.dashboard_host = dashboard_host
        self.dashboard_port = dashboard_port
        self.base_url = f"http://{dashboard_host}:{dashboard_port}"

    def test_dashboard_api(self):
        """Test dashboard API endpoints"""
        import requests

        logger.info("🧪 Testing dashboard API endpoints...")

        try:
            # Test status endpoint
            response = requests.get(f"{self.base_url}/api/status", timeout=5)
            if response.status_code == 200:
                logger.info("✅ Dashboard status endpoint working")
                status = response.json()
                logger.info(f"   Node ID: {status.get('node_id')}")
                logger.info(f"   Running: {status.get('running')}")
            else:
                logger.error(f"❌ Dashboard status endpoint failed: {response.status_code}")

            # Test metrics endpoint
            response = requests.get(f"{self.base_url}/api/metrics", timeout=5)
            if response.status_code == 200:
                logger.info("✅ Dashboard metrics endpoint working")
                metrics = response.json()
                logger.info(f"   Events received: {metrics.get('events_received', 0)}")
                logger.info(f"   Commands sent: {metrics.get('commands_sent', 0)}")
            else:
                logger.error(f"❌ Dashboard metrics endpoint failed: {response.status_code}")

            # Test manual firewall command
            manual_block_data = {
                "ip": "192.168.1.999",
                "port": 80,
                "duration": 300,
                "reason": "Test block from pipeline tester",
                "priority": 5,
                "event_id": "test_manual_block"
            }

            response = requests.post(f"{self.base_url}/api/firewall/block",
                                     json=manual_block_data, timeout=5)
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    logger.info("✅ Manual firewall block command working")
                    logger.info(f"   Command ID: {result.get('command_id')}")
                else:
                    logger.error("❌ Manual firewall block command failed")
            else:
                logger.error(f"❌ Manual firewall block endpoint failed: {response.status_code}")

        except requests.RequestException as e:
            logger.error(f"❌ Dashboard API test failed: {e}")
        except Exception as e:
            logger.error(f"❌ Unexpected error in dashboard test: {e}")


class PipelineIntegrationTester:
    """Complete pipeline integration tester"""

    def __init__(self):
        self.ml_simulator = MLDetectorSimulator()
        self.firewall_simulator = FirewallAgentSimulator()
        self.dashboard_tester = DashboardTester()
        self.firewall_thread = None

    def run_complete_test(self):
        """Run complete pipeline test"""
        logger.info("🚀 Starting complete pipeline integration test")
        logger.info("=" * 60)

        # Step 1: Start firewall agent simulator
        logger.info("🛡️ Step 1: Starting firewall agent simulator...")
        self.firewall_thread = threading.Thread(target=self.firewall_simulator.listen_for_commands, daemon=True)
        self.firewall_thread.start()
        time.sleep(2)  # Give it time to start

        # Step 2: Test dashboard API
        logger.info("📊 Step 2: Testing dashboard API...")
        self.dashboard_tester.test_dashboard_api()
        time.sleep(2)

        # Step 3: Send test events from ML detector
        logger.info("🤖 Step 3: Sending test events from ML detector...")
        self.ml_simulator.send_test_events(count=8, interval=3.0)

        # Step 4: Wait for processing
        logger.info("⏳ Step 4: Waiting for pipeline processing...")
        time.sleep(10)

        # Step 5: Check results
        logger.info("📈 Step 5: Checking results...")
        self._check_results()

        # Step 6: Cleanup
        logger.info("🧹 Step 6: Cleaning up...")
        self.cleanup()

        logger.info("=" * 60)
        logger.info("✅ Complete pipeline integration test finished")

    def _check_results(self):
        """Check test results"""
        try:
            import requests

            # Get final metrics
            response = requests.get("http://localhost:8080/api/metrics", timeout=5)
            if response.status_code == 200:
                metrics = response.json()

                logger.info("📊 Final Pipeline Metrics:")
                logger.info(f"   Events received: {metrics.get('events_received', 0)}")
                logger.info(f"   Events processed: {metrics.get('events_processed', 0)}")
                logger.info(f"   Commands sent: {metrics.get('commands_sent', 0)}")
                logger.info(f"   Responses received: {metrics.get('responses_received', 0)}")
                logger.info(f"   Errors: {metrics.get('errors', 0)}")

                # Check firewall simulator metrics
                logger.info("🛡️ Firewall Simulator Metrics:")
                logger.info(f"   Commands received: {self.firewall_simulator.commands_received}")
                logger.info(f"   Responses sent: {self.firewall_simulator.responses_sent}")

                # Check ML simulator metrics
                logger.info("🤖 ML Simulator Metrics:")
                logger.info(f"   Events sent: {self.ml_simulator.events_sent}")

                # Evaluate success
                events_sent = self.ml_simulator.events_sent
                events_received = metrics.get('events_received', 0)
                commands_sent = metrics.get('commands_sent', 0)

                if events_received >= events_sent:
                    logger.info("✅ Event flow: ML Detector → Dashboard - SUCCESS")
                else:
                    logger.error("❌ Event flow: ML Detector → Dashboard - FAILED")

                if commands_sent > 0:
                    logger.info("✅ Command flow: Dashboard → Firewall - SUCCESS")
                else:
                    logger.error("❌ Command flow: Dashboard → Firewall - FAILED")

                if self.firewall_simulator.responses_sent > 0:
                    logger.info("✅ Response flow: Firewall → Dashboard - SUCCESS")
                else:
                    logger.error("❌ Response flow: Firewall → Dashboard - FAILED")

            else:
                logger.error("❌ Could not retrieve final metrics")

        except Exception as e:
            logger.error(f"❌ Error checking results: {e}")

    def cleanup(self):
        """Cleanup resources"""
        self.firewall_simulator.stop()
        self.ml_simulator.cleanup()
        self.firewall_simulator.cleanup()
        logger.info("🧹 Cleanup completed")


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description="Pipeline Integration Tester")
    parser.add_argument("--ml-port", type=int, default=5570, help="ML detector output port")
    parser.add_argument("--firewall-cmd-port", type=int, default=5580, help="Firewall commands port")
    parser.add_argument("--firewall-resp-port", type=int, default=5581, help="Firewall responses port")
    parser.add_argument("--dashboard-port", type=int, default=8080, help="Dashboard web port")
    parser.add_argument("--events-count", type=int, default=8, help="Number of test events to send")
    parser.add_argument("--events-interval", type=float, default=3.0, help="Interval between events")

    args = parser.parse_args()

    print("🧬 Sistema Autoinmune Digital - Pipeline Integration Tester")
    print("=" * 60)
    print(f"ML Detector Port: {args.ml_port}")
    print(f"Firewall Commands Port: {args.firewall_cmd_port}")
    print(f"Firewall Responses Port: {args.firewall_resp_port}")
    print(f"Dashboard Port: {args.dashboard_port}")
    print(f"Test Events: {args.events_count}")
    print(f"Events Interval: {args.events_interval}s")
    print("=" * 60)

    # Wait for user confirmation
    input("⏳ Make sure the dashboard is running, then press Enter to start the test...")

    # Run the test
    tester = PipelineIntegrationTester()

    try:
        tester.run_complete_test()
    except KeyboardInterrupt:
        logger.info("🛑 Test interrupted by user")
        tester.cleanup()
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        tester.cleanup()


if __name__ == "__main__":
    main()