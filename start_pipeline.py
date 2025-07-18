# start_pipeline.py - Pipeline Startup Manager
import os
import sys
import json
import time
import signal
import subprocess
import threading
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ComponentConfig:
    """Configuration for a pipeline component"""
    name: str
    script_path: str
    config_path: str
    required_privileges: bool = False
    dependencies: List[str] = None
    startup_delay: float = 0.0
    health_check_port: Optional[int] = None
    description: str = ""


class PipelineManager:
    """Manages the complete pipeline startup and shutdown"""

    def __init__(self):
        self.components = {}
        self.processes = {}
        self.startup_order = []
        self.shutdown_handlers = []
        self.running = False

        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Define components
        self._define_components()

    def _define_components(self):
        """Define all pipeline components"""

        # Dashboard (central component)
        self.components["dashboard"] = ComponentConfig(
            name="dashboard",
            script_path="real_zmq_dashboard_refactored.py",
            config_path="configs/dashboard_config.json",
            required_privileges=False,
            dependencies=[],
            startup_delay=2.0,
            health_check_port=8080,
            description="Central dashboard - ML events → Firewall commands"
        )

        # Firewall Agent
        self.components["firewall_agent"] = ComponentConfig(
            name="firewall_agent",
            script_path="simple_firewall_agent_refactored.py",
            config_path="configs/firewall_agent_config.json",
            required_privileges=True,
            dependencies=["dashboard"],
            startup_delay=1.0,
            health_check_port=None,
            description="Firewall agent - Applies firewall rules"
        )

        # ML Detector (for testing)
        self.components["ml_detector"] = ComponentConfig(
            name="ml_detector",
            script_path="lightweight_ml_detector.py",
            config_path="configs/ml_detector_config.json",
            required_privileges=False,
            dependencies=[],
            startup_delay=0.0,
            health_check_port=None,
            description="ML Detector - Sends events to dashboard"
        )

        # GeoIP Enricher (for testing)
        self.components["geoip_enricher"] = ComponentConfig(
            name="geoip_enricher",
            script_path="geoip_enricher.py",
            config_path="configs/geoip_enricher_config.json",
            required_privileges=False,
            dependencies=[],
            startup_delay=0.0,
            health_check_port=None,
            description="GeoIP Enricher - Enriches events with geo data"
        )

        # Promiscuous Agent (for testing)
        self.components["promiscuous_agent"] = ComponentConfig(
            name="promiscuous_agent",
            script_path="promiscuous_agent.py",
            config_path="configs/promiscuous_agent_config.json",
            required_privileges=True,
            dependencies=[],
            startup_delay=0.0,
            health_check_port=None,
            description="Promiscuous Agent - Captures network packets"
        )

        # Define startup order
        self.startup_order = [
            "dashboard",
            "firewall_agent"
        ]

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down pipeline...")
        self.shutdown()
        sys.exit(0)

    def _check_prerequisites(self):
        """Check if all prerequisites are met"""
        logger.info("🔍 Checking prerequisites...")

        # Check Python version
        if sys.version_info < (3, 8):
            logger.error("❌ Python 3.8+ required")
            return False

        # Check required directories
        required_dirs = ["configs", "logs", "data", "src/protocols/protobuf"]
        for dir_path in required_dirs:
            if not os.path.exists(dir_path):
                logger.error(f"❌ Required directory missing: {dir_path}")
                return False

        # Check protobuf files
        protobuf_files = [
            "src/protocols/protobuf/network_event_extended_v2_pb2.py",
            "src/protocols/protobuf/firewall_commands_pb2.py"
        ]

        for pb_file in protobuf_files:
            if not os.path.exists(pb_file):
                logger.error(f"❌ Required protobuf file missing: {pb_file}")
                logger.error("   Please generate protobuf files first")
                return False

        # Check component scripts
        for component in self.components.values():
            if not os.path.exists(component.script_path):
                logger.error(f"❌ Component script missing: {component.script_path}")
                return False

        logger.info("✅ Prerequisites check passed")
        return True

    def _check_config_files(self):
        """Check if configuration files exist"""
        logger.info("📋 Checking configuration files...")

        missing_configs = []

        for component in self.components.values():
            if not os.path.exists(component.config_path):
                missing_configs.append(component.config_path)

        if missing_configs:
            logger.error("❌ Missing configuration files:")
            for config in missing_configs:
                logger.error(f"   - {config}")

            logger.info("💡 Creating default configuration files...")
            self._create_default_configs()

        logger.info("✅ Configuration files check passed")
        return True

    def _create_default_configs(self):
        """Create default configuration files"""

        # Create configs directory
        os.makedirs("configs", exist_ok=True)

        # Default dashboard config
        dashboard_config = {
            "component": {
                "name": "real_zmq_dashboard_with_firewall",
                "version": "2.0.0",
                "mode": "distributed"
            },
            "node_id": "dashboard_refactored_001",
            "version": "2.0.0",
            "component_type": "dashboard",
            "network": {
                "ml_events_input": {
                    "address": "localhost",
                    "port": 5570,
                    "mode": "bind",
                    "socket_type": "PULL",
                    "description": "Receives ML events",
                    "high_water_mark": 1000
                },
                "firewall_commands_output": {
                    "address": "localhost",
                    "port": 5580,
                    "mode": "bind",
                    "socket_type": "PUSH",
                    "description": "Sends firewall commands",
                    "high_water_mark": 1000
                },
                "firewall_responses_input": {
                    "address": "localhost",
                    "port": 5581,
                    "mode": "bind",
                    "socket_type": "PULL",
                    "description": "Receives firewall responses",
                    "high_water_mark": 1000
                }
            },
            "ml_processing": {
                "auto_block_threshold": 0.9,
                "auto_rate_limit_threshold": 0.7,
                "auto_allow_threshold": 0.3
            },
            "web_interface": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 8080,
                "debug": False
            },
            "compression": {
                "enabled": False
            },
            "encryption": {
                "enabled": False
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        }

        # Default firewall agent config
        firewall_config = {
            "component": {
                "name": "simple_firewall_agent",
                "version": "2.0.0",
                "mode": "distributed"
            },
            "node_id": "firewall_agent_001",
            "version": "2.0.0",
            "component_type": "firewall_agent",
            "network": {
                "commands_input": {
                    "address": "localhost",
                    "port": 5580,
                    "mode": "connect",
                    "socket_type": "PULL",
                    "description": "Receives firewall commands",
                    "high_water_mark": 1000
                },
                "responses_output": {
                    "address": "localhost",
                    "port": 5581,
                    "mode": "connect",
                    "socket_type": "PUSH",
                    "description": "Sends firewall responses",
                    "high_water_mark": 1000
                }
            },
            "firewall": {
                "sudo_enabled": True,
                "dry_run": False,
                "auto_detect_type": True
            },
            "compression": {
                "enabled": False
            },
            "encryption": {
                "enabled": False
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        }

        # Write config files
        with open("configs/dashboard_config.json", "w") as f:
            json.dump(dashboard_config, f, indent=2)

        with open("configs/firewall_agent_config.json", "w") as f:
            json.dump(firewall_config, f, indent=2)

        logger.info("✅ Default configuration files created")

    def _check_permissions(self):
        """Check if required permissions are available"""
        logger.info("🔐 Checking permissions...")

        # Check if we need sudo for firewall agent
        firewall_component = self.components["firewall_agent"]
        if firewall_component.required_privileges:
            if os.geteuid() != 0:
                logger.warning("⚠️  Firewall agent requires sudo privileges")
                logger.warning("   You may be prompted for sudo password")

        logger.info("✅ Permissions check completed")
        return True

    def _start_component(self, component_name: str) -> bool:
        """Start a single component"""
        component = self.components[component_name]

        logger.info(f"🚀 Starting {component.name}: {component.description}")

        # Check dependencies
        if component.dependencies:
            for dep in component.dependencies:
                if dep not in self.processes or self.processes[dep].poll() is not None:
                    logger.error(f"❌ Dependency {dep} not running for {component.name}")
                    return False

        # Build command
        cmd = [sys.executable, component.script_path, component.config_path]

        # Add sudo if required
        if component.required_privileges and os.geteuid() != 0:
            cmd = ["sudo"] + cmd

        try:
            # Start process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            self.processes[component_name] = process

            # Start output monitoring thread
            threading.Thread(
                target=self._monitor_output,
                args=(component_name, process),
                daemon=True
            ).start()

            # Wait for startup delay
            if component.startup_delay > 0:
                logger.info(f"⏳ Waiting {component.startup_delay}s for {component.name} startup...")
                time.sleep(component.startup_delay)

            # Check if process is still running
            if process.poll() is None:
                logger.info(f"✅ {component.name} started successfully (PID: {process.pid})")
                return True
            else:
                logger.error(f"❌ {component.name} failed to start")
                return False

        except Exception as e:
            logger.error(f"❌ Error starting {component.name}: {e}")
            return False

    def _monitor_output(self, component_name: str, process: subprocess.Popen):
        """Monitor component output"""
        try:
            for line in iter(process.stdout.readline, ''):
                if line.strip():
                    logger.info(f"[{component_name}] {line.strip()}")

            # Also monitor stderr
            for line in iter(process.stderr.readline, ''):
                if line.strip():
                    logger.error(f"[{component_name}] {line.strip()}")

        except Exception as e:
            logger.error(f"Error monitoring output for {component_name}: {e}")

    def _health_check(self, component_name: str) -> bool:
        """Perform health check on component"""
        component = self.components[component_name]

        # Check if process is running
        if component_name not in self.processes:
            return False

        process = self.processes[component_name]
        if process.poll() is not None:
            return False

        # Check health endpoint if available
        if component.health_check_port:
            try:
                import requests
                response = requests.get(
                    f"http://localhost:{component.health_check_port}/api/status",
                    timeout=5
                )
                return response.status_code == 200
            except:
                return False

        return True

    def start_pipeline(self, components: List[str] = None):
        """Start the complete pipeline"""
        logger.info("🧬 Starting Sistema Autoinmune Digital Pipeline")
        logger.info("=" * 60)

        if not self._check_prerequisites():
            logger.error("❌ Prerequisites check failed")
            return False

        if not self._check_config_files():
            logger.error("❌ Configuration check failed")
            return False

        if not self._check_permissions():
            logger.error("❌ Permissions check failed")
            return False

        # Use provided components or default startup order
        components_to_start = components if components else self.startup_order

        # Start components in order
        for component_name in components_to_start:
            if component_name not in self.components:
                logger.error(f"❌ Unknown component: {component_name}")
                continue

            if not self._start_component(component_name):
                logger.error(f"❌ Failed to start {component_name}")
                self.shutdown()
                return False

        self.running = True

        logger.info("=" * 60)
        logger.info("✅ Pipeline started successfully!")
        logger.info("🌐 Dashboard: http://localhost:8080")
        logger.info("🧪 Run tests: python test_pipeline_complete.py")
        logger.info("🛑 Stop pipeline: Ctrl+C")
        logger.info("=" * 60)

        return True

    def monitor_pipeline(self):
        """Monitor pipeline health"""
        logger.info("👁️  Pipeline monitoring started")

        while self.running:
            try:
                # Check component health
                for component_name in self.processes:
                    if not self._health_check(component_name):
                        logger.warning(f"⚠️  Health check failed for {component_name}")

                time.sleep(10)  # Check every 10 seconds

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error in pipeline monitoring: {e}")
                time.sleep(10)

    def shutdown(self):
        """Shutdown the pipeline"""
        logger.info("🛑 Shutting down pipeline...")

        self.running = False

        # Stop components in reverse order
        for component_name in reversed(self.startup_order):
            if component_name in self.processes:
                process = self.processes[component_name]

                if process.poll() is None:
                    logger.info(f"⏹️  Stopping {component_name}...")

                    # Try graceful shutdown first
                    process.terminate()

                    # Wait for graceful shutdown
                    try:
                        process.wait(timeout=5)
                        logger.info(f"✅ {component_name} stopped gracefully")
                    except subprocess.TimeoutExpired:
                        # Force kill if graceful shutdown fails
                        logger.warning(f"⚠️  Force killing {component_name}...")
                        process.kill()
                        process.wait()
                        logger.info(f"✅ {component_name} force stopped")

        logger.info("✅ Pipeline shutdown completed")

    def get_status(self) -> Dict:
        """Get pipeline status"""
        status = {
            "running": self.running,
            "components": {},
            "timestamp": time.time()
        }

        for component_name in self.startup_order:
            component = self.components[component_name]

            if component_name in self.processes:
                process = self.processes[component_name]
                is_running = process.poll() is None
                pid = process.pid if is_running else None
            else:
                is_running = False
                pid = None

            status["components"][component_name] = {
                "name": component.name,
                "description": component.description,
                "running": is_running,
                "pid": pid,
                "health_check_port": component.health_check_port
            }

        return status


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description="Pipeline Startup Manager")
    parser.add_argument("--components", nargs="*",
                        help="Components to start (default: dashboard, firewall_agent)")
    parser.add_argument("--status", action="store_true",
                        help="Show pipeline status")
    parser.add_argument("--test", action="store_true",
                        help="Run integration test after startup")

    args = parser.parse_args()

    # Create pipeline manager
    pipeline = PipelineManager()

    if args.status:
        status = pipeline.get_status()
        print(json.dumps(status, indent=2))
        return

    try:
        # Start pipeline
        if pipeline.start_pipeline(args.components):

            # Run test if requested
            if args.test:
                logger.info("🧪 Running integration test...")
                time.sleep(5)  # Wait for pipeline to stabilize

                try:
                    subprocess.run([sys.executable, "test_pipeline_complete.py"],
                                   check=True)
                except subprocess.CalledProcessError as e:
                    logger.error(f"❌ Integration test failed: {e}")
                except FileNotFoundError:
                    logger.error("❌ test_pipeline_complete.py not found")

            # Monitor pipeline
            pipeline.monitor_pipeline()

    except KeyboardInterrupt:
        logger.info("🛑 Shutdown requested by user")
    except Exception as e:
        logger.error(f"❌ Pipeline error: {e}")
    finally:
        pipeline.shutdown()


if __name__ == "__main__":
    main()