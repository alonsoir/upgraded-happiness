#!/usr/bin/env python3
"""
🚀 ZMQ PERFORMANCE OPTIMIZER v3.1
zmq_performance_optimizer.py

Script para optimizar configuración ZMQ y evitar buffer full
"""

import zmq
import json
import time
import threading
from typing import Dict, Any, Optional


class ZMQPerformanceTuner:
    """Tuner para optimizar rendimiento ZMQ"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.load_config()

    def load_config(self):
        """Load current config"""
        with open(self.config_file, 'r') as f:
            self.config = json.load(f)

    def save_config(self):
        """Save optimized config"""
        backup_file = f"{self.config_file}.backup"

        # Create backup
        with open(backup_file, 'w') as f:
            json.dump(self.config, f, indent=2)
        print(f"📝 Backup created: {backup_file}")

        # Save new config
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
        print(f"✅ Config updated: {self.config_file}")

    def optimize_zmq_config(self):
        """Optimize ZMQ configuration"""
        print("🔧 Optimizing ZMQ configuration...")

        # Ensure zmq section exists
        if "zmq" not in self.config:
            self.config["zmq"] = {}

        zmq_config = self.config["zmq"]

        # High-performance ZMQ settings
        optimizations = {
            # Buffer sizes (increase for high throughput)
            "sndhwm": 10000,  # Send High Water Mark (was 2000)
            "rcvhwm": 10000,  # Receive High Water Mark

            # Timeouts (reduce for faster drops when needed)
            "send_timeout_ms": 1,  # Very short timeout (was 100)
            "recv_timeout_ms": 1,
            "linger_ms": 0,  # Don't wait on close (was 5000)

            # I/O threads and TCP settings
            "io_threads": 2,  # More I/O threads
            "tcp_keepalive": 1,  # Enable TCP keepalive
            "tcp_keepalive_idle": 600,
            "tcp_keepalive_cnt": 3,
            "tcp_keepalive_intvl": 60,

            # Performance tuning
            "immediate": 1,  # Send immediately, don't batch
            "tcp_nodelay": 1,  # Disable Nagle's algorithm
            "sndbuf": 1048576,  # 1MB send buffer (OS level)
            "rcvbuf": 1048576,  # 1MB receive buffer (OS level)

            # ZMQ-specific optimizations
            "affinity": 1,  # CPU affinity
            "rate": 100000,  # Max rate (100k msg/sec)
            "recovery_ivl": 10000,  # Recovery interval (10s)
            "multicast_hops": 1,
            "maxmsgsize": 1048576,  # Max message size 1MB
        }

        # Apply optimizations
        current_values = {}
        for key, new_value in optimizations.items():
            current_values[key] = zmq_config.get(key, "not set")
            zmq_config[key] = new_value

        # Show changes
        print("📊 ZMQ Configuration Changes:")
        for key, new_value in optimizations.items():
            old_value = current_values[key]
            print(f"   {key}: {old_value} → {new_value}")

    def optimize_processing_config(self):
        """Optimize processing configuration"""
        print("\n⚙️ Optimizing processing configuration...")

        processing = self.config.get("processing", {})

        # Reduce queue sizes and processing overhead
        processing_optimizations = {
            "internal_queue_size": 1000,  # Smaller queue (was probably higher)
            "batch_size": 10,  # Process in small batches
            "worker_threads": 2,  # Limit threads to reduce overhead
            "packet_buffer_size": 500,  # Smaller packet buffer
            "flow_timeout_seconds": 30,  # Shorter flow timeout
            "max_flows_in_memory": 1000,  # Limit memory usage
        }

        print("📊 Processing Configuration Changes:")
        for key, new_value in processing_optimizations.items():
            old_value = processing.get(key, "not set")
            processing[key] = new_value
            print(f"   {key}: {old_value} → {new_value}")

        self.config["processing"] = processing

    def optimize_monitoring_config(self):
        """Optimize monitoring to reduce overhead"""
        print("\n📊 Optimizing monitoring configuration...")

        monitoring = self.config.get("monitoring", {})

        monitoring_optimizations = {
            "stats_interval_seconds": 30,  # Less frequent stats (was probably 10)
            "detailed_logging": False,  # Reduce logging overhead
            "performance_metrics": True,  # Keep essential metrics
            "debug_level": "INFO",  # Reduce debug noise
        }

        print("📊 Monitoring Configuration Changes:")
        for key, new_value in monitoring_optimizations.items():
            old_value = monitoring.get(key, "not set")
            monitoring[key] = new_value
            print(f"   {key}: {old_value} → {new_value}")

        self.config["monitoring"] = monitoring

    def add_backpressure_config(self):
        """Add backpressure handling configuration"""
        print("\n🔄 Adding backpressure handling...")

        # Add backpressure section
        backpressure = {
            "enabled": True,
            "max_drops_per_second": 100,  # Alert if dropping too much
            "drop_threshold_percent": 5.0,  # Alert if >5% drops
            "adaptive_rate_limiting": True,  # Slow down if dropping
            "circuit_breaker": {
                "enabled": True,
                "failure_threshold": 50,  # Open circuit after 50 consecutive failures
                "recovery_timeout": 30,  # Try again after 30s
                "half_open_max_calls": 5,  # Test with 5 calls
            }
        }

        self.config["backpressure"] = backpressure
        print("✅ Backpressure configuration added")

    def suggest_system_optimizations(self):
        """Suggest system-level optimizations"""
        print("\n🖥️ System-level optimization suggestions:")
        print("""
🔧 Kernel TCP optimizations:
   sudo sysctl -w net.core.rmem_max=134217728
   sudo sysctl -w net.core.wmem_max=134217728
   sudo sysctl -w net.ipv4.tcp_rmem='4096 87380 134217728'
   sudo sysctl -w net.ipv4.tcp_wmem='4096 65536 134217728'
   sudo sysctl -w net.core.netdev_max_backlog=5000

🚀 CPU optimizations:
   # Pin sniffer to specific CPU cores
   taskset -c 0,1 python evolutionary_sniffer_standalone_fixed.py config.json

   # Increase process priority
   sudo nice -n -10 python evolutionary_sniffer_standalone_fixed.py config.json

💾 Memory optimizations:
   # Increase max map count
   sudo sysctl -w vm.max_map_count=262144

   # Optimize memory allocation
   export MALLOC_ARENA_MAX=2

🔍 Monitoring commands:
   # Monitor ZMQ buffer usage
   ss -tuln | grep 5571

   # Monitor process performance
   top -p $(pgrep -f evolutionary_sniffer)

   # Monitor network traffic
   iftop -i lo  # for localhost testing
        """)


class ZMQBufferMonitor:
    """Monitor ZMQ buffer usage and suggest adjustments"""

    def __init__(self, context: zmq.Context, socket: zmq.Socket):
        self.context = context
        self.socket = socket
        self.stats = {
            'sends_attempted': 0,
            'sends_successful': 0,
            'sends_dropped': 0,
            'buffer_full_count': 0,
            'last_reset': time.time()
        }
        self.monitoring = True

    def monitor_send_attempt(self, success: bool, buffer_full: bool = False):
        """Record send attempt"""
        self.stats['sends_attempted'] += 1

        if success:
            self.stats['sends_successful'] += 1
        else:
            self.stats['sends_dropped'] += 1
            if buffer_full:
                self.stats['buffer_full_count'] += 1

    def get_performance_metrics(self) -> Dict[str, float]:
        """Get current performance metrics"""
        runtime = time.time() - self.stats['last_reset']

        if runtime == 0:
            return {}

        return {
            'success_rate': (self.stats['sends_successful'] / max(1, self.stats['sends_attempted'])) * 100,
            'drop_rate': (self.stats['sends_dropped'] / max(1, self.stats['sends_attempted'])) * 100,
            'buffer_full_rate': (self.stats['buffer_full_count'] / max(1, self.stats['sends_attempted'])) * 100,
            'sends_per_second': self.stats['sends_attempted'] / runtime,
            'successful_sends_per_second': self.stats['sends_successful'] / runtime,
        }

    def reset_stats(self):
        """Reset statistics"""
        for key in self.stats:
            if key != 'last_reset':
                self.stats[key] = 0
        self.stats['last_reset'] = time.time()

    def suggest_adjustments(self) -> list:
        """Suggest configuration adjustments based on metrics"""
        metrics = self.get_performance_metrics()
        suggestions = []

        if metrics.get('drop_rate', 0) > 10:
            suggestions.append("🚨 High drop rate (>10%) - Consider increasing sndhwm or reducing send rate")

        if metrics.get('buffer_full_rate', 0) > 5:
            suggestions.append("📦 Buffer full frequently (>5%) - Increase ZMQ buffer sizes")

        if metrics.get('success_rate', 100) < 80:
            suggestions.append("⚠️ Low success rate (<80%) - Check consumer or reduce production rate")

        if metrics.get('sends_per_second', 0) > 1000:
            suggestions.append("🏃 High send rate (>1000/s) - Consider batching or rate limiting")

        return suggestions


def create_test_consumer(port: int = 5571):
    """Create a simple test consumer to drain ZMQ messages"""
    print(f"🔧 Creating test consumer on port {port}")

    def consumer_worker():
        context = zmq.Context()
        socket = context.socket(zmq.PULL)
        socket.connect(f"tcp://localhost:{port}")

        # Configure consumer socket
        socket.setsockopt(zmq.RCVHWM, 10000)
        socket.setsockopt(zmq.RCVTIMEO, 100)
        socket.setsockopt(zmq.LINGER, 0)

        message_count = 0
        start_time = time.time()

        print(f"📥 Consumer started, listening on port {port}")

        try:
            while True:
                try:
                    # Receive message
                    message = socket.recv(zmq.NOBLOCK)
                    message_count += 1

                    # Log progress every 100 messages
                    if message_count % 100 == 0:
                        elapsed = time.time() - start_time
                        rate = message_count / elapsed if elapsed > 0 else 0
                        print(f"📊 Consumer: {message_count} messages, {rate:.1f} msg/s, {len(message)} bytes")

                except zmq.Again:
                    # No message available
                    time.sleep(0.01)
                except KeyboardInterrupt:
                    break

        except Exception as e:
            print(f"❌ Consumer error: {e}")
        finally:
            socket.close()
            context.term()
            print(f"✅ Consumer stopped: {message_count} total messages")

    # Start consumer in background thread
    consumer_thread = threading.Thread(target=consumer_worker, daemon=True)
    consumer_thread.start()

    return consumer_thread


def main():
    """Main function"""
    import sys

    if len(sys.argv) < 2:
        print("❌ Usage: python zmq_performance_optimizer.py <config.json> [action]")
        print("📋 Actions:")
        print("   optimize  - Optimize ZMQ configuration (default)")
        print("   monitor   - Create test consumer to monitor")
        print("   consumer  - Start test consumer only")
        sys.exit(1)

    config_file = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else "optimize"

    if action == "consumer":
        print("🚀 Starting ZMQ test consumer...")
        consumer_thread = create_test_consumer()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping consumer...")

    elif action == "monitor":
        print("🚀 Starting ZMQ monitor with test consumer...")
        consumer_thread = create_test_consumer()
        print("💡 Now run your sniffer in another terminal:")
        print(f"   python evolutionary_sniffer_standalone_fixed.py {config_file}")
        try:
            while True:
                time.sleep(10)
                print("📊 Consumer is running... (Ctrl+C to stop)")
        except KeyboardInterrupt:
            print("\n🛑 Stopping monitor...")

    else:  # optimize
        print("🚀 ZMQ PERFORMANCE OPTIMIZER v3.1")
        print("=" * 50)

        tuner = ZMQPerformanceTuner(config_file)

        # Apply optimizations
        tuner.optimize_zmq_config()
        tuner.optimize_processing_config()
        tuner.optimize_monitoring_config()
        tuner.add_backpressure_config()

        # Save optimized config
        tuner.save_config()

        # System suggestions
        tuner.suggest_system_optimizations()

        print("\n✅ OPTIMIZATION COMPLETED!")
        print("\n🚀 Next steps:")
        print(f"   1. Start test consumer: python {sys.argv[0]} {config_file} consumer")
        print(f"   2. Run optimized sniffer: python evolutionary_sniffer_standalone_fixed.py {config_file}")
        print("   3. Monitor performance and adjust as needed")


if __name__ == "__main__":
    main()