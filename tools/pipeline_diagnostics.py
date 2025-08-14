#!/usr/bin/env python3
"""
pipeline_diagnostics.py - DIAGNÓSTICO COMPLETO DEL PIPELINE
🔍 Verifica cada paso del flujo: ml_detector → scheduler → consumer
"""
import zmq
import json
import time
import subprocess
import sys
import os
from datetime import datetime


def get_port_info():
    """Verificar estado de puertos"""
    print("🔌 PORT STATUS:")
    print("=" * 50)

    try:
        # Usar lsof para verificar puertos
        result = subprocess.run(['lsof', '-i', ':5580', '-i', ':5581', '-i', ':5582'],
                                capture_output=True, text=True)
        if result.stdout:
            print("   ✅ Ports in use:")
            for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 9:
                    cmd = parts[0]
                    pid = parts[1]
                    name = parts[8]
                    print(f"      {cmd}[{pid}] -> {name}")
        else:
            print("   ❌ No processes found on ports 5580, 5581, 5582")

        # También usar netstat como backup
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
        print("\n   📊 Netstat info:")
        for line in result.stdout.split('\n'):
            if '5580' in line or '5581' in line or '5582' in line:
                print(f"      {line.strip()}")

    except Exception as e:
        print(f"   ❌ Error checking ports: {e}")


def test_ml_detector_connection():
    """Probar conexión directa al ml_detector"""
    print("\n🎯 ML DETECTOR CONNECTION TEST:")
    print("=" * 50)

    try:
        context = zmq.Context()
        socket = context.socket(zmq.SUB)
        socket.setsockopt(zmq.SUBSCRIBE, b"")  # Subscribe to all messages
        socket.setsockopt(zmq.RCVTIMEO, 5000)  # 5 second timeout

        endpoint = "tcp://localhost:5580"
        socket.connect(endpoint)
        print(f"   🔌 Connected to {endpoint}")

        print("   ⏳ Waiting for messages (5 seconds)...")
        start_time = time.time()
        messages_received = 0

        while time.time() - start_time < 5:
            try:
                message = socket.recv(zmq.NOBLOCK)
                messages_received += 1
                print(f"   📨 Message {messages_received}: {len(message)} bytes")

                # Try to preview message content
                try:
                    # Try protobuf first (just check if it's binary)
                    if len(message) > 10 and not message[:50].decode('utf-8', errors='ignore').isprintable():
                        print(f"      🔍 Looks like protobuf (binary data)")
                    else:
                        preview = message[:100].decode('utf-8', errors='ignore')
                        print(f"      🔍 Preview: {preview}...")
                except:
                    print(f"      🔍 Binary message")

            except zmq.Again:
                time.sleep(0.1)

        if messages_received > 0:
            print(f"   ✅ ML Detector is publishing! Received {messages_received} messages")
        else:
            print(f"   ❌ No messages received from ML Detector")
            print(f"      Check if ml_detector is running and publishing")

        socket.close()
        context.term()

    except Exception as e:
        print(f"   ❌ Error testing ML Detector: {e}")


def test_scheduler_logs():
    """Verificar logs del scheduler"""
    print("\n📋 SCHEDULER LOGS ANALYSIS:")
    print("=" * 50)

    log_files = [
        "logs/scheduler_firewall.log",
        "logs/scheduler_decisions.log"
    ]

    for log_file in log_files:
        if os.path.exists(log_file):
            print(f"\n   📄 {log_file}:")
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()

                # Get last 10 lines
                recent_lines = lines[-10:] if lines else []

                for line in recent_lines:
                    line = line.strip()
                    if 'ML Events' in line or 'socket' in line.lower() or 'connect' in line.lower():
                        print(f"      🔍 {line}")
                    elif 'error' in line.lower() or 'fail' in line.lower():
                        print(f"      ❌ {line}")
                    elif 'command' in line.lower() or 'decision' in line.lower():
                        print(f"      🎯 {line}")

                # Count key events
                ml_events = sum(1 for line in lines if 'ML Events' in line)
                errors = sum(1 for line in lines if 'ERROR' in line)
                commands = sum(1 for line in lines if 'FirewallCommand' in line)

                print(f"      📊 Stats: {ml_events} ML events, {commands} commands, {errors} errors")

            except Exception as e:
                print(f"      ❌ Error reading log: {e}")
        else:
            print(f"   ❌ Log file not found: {log_file}")


def test_consumer_port():
    """Probar si el consumer está realmente escuchando en 5582"""
    print("\n📥 CONSUMER PORT TEST:")
    print("=" * 50)

    try:
        context = zmq.Context()
        socket = context.socket(zmq.PUSH)
        socket.setsockopt(zmq.SNDTIMEO, 2000)  # 2 second timeout

        endpoint = "tcp://localhost:5582"
        print(f"   🔌 Attempting to connect to consumer at {endpoint}")

        socket.connect(endpoint)
        time.sleep(0.5)  # Allow connection to establish

        # Try to send a test message
        test_message = json.dumps({
            "test": True,
            "timestamp": int(time.time() * 1000),
            "source": "diagnostic_tool"
        })

        socket.send_string(test_message, zmq.NOBLOCK)
        print(f"   ✅ Test message sent to consumer successfully")
        print(f"      Check consumer output for diagnostic message")

        socket.close()
        context.term()

    except zmq.Again:
        print(f"   ⚠️ Could not send to consumer - socket timeout")
        print(f"      Consumer might not be listening on 5582")
    except Exception as e:
        print(f"   ❌ Error testing consumer port: {e}")


def test_scheduler_to_consumer():
    """Probar el enlace scheduler → consumer específicamente"""
    print("\n🔗 SCHEDULER → CONSUMER LINK TEST:")
    print("=" * 50)

    # Check if scheduler config looks correct
    config_file = "config/json/scheduler_firewall_config.json"
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)

            ml_input_port = config.get('network', {}).get('ml_events_input', {}).get('port')
            commands_output_port = config.get('network', {}).get('firewall_commands_output', {}).get('port')
            responses_input_port = config.get('network', {}).get('firewall_responses_input', {}).get('port')

            print(f"   📋 Scheduler config:")
            print(f"      ML input port: {ml_input_port} (should be 5580)")
            print(f"      Commands output port: {commands_output_port} (should be 5582)")
            print(f"      Responses input port: {responses_input_port} (should be 5581)")

            # Validate configuration
            if ml_input_port == 5580:
                print(f"      ✅ ML input port correct")
            else:
                print(f"      ❌ ML input port wrong! Should be 5580, got {ml_input_port}")

            if commands_output_port == 5582:
                print(f"      ✅ Commands output port correct")
            else:
                print(f"      ❌ Commands output port wrong! Should be 5582, got {commands_output_port}")

        except Exception as e:
            print(f"   ❌ Error reading scheduler config: {e}")
    else:
        print(f"   ❌ Scheduler config file not found: {config_file}")


def get_process_info():
    """Información detallada de procesos"""
    print("\n🔄 PROCESS INFORMATION:")
    print("=" * 50)

    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)

        relevant_processes = []
        for line in result.stdout.split('\n'):
            if any(keyword in line for keyword in ['ml_detector', 'scheduler', 'consumer']) and 'grep' not in line:
                relevant_processes.append(line)

        if relevant_processes:
            print("   ✅ Running processes:")
            for proc in relevant_processes:
                parts = proc.split()
                if len(parts) >= 11:
                    pid = parts[1]
                    cpu = parts[2]
                    mem = parts[3]
                    cmd = ' '.join(parts[10:])[:80] + "..."
                    print(f"      PID {pid}: CPU {cpu}% MEM {mem}% - {cmd}")
        else:
            print("   ❌ No relevant processes found")

    except Exception as e:
        print(f"   ❌ Error getting process info: {e}")


def main():
    """Ejecutar diagnóstico completo"""
    print("🔍 PIPELINE DIAGNOSTIC TOOL")
    print("=" * 60)
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Execute all tests
    get_process_info()
    get_port_info()
    test_scheduler_logs()
    test_scheduler_to_consumer()
    test_ml_detector_connection()
    test_consumer_port()

    print("\n🎯 TROUBLESHOOTING RECOMMENDATIONS:")
    print("=" * 60)
    print("1. If ML Detector is not publishing:")
    print("   - Check logs/tricapa_ml_detector_v31.log")
    print("   - Verify ml_detector config has output_socket.port: 5580")
    print("")
    print("2. If Scheduler is not receiving from ML Detector:")
    print("   - Verify scheduler config has ml_events_input.port: 5580")
    print("   - Check logs/scheduler_firewall.log for connection errors")
    print("")
    print("3. If Scheduler is not sending to Consumer:")
    print("   - Verify scheduler config has firewall_commands_output.port: 5582")
    print("   - Check if scheduler is making decisions (logs/scheduler_decisions.log)")
    print("")
    print("4. If Consumer is not receiving:")
    print("   - Verify consumer is binding to port 5582")
    print("   - Check consumer startup messages")
    print("")
    print("🔧 Quick fixes:")
    print("   - Restart components: pkill -f 'ml_detector|scheduler|consumer'")
    print("   - Check configs match expected ports")
    print("   - Monitor logs in real-time: tail -f logs/*.log")


if __name__ == "__main__":
    main()