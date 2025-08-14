#!/usr/bin/env python3
"""
scheduler_queue_debugger.py - DEBUGGER ESPECÍFICO PARA COLA DEL SCHEDULER
🚨 Investiga por qué la cola del scheduler se llena constantemente
"""
import time
import subprocess
import re
import json
from datetime import datetime


def monitor_scheduler_logs():
    """Monitor en tiempo real de logs del scheduler"""
    print("🔍 MONITORING SCHEDULER LOGS IN REAL TIME")
    print("=" * 50)

    try:
        # Usar tail -f para seguir logs en tiempo real
        process = subprocess.Popen(
            ['tail', '-f', 'logs/scheduler_firewall.log'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        queue_full_count = 0
        decision_count = 0
        command_sent_count = 0
        start_time = time.time()

        print("📋 Watching for key patterns:")
        print("   🚨 'queue full' - Cola bloqueada")
        print("   ✅ 'Decision made' - Decisiones tomadas")
        print("   📤 'Command sent' - Comandos enviados")
        print("   🔄 'Firewall Command Sender' - Thread sender activo")
        print("   ⏹️ Press Ctrl+C to stop")
        print()

        while True:
            line = process.stdout.readline()
            if not line:
                break

            timestamp = datetime.now().strftime("%H:%M:%S")

            # Detectar patrones clave
            if 'queue full' in line.lower():
                queue_full_count += 1
                print(f"🚨 [{timestamp}] QUEUE FULL #{queue_full_count}")
                print(f"   📄 {line.strip()}")

            elif 'decision made' in line.lower():
                decision_count += 1
                # Extraer risk score si está disponible
                risk_match = re.search(r'(\d+(?:\.\d+)?).*?%', line)
                risk = risk_match.group(1) if risk_match else "unknown"
                print(f"✅ [{timestamp}] DECISION #{decision_count} (risk: {risk}%)")

            elif 'command sent' in line.lower() or 'sent successfully' in line.lower():
                command_sent_count += 1
                print(f"📤 [{timestamp}] COMMAND SENT #{command_sent_count}")

            elif 'firewall command sender' in line.lower():
                if 'started' in line.lower():
                    print(f"🔄 [{timestamp}] COMMAND SENDER THREAD STARTED")
                elif 'stopped' in line.lower():
                    print(f"⏹️ [{timestamp}] COMMAND SENDER THREAD STOPPED")

            elif 'error' in line.lower() or 'fail' in line.lower():
                print(f"❌ [{timestamp}] ERROR:")
                print(f"   📄 {line.strip()}")

            # Stats cada 30 segundos
            elapsed = time.time() - start_time
            if elapsed > 30 and elapsed % 30 < 1:
                print(f"\n📊 [{timestamp}] STATS (last {elapsed:.0f}s):")
                print(f"   🚨 Queue full events: {queue_full_count}")
                print(f"   ✅ Decisions made: {decision_count}")
                print(f"   📤 Commands sent: {command_sent_count}")

                # Análisis del problema
                if queue_full_count > 0 and command_sent_count == 0:
                    print(f"   🔥 PROBLEM: Decisions made but NO commands sent!")
                    print(f"   💡 Suggestion: Command sender thread may be stuck")
                elif decision_count > command_sent_count * 2:
                    print(f"   ⚠️ WARNING: More decisions than commands sent")

                print()

    except KeyboardInterrupt:
        print(f"\n🛑 Monitoring stopped")
        process.terminate()
    except Exception as e:
        print(f"❌ Error monitoring logs: {e}")


def analyze_current_scheduler_state():
    """Analizar estado actual del scheduler"""
    print("\n🔍 ANALYZING CURRENT SCHEDULER STATE")
    print("=" * 50)

    try:
        # Buscar patrones en logs recientes
        result = subprocess.run(
            ['tail', '-100', 'logs/scheduler_firewall.log'],
            capture_output=True, text=True
        )

        if result.stdout:
            lines = result.stdout.strip().split('\n')

            # Contar eventos recientes
            queue_full = len([l for l in lines if 'queue full' in l.lower()])
            decisions = len([l for l in lines if 'decision made' in l.lower()])
            commands_sent = len([l for l in lines if 'command sent' in l.lower() or 'sent successfully' in l.lower()])
            sender_started = len(
                [l for l in lines if 'firewall command sender' in l.lower() and 'started' in l.lower()])
            sender_stopped = len(
                [l for l in lines if 'firewall command sender' in l.lower() and 'stopped' in l.lower()])
            errors = len([l for l in lines if 'error' in l.lower() or 'fail' in l.lower()])

            print("📊 Recent Activity (last 100 log lines):")
            print(f"   🚨 Queue full events: {queue_full}")
            print(f"   ✅ Decisions made: {decisions}")
            print(f"   📤 Commands sent: {commands_sent}")
            print(f"   🔄 Sender threads started: {sender_started}")
            print(f"   ⏹️ Sender threads stopped: {sender_stopped}")
            print(f"   ❌ Errors: {errors}")

            # Diagnosis
            print("\n🔬 DIAGNOSIS:")
            if queue_full > 10:
                print("   🚨 CRITICAL: Queue constantly full!")
                if commands_sent == 0:
                    print("   💥 ROOT CAUSE: Command sender thread NOT WORKING")
                    print("   🔧 SOLUTION: Restart scheduler or fix sender thread")
                else:
                    print("   ⚠️ Commands being sent but queue still fills up")
                    print("   💡 May need to increase queue size or reduce decision rate")

            if decisions > 0 and commands_sent == 0:
                print("   🔥 PROBLEM: Making decisions but not sending commands")
                print("   💡 Command sender thread likely stuck or not started")

            if sender_started == 0:
                print("   ❌ PROBLEM: No command sender threads started")
                print("   🔧 SOLUTION: Check scheduler configuration")

            # Buscar último mensaje de queue full
            last_queue_full = None
            for line in reversed(lines):
                if 'queue full' in line.lower():
                    last_queue_full = line.strip()
                    break

            if last_queue_full:
                print(f"\n📄 Last queue full message:")
                print(f"   {last_queue_full}")

    except Exception as e:
        print(f"❌ Error analyzing scheduler state: {e}")


def check_scheduler_config_issues():
    """Verificar problemas de configuración del scheduler"""
    print("\n⚙️ CHECKING SCHEDULER CONFIGURATION")
    print("=" * 50)

    try:
        with open('config/json/scheduler_firewall_config.json', 'r') as f:
            config = json.load(f)

        # Verificar configuraciones críticas
        processing = config.get('processing', {})
        threads = processing.get('threads', {})
        queues = processing.get('internal_queues', {})

        print("📋 Current Configuration:")
        print(f"   🧵 Firewall command producers: {threads.get('firewall_command_producers', 'NOT SET')}")
        print(f"   📦 Firewall commands queue size: {queues.get('firewall_commands_queue_size', 'NOT SET')}")
        print(
            f"   ⚙️ Queue overflow strategy: {processing.get('queue_management', {}).get('overflow_strategy', 'NOT SET')}")

        # Verificar si la configuración es problemática
        command_producers = threads.get('firewall_command_producers', 0)
        queue_size = queues.get('firewall_commands_queue_size', 0)

        print("\n🔬 Configuration Analysis:")
        if command_producers <= 0:
            print("   ❌ PROBLEM: No firewall command producer threads configured!")
            print("   🔧 SOLUTION: Set firewall_command_producers >= 1")

        if queue_size <= 10:
            print(f"   ⚠️ WARNING: Very small queue size ({queue_size})")
            print("   💡 Consider increasing to 200+ for high-volume scenarios")

        if command_producers == 1 and queue_size < 100:
            print("   ⚠️ Potential bottleneck: 1 producer thread with small queue")

        print(f"\n📄 Full processing config:")
        print(json.dumps(processing, indent=2))

    except Exception as e:
        print(f"❌ Error checking scheduler config: {e}")


def suggest_immediate_fixes():
    """Sugerir soluciones inmediatas"""
    print("\n🔧 IMMEDIATE FIXES")
    print("=" * 50)

    print("1. 🚨 EMERGENCY: Restart scheduler with queue drain:")
    print("   pkill -f scheduler-firewall")
    print("   sleep 3")
    print(
        "   python core/scheduler-firewall.py config/json/scheduler_firewall_config.json config/json/firewall_rules_agent.json &")

    print("\n2. 📊 MONITOR: Watch for immediate queue fill:")
    print("   tail -f logs/scheduler_firewall.log | grep -i 'queue\\|decision\\|command'")

    print("\n3. 🔧 CONFIG FIX: If queue fills immediately, increase queue size:")
    print("   Edit config/json/scheduler_firewall_config.json:")
    print("   Set processing.internal_queues.firewall_commands_queue_size to 500")

    print("\n4. 🧵 THREAD FIX: Ensure command sender threads are working:")
    print("   Look for 'Firewall Command Sender X started' in logs")
    print("   If missing, there's a threading issue in scheduler")

    print("\n5. 🎯 TEST: Send single command manually:")
    print("   python3 -c \"")
    print("import zmq, json, time")
    print("context = zmq.Context()")
    print("socket = context.socket(zmq.PUSH)")
    print("socket.connect('tcp://localhost:5582')")
    print("time.sleep(0.5)")
    print("socket.send_string(json.dumps({'test': True, 'manual': True}))")
    print("print('Manual test sent')")
    print("\"")


def main():
    """Función principal"""
    print("🚨 SCHEDULER QUEUE DEBUGGER")
    print("=" * 60)
    print("📅 " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    # Análisis estático primero
    analyze_current_scheduler_state()
    check_scheduler_config_issues()
    suggest_immediate_fixes()

    # Ofrecer monitoreo en tiempo real
    print("\n🔍 REAL-TIME MONITORING")
    print("=" * 50)
    try:
        choice = input("¿Iniciar monitoreo en tiempo real de logs? (y/n): ").strip().lower()
        if choice == 'y':
            monitor_scheduler_logs()
    except KeyboardInterrupt:
        pass

    print("\n✅ Debugging complete")


if __name__ == "__main__":
    main()