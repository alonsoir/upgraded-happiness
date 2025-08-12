#!/bin/bash

echo "🔍 TROUBLESHOOTING COMMANDS FOR PIPELINE DEBUG"
echo "=============================================="

function check_processes() {
    echo ""
    echo "🔄 1. CHECKING PROCESSES"
    echo "========================"

    echo "📊 All relevant processes:"
    ps aux | grep -E "(ml_detector|scheduler|consumer)" | grep -v grep | while read line; do
        echo "   ✅ $line"
    done

    echo ""
    echo "🔌 Port usage:"
    for port in 5580 5581 5582; do
        if lsof -ti:$port > /dev/null 2>&1; then
            process=$(lsof -ti:$port | head -1)
            cmd=$(ps -p $process -o comm= 2>/dev/null || echo "unknown")
            echo "   ✅ Port $port: PID $process ($cmd)"
        else
            echo "   ❌ Port $port: FREE"
        fi
    done
}

function check_configs() {
    echo ""
    echo "⚙️ 2. CHECKING CONFIGURATIONS"
    echo "=============================="

    # Check ML Detector config
    echo "📋 ML Detector config:"
    if [ -f "config/json/lightweight_ml_detector_tricapa_v31_config_dev.json" ]; then
        output_port=$(jq -r '.network.output_socket.port' config/json/lightweight_ml_detector_tricapa_v31_config_dev.json 2>/dev/null)
        echo "   Output port: $output_port (should be 5580)"
        if [ "$output_port" = "5580" ]; then
            echo "   ✅ ML Detector output port correct"
        else
            echo "   ❌ ML Detector output port WRONG!"
        fi
    else
        echo "   ❌ ML Detector config not found"
    fi

    echo ""
    echo "📋 Scheduler config:"
    if [ -f "config/json/scheduler_firewall_config.json" ]; then
        ml_input_port=$(jq -r '.network.ml_events_input.port' config/json/scheduler_firewall_config.json 2>/dev/null)
        commands_output_port=$(jq -r '.network.firewall_commands_output.port' config/json/scheduler_firewall_config.json 2>/dev/null)
        responses_input_port=$(jq -r '.network.firewall_responses_input.port' config/json/scheduler_firewall_config.json 2>/dev/null)

        echo "   ML input port: $ml_input_port (should be 5580)"
        echo "   Commands output port: $commands_output_port (should be 5582)"
        echo "   Responses input port: $responses_input_port (should be 5581)"

        if [ "$ml_input_port" = "5580" ]; then
            echo "   ✅ Scheduler ML input port correct"
        else
            echo "   ❌ Scheduler ML input port WRONG! Should be 5580"
        fi

        if [ "$commands_output_port" = "5582" ]; then
            echo "   ✅ Scheduler commands output port correct"
        else
            echo "   ❌ Scheduler commands output port WRONG! Should be 5582"
        fi
    else
        echo "   ❌ Scheduler config not found"
    fi
}

function check_logs() {
    echo ""
    echo "📋 3. CHECKING RECENT LOGS"
    echo "=========================="

    echo "🎯 ML Detector logs (last 5 lines):"
    if [ -f "logs/tricapa_ml_detector_v31.log" ]; then
        tail -5 logs/tricapa_ml_detector_v31.log | while read line; do
            echo "   📄 $line"
        done

        # Count recent events
        recent_events=$(grep "$(date +%Y-%m-%d)" logs/tricapa_ml_detector_v31.log 2>/dev/null | wc -l | tr -d ' ')
        echo "   📊 Events today: $recent_events"
    else
        echo "   ❌ ML Detector log not found"
    fi

    echo ""
    echo "🎯 Scheduler logs (last 5 lines):"
    if [ -f "logs/scheduler_firewall.log" ]; then
        tail -5 logs/scheduler_firewall.log | while read line; do
            echo "   📄 $line"
        done

        # Look for key indicators
        ml_events=$(grep "ML Events" logs/scheduler_firewall.log 2>/dev/null | wc -l | tr -d ' ')
        commands=$(grep -i "firewall.*command" logs/scheduler_firewall.log 2>/dev/null | wc -l | tr -d ' ')
        errors=$(grep -i "error\|fail" logs/scheduler_firewall.log 2>/dev/null | wc -l | tr -d ' ')

        echo "   📊 ML events received: $ml_events"
        echo "   📊 Commands generated: $commands"
        echo "   📊 Errors: $errors"
    else
        echo "   ❌ Scheduler log not found"
    fi
}

function test_ml_detector_output() {
    echo ""
    echo "🎯 4. TESTING ML DETECTOR OUTPUT"
    echo "================================"

    echo "📡 Attempting to connect to ml_detector port 5580 for 10 seconds..."
    timeout 10s python3 -c "
import zmq
import time

context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.setsockopt(zmq.SUBSCRIBE, b'')
socket.setsockopt(zmq.RCVTIMEO, 1000)

try:
    socket.connect('tcp://localhost:5580')
    print('   🔌 Connected to ml_detector')

    messages = 0
    start_time = time.time()

    while time.time() - start_time < 10:
        try:
            msg = socket.recv(zmq.NOBLOCK)
            messages += 1
            print(f'   📨 Message {messages}: {len(msg)} bytes')
        except zmq.Again:
            time.sleep(0.1)
        except Exception as e:
            print(f'   ❌ Error: {e}')
            break

    if messages > 0:
        print(f'   ✅ ML Detector is publishing! ({messages} messages)')
    else:
        print(f'   ❌ No messages from ML Detector')

except Exception as e:
    print(f'   ❌ Could not connect: {e}')
finally:
    socket.close()
    context.term()
" 2>/dev/null || echo "   ⚠️ Python/ZMQ test failed"
}

function test_consumer_port() {
    echo ""
    echo "📥 5. TESTING CONSUMER PORT"
    echo "=========================="

    echo "🔌 Attempting to send test message to consumer port 5582..."
    python3 -c "
import zmq
import json
import time

context = zmq.Context()
socket = context.socket(zmq.PUSH)
socket.setsockopt(zmq.SNDTIMEO, 2000)

try:
    socket.connect('tcp://localhost:5582')
    time.sleep(0.5)  # Allow connection

    test_msg = json.dumps({
        'test': True,
        'message': 'Troubleshooting test from script',
        'timestamp': int(time.time() * 1000)
    })

    socket.send_string(test_msg, zmq.NOBLOCK)
    print('   ✅ Test message sent to consumer')
    print('   📋 Check consumer output for this test message')

except Exception as e:
    print(f'   ❌ Could not send to consumer: {e}')
finally:
    socket.close()
    context.term()
" 2>/dev/null || echo "   ⚠️ Python/ZMQ test failed"
}

function show_network_analysis() {
    echo ""
    echo "🌐 6. NETWORK ANALYSIS"
    echo "====================="

    echo "📊 TCP connections for our ports:"
    netstat -an 2>/dev/null | grep -E "(5580|5581|5582)" | while read line; do
        echo "   📡 $line"
    done

    echo ""
    echo "🔍 Detailed port analysis:"
    for port in 5580 5581 5582; do
        echo "   Port $port:"
        lsof -i :$port 2>/dev/null | while read line; do
            echo "      📋 $line"
        done
    done
}

function suggest_fixes() {
    echo ""
    echo "🔧 7. SUGGESTED FIXES"
    echo "===================="

    echo "📋 Common issues and fixes:"

    echo ""
    echo "Issue: Consumer not receiving messages"
    echo "   🔧 Check consumer is binding to 5582:"
    echo "      python core/scheduler-simple-consumer.py 5582 5581"
    echo ""

    echo "Issue: Scheduler not receiving from ML Detector"
    echo "   🔧 Verify scheduler config ml_events_input.port = 5580"
    echo "   🔧 Check if ml_detector is actually publishing"
    echo ""

    echo "Issue: Scheduler not making decisions"
    echo "   🔧 Check firewall rules in config/json/firewall_rules_agent.json"
    echo "   🔧 Verify ML events have sufficient risk scores"
    echo ""

    echo "Quick restart sequence:"
    echo "   1. pkill -f 'ml_detector|scheduler|consumer'"
    echo "   2. python core/lightweight_ml_detector_tricapa_v31.py config/json/lightweight_ml_detector_tricapa_v31_config_dev.json &"
    echo "   3. python core/scheduler-simple-consumer.py 5582 5581 &"
    echo "   4. python core/scheduler-firewall.py config/json/scheduler_firewall_config.json config/json/firewall_rules_agent.json &"
}

function main() {
    echo "🔍 Starting comprehensive troubleshooting..."
    echo "📅 $(date)"
    echo ""

    check_processes
    check_configs
    check_logs
    test_ml_detector_output
    test_consumer_port
    show_network_analysis
    suggest_fixes

    echo ""
    echo "🎯 TROUBLESHOOTING COMPLETE"
    echo "=========================="
    echo "📋 Review the output above to identify issues"
    echo "🔧 Apply suggested fixes as needed"
    echo "📞 If issues persist, check that:"
    echo "   - All configs have correct ports"
    echo "   - No firewall blocking localhost connections"
    echo "   - ZMQ library is working correctly"
}

# Check if being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi