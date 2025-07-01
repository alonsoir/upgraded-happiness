#!/bin/bash
# Platform Monitor Script - Upgraded Happiness
# ============================================
# Comprehensive monitoring and verification script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "OK") echo -e "${GREEN}✅ $message${NC}" ;;
        "ERROR") echo -e "${RED}❌ $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "INFO") echo -e "${BLUE}ℹ️  $message${NC}" ;;
        "HEADER") echo -e "${CYAN}📊 $message${NC}" ;;
    esac
}

# Function to check if process is running
check_process() {
    local process_name=$1
    local friendly_name=$2
    local pid=$(ps aux | grep "$process_name" | grep -v grep | awk '{print $2}' | head -1)
    
    if [ ! -z "$pid" ]; then
        local memory=$(ps aux | grep "$process_name" | grep -v grep | awk '{print $6}' | head -1)
        local cpu=$(ps aux | grep "$process_name" | grep -v grep | awk '{print $3}' | head -1)
        print_status "OK" "$friendly_name running (PID: $pid, Memory: ${memory}KB, CPU: ${cpu}%)"
        return 0
    else
        print_status "ERROR" "$friendly_name not running"
        return 1
    fi
}

# Function to check port
check_port() {
    local port=$1
    local description=$2
    
    if netstat -an 2>/dev/null | grep -q ":$port.*LISTEN"; then
        print_status "OK" "$description (Port $port) - LISTENING"
        return 0
    else
        print_status "ERROR" "$description (Port $port) - NOT LISTENING"
        return 1
    fi
}

# Function to test connectivity
test_connectivity() {
    local host=$1
    local description=$2
    
    if ping -c 1 -W 1000 "$host" >/dev/null 2>&1; then
        print_status "OK" "$description connectivity"
        return 0
    else
        print_status "WARNING" "$description connectivity failed"
        return 1
    fi
}

# Main monitoring function
main_monitor() {
    print_status "HEADER" "UPGRADED HAPPINESS PLATFORM MONITOR"
    echo "$(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================"
    
    # Check virtual environment
    if [ -d "upgraded_happiness_venv" ]; then
        print_status "OK" "Virtual environment exists"
    else
        print_status "ERROR" "Virtual environment not found"
    fi
    
    echo ""
    print_status "HEADER" "PROCESS STATUS"
    echo "----------------------------------------"
    
    # Check core processes
    local broker_ok=0
    local ml_ok=0
    local agent_ok=0
    
    if check_process "smart_broker.py" "ZeroMQ Broker"; then
        broker_ok=1
    fi
    
    if check_process "lightweight_ml_detector.py" "ML Detector"; then
        ml_ok=1
    fi
    
    if check_process "promiscuous_agent.py" "Promiscuous Agent"; then
        agent_ok=1
    fi
    
    echo ""
    print_status "HEADER" "NETWORK STATUS"
    echo "----------------------------------------"
    
    # Check ports
    check_port "5555" "ZeroMQ Primary Port"
    check_port "5556" "ZeroMQ Secondary Port"
    
    # Check for UDP ports
    if netstat -an 2>/dev/null | grep -q "55565.*\*\.\*"; then
        print_status "OK" "ZeroMQ UDP Port (55565) - ACTIVE"
    else
        print_status "WARNING" "ZeroMQ UDP Port (55565) - NOT DETECTED"
    fi
    
    echo ""
    print_status "HEADER" "CONNECTIVITY TESTS"
    echo "----------------------------------------"
    
    # Test external connectivity
    test_connectivity "8.8.8.8" "Google DNS"
    test_connectivity "1.1.1.1" "Cloudflare DNS"
    
    echo ""
    print_status "HEADER" "SYSTEM RESOURCES"
    echo "----------------------------------------"
    
    # Memory usage
    local total_memory=$(ps aux | grep -E "(smart_broker|lightweight_ml|promiscuous)" | grep -v grep | awk '{sum += $6} END {print sum}')
    if [ ! -z "$total_memory" ]; then
        print_status "INFO" "Total platform memory usage: ${total_memory}KB ($((total_memory/1024))MB)"
    fi
    
    # CPU usage
    local total_cpu=$(ps aux | grep -E "(smart_broker|lightweight_ml|promiscuous)" | grep -v grep | awk '{sum += $3} END {print sum}')
    if [ ! -z "$total_cpu" ]; then
        print_status "INFO" "Total platform CPU usage: ${total_cpu}%"
    fi
    
    echo ""
    print_status "HEADER" "PLATFORM SUMMARY"
    echo "----------------------------------------"
    
    # Overall status
    local total_components=$((broker_ok + ml_ok + agent_ok))
    case $total_components in
        3) print_status "OK" "Platform fully operational (3/3 components)" ;;
        2) print_status "WARNING" "Platform partially operational (2/3 components)" ;;
        1) print_status "WARNING" "Platform minimal operational (1/3 components)" ;;
        0) print_status "ERROR" "Platform not operational (0/3 components)" ;;
    esac
    
    echo ""
    if [ "$1" = "--continuous" ]; then
        print_status "INFO" "Continuous monitoring mode (Ctrl+C to stop)"
        print_status "INFO" "Refreshing every 5 seconds..."
        echo "========================================"
    fi
}

# Continuous monitoring mode
continuous_monitor() {
    while true; do
        clear
        main_monitor --continuous
        sleep 5
    done
}

# Generate traffic for testing
generate_test_traffic() {
    print_status "HEADER" "GENERATING TEST TRAFFIC"
    echo "----------------------------------------"
    
    print_status "INFO" "Generating HTTP requests..."
    curl -s https://httpbin.org/get > /dev/null 2>&1 && print_status "OK" "HTTP test 1 completed"
    curl -s https://jsonplaceholder.typicode.com/posts/1 > /dev/null 2>&1 && print_status "OK" "HTTP test 2 completed"
    
    print_status "INFO" "Generating DNS queries..."
    nslookup google.com > /dev/null 2>&1 && print_status "OK" "DNS test completed"
    
    print_status "INFO" "Generating ICMP traffic..."
    ping -c 3 8.8.8.8 > /dev/null 2>&1 && print_status "OK" "ICMP test completed"
    
    print_status "OK" "Test traffic generation completed"
}

# Emergency stop function
emergency_stop() {
    print_status "HEADER" "EMERGENCY STOP"
    echo "----------------------------------------"
    
    print_status "INFO" "Stopping all platform components..."
    
    # Stop promiscuous agent (running as root)
    sudo pkill -f promiscuous_agent.py 2>/dev/null && print_status "OK" "Promiscuous agent stopped"
    
    # Stop ML detector
    pkill -f lightweight_ml_detector.py 2>/dev/null && print_status "OK" "ML detector stopped"
    
    # Stop broker
    pkill -f smart_broker.py 2>/dev/null && print_status "OK" "ZeroMQ broker stopped"
    
    print_status "OK" "Emergency stop completed"
}

# Show help
show_help() {
    echo "Upgraded Happiness Platform Monitor"
    echo "=================================="
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  --status, -s        Show platform status (default)"
    echo "  --continuous, -c    Continuous monitoring mode"
    echo "  --test-traffic, -t  Generate test traffic"
    echo "  --stop, -x          Emergency stop all components"
    echo "  --help, -h          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                  # Show current status"
    echo "  $0 --continuous     # Monitor continuously"
    echo "  $0 --test-traffic   # Generate test traffic"
    echo "  $0 --stop           # Emergency stop"
}

# Parse command line arguments
case "${1:-}" in
    --status|-s)
        main_monitor
        ;;
    --continuous|-c)
        continuous_monitor
        ;;
    --test-traffic|-t)
        generate_test_traffic
        ;;
    --stop|-x)
        emergency_stop
        ;;
    --help|-h)
        show_help
        ;;
    "")
        main_monitor
        ;;
    *)
        echo "Unknown option: $1"
        show_help
        exit 1
        ;;
esac
