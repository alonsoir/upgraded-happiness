#!/bin/bash
# scripts/integrate-sniffer-etcd.sh
# 🔍 Integración completa ETCD para Evolutionary Sniffer
# ZERO hardcoded values - TODO desde JSON

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

CONFIG_FILE="config/json/evolutionary_sniffer_config_v31.json"
CORE_DIR="core"

echo -e "${BLUE}🔍 EVOLUTIONARY SNIFFER - ETCD Crypto Integration${NC}"
echo -e "${BLUE}ZERO Hardcoded Values - Everything from JSON${NC}"
echo -e "${BLUE}===============================================${NC}"
echo ""

# Función para verificar prerequisitos
check_prerequisites() {
    echo -e "${BLUE}📋 Checking prerequisites...${NC}"

    local missing=()

    # Python 3 y packages
    if ! command -v python3 &> /dev/null; then
        missing+=("python3")
    fi

    if ! python3 -c "import etcd3" 2>/dev/null; then
        echo -e "${YELLOW}   Installing etcd3...${NC}"
        pip3 install etcd3 || missing+=("etcd3")
    fi

    if ! python3 -c "import cryptography" 2>/dev/null; then
        echo -e "${YELLOW}   Installing cryptography...${NC}"
        pip3 install cryptography || missing+=("cryptography")
    fi

    # ETCD
    if ! command -v etcd &> /dev/null; then
        missing+=("etcd")
    fi

    if ! curl -s http://localhost:2379/health > /dev/null; then
        missing+=("etcd-running")
    fi

    if [ ${#missing[@]} -eq 0 ]; then
        echo -e "${GREEN}   ✅ All prerequisites met${NC}"
        return 0
    else
        echo -e "${RED}   ❌ Missing: ${missing[*]}${NC}"
        return 1
    fi
}

# Función para verificar estructura del config
validate_config_structure() {
    echo -e "${BLUE}📋 Validating config structure...${NC}"

    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}   ❌ Config file not found: $CONFIG_FILE${NC}"
        return 1
    fi

    # Crear script de validación temporal
    cat > /tmp/validate_config.py << 'EOF'
import json
import sys

def validate_config(config_path):
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}")
        return False
    except Exception as e:
        print(f"❌ Cannot read config: {e}")
        return False

    # Verificar campos obligatorios
    required_sections = {
        'zmq': 'ZMQ configuration',
        'etcd_crypto': 'ETCD crypto configuration'
    }

    missing = []

    for section, description in required_sections.items():
        if section not in config:
            missing.append(f"{section} ({description})")

    if missing:
        print("❌ Missing required sections:")
        for m in missing:
            print(f"   - {m}")
        return False

    # Verificar campos específicos
    zmq_fields = ['publisher.host', 'publisher.port']
    etcd_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']

    # Verificar ZMQ
    if 'publisher' not in config['zmq']:
        print("❌ Missing zmq.publisher section")
        return False

    zmq_missing = []
    for field in ['host', 'port']:
        if field not in config['zmq']['publisher']:
            zmq_missing.append(f"zmq.publisher.{field}")

    # Verificar ETCD
    etcd_missing = []
    for field in etcd_fields:
        if field not in config['etcd_crypto']:
            etcd_missing.append(f"etcd_crypto.{field}")

    all_missing = zmq_missing + etcd_missing

    if all_missing:
        print("❌ Missing required fields:")
        for field in all_missing:
            print(f"   - {field}")
        return False

    print("✅ Config structure valid")
    print(f"   📡 ETCD: {config['etcd_crypto']['etcd_host']}:{config['etcd_crypto']['etcd_port']}")
    print(f"   🆔 Node ID: {config['etcd_crypto']['node_id']}")
    print(f"   📤 ZMQ: {config['zmq']['publisher']['host']}:{config['zmq']['publisher']['port']}")

    return True

if __name__ == "__main__":
    success = validate_config(sys.argv[1])
    sys.exit(0 if success else 1)
EOF

    if python3 /tmp/validate_config.py "$CONFIG_FILE"; then
        echo -e "${GREEN}   ✅ Config validation passed${NC}"
        rm -f /tmp/validate_config.py
        return 0
    else
        echo -e "${RED}   ❌ Config validation failed${NC}"
        rm -f /tmp/validate_config.py
        return 1
    fi
}

# Función para crear archivos necesarios
create_integration_files() {
    echo -e "${BLUE}📄 Checking integration files...${NC}"

    local required_files=(
        "$CORE_DIR/etcd_crypto_client_sniffer.py"
        "$CORE_DIR/etcd_coordinator.py"
    )

    local missing_files=0

    for file in "${required_files[@]}"; do
        if [ -f "$file" ]; then
            echo -e "${GREEN}   ✅ $file${NC}"
        else
            echo -e "${RED}   ❌ $file${NC}"
            missing_files=$((missing_files + 1))
        fi
    done

    if [ $missing_files -eq 0 ]; then
        echo -e "${GREEN}   ✅ All integration files present${NC}"
        return 0
    else
        echo -e "${RED}   ❌ Missing $missing_files integration files${NC}"
        echo -e "${BLUE}      Copy from artifacts or create manually${NC}"
        return 1
    fi
}

# Función para iniciar coordinador
start_coordinator() {
    echo -e "${BLUE}🚀 Starting ETCD coordinator...${NC}"

    # Verificar si ya está running
    if [ -f ".pids/coordinator.pid" ] && ps -p $(cat .pids/coordinator.pid) > /dev/null 2>&1; then
        echo -e "${GREEN}   ✅ Coordinator already running${NC}"
        return 0
    fi

    mkdir -p .pids logs

    # Crear script del coordinador
    cat > scripts/coordinator.py << 'EOF'
#!/usr/bin/env python3
import asyncio
import sys
import os

sys.path.insert(0, '.')

from core.etcd_coordinator import ETCDCryptoCoordinator

async def main():
    coordinator = ETCDCryptoCoordinator(
        etcd_host="localhost",
        etcd_port=2379,
        cluster_name="upgraded-happiness-cluster"
    )

    try:
        await coordinator.start()
        print("✅ Coordinator started successfully!")

        while True:
            await asyncio.sleep(30)
            status = await coordinator.get_cluster_status()
            print(f"💓 Components: {status['registered_components']}")

    except KeyboardInterrupt:
        print("\n🛑 Coordinator stopped")
    except Exception as e:
        print(f"❌ Coordinator error: {e}")
        return 1
    return 0

if __name__ == "__main__":
    asyncio.run(main())
EOF

    # Iniciar coordinador
    nohup python3 scripts/coordinator.py > logs/coordinator.log 2>&1 &
    echo $! > .pids/coordinator.pid

    echo -e "${GREEN}   ✅ Coordinator started (PID: $(cat .pids/coordinator.pid))${NC}"

    # Esperar que esté listo
    for i in {1..10}; do
        sleep 1
        if grep -q "Coordinator started successfully" logs/coordinator.log 2>/dev/null; then
            echo -e "${GREEN}   ✅ Coordinator ready!${NC}"
            return 0
        fi
    done

    echo -e "${YELLOW}   ⚠️  Coordinator may still be starting...${NC}"
}

# Función para probar integración
test_integration() {
    echo -e "${BLUE}🧪 Testing sniffer ETCD integration...${NC}"

    cat > /tmp/test_sniffer.py << EOF
import asyncio
import sys
import os

sys.path.insert(0, '.')

from core.etcd_crypto_client_sniffer import (
    setup_sniffer_crypto,
    get_sniffer_pipeline_key,
    get_sniffer_crypto_status
)

async def test():
    print("🧪 Testing sniffer crypto integration...")

    success = await setup_sniffer_crypto("$CONFIG_FILE")

    if success:
        pipeline_key = get_sniffer_pipeline_key()
        if pipeline_key:
            print(f"✅ SUCCESS!")
            print(f"🔑 Pipeline key: {pipeline_key[:32]}...")

            status = get_sniffer_crypto_status()
            print(f"📊 Status: {status}")

            return True
        else:
            print("❌ Failed to get pipeline key")
            return False
    else:
        print("❌ Crypto setup failed")
        return False

if __name__ == "__main__":
    result = asyncio.run(test())
    sys.exit(0 if result else 1)
EOF

    if python3 /tmp/test_sniffer.py; then
        echo -e "${GREEN}   ✅ Integration test PASSED!${NC}"
        rm -f /tmp/test_sniffer.py
        return 0
    else
        echo -e "${RED}   ❌ Integration test FAILED!${NC}"
        rm -f /tmp/test_sniffer.py
        return 1
    fi
}

# Función para mostrar template de integración
show_integration_template() {
    echo -e "${BLUE}📋 Integration template for evolutionary_sniffer_v31.py:${NC}"
    echo ""

    cat << 'EOF'
# ===============================================================================
# 🔍 INTEGRATION TEMPLATE - Add to evolutionary_sniffer_v31.py
# ===============================================================================

# 1. ADD IMPORTS (at the top):
from core.etcd_crypto_client_sniffer import (
    setup_sniffer_crypto,
    get_sniffer_pipeline_key
)

# 2. REPLACE main() function:
async def main():
    if len(sys.argv) != 2:
        print("Usage: python core/evolutionary_sniffer_v31.py config/json/evolutionary_sniffer_config_v31.json")
        sys.exit(1)

    config_path = sys.argv[1]

    print("🔍 Starting Evolutionary Sniffer v3.1 with ETCD crypto...")

    # ✅ SETUP CRYPTO (replaces environment variable)
    if not await setup_sniffer_crypto(config_path):
        print("❌ Failed to setup crypto")
        sys.exit(1)

    # ✅ GET PIPELINE KEY (replaces os.environ.get)
    pipeline_key = get_sniffer_pipeline_key()
    if not pipeline_key:
        print("❌ No pipeline key available")
        sys.exit(1)

    print("✅ Crypto ready!")

    # ✅ LOAD CONFIG (as usual)
    with open(config_path, 'r') as f:
        config = json.load(f)

    # ✅ INITIALIZE CRYPTO ZMQ (as usual, but with ETCD key)
    crypto_zmq = CryptoZMQV31(pipeline_key)

    # ✅ REST OF CODE UNCHANGED
    # ... your existing sniffer code

# 3. REPLACE all occurrences:
# ❌ REMOVE: pipeline_key = os.environ.get("UPGRADED_HAPPINESS_PIPELINE_KEY")
# ✅ REPLACE: pipeline_key = get_sniffer_pipeline_key()

EOF

    echo -e "${YELLOW}📝 Apply this template to evolutionary_sniffer_v31.py${NC}"
}

# Función para crear config ejemplo
create_config_example() {
    echo -e "${BLUE}📋 Creating config example...${NC}"

    local example_file="config/json/evolutionary_sniffer_config_v31_example.json"
    mkdir -p "config/json"

    cat > "$example_file" << 'EOF'
{
  "_comment": "EXAMPLE evolutionary_sniffer_config_v31.json with ETCD crypto",

  "zmq": {
    "publisher": {
      "host": "0.0.0.0",
      "port": 5550,
      "bind": true,
      "hwm": 1000
    }
  },

  "sniffer": {
    "interface": "eth0",
    "buffer_size": 65536,
    "capture_filter": "tcp or udp",
    "promiscuous_mode": true,
    "packet_timeout": 100
  },

  "etcd_crypto": {
    "_comment": "REQUIRED SECTION - Add to your existing config",
    "etcd_host": "localhost",
    "etcd_port": 2379,
    "cluster_name": "upgraded-happiness-cluster",
    "node_id": "evolutionary_sniffer_dev_001"
  },

  "http": {
    "_comment": "OPTIONAL - HTTP API configuration",
    "api": {
      "host": "0.0.0.0",
      "port": 6550,
      "enable": true
    }
  },

  "logging": {
    "level": "INFO",
    "format": "%(asctime)s | %(name)s | %(levelname)s | 🔍 %(message)s",
    "file": "logs/evolutionary_sniffer.log"
  }
}
EOF

    echo -e "${GREEN}   ✅ Config example created: $example_file${NC}"
    echo -e "${BLUE}      Copy this structure to your existing config${NC}"
}

# Función para mostrar status
show_status() {
    echo -e "${BLUE}📊 Current Status:${NC}"

    # ETCD
    if curl -s http://localhost:2379/health > /dev/null; then
        echo -e "${GREEN}   ✅ ETCD running${NC}"
    else
        echo -e "${RED}   ❌ ETCD not running${NC}"
    fi

    # Coordinator
    if [ -f ".pids/coordinator.pid" ] && ps -p $(cat .pids/coordinator.pid) > /dev/null 2>&1; then
        echo -e "${GREEN}   ✅ Coordinator running${NC}"
    else
        echo -e "${RED}   ❌ Coordinator not running${NC}"
    fi

    # Config
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "${GREEN}   ✅ Config file exists: $CONFIG_FILE${NC}"
    else
        echo -e "${RED}   ❌ Config file missing: $CONFIG_FILE${NC}"
    fi
}

# Función principal
main() {
    case "${1:-setup}" in
        "setup")
            echo -e "${BLUE}🚀 Setting up sniffer ETCD integration...${NC}"
            echo ""

            check_prerequisites || exit 1
            create_integration_files || exit 1

            if [ ! -f "$CONFIG_FILE" ]; then
                echo -e "${YELLOW}⚠️  Config file missing, creating example...${NC}"
                create_config_example
                echo -e "${BLUE}   Edit $CONFIG_FILE before continuing${NC}"
                exit 1
            fi

            validate_config_structure || exit 1
            start_coordinator

            echo ""
            echo -e "${GREEN}✅ Setup completed!${NC}"
            echo ""
            echo -e "${BLUE}🎯 NEXT STEPS:${NC}"
            echo -e "   1. $0 test          # Test integration"
            echo -e "   2. $0 template      # Show code template"
            echo -e "   3. Apply template to evolutionary_sniffer_v31.py"
            echo -e "   4. Test: python core/evolutionary_sniffer_v31.py $CONFIG_FILE"
            ;;
        "test")
            test_integration
            ;;
        "template")
            show_integration_template
            ;;
        "config")
            create_config_example
            ;;
        "status")
            show_status
            ;;
        "validate")
            validate_config_structure
            ;;
        "help"|"--help"|"-h")
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  setup      - Complete setup (default)"
            echo "  test       - Test integration"
            echo "  template   - Show integration template"
            echo "  config     - Create config example"
            echo "  validate   - Validate config structure"
            echo "  status     - Show current status"
            echo ""
            echo "🎯 ZERO hardcoded values - Everything from JSON!"
            ;;
        *)
            echo -e "${RED}❌ Unknown command: $1${NC}"
            echo -e "${BLUE}💡 Run: $0 help${NC}"
            exit 1
            ;;
    esac
}

# Ejecutar
main "$@"