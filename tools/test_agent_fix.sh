#!/bin/bash
# 🧪 Test Firewall Agent V3.1 Fix
# Verifica que el agent lea configuración JSON correctamente

echo "🧪 TESTING FIREWALL AGENT V3.1 FIX..."
echo "======================================"

# Verificar archivos necesarios
if [ ! -f "core/simple_firewall_agent_v31.py" ]; then
    echo "❌ ERROR: core/simple_firewall_agent_v31.py no encontrado"
    exit 1
fi

if [ ! -f "config/json/simple_firewall_agent_v31_config.json" ]; then
    echo "❌ ERROR: config/json/simple_firewall_agent_v31_config.json no encontrado"
    exit 1
fi

# Verificar key de ambiente
if [ -z "$UPGRADED_HAPPINESS_PIPELINE_KEY" ]; then
    echo "⚠️  WARNING: UPGRADED_HAPPINESS_PIPELINE_KEY no configurada"
    echo "🔧 Configurando key por defecto..."
    export UPGRADED_HAPPINESS_PIPELINE_KEY=kAOehVZk47zSYEzLMDJkhXJZqNoLwK8/rwga0Z7In8I=
fi

echo "✅ Key configurada: ${UPGRADED_HAPPINESS_PIPELINE_KEY:0:20}..."

# Test 1: Verificar importación protobuf
echo ""
echo "🔍 Test 1: Verificando importación protobuf V3.1..."
python3 -c "
import sys, os
sys.path.insert(0, 'protocols/v3.1')
try:
    import firewall_commands_v31_pb2
    print('✅ firewall_commands_v31_pb2 importado correctamente')

    # Verificar campos V3.1
    cmd = firewall_commands_v31_pb2.FirewallCommand()
    if hasattr(cmd, 'node_id') and hasattr(cmd, 'timestamp'):
        print('✅ Campos V3.1 (node_id, timestamp) verificados')
    else:
        print('❌ Campos V3.1 faltantes')
        sys.exit(1)

except ImportError as e:
    print(f'❌ Error importando protobuf V3.1: {e}')
    sys.exit(1)
"

if [ $? -ne 0 ]; then
    echo "❌ Test 1 FAILED: Protobuf V3.1 no disponible"
    exit 1
fi

echo "✅ Test 1 PASSED: Protobuf V3.1 disponible"

# Test 2: Verificar configuración de puertos
echo ""
echo "🔍 Test 2: Verificando compatibilidad de puertos..."
python tools/check_ports_firewall_agent_scheduler_firewall.py \
    config/json/scheduler_firewall_config.json \
    config/json/simple_firewall_agent_v31_config.json

if [ $? -ne 0 ]; then
    echo "❌ Test 2 FAILED: Configuración de puertos incompatible"
    exit 1
fi

echo "✅ Test 2 PASSED: Puertos compatibles"

# Test 3: Verificar que agent lea configuración
echo ""
echo "🔍 Test 3: Verificando lectura de configuración JSON..."
timeout 10s python core/simple_firewall_agent_v31.py \
    config/json/simple_firewall_agent_v31_config.json \
    config/json/firewall_rules_v31.json > /tmp/agent_test.log 2>&1 &

AGENT_PID=$!
sleep 3

# Verificar si agent está leyendo puerto correcto
if grep -q "tcp://localhost:5582" /tmp/agent_test.log; then
    echo "✅ Agent lee puerto 5582 desde configuración JSON"
    TEST3_RESULT="PASSED"
else
    echo "❌ Agent no lee puerto correcto desde JSON"
    echo "📋 Log del agent:"
    cat /tmp/agent_test.log
    TEST3_RESULT="FAILED"
fi

# Matar proceso del agent
kill $AGENT_PID 2>/dev/null
wait $AGENT_PID 2>/dev/null

if [ "$TEST3_RESULT" = "FAILED" ]; then
    echo "❌ Test 3 FAILED: Agent no lee configuración correctamente"
    echo ""
    echo "🔧 POSIBLES CAUSAS:"
    echo "   • Código no actualizado con la versión corregida"
    echo "   • Error en _setup_sockets() method"
    echo "   • Configuración JSON mal formateada"
    exit 1
fi

echo "✅ Test 3 PASSED: Agent lee configuración JSON correctamente"

# Test 4: Verificar crypto (opcional)
echo ""
echo "🔍 Test 4: Verificando crypto V31 (opcional)..."
if grep -q "CryptoZMQV31 disponible" /tmp/agent_test.log; then
    echo "✅ Crypto V31 disponible"
elif grep -q "CryptoZMQV31 NO disponible" /tmp/agent_test.log; then
    echo "⚠️  Crypto V31 no disponible (OK, es opcional)"
else
    echo "❌ No se pudo verificar estado de crypto"
fi

# Cleanup
rm -f /tmp/agent_test.log

echo ""
echo "🎉 TODOS LOS TESTS PASADOS!"
echo "======================================"
echo "✅ Protobuf V3.1: Disponible y funcional"
echo "✅ Puertos: Compatibles con scheduler"
echo "✅ Config JSON: Leída correctamente"
echo "✅ Agent: Listo para conexión"
echo ""
echo "🚀 PRÓXIMO PASO:"
echo "   Iniciar scheduler y agent en terminales separados:"
echo ""
echo "   Terminal 1:"
echo "   python core/scheduler-firewall.py config/json/scheduler_firewall_config.json config/json/firewall_rules_v31.json"
echo ""
echo "   Terminal 2:"
echo "   export UPGRADED_HAPPINESS_PIPELINE_KEY=kAOehVZk47zSYEzLMDJkhXJZqNoLwK8/rwga0Z7In8I="
echo "   python core/simple_firewall_agent_v31.py config/json/simple_firewall_agent_v31_config.json config/json/firewall_rules_v31.json"