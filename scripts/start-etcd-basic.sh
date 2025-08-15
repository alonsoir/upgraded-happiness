#!/bin/bash
# scripts/start-etcd-basic.sh
# Script básico para levantar etcd en modo desarrollo

set -e

echo "🚀 Iniciando etcd básico para desarrollo..."

# Crear directorios necesarios
mkdir -p data/etcd logs

# Verificar si etcd está instalado
if ! command -v etcd &> /dev/null; then
    echo "❌ etcd no está instalado"
    echo "💡 Instalar con:"
    echo "   # macOS: brew install etcd"
    echo "   # Linux: apt-get install etcd-server"
    echo "   # o descargar desde: https://github.com/etcd-io/etcd/releases"
    exit 1
fi

# Limpiar datos anteriores si existen
if [ -d "data/etcd" ]; then
    echo "🧹 Limpiando datos anteriores..."
    rm -rf data/etcd/*
fi

echo "🔧 Configuración:"
echo "   - Nombre: etcd-node1"
echo "   - Cliente: http://localhost:2379"
echo "   - Peer: http://localhost:2380"
echo "   - Data dir: ./data/etcd"

# Iniciar etcd con configuración básica
echo "🎯 Iniciando etcd..."
etcd \
  --config-file config/etcd/etcd-basic-config.yaml \
  2>&1 | tee logs/etcd.log &

ETCD_PID=$!
echo "📊 etcd iniciado con PID: $ETCD_PID"

# Esperar a que etcd esté listo
echo "⏳ Esperando que etcd esté listo..."
sleep 3

# Verificar que etcd está funcionando
if curl -s http://localhost:2379/health > /dev/null; then
    echo "✅ etcd está funcionando correctamente"
    echo "🌐 Cliente disponible en: http://localhost:2379"
    echo ""
    echo "🔍 Comandos útiles:"
    echo "   etcdctl --endpoints=localhost:2379 member list"
    echo "   etcdctl --endpoints=localhost:2379 endpoint health"
    echo ""
    echo "🛑 Para detener: kill $ETCD_PID"
else
    echo "❌ etcd no responde correctamente"
    kill $ETCD_PID 2>/dev/null || true
    exit 1
fi

# Mantener el script corriendo
echo "🎯 etcd corriendo... Presiona Ctrl+C para detener"
trap "echo '🛑 Deteniendo etcd...'; kill $ETCD_PID 2>/dev/null || true; exit 0" INT
wait $ETCD_PID