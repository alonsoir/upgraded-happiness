#!/bin/bash
# scripts/start-etcd-basic.sh
# Script básico para levantar etcd en modo desarrollo
# Versión optimizada para integración con Makefile

set -e

ETCD_DATA_DIR="data/etcd"
ETCD_LOG_FILE="logs/etcd.log"
ETCD_PID_FILE=".pids/etcd.pid"
ETCD_CONFIG_FILE="config/etcd/etcd-basic-config.yaml"

echo "🚀 Iniciando etcd básico para desarrollo..."

# Crear directorios necesarios
mkdir -p data/etcd logs .pids

# Verificar si etcd está instalado
if ! command -v etcd &> /dev/null; then
    echo "❌ etcd no está instalado"
    echo "💡 Instalar con:"
    echo "   # macOS: brew install etcd"
    echo "   # Linux: apt-get install etcd-server"
    echo "   # o descargar desde: https://github.com/etcd-io/etcd/releases"
    exit 1
fi

# Verificar si ya está corriendo
if [ -f "$ETCD_PID_FILE" ] && ps -p $(cat $ETCD_PID_FILE) > /dev/null 2>&1; then
    echo "✅ etcd ya está corriendo (PID: $(cat $ETCD_PID_FILE))"
    exit 0
fi

# Limpiar archivos antiguos
rm -f $ETCD_PID_FILE

# Verificar archivo de configuración
if [ ! -f "$ETCD_CONFIG_FILE" ]; then
    echo "❌ Archivo de configuración no encontrado: $ETCD_CONFIG_FILE"
    echo "💡 Ejecuta: make dist-setup"
    exit 1
fi

echo "🔧 Configuración:"
echo "   - Config: $ETCD_CONFIG_FILE"
echo "   - Cliente: http://localhost:2379"
echo "   - Peer: http://localhost:2380"
echo "   - Data dir: $ETCD_DATA_DIR"
echo "   - Log: $ETCD_LOG_FILE"

# Limpiar datos anteriores si existen
if [ -d "$ETCD_DATA_DIR" ]; then
    echo "🧹 Limpiando datos anteriores..."
    rm -rf $ETCD_DATA_DIR/*
fi

# Iniciar etcd con configuración básica (en background para Makefile)
echo "🎯 Iniciando etcd..."
nohup etcd --config-file $ETCD_CONFIG_FILE > $ETCD_LOG_FILE 2>&1 &
ETCD_PID=$!

# Guardar PID
echo $ETCD_PID > $ETCD_PID_FILE
echo "📊 etcd iniciado con PID: $ETCD_PID"

# Esperar a que etcd esté listo
echo "⏳ Esperando que etcd esté listo..."
for i in {1..15}; do
    if curl -s http://localhost:2379/health > /dev/null; then
        echo "✅ etcd está funcionando correctamente"
        echo "🌐 Cliente disponible en: http://localhost:2379"
        echo "📋 Log disponible en: $ETCD_LOG_FILE"
        echo "🔍 PID guardado en: $ETCD_PID_FILE"
        echo ""
        echo "🔍 Comandos útiles:"
        echo "   etcdctl --endpoints=localhost:2379 member list"
        echo "   etcdctl --endpoints=localhost:2379 endpoint health"
        echo ""
        echo "🛑 Para detener: make dist-stop"
        exit 0
    fi
    echo "   Intento $i/15... esperando..."
    sleep 2
done

# Si llegamos aquí, etcd no arrancó correctamente
echo "❌ etcd no responde correctamente después de 30 segundos"
echo "📋 Verificar logs en: $ETCD_LOG_FILE"
if [ -f "$ETCD_PID_FILE" ]; then
    kill $(cat $ETCD_PID_FILE) 2>/dev/null || true
    rm -f $ETCD_PID_FILE
fi
exit 1