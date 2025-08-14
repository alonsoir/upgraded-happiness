#!/bin/bash

echo "🚨 ARREGLO DE EMERGENCIA para dashboard_v31.js"

# Crear backup del estado actual
cp static/js/dashboard_v31.js static/js/dashboard_v31.js.broken_backup

echo "🔍 Buscando problemas estructurales..."

# Buscar template strings no cerradas desde línea 3965
echo "Template strings abiertas:"
sed -n '3965,$p' static/js/dashboard_v31.js | grep -n '`' | head -5

echo -e "\n🔧 Arreglando línea 3965 específicamente..."

# Solucion 1: Restaurar la línea 3965 a su estado simple
sed -i '' '3965s/.*console\.log.*$/console.log("🚀 V3.1: Compatible con backend dashboard_v31.py");/' static/js/dashboard_v31.js

# Verificar si todavía hay problemas
if ! node -c static/js/dashboard_v31.js; then
    echo "❌ Aún hay errores, necesitamos más diagnóstico"

    # Mostrar más contexto
    echo -e "\n📊 Contexto de líneas problemáticas:"
    sed -n '3960,3975p' static/js/dashboard_v31.js
    echo -e "\n---"
    sed -n '4125,4135p' static/js/dashboard_v31.js
else
    echo "✅ ¡JavaScript arreglado!"
fi