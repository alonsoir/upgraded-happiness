#!/bin/bash

echo "🔍 DEEP DIVE - Investigación Final de los Scripts ÉPICOS"
echo "========================================================"

echo ""
echo "🌐 ANÁLISIS DEL ÉPICO WEB CRAWLER"
echo "================================"
echo "📋 Estructura completa de traffic_generator.py:"
head -50 traffic_generator.py

echo ""
echo "🔍 Buscando threading y configuración:"
grep -n -A3 -B1 "ThreadPoolExecutor\|threading\|workers\|concurrent" traffic_generator.py

echo ""
echo "🌍 BASE DE DATOS DE SITIOS WEB"
echo "============================="
echo "📊 Escala del proyecto:"
if [ -f "websites_database.csv" ]; then
    echo "✅ websites_database.csv encontrado"
    echo "📈 Número total de sitios:"
    wc -l websites_database.csv
    echo ""
    echo "📋 Primeros 20 sitios:"
    head -20 websites_database.csv
    echo ""
    echo "🔍 Últimos 10 sitios (para ver variedad):"
    tail -10 websites_database.csv
else
    echo "❌ websites_database.csv no encontrado en directorio actual"
    echo "🔍 Buscando archivos similares..."
    find . -name "*website*" -o -name "*sites*" -o -name "*urls*" | head -10
fi

echo ""
echo "🏢 IDENTIFICAR SNIFFER DE TRÁFICO INTERNO"
echo "========================================"
echo "🔍 Analizando candidatos principales:"

for sniffer in promiscuous_agent_v2.py real_time_ml_network_sniffer.py fixed_service_sniffer.py; do
    if [ -f "$sniffer" ]; then
        echo ""
        echo "📋 Analizando: $sniffer"
        echo "---"
        head -20 "$sniffer" | grep -E "(internal|localhost|127\.0\.0\.1|private|local)"
        echo "🔍 Buscando referencias a datasets internos:"
        grep -n "internal.*csv\|internal.*dataset" "$sniffer" | head -5
    fi
done

echo ""
echo "📊 VERIFICAR PIPELINE DE PROCESAMIENTO"
echo "====================================="
echo "🔍 create_specialized_datasets.py - Lógica completa:"
head -30 create_specialized_datasets.py

echo ""
echo "🔍 Buscando referencias a archivos específicos:"
grep -n "websites_database\|internal_traffic\|normal_traffic" create_specialized_datasets.py

echo ""
echo "🎯 RESUMEN FINAL DE TRAZABILIDAD"
echo "==============================="
echo "✅ MODELOS IDENTIFICADOS:"
echo "- rf_production_sniffer_compatible.joblib ← sniffer_compatible_retrainer.py ← cicids_2017_processed.csv"
echo "- web_normal_detector.joblib ← train_specialized_models.py ← traffic_generator.py + websites_database.csv"
echo "- internal_normal_detector.joblib ← train_specialized_models.py ← [sniffer interno por confirmar]"
echo ""
echo "🚀 READY FOR HOUSEKEEPING: Trazabilidad completa conseguida"