#!/bin/bash

echo "🕵️ DETECTIVE WORK - Rastreando Scripts de Generación de Datos"
echo "=================================================================="

echo ""
echo "🔍 PASO 1: Buscar datasets generados"
echo "-----------------------------------"
echo "Buscando CSVs de tráfico web y interno..."
find . -name "*.csv" | grep -E "(web|internal|normal|traffic)" || echo "No encontrados en ubicación actual"

echo ""
echo "¿Existe directorio data/specialized/?"
ls -la data/specialized/ 2>/dev/null || echo "Directorio data/specialized/ no encontrado"

echo ""
echo "🌐 PASO 2: Cazando el ÉPICO Web Crawler"
echo "--------------------------------------"
echo "Buscando traffic_generator.py..."
if [ -f "traffic_generator.py" ]; then
    echo "✅ ENCONTRADO: traffic_generator.py"
    echo "📋 Primeras líneas:"
    head -20 traffic_generator.py
    echo ""
    echo "🔍 Buscando palabras clave del crawler..."
    grep -i "countries\|websites\|millions\|crawler\|url\|http\|requests" traffic_generator.py | head -10
else
    echo "❌ traffic_generator.py no encontrado"
fi

echo ""
echo "🏢 PASO 3: Buscando Sniffer de Tráfico Interno"
echo "---------------------------------------------"
echo "Candidatos para captura de tráfico interno:"
ls -la *sniffer*.py *agent*.py 2>/dev/null || echo "No se encontraron sniffers"

echo ""
echo "🔍 Buscando referencias a tráfico local/interno..."
grep -r -l -i "localhost\|127.0.0.1\|internal\|private\|laptop" *.py 2>/dev/null | head -5

echo ""
echo "📊 PASO 4: Verificar create_specialized_datasets.py"
echo "------------------------------------------------"
if [ -f "create_specialized_datasets.py" ]; then
    echo "✅ ENCONTRADO: create_specialized_datasets.py"
    echo "🔍 Buscando rutas de datasets..."
    grep -i "web_normal\|internal_normal\|csv\|output" create_specialized_datasets.py | head -10
else
    echo "❌ create_specialized_datasets.py no encontrado"
fi

echo ""
echo "🎯 RESUMEN DE LA INVESTIGACIÓN:"
echo "================================"
echo "Modelos conocidos:"
echo "- rf_production_sniffer_compatible.joblib → sniffer_compatible_retrainer.py"
echo "- web_normal_detector.joblib → train_specialized_models.py"
echo "- internal_normal_detector.joblib → train_specialized_models.py"
echo ""
echo "Próximo paso: Identificar scripts de generación de datos raw"