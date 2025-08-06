#!/bin/bash
# Script para arreglar el archivo ASN GeoIP
# Busca y renombra archivos ASN al nombre esperado

echo "🔧 Arreglando archivo ASN GeoIP..."
echo "=================================="

# Crear directorio geodata si no existe
mkdir -p geodata

cd geodata

# Verificar si ya existe el archivo correcto
if [ -f "GeoLite2-ASN-Test.mmdb" ]; then
    echo "✅ GeoLite2-ASN-Test.mmdb ya existe"
    ls -la GeoLite2-ASN-Test.mmdb
    exit 0
fi

# Buscar archivos ASN alternativos
asn_files=(
    "GeoLite2-ASN.mmdb"
    "GeoLite2-ASN-*.mmdb"
    "../GeoLite2-ASN.mmdb"
    "../GeoLite2-ASN-*.mmdb"
)

found_file=""

echo "🔍 Buscando archivos ASN..."

for pattern in "${asn_files[@]}"; do
    for file in $pattern; do
        if [ -f "$file" ] && [ "$file" != "GeoLite2-ASN-Test.mmdb" ]; then
            echo "📁 Encontrado: $file"
            found_file="$file"
            break 2
        fi
    done
done

if [ -n "$found_file" ]; then
    echo "🔄 Renombrando $found_file a GeoLite2-ASN-Test.mmdb..."

    # Si el archivo está en el directorio padre, moverlo
    if [[ "$found_file" == ../* ]]; then
        cp "$found_file" "GeoLite2-ASN-Test.mmdb"
        echo "📋 Copiado desde directorio padre"
    else
        mv "$found_file" "GeoLite2-ASN-Test.mmdb"
        echo "📝 Renombrado en directorio actual"
    fi

    echo "✅ Archivo ASN configurado correctamente"
    ls -la GeoLite2-ASN-Test.mmdb
else
    echo "❌ No se encontró ningún archivo ASN"
    echo ""
    echo "💡 Soluciones:"
    echo "   1. Descargar desde MaxMind:"
    echo "      https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    echo "   2. Registrarse para obtener licencia gratuita"
    echo "   3. Descargar GeoLite2 ASN en formato MMDB"
    echo "   4. Colocar el archivo en geodata/GeoLite2-ASN-Test.mmdb"
    echo ""
    echo "🔍 Archivos actuales en geodata/:"
    ls -la .
    exit 1
fi

echo ""
echo "🎉 ¡Archivo ASN configurado correctamente!"
echo "🚀 Ahora puedes ejecutar: sudo ./start_capture.sh"