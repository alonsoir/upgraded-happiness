#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
echo "📊 Iniciando solo Dashboard..."
echo "🌐 Dashboard estará disponible en: http://localhost:8765"
python3 bitdefender_integration.py --dashboard-only --config bitdefender_config.yaml
