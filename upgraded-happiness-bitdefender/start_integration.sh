#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
echo "🚀 Iniciando BitDefender Integration..."
python3 bitdefender_integration.py --config bitdefender_config.yaml
