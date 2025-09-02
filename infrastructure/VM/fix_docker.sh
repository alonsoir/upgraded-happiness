#!/bin/bash
# fix_docker.sh
set -euo pipefail

VM_USER="idsadmin"
SSH_KEY="$HOME/.ssh/id_ed25519_vm"

echo "🔧 Arreglando instalación de Docker en VM..."

ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no "$VM_USER@127.0.0.1" <<'EOF'
set -e

echo "🗑️ Limpiando configuración incorrecta de Docker..."
sudo rm -f /etc/apt/sources.list.d/docker.list
sudo apt-get clean
sudo apt-get update

echo "🐳 Instalando Docker correctamente..."
# Descargar e instalar script oficial de Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

echo "👤 Añadiendo usuario al grupo docker..."
sudo usermod -aG docker $USER

echo "🚀 Iniciando servicio Docker..."
sudo systemctl enable docker
sudo systemctl start docker

echo "🔍 Verificando instalación..."
sudo docker --version
sudo docker info | head -5

echo "✅ Docker instalado correctamente!"

echo "📋 Verificando docker-compose..."
if ! command -v docker-compose &> /dev/null; then
    echo "📦 Instalando docker-compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

docker-compose --version || docker compose version

echo "🎯 Todo listo para usar Docker!"
EOF

echo "✅ Docker arreglado. Ahora puedes conectarte y usar el pipeline!"
echo
echo "🔗 Para conectar:"
echo "ssh -i $SSH_KEY -p 2222 $VM_USER@127.0.0.1"
echo
echo "🚀 Para iniciar el pipeline (dentro de la VM):"
echo "./start_pipeline.sh"