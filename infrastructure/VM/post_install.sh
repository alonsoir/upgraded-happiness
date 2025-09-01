#!/bin/bash
# infrastructure/VM/post_install.sh
# Actualizar sistema
sudo apt-get update && sudo apt-get upgrade -y

# Instalar SSH server (si no está)
sudo apt-get install -y openssh-server

# Instalar Git
sudo apt-get install -y git

sudo apt-get install -y htop

# Instalar Docker CE
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker <<EONG
docker run hello-world
EONG

# Instalar docker-compose plugin
sudo apt-get install -y docker-compose-plugin

# Instalar k3s
curl -sfL https://get.k3s.io | sh -

# Optimización para sniffer (opcional)
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
sudo sysctl -w net.core.rmem_default=26214400
sudo sysctl -w net.core.wmem_default=26214400

