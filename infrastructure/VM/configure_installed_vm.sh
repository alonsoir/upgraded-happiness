#!/bin/bash
set -euo pipefail

VM_NAME="ubuntu-infra"
VM_USER="aironman"
SSH_KEY="$HOME/.ssh/id_ed25519_vm"

echo "Configurando VM después de instalación manual..."

# Limpiar claves SSH anteriores
ssh-keygen -R "[127.0.0.1]:2222" 2>/dev/null || true

# Esperar SSH
echo "Esperando SSH..."
while ! nc -zv 127.0.0.1 2222 2>/dev/null; do
    sleep 5
done

echo "Configurando claves SSH..."
# Copiar clave pública
ssh-copy-id -i "$SSH_KEY.pub" -p 2222 "$VM_USER@127.0.0.1" || {
    echo "Instalando clave SSH manualmente..."
    sshpass -p 'aironman' ssh -o StrictHostKeyChecking=no -p 2222 "$VM_USER@127.0.0.1" \
        "mkdir -p ~/.ssh && echo '$(cat "$SSH_KEY.pub")' >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
}

echo "Instalando Docker y dependencias..."
ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no "$VM_USER@127.0.0.1" <<'EOF'
sudo apt update && sudo apt upgrade -y
sudo apt install -y git htop curl

# Instalar Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Instalar k3s
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644

# Instalar docker-compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

echo "Reiniciando para aplicar cambios de grupos..."
EOF

echo "Reiniciando VM..."
ssh -i "$SSH_KEY" -p 2222 "$VM_USER@127.0.0.1" "sudo reboot"

sleep 30

echo "Esperando reconexión..."
while ! nc -zv 127.0.0.1 2222 2>/dev/null; do
    sleep 5
done

echo "Configurando proyecto..."
ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no "$VM_USER@127.0.0.1" <<'EOF'
mkdir -p projects
cd projects

if [ -d "upgraded-happiness" ]; then
    cd upgraded-happiness
    git pull
else
    git clone https://github.com/alonsoir/upgraded-happiness.git
    cd upgraded-happiness
fi

git checkout feature/docker-k8s

# Verificar espacio en disco
df -h

echo "Configuración completada. Ejecutar: ./infrastructure/docker/build_all_images.sh"
EOF

echo "VM configurada correctamente!"
echo "Conectar con: ssh -i $SSH_KEY -p 2222 $VM_USER@127.0.0.1"