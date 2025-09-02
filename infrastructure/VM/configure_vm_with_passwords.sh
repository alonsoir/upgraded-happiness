#!/bin/bash
# infrastructure/VM/configure_vm_with_passwords.sh
set -euo pipefail

VM_USER="aironman"
VM_PASSWORD="aironman"
SSH_KEY="$HOME/.ssh/id_ed25519_vm"

echo "Configurando VM con manejo automático de contraseñas..."

# Configurar sudoers para no requerir contraseña temporalmente
ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no "$VM_USER@127.0.0.1" <<EOF
echo '$VM_PASSWORD' | sudo -S bash -c 'echo "$VM_USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/$VM_USER'
EOF

echo "Instalando software..."
ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no "$VM_USER@127.0.0.1" <<'EOF'
# Actualizar sistema
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

# Crear directorio projects
mkdir -p /home/$USER/projects
EOF

echo "Configurando proyecto..."
ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no "$VM_USER@127.0.0.1" <<'EOF'
cd /home/$USER/projects

if [ -d "upgraded-happiness" ]; then
    cd upgraded-happiness
    git pull
else
    git clone https://github.com/alonsoir/upgraded-happiness.git
    cd upgraded-happiness
fi

git checkout feature/docker-k8s

echo "Espacio disponible:"
df -h

echo "Configuración completada. Reiniciando para aplicar cambios..."
EOF

# Reiniciar VM
ssh -i "$SSH_KEY" -p 2222 "$VM_USER@127.0.0.1" "sudo reboot"

echo "VM reiniciándose. Espera 30 segundos y conecta con:"
echo "ssh -i $SSH_KEY -p 2222 $VM_USER@127.0.0.1"