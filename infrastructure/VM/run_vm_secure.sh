#!/bin/bash
set -euo pipefail

VM_NAME="ubuntu-infra"
VM_USER="idsadmin"
SSH_KEY="$HOME/.ssh/id_ed25519_vm"
ISO_PATH="$HOME/Downloads/ubuntu-24.04.3-live-server-amd64.iso"

echo "⚠️  Borrando VM existente si la hay..."
VBoxManage controlvm "$VM_NAME" poweroff || true
VBoxManage unregistervm "$VM_NAME" --delete || true

echo "🖥️  Creando nueva VM..."
VBoxManage createvm --name "$VM_NAME" --ostype Ubuntu_64 --register
VBoxManage modifyvm "$VM_NAME" --memory 4096 --cpus 2 --nic1 nat --natpf1 "ssh,tcp,,2222,,22"
VBoxManage createhd --filename "$HOME/VirtualBox VMs/$VM_NAME/$VM_NAME.vdi" --size 20000
VBoxManage storagectl "$VM_NAME" --name "SATA" --add sata --controller IntelAhci
VBoxManage storageattach "$VM_NAME" --storagectl "SATA" --port 0 --device 0 --type hdd --medium "$HOME/VirtualBox VMs/$VM_NAME/$VM_NAME.vdi"
VBoxManage storageattach "$VM_NAME" --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium "$ISO_PATH"

echo "🚀 Iniciando VM para instalación..."
VBoxManage startvm "$VM_NAME"

echo "⏳ Esperando a que SSH esté disponible..."
until nc -zv 127.0.0.1 2222; do sleep 2; done

echo "🔧 Configurando usuario y SSH..."
ssh-keygen -f "$SSH_KEY" -t ed25519 -N "" || true

# Copiar clave pública a la VM usando cloud-init o script de primera conexión
sshpass -p 'ubuntu' ssh -o StrictHostKeyChecking=no -p 2222 ubuntu@127.0.0.1 <<EOF
sudo adduser --disabled-password --gecos "" $VM_USER
sudo mkdir -p /home/$VM_USER/.ssh
sudo bash -c 'echo "$(cat ~/.ssh/id_ed25519_vm.pub)" > /home/$VM_USER/.ssh/authorized_keys'
sudo chown -R $VM_USER:$VM_USER /home/$VM_USER/.ssh
sudo chmod 700 /home/$VM_USER/.ssh
sudo chmod 600 /home/$VM_USER/.ssh/authorized_keys
EOF

echo "🚀 Instalando Docker, k3s y utilidades..."
ssh -i "$SSH_KEY" -p 2222 $VM_USER@127.0.0.1 <<'EOF'
sudo apt update && sudo apt upgrade -y
sudo apt install -y git htop curl
# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# K3s
curl -sfL https://get.k3s.io | sh -
sudo chmod +x /usr/local/bin/kubectl
sudo chown $USER:$USER /etc/rancher/k3s/k3s.yaml
EOF

echo "✅ VM lista. Puedes conectarte con:"
echo "ssh -i $SSH_KEY -p 2222 $VM_USER@127.0.0.1"
