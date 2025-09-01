#!/bin/bash
# infrastructure/VM/run_vm_auto.sh

VM_NAME="ubuntu-ids-lab"
ISO_PATH="$HOME/Downloads/ubuntu-24.04.3-live-server-amd64.iso"
VM_RAM=20480           # 20 GB
VM_VCPUS=7             # hilos asignados
VM_HDD=100000          # 100 GB
VM_NET="en0"           # adaptador físico para bridged
SSH_PORT=2222           # redirección SSH desde host (NAT)

# ===============================
# Crear VM si no existe
# ===============================
if VBoxManage list vms | grep -q "$VM_NAME"; then
    echo "⚠️ La VM $VM_NAME ya existe. Arrancando..."
    VBoxManage startvm "$VM_NAME" --type headless
else
    echo "Creando VM $VM_NAME..."
    VBoxManage createvm --name "$VM_NAME" --ostype Ubuntu_64 --register
    VBoxManage modifyvm "$VM_NAME" --cpus $VM_VCPUS --memory $VM_RAM --vram 16 --ioapic on

    # Red bridged + NAT con port-forward SSH
    VBoxManage modifyvm "$VM_NAME" --nic1 bridged --bridgeadapter1 "$VM_NET" --cableconnected1 on --nictype1 82540EM --promisc1 allow-all
    VBoxManage modifyvm "$VM_NAME" --nic2 nat
    VBoxManage modifyvm "$VM_NAME" --natpf2 "ssh,tcp,,$SSH_PORT,,22"

    # Disco duro
    VBoxManage createmedium disk --filename "$HOME/VirtualBox VMs/$VM_NAME/$VM_NAME.vdi" --size $VM_HDD --format VDI
    VBoxManage storagectl "$VM_NAME" --name "SATA Controller" --add sata --controller IntelAhci
    VBoxManage storageattach "$VM_NAME" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$HOME/VirtualBox VMs/$VM_NAME/$VM_NAME.vdi"
    VBoxManage storageattach "$VM_NAME" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "$ISO_PATH"

    # Arrancar VM headless para instalación interactiva
    VBoxManage startvm "$VM_NAME" --type headless
    echo "💡 Instala Ubuntu Server manualmente vía VNC/VRDP o monitor físico virtual."
    echo "Después, reejecuta este script para la post-instalación automática."
    exit 0
fi

# ===============================
# Post-instalación automática via SSH
# ===============================
echo "Esperando que Ubuntu esté accesible por SSH en el puerto $SSH_PORT..."
sleep 15  # ajustar si tarda más en boot

# Intentar SSH y ejecutar comandos de post-instalación
ssh -o StrictHostKeyChecking=no -p $SSH_PORT ubuntu@127.0.0.1 <<'ENDSSH'
# Actualizar sistema
sudo apt-get update && sudo apt-get upgrade -y

# SSH server (ya debería estar, pero por si acaso)
sudo apt-get install -y openssh-server

# Git y utilidades
sudo apt-get install -y git htop curl

# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Docker Compose plugin
sudo apt-get install -y docker-compose-plugin

# k3s
curl -sfL https://get.k3s.io | sh -

# Optimización para sniffer
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
sudo sysctl -w net.core.rmem_default=26214400
sudo sysctl -w net.core.wmem_default=26214400
ENDSSH

echo "✅ Post-instalación completada. Conecta por SSH: ssh -p $SSH_PORT ubuntu@127.0.0.1"
