#!/bin/bash
# infrastructure/VM/run_vm.sh
# ===============================
# Configuración de la VM
# ===============================
VM_NAME="ubuntu-ids-lab"
ISO_PATH="$HOME/Downloads/ubuntu-24.04.3-live-server-amd64.iso"
VM_RAM=20480           # 20 GB
VM_VCPUS=7             # hilos asignados
VM_HDD=100000          # 100 GB
VM_NET="en0"           # adaptador físico para bridged (ajusta según tu Mac)
SSH_PORT=2222          # puerto de redirección SSH desde host si usas NAT

if VBoxManage list vms | grep -q "$VM_NAME"; then
    echo "⚠️ La VM $VM_NAME ya existe. Arrancando..."
    VBoxManage startvm "$VM_NAME"
    exit 0
fi


# ===============================
# Crear la VM
# ===============================
VBoxManage createvm --name "$VM_NAME" --ostype Ubuntu_64 --register

# Asignar memoria y CPU
VBoxManage modifyvm "$VM_NAME" --cpus $VM_VCPUS --memory $VM_RAM --vram 16 --ioapic on

VBoxManage modifyvm "$VM_NAME" --nic2 nat
VBoxManage modifyvm "$VM_NAME" --natpf2 "ssh,tcp,,$SSH_PORT,,22"

# Configurar red en modo puente
VBoxManage modifyvm "$VM_NAME" --nic1 bridged --bridgeadapter1 "$VM_NET" --cableconnected1 on --nictype1 82540EM
VBoxManage modifyvm "$VM_NAME" --nictype1 82540EM --promisc1 allow-all

# Crear disco duro
VBoxManage createmedium disk --filename "$HOME/VirtualBox VMs/$VM_NAME/$VM_NAME.vdi" --size $VM_HDD --format VDI

# Adjuntar disco y ISO
VBoxManage storagectl "$VM_NAME" --name "SATA Controller" --add sata --controller IntelAhci
VBoxManage storageattach "$VM_NAME" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$HOME/VirtualBox VMs/$VM_NAME/$VM_NAME.vdi"
VBoxManage storageattach "$VM_NAME" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "$ISO_PATH"

# Arrancar VM (interactivo para instalar Ubuntu)
VBoxManage startvm "$VM_NAME"
