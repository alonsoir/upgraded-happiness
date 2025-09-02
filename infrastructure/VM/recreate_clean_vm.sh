#!/bin/bash
# infrastructure/VM/recreate_clean_vm.sh
set -euo pipefail

VM_NAME="ubuntu-infra"
ISO_PATH="$HOME/Downloads/ubuntu-24.04.3-live-server-amd64.iso"

echo "Recreando VM limpia para instalación..."

# Eliminar VM actual completamente
VBoxManage controlvm "$VM_NAME" poweroff || true
sleep 5
VBoxManage unregistervm "$VM_NAME" --delete || true

echo "Creando VM nueva y limpia..."

# Crear VM con configuración optimizada
VBoxManage createvm --name "$VM_NAME" --ostype Ubuntu_64 --register

# Configuración de hardware
VBoxManage modifyvm "$VM_NAME" \
    --memory 4096 \
    --cpus 2 \
    --vram 16 \
    --nic1 nat \
    --natpf1 "ssh,tcp,,2222,,22" \
    --natpf1 "http,tcp,,8080,,80" \
    --natpf1 "https,tcp,,8443,,443" \
    --natpf1 "k3s,tcp,,6443,,6443" \
    --rtcuseutc on \
    --boot1 dvd \
    --boot2 disk \
    --boot3 none \
    --boot4 none

# Crear disco duro
VBoxManage createhd --filename "$HOME/VirtualBox VMs/$VM_NAME/$VM_NAME.vdi" --size 30000 --format VDI

# Configurar controlador SATA
VBoxManage storagectl "$VM_NAME" --name "SATA" --add sata --controller IntelAhci

# Adjuntar disco duro
VBoxManage storageattach "$VM_NAME" \
    --storagectl "SATA" \
    --port 0 \
    --device 0 \
    --type hdd \
    --medium "$HOME/VirtualBox VMs/$VM_NAME/$VM_NAME.vdi"

# Adjuntar ISO de instalación
VBoxManage storageattach "$VM_NAME" \
    --storagectl "SATA" \
    --port 1 \
    --device 0 \
    --type dvddrive \
    --medium "$ISO_PATH"

echo "Iniciando VM para instalación..."
VBoxManage startvm "$VM_NAME"

echo ""
echo "INSTALACIÓN MANUAL - PASOS SIMPLIFICADOS:"
echo "=========================================="
echo ""
echo "1. Selecciona idioma e instalar Ubuntu Server"
echo "2. Red: Usar DHCP automático"
echo "3. Disco: Usar disco completo, NO LVM"
echo "4. Usuario: aironman / Contraseña: aironman"
echo "5. SSH: SÍ instalar OpenSSH server"
echo "6. Snaps: Saltar todos"
echo "7. Esperar instalación completa"
echo "8. IMPORTANTE: Cuando pida reiniciar, presiona ENTER y espera"
echo ""
echo "Una vez completado, la VM se reiniciará automáticamente."
echo "Después ejecuta: ./configure_installed_vm.sh"