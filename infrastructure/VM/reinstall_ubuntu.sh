#!/bin/bash
set -euo pipefail

VM_NAME="ubuntu-infra"
VM_USER="idsadmin"
SSH_KEY="$HOME/.ssh/id_ed25519_vm"
ISO_PATH="$HOME/Downloads/ubuntu-24.04.3-live-server-amd64.iso"

echo "🔄 Reinstalando Ubuntu correctamente en la VM..."

# Parar VM
echo "🛑 Parando VM..."
VBoxManage controlvm "$VM_NAME" poweroff || true
sleep 5

# Reattach ISO para instalación
echo "💿 Configurando para nueva instalación..."
VBoxManage storageattach "$VM_NAME" --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium "$ISO_PATH"

# Cambiar orden de arranque para que arranque desde CD primero
VBoxManage modifyvm "$VM_NAME" --boot1 dvd --boot2 disk --boot3 none --boot4 none

echo "🚀 Iniciando VM para instalación manual..."
VBoxManage startvm "$VM_NAME"

echo ""
echo "🎯 INSTRUCCIONES PARA INSTALACIÓN MANUAL:"
echo "=============================================="
echo ""
echo "1. 📋 En la pantalla de instalación, selecciona:"
echo "   - Language: English"
echo "   - Keyboard: US (o tu configuración)"
echo "   - Network: Use DHCP (automático)"
echo ""
echo "2. 💾 Configuración de disco:"
echo "   - Use entire disk"
echo "   - Set up this disk as an LVM group: NO"
echo "   - Confirmar particionado"
echo ""
echo "3. 👤 Configuración de usuario:"
echo "   - Your name: idsadmin"
echo "   - Your server's name: ubuntu-server"
echo "   - Pick a username: idsadmin"
echo "   - Choose a password: temp123"
echo ""
echo "4. ☑️ SSH Setup:"
echo "   - Install OpenSSH server: YES"
echo "   - Import SSH identity: NO"
echo ""
echo "5. 📦 Featured Server Snaps:"
echo "   - Skip all (no seleccionar ninguno)"
echo ""
echo "6. ⏳ Esperar instalación completa y REINICIAR"
echo ""
echo "7. 🔄 Una vez reiniciada, ejecutar desde macOS:"
echo "   ./configure_installed_vm.sh"
echo ""