#!/bin/bash
set -euo pipefail

# Configuración
VM_NAME="ubuntu-infra"
VM_USER="idsadmin"
VM_PASSWORD="temp123"  # Contraseña temporal
SSH_KEY="$HOME/.ssh/id_ed25519_vm"
ISO_PATH="$HOME/Downloads/ubuntu-24.04.3-live-server-amd64.iso"
PRESEED_PATH="/tmp/preseed.cfg"
CLOUD_INIT_PATH="/tmp/cloud-init"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] ⚠️${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ❌${NC} $1"
    exit 1
}

# Función para verificar dependencias
check_dependencies() {
    log "🔍 Verificando dependencias..."

    for cmd in VBoxManage ssh-keygen sshpass nc; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Comando requerido no encontrado: $cmd"
        fi
    done

    if [ ! -f "$ISO_PATH" ]; then
        error "ISO no encontrada en: $ISO_PATH"
    fi

    log "✅ Todas las dependencias están disponibles"
}

# Función para generar cloud-init
create_cloud_init() {
    log "📝 Creando configuración cloud-init..."

    mkdir -p "$CLOUD_INIT_PATH"

    # Generar clave SSH si no existe
    if [ ! -f "$SSH_KEY" ]; then
        ssh-keygen -f "$SSH_KEY" -t ed25519 -N "" -C "vm-key-$(date +%s)"
    fi

    # user-data para cloud-init
    cat > "$CLOUD_INIT_PATH/user-data" <<EOF
#cloud-config
users:
  - name: $VM_USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [sudo, docker]
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$SSH_KEY.pub")
    passwd: $(echo "$VM_PASSWORD" | openssl passwd -6 -stdin)
    lock_passwd: false

packages:
  - curl
  - git
  - htop
  - apt-transport-https
  - ca-certificates
  - gnupg
  - lsb-release

runcmd:
  # Asegurar kernel genérico (no HWE para VirtualBox)
  - apt-get update
  - apt-get install -y linux-image-generic linux-headers-generic
  - apt-get remove -y linux-image-generic-hwe-* linux-headers-generic-hwe-* || true

  # Instalar Docker
  - curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  - echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu noble stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  - apt-get update
  - apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  - systemctl enable docker
  - systemctl start docker
  - usermod -aG docker $VM_USER

  # Instalar k3s
  - curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644
  - chmod +r /etc/rancher/k3s/k3s.yaml

  # Instalar docker-compose standalone (por compatibilidad)
  - curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  - chmod +x /usr/local/bin/docker-compose

  # Preparar directorio para el proyecto
  - mkdir -p /home/$VM_USER/projects
  - chown -R $VM_USER:$VM_USER /home/$VM_USER/projects

power_state:
  delay: "+1"
  mode: reboot
  message: "Reiniciando tras configuración inicial"
EOF

    # meta-data vacío
    cat > "$CLOUD_INIT_PATH/meta-data" <<EOF
instance-id: ubuntu-infra-$(date +%s)
local-hostname: ubuntu-infra
EOF

    # Crear ISO de cloud-init (compatible con macOS)
    if command -v hdiutil &> /dev/null; then
        # macOS - usar hdiutil (nativo)
        hdiutil makehybrid -o "$CLOUD_INIT_PATH/cidata.iso" -hfs -joliet -iso -default-volume-name cidata "$CLOUD_INIT_PATH"
    elif command -v genisoimage &> /dev/null; then
        # Linux - genisoimage
        genisoimage -output "$CLOUD_INIT_PATH/cidata.iso" -volid cidata -joliet -rock "$CLOUD_INIT_PATH/user-data" "$CLOUD_INIT_PATH/meta-data"
    elif command -v mkisofs &> /dev/null; then
        # Alternativa - mkisofs
        mkisofs -output "$CLOUD_INIT_PATH/cidata.iso" -volid cidata -joliet -rock "$CLOUD_INIT_PATH/user-data" "$CLOUD_INIT_PATH/meta-data"
    else
        warn "No se encontró herramienta para crear ISO. La instalación requerirá configuración manual."
        return 1
    fi

    log "✅ Cloud-init configurado"
}

# Función para limpiar VM existente
cleanup_vm() {
    log "🗑️ Limpiando VM existente..."

    if VBoxManage showvminfo "$VM_NAME" &> /dev/null; then
        VBoxManage controlvm "$VM_NAME" poweroff &> /dev/null || true
        sleep 2
        VBoxManage unregistervm "$VM_NAME" --delete &> /dev/null || true
        log "✅ VM anterior eliminada"
    else
        log "ℹ️ No hay VM anterior que eliminar"
    fi
}

# Función para crear VM
create_vm() {
    log "🖥️ Creando nueva VM..."

    VBoxManage createvm --name "$VM_NAME" --ostype Ubuntu_64 --register
    VBoxManage modifyvm "$VM_NAME" \
        --memory 4096 \
        --cpus 2 \
        --nic1 nat \
        --natpf1 "ssh,tcp,,2222,,22" \
        --natpf1 "http,tcp,,8080,,80" \
        --natpf1 "https,tcp,,8443,,443" \
        --natpf1 "k3s,tcp,,6443,,6443" \
        --boot1 dvd \
        --boot2 disk \
        --boot3 none \
        --boot4 none

    # Crear disco duro
    local vdi_path="$HOME/VirtualBox VMs/$VM_NAME/$VM_NAME.vdi"
    VBoxManage createhd --filename "$vdi_path" --size 25000 --format VDI

    # Configurar controladores de almacenamiento
    VBoxManage storagectl "$VM_NAME" --name "SATA" --add sata --controller IntelAhci
    VBoxManage storageattach "$VM_NAME" --storagectl "SATA" --port 0 --device 0 --type hdd --medium "$vdi_path"
    VBoxManage storageattach "$VM_NAME" --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium "$ISO_PATH"

    # Adjuntar cloud-init si existe
    if [ -f "$CLOUD_INIT_PATH/cidata.iso" ]; then
        VBoxManage storageattach "$VM_NAME" --storagectl "SATA" --port 2 --device 0 --type dvddrive --medium "$CLOUD_INIT_PATH/cidata.iso"
        log "✅ Cloud-init ISO adjuntado"
    fi

    log "✅ VM creada correctamente"
}

# Función para esperar SSH
wait_for_ssh() {
    log "⏳ Esperando SSH (esto puede tomar varios minutos)..."

    # Limpiar claves SSH anteriores
    ssh-keygen -R "[127.0.0.1]:2222" 2>/dev/null || true

    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if nc -zv 127.0.0.1 2222 2>/dev/null; then
            log "✅ SSH disponible"
            return 0
        fi

        attempt=$((attempt + 1))
        if [ $((attempt % 10)) -eq 0 ]; then
            log "⏳ Intentando conectar SSH... ($attempt/$max_attempts)"
        fi
        sleep 10
    done

    error "Timeout esperando SSH después de $max_attempts intentos"
}

# Función para esperar cloud-init
wait_for_cloud_init() {
    log "☁️ Esperando cloud-init (configuración automática)..."

    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
           "$VM_USER@127.0.0.1" "cloud-init status --wait --long" 2>/dev/null; then
            log "✅ Cloud-init completado"
            return 0
        fi

        # Si cloud-init no está disponible, intentar verificar manualmente
        if ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
           "$VM_USER@127.0.0.1" "test -f /var/lib/cloud/instance/boot-finished" 2>/dev/null; then
            log "✅ Configuración inicial completada"
            return 0
        fi

        attempt=$((attempt + 1))
        if [ $((attempt % 5)) -eq 0 ]; then
            log "☁️ Esperando cloud-init... ($attempt/$max_attempts)"
        fi
        sleep 20
    done

    warn "Timeout esperando cloud-init, continuando..."
    return 0
}

# Función para verificar conectividad SSH
test_ssh_connection() {
    log "🔐 Probando conexión SSH..."

    local max_attempts=10
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
           "$VM_USER@127.0.0.1" "echo 'SSH OK'" &> /dev/null; then
            log "✅ Conexión SSH establecida"
            return 0
        fi

        attempt=$((attempt + 1))
        log "🔄 Reintentando SSH... ($attempt/$max_attempts)"
        sleep 15
    done

    error "No se pudo establecer conexión SSH"
}

# Función para instalar proyecto
setup_project() {
    log "📦 Configurando proyecto en VM..."

    ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no "$VM_USER@127.0.0.1" <<'EOFVM'
set -e

# Verificar y crear directorio de proyectos si no existe
if [ ! -d "/home/$USER/projects" ]; then
    echo "📁 Creando directorio projects..."
    mkdir -p /home/$USER/projects
fi

cd /home/$USER/projects

# Clonar repositorio
if [ -d "upgraded-happiness" ]; then
    echo "🔄 Actualizando repositorio existente..."
    cd upgraded-happiness
    git pull || echo "⚠️ Error actualizando, continuando..."
else
    echo "📥 Clonando repositorio..."
    git clone https://github.com/alonsoir/upgraded-happiness.git || {
        echo "❌ Error clonando repositorio"
        exit 1
    }
    cd upgraded-happiness
fi

# Cambiar a branch específico
echo "🔄 Cambiando a branch feature/docker-k8s..."
git checkout feature/docker-k8s || {
    echo "❌ Error cambiando a branch"
    exit 1
}

# Verificar estructura del proyecto
if [ ! -f "./infrastructure/docker/docker-compose.yml" ]; then
    echo "❌ No se encontró docker-compose.yml en la ruta esperada"
    echo "📂 Estructura encontrada:"
    find . -name "docker-compose.yml" -type f 2>/dev/null || echo "No se encontró docker-compose.yml"
    find . -path "*/infrastructure/*" -type d 2>/dev/null || echo "No se encontró directorio infrastructure"
    exit 1
fi

echo "✅ Proyecto configurado correctamente"

# Preparar script de inicio
cat > /home/$USER/start_pipeline.sh <<'EOFSCRIPT'
#!/bin/bash
set -e

cd /home/$USER/projects/upgraded-happiness

echo "🚀 Iniciando pipeline..."

# Verificar que Docker esté corriendo
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker no está disponible"
    echo "💡 Intenta: sudo systemctl start docker"
    exit 1
fi

# Iniciar servicios
echo "📋 Docker Compose file:"
cat ./infrastructure/docker/docker-compose.yml | head -20

echo -e "\n🚀 Iniciando servicios..."
docker compose -f ./infrastructure/docker/docker-compose.yml up -d

echo -e "\n✅ Pipeline iniciado. Servicios disponibles:"
docker compose -f ./infrastructure/docker/docker-compose.yml ps

echo -e "\n📊 Para ver logs:"
echo "docker compose -f ./infrastructure/docker/docker-compose.yml logs -f"
EOFSCRIPT

chmod +x /home/$USER/start_pipeline.sh

echo "🎯 Para iniciar el pipeline ejecuta: ./start_pipeline.sh"
EOFVM

    if [ $? -eq 0 ]; then
        log "✅ Proyecto configurado en VM"
    else
        error "❌ Error configurando proyecto"
    fi
}

# Función para mostrar información final
show_info() {
    log "🎉 VM configurada exitosamente!"
    echo
    echo -e "${BLUE}📋 Información de conexión:${NC}"
    echo -e "   SSH: ${GREEN}ssh -i $SSH_KEY -p 2222 $VM_USER@127.0.0.1${NC}"
    echo
    echo -e "${BLUE}🔗 Puertos mapeados:${NC}"
    echo -e "   SSH:   127.0.0.1:2222 → VM:22"
    echo -e "   HTTP:  127.0.0.1:8080 → VM:80"
    echo -e "   HTTPS: 127.0.0.1:8443 → VM:443"
    echo -e "   K3s:   127.0.0.1:6443 → VM:6443"
    echo
    echo -e "${BLUE}🚀 Para iniciar el pipeline:${NC}"
    echo -e "   ${GREEN}ssh -i $SSH_KEY -p 2222 $VM_USER@127.0.0.1${NC}"
    echo -e "   ${GREEN}./start_pipeline.sh${NC}"
    echo
    echo -e "${BLUE}📁 Proyecto ubicado en:${NC} /home/$VM_USER/projects/upgraded-happiness"
}

# Función principal
main() {
    log "🚀 Iniciando configuración de VM para pipeline Docker/Kubernetes"

    check_dependencies
    create_cloud_init || warn "Cloud-init no disponible, instalación manual requerida"
    cleanup_vm
    create_vm

    log "🔌 Iniciando VM..."
    VBoxManage startvm "$VM_NAME"

    wait_for_ssh
    wait_for_cloud_init
    test_ssh_connection
    setup_project
    show_info

    log "✅ ¡Configuración completa!"
}

# Manejo de señales para limpieza
trap 'error "Script interrumpido"' INT TERM

# Ejecutar función principal
main "$@"