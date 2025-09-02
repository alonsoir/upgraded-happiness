#!/bin/bash
# debug_current_vm.sh
set -euo pipefail

VM_USER="idsadmin"
SSH_KEY="$HOME/.ssh/id_ed25519_vm"

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +'%H:%M:%S')] ⚠️${NC} $1"; }
error() { echo -e "${RED}[$(date +'%H:%M:%S')] ❌${NC} $1"; }

log "🔍 Depurando VM actual..."

# Limpiar claves SSH conocidas
ssh-keygen -R "[127.0.0.1]:2222" 2>/dev/null || true

# Verificar conectividad
if ! nc -zv 127.0.0.1 2222 2>/dev/null; then
    error "SSH no está disponible en puerto 2222"
    exit 1
fi

log "✅ SSH disponible"

# Verificar estado de cloud-init
log "☁️ Verificando estado de cloud-init..."
ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no "$VM_USER@127.0.0.1" <<'EOF'
echo "=== ESTADO DE CLOUD-INIT ==="
if command -v cloud-init >/dev/null 2>&1; then
    cloud-init status --long || true
    echo -e "\n=== LOGS DE CLOUD-INIT ==="
    sudo tail -20 /var/log/cloud-init.log || true
else
    echo "Cloud-init no disponible"
fi

echo -e "\n=== INFORMACIÓN DEL USUARIO ==="
whoami
id
pwd
ls -la /home/$USER/ || true

echo -e "\n=== INFORMACIÓN DOCKER ==="
if command -v docker >/dev/null 2>&1; then
    docker --version
    docker info | head -10 || true
else
    echo "Docker no instalado"
fi

echo -e "\n=== INFORMACIÓN K3S ==="
if command -v kubectl >/dev/null 2>&1; then
    kubectl version --client=true || true
else
    echo "kubectl no disponible"
fi

echo -e "\n=== CONFIGURACION MANUAL ==="
if [ ! -d "/home/$USER/projects" ]; then
    echo "📁 Creando directorio projects..."
    mkdir -p /home/$USER/projects
fi

echo -e "\n=== INSTALACION MANUAL DOCKER SI ES NECESARIO ==="
if ! command -v docker >/dev/null 2>&1; then
    echo "🐳 Instalando Docker manualmente..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo "✅ Docker instalado"
fi

echo -e "\n✅ Configuración básica completada"
EOF

log "🚀 Configurando proyecto manualmente..."
ssh -i "$SSH_KEY" -p 2222 -o StrictHostKeyChecking=no "$VM_USER@127.0.0.1" <<'EOF'
cd /home/$USER/projects

# Clonar repositorio si no existe
if [ ! -d "upgraded-happiness" ]; then
    echo "📥 Clonando repositorio..."
    git clone https://github.com/alonsoir/upgraded-happiness.git
fi

cd upgraded-happiness
echo "🔄 Cambiando a branch feature/docker-k8s..."
git checkout feature/docker-k8s

echo "📂 Verificando estructura del proyecto..."
find . -name "docker-compose.yml" -type f

# Crear script de inicio
cat > /home/$USER/start_pipeline.sh <<'EOFSCRIPT'
#!/bin/bash
set -e

cd /home/$USER/projects/upgraded-happiness

echo "🚀 Iniciando pipeline..."

# Buscar docker-compose.yml
COMPOSE_FILE=""
if [ -f "./infrastructure/docker/docker-compose.yml" ]; then
    COMPOSE_FILE="./infrastructure/docker/docker-compose.yml"
elif [ -f "./docker-compose.yml" ]; then
    COMPOSE_FILE="./docker-compose.yml"
else
    echo "❌ No se encontró docker-compose.yml"
    find . -name "docker-compose.yml" -type f
    exit 1
fi

echo "📋 Usando archivo: $COMPOSE_FILE"
docker compose -f "$COMPOSE_FILE" up -d

echo "✅ Pipeline iniciado. Servicios:"
docker compose -f "$COMPOSE_FILE" ps
EOFSCRIPT

chmod +x /home/$USER/start_pipeline.sh
echo "✅ Script creado: /home/$USER/start_pipeline.sh"
EOF

log "🎉 VM configurada manualmente!"
echo
echo -e "🔗 Para conectar: ${GREEN}ssh -i $SSH_KEY -p 2222 $VM_USER@127.0.0.1${NC}"
echo -e "🚀 Para iniciar pipeline: ${GREEN}./start_pipeline.sh${NC}"