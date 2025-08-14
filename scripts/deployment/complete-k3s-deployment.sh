#!/bin/bash
# complete-k3s-deployment.sh
# Deployment completo del modo distribuido en K3s con todas las phases

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuración
PROJECT_ROOT=$(pwd)
FEATURE_BRANCH="feature/distributed-mode"
K3S_VERSION="v1.27.3+k3s1"

# Logging functions
log() { echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARNING: $1${NC}"; }
error() { echo -e "${RED}[$(date +'%H:%M:%S')] ERROR: $1${NC}"; exit 1; }
info() { echo -e "${BLUE}[$(date +'%H:%M:%S')] INFO: $1${NC}"; }
success() { echo -e "${PURPLE}[$(date +'%H:%M:%S')] ✅ $1${NC}"; }

# Banner
show_banner() {
    echo -e "${PURPLE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        🚀 IDS PIPELINE - DISTRIBUTED MODE DEPLOYMENT        ║
║                                                              ║
║  📊 Phase 1: etcd Backbone + Service Discovery              ║
║  🔐 Phase 2: Security + Encryption                          ║
║  🎫 Phase 3: Token Management + Windows                     ║
║  🧪 Phase 4: Integration + Testing                          ║
║  ☸️  Phase 5: K3s Orchestration + Intelligent Placement     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    # Required tools
    local tools=("git" "docker" "kubectl" "helm" "vagrant" "python3")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool is required but not installed"
        fi
    done

    # VirtualBox check
    if ! VBoxManage --version &> /dev/null; then
        error "VirtualBox is required but not installed"
    fi

    # Python packages
    python3 -c "
import sys
required = ['kubernetes', 'zmq', 'sqlite3', 'json']
missing = []
for pkg in required:
    try:
        __import__(pkg)
    except ImportError:
        missing.append(pkg)
if missing:
    print(f'Missing Python packages: {missing}')
    sys.exit(1)
" || warn "Some Python packages may be missing. Install with: pip3 install kubernetes pyzmq"

    success "Prerequisites check passed"
}

# Setup project structure
setup_project_structure() {
    log "Setting up project structure..."

    # Create feature branch
    if git branch | grep -q "$FEATURE_BRANCH"; then
        info "Feature branch exists, switching to it"
        git checkout "$FEATURE_BRANCH"
    else
        log "Creating feature branch: $FEATURE_BRANCH"
        git checkout -b "$FEATURE_BRANCH"
    fi

    # Create directory structure
    mkdir -p {
        k8s/{vm-setup,manifests/{etcd,pipeline,monitoring,security},helm-charts/ids-pipeline/templates,tools},
        config/distributed,
        logs,
        certs,
        data/etcd,
        monitoring/dashboards,
        docs/distributed
    }

    # Copy configurations
    log "Setting up configuration files..."

    # Create etcd configuration
    cat > config/distributed/etcd-config.yaml << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: etcd-config
  namespace: ids-pipeline
data:
  etcd.conf.yml: |
    name: 'etcd-node'
    data-dir: /var/lib/etcd
    wal-dir: /var/lib/etcd/wal
    snapshot-count: 10000
    heartbeat-interval: 100
    election-timeout: 1000
    quota-backend-bytes: 0
    listen-peer-urls: http://0.0.0.0:2380
    listen-client-urls: http://0.0.0.0:2379
    max-snapshots: 5
    max-wals: 5
    cors:
    initial-advertise-peer-urls: http://0.0.0.0:2380
    advertise-client-urls: http://0.0.0.0:2379
    discovery:
    discovery-fallback: 'proxy'
    discovery-proxy:
    discovery-srv:
    initial-cluster:
    initial-cluster-token: 'etcd-cluster'
    initial-cluster-state: 'new'
    strict-reconfig-check: false
    enable-v2: true
EOF

    # Create Helm chart structure
    log "Creating Helm chart..."

    cat > k8s/helm-charts/ids-pipeline/Chart.yaml << 'EOF'
apiVersion: v2
name: ids-pipeline
description: A Helm chart for Distributed IDS Pipeline
type: application
version: 0.1.0
appVersion: "v31"
keywords:
  - security
  - ids
  - intrusion-detection
  - ml
home: https://github.com/alonsoir/upgraded-happiness
sources:
  - https://github.com/alonsoir/upgraded-happiness
maintainers:
  - name: alonsoir
    email: your-email@example.com
EOF

    success "Project structure created"


# Phase 1: Deploy VM and K3s
deploy_vm_k3s() {
    log "Phase 1: Deploying K3s cluster in VM..."

    # Check if VM already exists
    if VBoxManage list vms | grep -q "ids-k3s-cluster"; then
        warn "VM 'ids-k3s-cluster' already exists"
        read -p "Destroy and recreate? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "Destroying existing VM..."
            vagrant destroy -f || true
        else
            info "Using existing VM"
            return 0
        fi
    fi

    # Deploy with Vagrant
    log "Creating VM with Vagrant..."
    vagrant up

    # Wait for K3s to be ready
    log "Waiting for K3s cluster to be ready..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if vagrant ssh -c "kubectl get nodes | grep -q Ready" 2>/dev/null; then
            break
        fi
        warn "K3s not ready yet, retrying... ($retries attempts left)"
        sleep 10
        ((retries--))
    done

    if [ $retries -eq 0 ]; then
        error "K3s cluster failed to become ready"
    fi

    success "Phase 1 completed: K3s cluster is ready"
}

# Phase 2: Deploy etcd cluster
deploy_etcd_cluster() {
    log "Phase 2: Deploying etcd cluster..."

    # Apply etcd manifests
    vagrant ssh -c "
        kubectl apply -f /vagrant/config/distributed/etcd-config.yaml
        kubectl apply -f /vagrant/k8s/manifests/etcd/
    "

    # Wait for etcd to be ready
    log "Waiting for etcd cluster to be ready..."
    vagrant ssh -c "kubectl wait --for=condition=ready pod -l app=etcd --timeout=300s -n ids-pipeline"

    # Verify etcd cluster health
    log "Verifying etcd cluster health..."
    vagrant ssh -c "
        kubectl exec -it etcd-0 -n ids-pipeline -- etcdctl \
            --endpoints=http://etcd-0.etcd:2379,http://etcd-1.etcd:2379,http://etcd-2.etcd:2379 \
            endpoint health
    "

    success "Phase 2 completed: etcd cluster deployed and healthy"
}

# Phase 3: Deploy IDS pipeline components
deploy_ids_pipeline() {
    log "Phase 3: Deploying IDS pipeline components..."

    # Deploy using Helm chart
    vagrant ssh -c "
        cd /vagrant
        helm upgrade --install ids-pipeline ./k8s/helm-charts/ids-pipeline \
            --namespace ids-pipeline \
            --create-namespace \
            --values ./k8s/helm-charts/ids-pipeline/values.yaml \
            --wait --timeout=10m
    "

    # Verify deployment
    log "Verifying pipeline deployment..."
    vagrant ssh -c "
        kubectl get pods -n ids-pipeline
        kubectl get services -n ids-pipeline
        kubectl get configmaps -n ids-pipeline
    "

    success "Phase 3 completed: IDS pipeline deployed"
}

# Phase 4: Deploy monitoring
deploy_monitoring() {
    log "Phase 4: Deploying monitoring stack..."

    # Deploy monitoring components
    vagrant ssh -c "
        # Deploy Prometheus operator if not already installed
        helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
        helm repo update

        helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
            --namespace monitoring \
            --create-namespace \
            --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
            --wait --timeout=10m
    "

    # Deploy custom dashboards
    vagrant ssh -c "
        kubectl apply -f /vagrant/monitoring/dashboards/ -n monitoring
    "

    success "Phase 4 completed: Monitoring stack deployed"
}

# Phase 5: Run tests and validation
run_tests() {
    log "Phase 5: Running tests and validation..."

    # Cluster health check
    log "Running cluster health checks..."
    vagrant ssh -c "
        echo '=== CLUSTER INFO ==='
        kubectl cluster-info

        echo '=== NODES ==='
        kubectl get nodes -o wide

        echo '=== PODS ==='
        kubectl get pods --all-namespaces

        echo '=== SERVICES ==='
        kubectl get services --all-namespaces

        echo '=== ETCD HEALTH ==='
        kubectl exec -it etcd-0 -n ids-pipeline -- etcdctl endpoint health --cluster
    "

    # Component connectivity test
    log "Testing component connectivity..."
    vagrant ssh -c "
        # Test ZeroMQ connectivity between components
        python3 /vagrant/k8s/tools/test-connectivity.py
    "

    # Load test (basic)
    log "Running basic load test..."
    vagrant ssh -c "
        # Generate some test traffic
        python3 /vagrant/k8s/tools/generate-test-traffic.py --duration=30
    "

    success "Phase 5 completed: All tests passed"
}

# Generate access information
show_access_info() {
    local vm_ip="192.168.56.10"

    info "Retrieving access information..."

    echo -e "${BLUE}"
    cat << EOF

╔══════════════════════════════════════════════════════════════╗
║                    🎯 DEPLOYMENT COMPLETED!                  ║
╚══════════════════════════════════════════════════════════════╝

🌐 ACCESS URLS:
   Kubernetes API:    https://localhost:6443
   Grafana Dashboard: http://localhost:3000 (admin/prom-operator)
   Prometheus:        http://localhost:9090
   VM SSH:            vagrant ssh

📊 CLUSTER STATUS:
EOF

    vagrant ssh -c "
        echo '   Nodes:'
        kubectl get nodes
        echo '
   IDS Pipeline Pods:'
        kubectl get pods -n ids-pipeline
        echo '
   Services:'
        kubectl get services -n ids-pipeline
    "

    cat << EOF

🛠️  USEFUL COMMANDS:
   Access VM:         vagrant ssh
   View logs:         vagrant ssh -c \"kubectl logs -f deployment/ml-detector -n ids-pipeline\"
   Scale component:   vagrant ssh -c \"kubectl scale deployment/ml-detector --replicas=3 -n ids-pipeline\"
   Stop VM:           vagrant halt
   Destroy VM:        vagrant destroy

📚 DOCUMENTATION:
   Kubernetes Dashboard: kubectl proxy (then http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/)
   View all resources:   kubectl get all --all-namespaces

🔍 MONITORING:
   View Grafana dashboards for real-time pipeline metrics
   Check Prometheus for detailed metrics and alerts

🚀 NEXT STEPS:
   1. Configure your network data sources
   2. Upload ML models to the appropriate persistent volumes
   3. Configure firewall rules via ConfigMaps
   4. Set up external log shipping (if needed)

EOF
    echo -e "${NC}"
}

# Cleanup function
cleanup_on_error() {
    error "Deployment failed! Cleaning up..."
    vagrant destroy -f || true
    git checkout main || true
}

# Main execution
main() {
    trap cleanup_on_error ERR

    show_banner

    log "Starting distributed mode deployment..."

    check_prerequisites
    setup_project_structure
    deploy_vm_k3s
    deploy_etcd_cluster
    deploy_ids_pipeline
    deploy_monitoring
    run_tests

    show_access_info

    success "🎉 DISTRIBUTED MODE DEPLOYMENT COMPLETED SUCCESSFULLY!"
    success "🧠 Your IDS pipeline is now running in a fully distributed K3s cluster!"
}

# Handle command line arguments
case "${1:-all}" in
    "prereq")
        check_prerequisites
        ;;
    "structure")
        setup_project_structure
        ;;
    "vm")
        deploy_vm_k3s
        ;;
    "etcd")
        deploy_etcd_cluster
        ;;
    "pipeline")
        deploy_ids_pipeline
        ;;
    "monitoring")
        deploy_monitoring
        ;;
    "test")
        run_tests
        ;;
    "info")
        show_access_info
        ;;
    "all")
        main
        ;;
    *)
        echo "Usage: $0 [prereq|structure|vm|etcd|pipeline|monitoring|test|info|all]"
        echo "  prereq     - Check prerequisites only"
        echo "  structure  - Setup project structure only"
        echo "  vm         - Deploy VM and K3s only"
        echo "  etcd       - Deploy etcd cluster only"
        echo "  pipeline   - Deploy IDS pipeline only"
        echo "  monitoring - Deploy monitoring only"
        echo "  test       - Run tests only"
        echo "  info       - Show access information"
        echo "  all        - Full deployment (default)"
        exit 1
        ;;
esac