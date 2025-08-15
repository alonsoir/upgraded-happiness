# =============================================================================
# 🛡️ Upgraded Happiness - Sistema Autoinmune Digital v3.1 EVOLUTIVO + DISTRIBUTED
# =============================================================================
# Arquitectura V3.1: evolutionary_sniffer → geoip_enricher → ml_detector_tricapa → scheduler → firewall_agent → dashboard
# Branch: feature/distributed-mode
# Estado: Pipeline V3.1 + etcd backbone distribuido
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# =============================================================================
# COLORES Y EMOJIS
# =============================================================================
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
PURPLE = \033[0;35m
CYAN = \033[0;36m
NC = \033[0m # No Color

# =============================================================================
# CONFIGURACIÓN DEL PROYECTO V3.1 + DISTRIBUTED
# =============================================================================
PROJECT_NAME = upgraded-happiness
PROJECT_VERSION = v3.1.0-distributed
BRANCH = feature/distributed-mode
REPO_URL = https://github.com/alonsoir/upgraded-happiness

# Python y Entorno
PYTHON = python3
CORE_DIR = core
MODELS_DIR = models/production/tricapa
VENV_NAME = upgraded_happiness_venv
VENV_BIN = $(VENV_NAME)/bin
PYTHON_VENV = $(VENV_BIN)/python
PIP_VENV = $(VENV_BIN)/pip
ACTIVATE = source $(VENV_BIN)/activate

# =============================================================================
# CONFIGURACIÓN DISTRIBUIDA - etcd BACKBONE
# =============================================================================
# etcd Configuration
ETCD_ENDPOINT := http://localhost:2379
ETCD_CLUSTER_ENDPOINTS := http://localhost:2379,http://localhost:2389,http://localhost:2399
ETCD_CONFIG_DIR := config/etcd
ETCD_DATA_DIR := data/etcd
ETCD_LOG_DIR := logs
ETCD_CONFIG_FILE := $(ETCD_CONFIG_DIR)/etcd-basic-config.yaml
ETCD_PID_FILE := .pids/etcd.pid

# Service Discovery
SERVICE_DISCOVERY_SCRIPT := scripts/service-discovery-basic.sh
ETCD_START_SCRIPT := scripts/start-etcd-basic.sh
ETCD_INSTALL_SCRIPT := scripts/install-etcd.sh

# Distributed Mode Components
DISTRIBUTED_SERVICES := axiom-api axiom-worker axiom-scheduler axiom-firewall axiom-dashboard

# =============================================================================
# PROTOBUF CONFIGURATION V3.1
# =============================================================================
PROTOBUF_DIR = protocols/current
SCHEMA_NETWORK_V31 = $(PROTOBUF_DIR)/network_security_clean_v31.proto
SCHEMA_FIREWALL_V31 = $(PROTOBUF_DIR)/firewall_commands_v31.proto
PROTOBUF_COMPILED_V31 = $(PROTOBUF_DIR)/network_security_clean_v31_pb2.py \
                       $(PROTOBUF_DIR)/firewall_commands_v31_pb2.py

# =============================================================================
# COMPONENTES V3.1 EVOLUTIVOS
# =============================================================================
EVOLUTIONARY_SNIFFER_V31 = core/evolutionary_sniffer_v31.py
GEOIP_ENRICHER_V31 = core/geoip_enricher_v31.py
ML_DETECTOR_TRICAPA_V31 = core/lightweight_ml_detector_tricapa_v31.py
SCHEDULER_FIREWALL = core/scheduler-firewall.py
FIREWALL_AGENT_V31 = core/simple_firewall_agent_v31.py
DASHBOARD_V31 = core/dashboard_v31.py

# Componentes DEMO
PROMISCUOUS_AGENT_DEMO = core/promiscuous_agent.py
GEOIP_ENRICHER_DEMO = core/geoip_enricher.py
ML_DETECTOR_DEMO = core/lightweight_ml_detector.py
DASHBOARD_DEMO = core/real_zmq_dashboard_with_firewall.py
FIREWALL_AGENT_DEMO = core/simple_firewall_agent.py

# =============================================================================
# CONFIGURACIONES JSON V3.1
# =============================================================================
CONFIG_DIR = config/json
EVOLUTIONARY_SNIFFER_CONFIG_V31 = $(CONFIG_DIR)/evolutionary_sniffer_config_v31.json
GEOIP_ENRICHER_CONFIG_V31 = $(CONFIG_DIR)/geoip_enricher_config_v31.json
ML_DETECTOR_TRICAPA_CONFIG_V31 = $(CONFIG_DIR)/lightweight_ml_detector_tricapa_v31_config_dev.json
SCHEDULER_FIREWALL_CONFIG = $(CONFIG_DIR)/scheduler_firewall_config.json
FIREWALL_AGENT_CONFIG_V31 = $(CONFIG_DIR)/simple_firewall_agent_v31_config.json
DASHBOARD_CONFIG_V31 = $(CONFIG_DIR)/dashboard_config_v31.json
FIREWALL_RULES_V31 = $(CONFIG_DIR)/firewall_rules_v31.json

# Configuraciones DEMO
PROMISCUOUS_CONFIG_DEMO = $(CONFIG_DIR)/enhanced_agent_config.json
GEOIP_CONFIG_DEMO = $(CONFIG_DIR)/geoip_enricher_config.json
ML_CONFIG_DEMO = $(CONFIG_DIR)/lightweight_ml_detector_config.json
DASHBOARD_CONFIG_DEMO = $(CONFIG_DIR)/dashboard_config.json
FIREWALL_CONFIG_DEMO = $(CONFIG_DIR)/simple_firewall_agent_config.json
FIREWALL_RULES_DEMO = $(CONFIG_DIR)/firewall_rules_dashboard.json

# =============================================================================
# ARQUITECTURA DE RED V3.1
# =============================================================================
CAPTURE_PORT_V31 = 5559
GEOIP_PORT_V31 = 5560
ML_PORT_V31 = 5561
FIREWALL_PORT_V31 = 5562
DASHBOARD_PORT_V31 = 5580
DASHBOARD_WEB_PORT = 8080

# =============================================================================
# GESTIÓN DE PROCESOS
# =============================================================================
PIDS_DIR = .pids
LOGS_DIR = logs

# PIDs V3.1
EVOLUTIONARY_SNIFFER_PID_V31 = $(PIDS_DIR)/evolutionary_sniffer_v31.pid
GEOIP_PID_V31 = $(PIDS_DIR)/geoip_enricher_v31.pid
ML_TRICAPA_PID_V31 = $(PIDS_DIR)/ml_detector_tricapa_v31.pid
SCHEDULER_PID = $(PIDS_DIR)/scheduler_firewall.pid
FIREWALL_PID_V31 = $(PIDS_DIR)/firewall_agent_v31.pid
DASHBOARD_PID_V31 = $(PIDS_DIR)/dashboard_v31.pid

# PIDs DEMO
PROMISCUOUS_PID_DEMO = $(PIDS_DIR)/promiscuous_agent.pid
GEOIP_PID_DEMO = $(PIDS_DIR)/geoip_enricher.pid
ML_PID_DEMO = $(PIDS_DIR)/ml_detector.pid
DASHBOARD_PID_DEMO = $(PIDS_DIR)/dashboard.pid
FIREWALL_PID_DEMO = $(PIDS_DIR)/firewall_agent.pid

# Logs V3.1
EVOLUTIONARY_SNIFFER_LOG_V31 = $(LOGS_DIR)/evolutionary_sniffer_v31.log
GEOIP_LOG_V31 = $(LOGS_DIR)/geoip_enricher_v31.log
ML_TRICAPA_LOG_V31 = $(LOGS_DIR)/ml_detector_tricapa_v31.log
SCHEDULER_LOG = $(LOGS_DIR)/scheduler_firewall.log
FIREWALL_LOG_V31 = $(LOGS_DIR)/firewall_agent_v31.log
DASHBOARD_LOG_V31 = $(LOGS_DIR)/dashboard_v31.log

# Scripts de utilidad V3.1
MONITOR_SCRIPT_V31 = scripts/utils/monitor_autoinmune_v31.sh
NUCLEAR_STOP_SCRIPT = scripts/deployment/nuclear-stop.sh

# =============================================================================
# PHONY DECLARATIONS
# =============================================================================
.PHONY: help setup install clean test \
        compile-protobuf-v31 check-protobuf-v31 verify-protobuf-compiled-v31 \
        start start_v31 start-demo start-bg stop stop-nuclear restart \
        status status_v31 monitor monitor_v31 logs logs-v31 \
        setup-perms verify check-deps \
        show-dashboard show-architecture-v31 show-roadmap-v31 \
        quick quick_v31 debug benchmark \
        create-configs-v31 verify-configs-v31 \
        dist-setup dist-start dist-stop dist-status dist-test dist-discover dist-watch dist-clean dist-register dist-reset \
        dist-cluster dist-cluster-status dist-cluster-stop dist-cluster-test dist-cluster-advanced create-cluster-configs create-cluster-configs-from-file \
        dist-ha dist-register-cluster \
        dist-ui dist-ui-stop dist-ui-open dist-secure dist-info dist-troubleshoot \
        dist-quick dist-install-etcd dist-dev

# =============================================================================
# HELP INTEGRADO - TODAS LAS FUNCIONALIDADES
# =============================================================================
help:
	@echo "$(CYAN)🧬 Sistema Autoinmune Digital V3.1 EVOLUTIVO + DISTRIBUIDO$(NC)"
	@echo "$(CYAN)==========================================================$(NC)"
	@echo "$(PURPLE)Versión: $(PROJECT_VERSION)$(NC)"
	@echo "$(PURPLE)Branch: $(BRANCH)$(NC)"
	@echo "$(PURPLE)Estado: Pipeline V3.1 + etcd backbone distribuido$(NC)"
	@echo "$(PURPLE)Repo: $(REPO_URL)$(NC)"
	@echo ""
	@echo "$(YELLOW)🚀 INICIO RÁPIDO:$(NC)"
	@echo "  $(GREEN)make quick_v31$(NC)           - Setup completo V3.1 (RECOMENDADO)"
	@echo "  $(GREEN)make dist-quick$(NC)          - Setup distribuido completo (etcd + V3.1)"
	@echo "  $(PURPLE)make dist-ha$(NC)             - Setup HA completo (cluster 3 nodos + V3.1)"
	@echo ""
	@echo "$(YELLOW)🌐 MODO DISTRIBUIDO (etcd backbone):$(NC)"
	@echo "  $(CYAN)make dist-setup$(NC)          - Configurar infraestructura distribuida"
	@echo "  $(CYAN)make dist-start$(NC)          - Iniciar backbone etcd + service discovery"
	@echo "  $(CYAN)make dist-status$(NC)         - Estado del sistema distribuido"
	@echo "  $(CYAN)make dist-test$(NC)           - Probar service discovery"
	@echo "  $(CYAN)make dist-discover$(NC)       - Ver servicios registrados"
	@echo "  $(CYAN)make dist-watch$(NC)          - Monitorear cambios en tiempo real"
	@echo "  $(CYAN)make dist-register$(NC)       - Re-registrar servicios V3.1"
	@echo "  $(CYAN)make dist-stop$(NC)           - Detener infraestructura distribuida"
	@echo "  $(CYAN)make dist-clean$(NC)          - Limpiar datos distribuidos"
	@echo ""
	@echo "$(YELLOW)🛡️ SISTEMA V3.1 (Pipeline evolutivo):$(NC)"
	@echo "  $(GREEN)make start_v31$(NC)           - Iniciar pipeline V3.1 evolutivo"
	@echo "  $(GREEN)make status_v31$(NC)          - Estado sistema V3.1"
	@echo "  $(GREEN)make monitor_v31$(NC)         - Monitor tiempo real V3.1"
	@echo "  $(GREEN)make logs-v31$(NC)            - Logs específicos V3.1"
	@echo ""
	@echo "$(YELLOW)📚 DEMO Y ENSEÑANZA:$(NC)"
	@echo "  $(BLUE)make start$(NC)               - Iniciar versión demo (enseñanza)"
	@echo "  $(BLUE)make status$(NC)              - Estado versión demo"
	@echo "  $(BLUE)make monitor$(NC)             - Monitor versión demo"
	@echo ""
	@echo "$(YELLOW)🛑 CONTROL SISTEMA:$(NC)"
	@echo "  stop                     - Parada normal (V3.1 + demo)"
	@echo "  stop-nuclear             - Parada nuclear (TODO)"
	@echo "  restart                  - Reiniciar sistema completo"
	@echo ""
	@echo "$(YELLOW)📦 SETUP Y CONFIGURACIÓN:$(NC)"
	@echo "  setup                    - Crear entorno virtual"
	@echo "  install                  - Instalar dependencias"
	@echo "  setup-perms              - Configurar permisos sudo"
	@echo "  compile-protobuf-v31     - Compilar protobuf V3.1"
	@echo "  verify                   - Verificar integridad completa"
	@echo ""
	@echo "$(YELLOW)📊 MONITORIZACIÓN:$(NC)"
	@echo "  logs                     - Ver logs (ambas versiones + distribuido)"
	@echo "  debug                    - Modo debug interactivo"
	@echo "  benchmark                - Ejecutar benchmarks"
	@echo ""
	@echo "$(CYAN)🏗️ ARQUITECTURA DISTRIBUIDA + HA:$(NC)"
	@echo "  Modo Simple: etcd (puerto 2379) ← Service Discovery Backbone"
	@echo "  Modo HA: etcd Cluster (puertos 2379,2389,2399) ← Quorum + Consensus"
	@echo "  ↓"
	@echo "  evolutionary_sniffer_v31 → geoip_enricher_v31 → ml_detector_tricapa_v31"
	@echo "  ↓"
	@echo "  scheduler-firewall ↔ simple_firewall_agent_v31"
	@echo "  ↓"
	@echo "  dashboard_v31 (puerto $(DASHBOARD_WEB_PORT))"
	@echo ""
	@echo "$(GREEN)💡 FLUJO RECOMENDADO:$(NC)"
	@echo "  $(BLUE)Desarrollo:$(NC) $(CYAN)make dist-quick$(NC)     # Setup distribuido"
	@echo "  $(PURPLE)Enterprise:$(NC) $(PURPLE)make dist-ha$(NC)       # Setup HA cluster"
	@echo "  $(GREEN)Dashboard:$(NC)  $(GREEN)make show-dashboard$(NC) # Abrir dashboard"
	@echo "  $(CYAN)Monitor:$(NC)    $(CYAN)make dist-watch$(NC)     # Monitorear servicios"

# =============================================================================
# MODO DISTRIBUIDO - etcd BACKBONE
# =============================================================================
dist-install-etcd: ## Instalar etcd si no está presente
	@echo "$(BLUE)🔧 Verificando instalación de etcd...$(NC)"
	@if command -v etcd &> /dev/null; then \
		echo "$(GREEN)✅ etcd ya está instalado: $$(etcd --version | head -n1)$(NC)"; \
	else \
		echo "$(YELLOW)📦 Instalando etcd...$(NC)"; \
		chmod +x $(ETCD_INSTALL_SCRIPT); \
		$(ETCD_INSTALL_SCRIPT); \
	fi

dist-setup: setup dist-install-etcd ## Configurar infraestructura distribuida
	@echo "$(BLUE)🔧 Configurando infraestructura distribuida...$(NC)"
	@mkdir -p $(ETCD_CONFIG_DIR) $(ETCD_DATA_DIR) $(ETCD_LOG_DIR) scripts $(PIDS_DIR)
	@chmod +x scripts/*.sh 2>/dev/null || true
	@echo "$(GREEN)✅ Infraestructura distribuida configurada$(NC)"

dist-start: dist-setup ## Iniciar backbone etcd + service discovery
	@echo "$(GREEN)🚀 Iniciando backbone distribuido...$(NC)"
	@echo "$(CYAN)====================================$(NC)"
	@echo ""

	@echo "$(BLUE)1. 🗂️  Iniciando etcd backbone...$(NC)"
	@chmod +x $(ETCD_START_SCRIPT)
	@$(ETCD_START_SCRIPT) &
	@sleep 5

	@echo "$(BLUE)2. 🔍 Verificando etcd...$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null; then \
		echo "$(GREEN)✅ etcd backbone operativo$(NC)"; \
		echo "$(YELLOW)🌐 Endpoint: $(ETCD_ENDPOINT)$(NC)"; \
	else \
		echo "$(RED)❌ etcd no responde$(NC)"; \
		exit 1; \
	fi

	@echo "$(BLUE)3. 📝 Registrando servicios básicos...$(NC)"
	@chmod +x $(SERVICE_DISCOVERY_SCRIPT)
	@$(SERVICE_DISCOVERY_SCRIPT) register axiom-backbone localhost 2379 300
	@$(SERVICE_DISCOVERY_SCRIPT) register axiom-ready localhost 8080 60

	@echo ""
	@echo "$(GREEN)🎉 BACKBONE DISTRIBUIDO OPERATIVO$(NC)"
	@echo "$(CYAN)===================================$(NC)"
	@echo "$(YELLOW)🔍 Service Discovery: make dist-discover$(NC)"
	@echo "$(YELLOW)👀 Monitoreo: make dist-watch$(NC)"
	@echo "$(YELLOW)📊 Estado: make dist-status$(NC)"

dist-stop: ## Detener infraestructura distribuida
	@echo "$(YELLOW)🛑 Deteniendo backbone distribuido...$(NC)"
	@pkill -f "etcd.*config-file.*etcd-basic-config.yaml" || echo "etcd no estaba corriendo"
	@rm -f $(ETCD_PID_FILE)
	@echo "$(GREEN)✅ Backbone distribuido detenido$(NC)"

dist-status: ## Estado del sistema distribuido
	@echo "$(CYAN)📊 Estado Sistema Distribuido$(NC)"
	@echo "$(CYAN)==============================$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null; then \
		echo "  🗂️  etcd Backbone: $(GREEN)✅ Operativo$(NC) ($(ETCD_ENDPOINT))"; \
		echo "  📊 Cluster Health: $(GREEN)$$(etcdctl --endpoints=$(ETCD_ENDPOINT) endpoint health 2>/dev/null | cut -d' ' -f3 || echo 'OK')$(NC)"; \
		echo "  🔢 Miembros: $$(etcdctl --endpoints=$(ETCD_ENDPOINT) member list | wc -l) nodo(s)"; \
		echo "  📝 Servicios registrados: $$(etcdctl --endpoints=$(ETCD_ENDPOINT) get /services/ --prefix --keys-only | grep -c /services/ || echo 0)"; \
	else \
		echo "  🗂️  etcd Backbone: $(RED)⭕ Detenido$(NC)"; \
	fi

dist-test: ## Probar service discovery básico
	@echo "$(BLUE)🧪 Ejecutando pruebas de service discovery...$(NC)"
	@chmod +x $(SERVICE_DISCOVERY_SCRIPT)
	@$(SERVICE_DISCOVERY_SCRIPT) test

dist-discover: ## Ver servicios registrados
	@echo "$(BLUE)🔍 Servicios registrados en el backbone:$(NC)"
	@chmod +x $(SERVICE_DISCOVERY_SCRIPT)
	@$(SERVICE_DISCOVERY_SCRIPT) discover

dist-watch: ## Monitorear cambios en tiempo real
	@echo "$(BLUE)👀 Monitoreando servicios en tiempo real...$(NC)"
	@echo "$(YELLOW)💡 Presiona Ctrl+C para salir$(NC)"
	@chmod +x $(SERVICE_DISCOVERY_SCRIPT)
	@$(SERVICE_DISCOVERY_SCRIPT) watch

dist-ui: ## Iniciar interfaz web para etcd (puerto 8081)
	@echo "$(BLUE)🌐 Iniciando interfaz web para etcd...$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "$(GREEN)✅ etcd disponible, iniciando UI...$(NC)"; \
		docker run -d --name etcd-browser \
			-p 8081:8081 \
			-e ETCD_ENDPOINT=$(ETCD_ENDPOINT) \
			-e EDITABLE=1 \
			--restart unless-stopped \
			rustyx/etcdv3-browser 2>/dev/null || echo "$(YELLOW)⚠️  Contenedor ya existe$(NC)"; \
		echo "$(GREEN)🌐 UI etcd disponible en: http://localhost:8081$(NC)"; \
		echo "$(YELLOW)💡 Para detener: make dist-ui-stop$(NC)"; \
	else \
		echo "$(RED)❌ etcd no disponible, inicia primero: make dist-start$(NC)"; \
	fi

dist-ui-stop: ## Detener interfaz web de etcd
	@echo "$(YELLOW)🛑 Deteniendo interfaz web de etcd...$(NC)"
	@docker stop etcd-browser 2>/dev/null || echo "$(YELLOW)⚠️  UI no estaba corriendo$(NC)"
	@docker rm etcd-browser 2>/dev/null || true
	@echo "$(GREEN)✅ UI etcd detenida$(NC)"

dist-ui-open: ## Abrir interfaz web de etcd en navegador
	@echo "$(BLUE)🌐 Abriendo interfaz web de etcd...$(NC)"
	@if curl -s http://localhost:8081 > /dev/null 2>&1; then \
		which open >/dev/null && open http://localhost:8081 || \
		which xdg-open >/dev/null && xdg-open http://localhost:8081 || \
		echo "💡 Abrir manualmente: http://localhost:8081"; \
	else \
		echo "$(RED)❌ UI no disponible. Ejecuta: make dist-ui$(NC)"; \
	fi

dist-secure: ## Configurar etcd con TLS + cifrado (modo seguro)
	@echo "$(BLUE)🔒 Configurando etcd en modo seguro...$(NC)"
	@echo "$(YELLOW)🚧 Implementación futura: TLS + at-rest encryption$(NC)"
	@echo "$(CYAN)📋 Características del modo seguro:$(NC)"
	@echo "  🔐 TLS client-server + peer-to-peer"
	@echo "  🗜️ Cifrado at-rest (database encryption)"
	@echo "  🛡️ RBAC + autenticación"
	@echo "  📊 Audit logging"
	@echo "$(YELLOW)💡 Para desarrollo usar: make dist-start (modo inseguro)$(NC)"

dist-info: ## Información completa del cluster etcd
	@echo "$(CYAN)📊 Información Cluster etcd$(NC)"
	@echo "$(CYAN)============================$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "$(GREEN)🗂️ Cluster Status:$(NC)"; \
		curl -s $(ETCD_ENDPOINT)/version | jq . 2>/dev/null || curl -s $(ETCD_ENDPOINT)/version; \
		echo ""; \
		echo "$(GREEN)🏥 Health Status:$(NC)"; \
		etcdctl --endpoints=$(ETCD_ENDPOINT) endpoint health; \
		echo ""; \
		echo "$(GREEN)👥 Cluster Members:$(NC)"; \
		etcdctl --endpoints=$(ETCD_ENDPOINT) member list; \
		echo ""; \
		echo "$(GREEN)📊 Database Size:$(NC)"; \
		etcdctl --endpoints=$(ETCD_ENDPOINT) endpoint status --write-out=table; \
		echo ""; \
		echo "$(GREEN)🔍 Services Registered:$(NC)"; \
		servicios=$(etcdctl --endpoints=$(ETCD_ENDPOINT) get /services/ --prefix --keys-only 2>/dev/null | grep -c /services/ || echo 0); \
		echo "  📝 Total servicios: $servicios"; \
		if [ "$servicios" -gt 0 ]; then \
			echo "  🏷️ Tipos de servicios: $(etcdctl --endpoints=$(ETCD_ENDPOINT) get /services/ --prefix --keys-only 2>/dev/null | cut -d'/' -f3 | sort | uniq | tr '\n' ' ')"; \
		fi; \
	else \
		echo "$(RED)❌ etcd no disponible$(NC)"; \
	fi

dist-reset: ## Reset completo del backbone distribuido
	@echo "$(YELLOW)🔄 Reset completo del backbone distribuido...$(NC)"
	@echo "$(RED)⚠️  Esto eliminará TODOS los datos de etcd$(NC)"
	@echo ""

	@echo "$(BLUE)1. 🛑 Deteniendo procesos etcd...$(NC)"
	@pkill -f "etcd.*config-file" 2>/dev/null || echo "  No hay procesos etcd corriendo"
	@docker stop etcd-browser 2>/dev/null || echo "  UI etcd no estaba corriendo"
	@docker rm etcd-browser 2>/dev/null || true

	@echo "$(BLUE)2. 🧹 Liberando puertos...$(NC)"
	@for port in 2379 2380; do \
		PIDS=$(lsof -ti:$port 2>/dev/null); \
		if [ ! -z "$PIDS" ]; then \
			echo "  💀 Liberando puerto $port..."; \
			echo "$PIDS" | xargs -r kill -9 2>/dev/null || true; \
		fi \
	done

	@echo "$(BLUE)3. 🗑️ Limpiando datos...$(NC)"
	@rm -rf $(ETCD_DATA_DIR)/* $(ETCD_LOG_DIR)/etcd.log 2>/dev/null || true
	@rm -f .pids/etcd.pid 2>/dev/null || true

	@echo "$(BLUE)4. ⏳ Esperando...$(NC)"
	@sleep 3

	@echo "$(GREEN)✅ Reset completado - Listo para iniciar limpio$(NC)"
	@echo "$(CYAN)💡 Ejecuta: make dist-start$(NC)"

dist-cluster: ## Iniciar cluster etcd de 3 nodos (HA real)
	@echo "$(GREEN)🏗️ Iniciando Cluster etcd de Alta Disponibilidad$(NC)"
	@echo "$(CYAN)===============================================$(NC)"
	@echo "$(YELLOW)💡 Cluster de 3 nodos para quorum y tolerancia a fallos$(NC)"
	@echo ""

	@echo "$(BLUE)🔍 Verificando configuración...$(NC)"
	@mkdir -p data/etcd/{node1,node2,node3} config/etcd logs/cluster

	@echo "$(BLUE)📝 Generando configuraciones de cluster...$(NC)"
	@$(MAKE) -s create-cluster-configs

	@echo "$(BLUE)🚀 Iniciando nodos del cluster...$(NC)"
	@echo "  🗂️ Nodo 1 (Leader candidate) - Puerto 2379..."
	@etcd --config-file config/etcd/etcd-node1.yaml > logs/cluster/node1.log 2>&1 & echo $! > .pids/etcd-node1.pid
	@sleep 3

	@echo "  🗂️ Nodo 2 (Follower) - Puerto 2389..."
	@etcd --config-file config/etcd/etcd-node2.yaml > logs/cluster/node2.log 2>&1 & echo $! > .pids/etcd-node2.pid
	@sleep 3

	@echo "  🗂️ Nodo 3 (Follower) - Puerto 2399..."
	@etcd --config-file config/etcd/etcd-node3.yaml > logs/cluster/node3.log 2>&1 & echo $! > .pids/etcd-node3.pid
	@sleep 5

	@echo "$(BLUE)🔍 Verificando quorum del cluster...$(NC)"
	@if etcdctl --endpoints=localhost:2379,localhost:2389,localhost:2399 endpoint health; then \
		echo "$(GREEN)✅ Cluster etcd operativo con quorum$(NC)"; \
		echo "$(CYAN)📊 Miembros del cluster:$(NC)"; \
		etcdctl --endpoints=localhost:2379 member list; \
		echo ""; \
		echo "$(GREEN)🎯 Cluster Endpoints:$(NC)"; \
		echo "  🗂️ Nodo 1: http://localhost:2379"; \
		echo "  🗂️ Nodo 2: http://localhost:2389"; \
		echo "  🗂️ Nodo 3: http://localhost:2399"; \
		echo "  🌐 Load Balancer: http://localhost:2379,localhost:2389,localhost:2399"; \
	else \
		echo "$(RED)❌ Error en el cluster, verificando logs...$(NC)"; \
		echo "$(YELLOW)💡 Logs en: logs/cluster/$(NC)"; \
	fi

create-cluster-configs-from-file: ## Usar archivo etcd-cluster-3nodes.yaml (corregido)
	@echo "$(BLUE)📝 Creando configuraciones desde etcd-cluster-3nodes.yaml...$(NC)"
	@if [ -f "config/etcd/etcd-cluster-3nodes.yaml" ]; then \
		echo "$(YELLOW)⚠️  Archivo encontrado, pero necesita corrección para localhost$(NC)"; \
		echo "$(BLUE)💡 Generando versión corregida para localhost...$(NC)"; \
		mkdir -p config/etcd; \
		echo "$(BLUE)  📄 Procesando configuración multi-nodo...$(NC)"; \
		cat > config/etcd/etcd-cluster-3nodes-fixed.yaml << 'EOF'
# Cluster etcd de alta disponibilidad (3 nodos) - CORREGIDO para localhost
# =============================================================================
# NODO 1 - etcd-node1
# =============================================================================
name: etcd-node1
data-dir: ./data/etcd/node1
listen-peer-urls: http://0.0.0.0:2380
listen-client-urls: http://0.0.0.0:2379
advertise-client-urls: http://localhost:2379
initial-advertise-peer-urls: http://localhost:2380

# Configuración del cluster
initial-cluster: etcd-node1=http://localhost:2380,etcd-node2=http://localhost:2390,etcd-node3=http://localhost:2400
initial-cluster-token: axiom-cluster-token
initial-cluster-state: new

# Quorum y consensus
heartbeat-interval: 100
election-timeout: 1000
max-snapshots: 5
max-wals: 5

# Logging
log-level: info
log-outputs: [stderr]
EOF
		echo "$(GREEN)✅ Archivo corregido creado: config/etcd/etcd-cluster-3nodes-fixed.yaml$(NC)"; \
		echo "$(YELLOW)💡 Para usar: make create-cluster-configs (recomendado)$(NC)"; \
	else \
		echo "$(RED)❌ Archivo config/etcd/etcd-cluster-3nodes.yaml no encontrado$(NC)"; \
		echo "$(CYAN)💡 Ejecuta: make create-cluster-configs$(NC)"; \
	fi

dist-cluster-advanced: ## Iniciar cluster usando configuración avanzada
	@echo "$(PURPLE)🏛️ Iniciando Cluster etcd Avanzado (3 nodos HA)$(NC)"
	@echo "$(PURPLE)===============================================$(NC)"
	@echo ""

	@echo "$(BLUE)🔍 Verificando configuraciones...$(NC)"
	@if [ ! -f "config/etcd/etcd-node1.yaml" ]; then \
		echo "$(YELLOW)⚠️  Configuraciones no encontradas, generando...$(NC)"; \
		$(MAKE) -s create-cluster-configs; \
	fi

	@echo "$(BLUE)🧹 Limpiando datos anteriores del cluster...$(NC)"
	@$(MAKE) -s dist-cluster-stop 2>/dev/null || true
	@rm -rf data/etcd/{node1,node2,node3} 2>/dev/null || true
	@mkdir -p data/etcd/{node1,node2,node3} logs/cluster

	@echo "$(BLUE)🚀 Iniciando nodos del cluster (modo avanzado)...$(NC)"
	@echo "  🗂️ Nodo 1 (Bootstrap) - Puerto 2379..."
	@ETCD_UNSUPPORTED_ARCH="$(shell uname -m)" etcd --config-file config/etcd/etcd-node1.yaml > logs/cluster/node1.log 2>&1 & echo $! > .pids/etcd-node1.pid
	@sleep 4

	@echo "  🗂️ Nodo 2 (Join cluster) - Puerto 2389..."
	@ETCD_UNSUPPORTED_ARCH="$(shell uname -m)" etcd --config-file config/etcd/etcd-node2.yaml > logs/cluster/node2.log 2>&1 & echo $! > .pids/etcd-node2.pid
	@sleep 4

	@echo "  🗂️ Nodo 3 (Join cluster) - Puerto 2399..."
	@ETCD_UNSUPPORTED_ARCH="$(shell uname -m)" etcd --config-file config/etcd/etcd-node3.yaml > logs/cluster/node3.log 2>&1 & echo $! > .pids/etcd-node3.pid
	@sleep 6

	@echo "$(BLUE)🔍 Verificando salud del cluster...$(NC)"
	@if etcdctl --endpoints=$(ETCD_CLUSTER_ENDPOINTS) endpoint health 2>/dev/null; then \
		echo "$(GREEN)✅ Cluster etcd HA operativo con quorum$(NC)"; \
		echo ""; \
		echo "$(CYAN)📊 Información del cluster:$(NC)"; \
		etcdctl --endpoints=localhost:2379 member list; \
		echo ""; \
		echo "$(CYAN)🎯 Endpoints del cluster:$(NC)"; \
		echo "  🗂️ Nodo 1: http://localhost:2379 (Leader candidate)"; \
		echo "  🗂️ Nodo 2: http://localhost:2389 (Follower)"; \
		echo "  🗂️ Nodo 3: http://localhost:2399 (Follower)"; \
		echo "  🌐 Load Balancer: $(ETCD_CLUSTER_ENDPOINTS)"; \
		echo ""; \
		echo "$(GREEN)🎉 Cluster listo para service discovery HA$(NC)"; \
	else \
		echo "$(RED)❌ Error en el cluster$(NC)"; \
		echo "$(YELLOW)💡 Verificando logs:$(NC)"; \
		echo "  📋 Nodo 1: logs/cluster/node1.log"; \
		echo "  📋 Nodo 2: logs/cluster/node2.log"; \
		echo "  📋 Nodo 3: logs/cluster/node3.log"; \
		echo "$(BLUE)🔧 Para diagnóstico: make dist-troubleshoot$(NC)"; \
	fi

create-cluster-configs: ## Crear configuraciones para cluster de 3 nodos
	@echo "$(BLUE)📝 Creando configuraciones de cluster etcd (método integrado)...$(NC)"
	@mkdir -p $(ETCD_CONFIG_DIR)

	@echo "$(BLUE)  📄 Configuración Nodo 1 (Leader candidate)...$(NC)"
	@cat > config/etcd/etcd-node1.yaml << 'EOF'
# Nodo 1 del cluster etcd - Leader candidate
name: etcd-node1
data-dir: ./data/etcd/node1

# URLs de cliente (donde los clientes se conectan)
listen-client-urls: http://0.0.0.0:2379
advertise-client-urls: http://localhost:2379

# URLs de peer (comunicación interna cluster)
listen-peer-urls: http://0.0.0.0:2380
initial-advertise-peer-urls: http://localhost:2380

# Configuración del cluster (TODOS los nodos iguales)
initial-cluster: etcd-node1=http://localhost:2380,etcd-node2=http://localhost:2390,etcd-node3=http://localhost:2400
initial-cluster-token: axiom-cluster-ha-token
initial-cluster-state: new

# Configuración de consenso Raft
heartbeat-interval: 100
election-timeout: 1000
max-snapshots: 5
max-wals: 5

# Logging
log-level: info
log-outputs: [stderr]

# Configuración de rendimiento
quota-backend-bytes: 2147483648
max-request-bytes: 1572864
EOF

	@echo "$(BLUE)  📄 Configuración Nodo 2 (Follower)...$(NC)"
	@cat > config/etcd/etcd-node2.yaml << 'EOF'
# Nodo 2 del cluster etcd - Follower
name: etcd-node2
data-dir: ./data/etcd/node2

# URLs de cliente
listen-client-urls: http://0.0.0.0:2389
advertise-client-urls: http://localhost:2389

# URLs de peer
listen-peer-urls: http://0.0.0.0:2390
initial-advertise-peer-urls: http://localhost:2390

# Configuración del cluster (IDÉNTICA para todos)
initial-cluster: etcd-node1=http://localhost:2380,etcd-node2=http://localhost:2390,etcd-node3=http://localhost:2400
initial-cluster-token: axiom-cluster-ha-token
initial-cluster-state: new

# Configuración de consenso Raft
heartbeat-interval: 100
election-timeout: 1000
max-snapshots: 5
max-wals: 5

# Logging
log-level: info
log-outputs: [stderr]

# Configuración de rendimiento
quota-backend-bytes: 2147483648
max-request-bytes: 1572864
EOF

	@echo "$(BLUE)  📄 Configuración Nodo 3 (Follower)...$(NC)"
	@cat > config/etcd/etcd-node3.yaml << 'EOF'
# Nodo 3 del cluster etcd - Follower
name: etcd-node3
data-dir: ./data/etcd/node3

# URLs de cliente
listen-client-urls: http://0.0.0.0:2399
advertise-client-urls: http://localhost:2399

# URLs de peer
listen-peer-urls: http://0.0.0.0:2400
initial-advertise-peer-urls: http://localhost:2400

# Configuración del cluster (IDÉNTICA para todos)
initial-cluster: etcd-node1=http://localhost:2380,etcd-node2=http://localhost:2390,etcd-node3=http://localhost:2400
initial-cluster-token: axiom-cluster-ha-token
initial-cluster-state: new

# Configuración de consenso Raft
heartbeat-interval: 100
election-timeout: 1000
max-snapshots: 5
max-wals: 5

# Logging
log-level: info
log-outputs: [stderr]

# Configuración de rendimiento
quota-backend-bytes: 2147483648
max-request-bytes: 1572864
EOF

	@echo "$(GREEN)✅ Configuraciones de cluster creadas en:$(NC)"
	@echo "   📄 config/etcd/etcd-node1.yaml (2379/2380)"
	@echo "   📄 config/etcd/etcd-node2.yaml (2389/2390)"
	@echo "   📄 config/etcd/etcd-node3.yaml (2399/2400)"
	@echo ""
	@echo "$(CYAN)💡 Cluster endpoints: localhost:2379,localhost:2389,localhost:2399$(NC)"

dist-cluster-status: ## Estado del cluster etcd HA
	@echo "$(CYAN)📊 Estado Cluster etcd HA$(NC)"
	@echo "$(CYAN)==========================$(NC)"
	@echo ""

	@echo "$(YELLOW)🔍 Verificando nodos individuales:$(NC)"
	@for port in 2379 2389 2399; do \
		if curl -s http://localhost:$port/health > /dev/null 2>&1; then \
			echo "  Nodo puerto $port: $(GREEN)✅ Activo$(NC)"; \
		else \
			echo "  Nodo puerto $port: $(RED)⭕ Inactivo$(NC)"; \
		fi \
	done

	@echo ""
	@echo "$(YELLOW)🏛️ Estado del cluster:$(NC)"
	@if etcdctl --endpoints=localhost:2379,localhost:2389,localhost:2399 endpoint health 2>/dev/null; then \
		echo "$(GREEN)✅ Cluster operativo$(NC)"; \
		echo ""; \
		echo "$(YELLOW)👥 Miembros del cluster:$(NC)"; \
		etcdctl --endpoints=localhost:2379 member list; \
		echo ""; \
		echo "$(YELLOW)🎯 Leader actual:$(NC)"; \
		etcdctl --endpoints=localhost:2379,localhost:2389,localhost:2399 endpoint status --write-out=table; \
	else \
		echo "$(RED)❌ Cluster no operativo$(NC)"; \
	fi

dist-cluster-stop: ## Detener cluster etcd HA
	@echo "$(YELLOW)🛑 Deteniendo cluster etcd HA...$(NC)"
	@for node in node1 node2 node3; do \
		if [ -f .pids/etcd-$node.pid ]; then \
			echo "  🛑 Deteniendo $node..."; \
			kill $(cat .pids/etcd-$node.pid) 2>/dev/null || true; \
			rm -f .pids/etcd-$node.pid; \
		fi \
	done
	@pkill -f "etcd.*etcd-node" 2>/dev/null || true
	@echo "$(GREEN)✅ Cluster detenido$(NC)"

dist-cluster-test: ## Probar tolerancia a fallos del cluster
	@echo "$(BLUE)🧪 Probando Tolerancia a Fallos del Cluster$(NC)"
	@echo "$(BLUE)===========================================$(NC)"
	@echo ""

	@echo "$(YELLOW)1. 📝 Escribiendo datos de prueba...$(NC)"
	@etcdctl --endpoints=localhost:2379 put /test/ha "cluster-working" || exit 1
	@echo "   ✅ Datos escritos en cluster"

	@echo ""
	@echo "$(YELLOW)2. 📖 Leyendo desde diferentes nodos...$(NC)"
	@for port in 2379 2389 2399; do \
		value=$(etcdctl --endpoints=localhost:$port get /test/ha --print-value-only 2>/dev/null); \
		echo "   Nodo $port: $value"; \
	done

	@echo ""
	@echo "$(YELLOW)3. 💀 Simulando fallo de un nodo...$(NC)"
	@if [ -f .pids/etcd-node2.pid ]; then \
		echo "   🔥 Matando nodo 2 (puerto 2389)..."; \
		kill $(cat .pids/etcd-node2.pid) 2>/dev/null || true; \
		rm -f .pids/etcd-node2.pid; \
		sleep 3; \
	fi

	@echo ""
	@echo "$(YELLOW)4. 🔍 Verificando que el cluster sigue operativo...$(NC)"
	@if etcdctl --endpoints=localhost:2379,localhost:2399 get /test/ha > /dev/null 2>&1; then \
		echo "   $(GREEN)✅ Cluster sobrevivió al fallo de un nodo$(NC)"; \
		echo "   $(GREEN)✅ Quorum mantenido (2/3 nodos)$(NC)"; \
	else \
		echo "   $(RED)❌ Cluster falló$(NC)"; \
	fi

	@echo ""
	@echo "$(BLUE)💡 Para restaurar el nodo: make dist-cluster$(NC)"

dist-troubleshoot: ## Diagnosticar problemas del backbone distribuido
	@echo "$(BLUE)🔧 Diagnóstico del Backbone Distribuido$(NC)"
	@echo "$(BLUE)======================================$(NC)"
	@echo ""

	@echo "$(YELLOW)🔍 1. Verificando puertos etcd:$(NC)"
	@for port in 2379 2380; do \
		if lsof -i:$port > /dev/null 2>&1; then \
			process=$(lsof -i:$port | tail -1 | awk '{print $1 " (PID " $2 ")"}'); \
			echo "  Puerto $port: $(GREEN)✅ En uso$(NC) - $process"; \
		else \
			echo "  Puerto $port: $(RED)⭕ Libre$(NC)"; \
		fi \
	done

	@echo ""
	@echo "$(YELLOW)🔍 2. Verificando procesos etcd:$(NC)"
	@if pgrep -f "etcd.*config-file" > /dev/null; then \
		echo "  $(GREEN)✅ Proceso etcd encontrado:$(NC)"; \
		ps aux | grep -E "etcd.*config-file" | grep -v grep | awk '{print "    PID " $2 ": " $11}'; \
	else \
		echo "  $(RED)❌ No hay procesos etcd corriendo$(NC)"; \
	fi

	@echo ""
	@echo "$(YELLOW)🔍 3. Verificando conectividad API:$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "  $(GREEN)✅ API etcd responde$(NC) ($(ETCD_ENDPOINT))"; \
		version=$(curl -s $(ETCD_ENDPOINT)/version | jq -r '.etcdserver' 2>/dev/null || echo "N/A"); \
		echo "    Versión: $version"; \
	else \
		echo "  $(RED)❌ API etcd no responde$(NC) ($(ETCD_ENDPOINT))"; \
	fi

	@echo ""
	@echo "$(YELLOW)🔍 4. Verificando Docker:$(NC)"
	@if docker info > /dev/null 2>&1; then \
		echo "  $(GREEN)✅ Docker disponible$(NC)"; \
		if docker ps --filter name=etcd-browser --format "table {{.Names}}\t{{.Status}}" | grep -q etcd-browser; then \
			echo "  $(GREEN)✅ UI etcd corriendo$(NC)"; \
		else \
			echo "  $(YELLOW)⚠️  UI etcd no corriendo$(NC)"; \
		fi \
	else \
		echo "  $(RED)❌ Docker no disponible$(NC)"; \
	fi

	@echo ""
	@echo "$(YELLOW)💡 Soluciones recomendadas:$(NC)"
	@if ! pgrep -f "etcd.*config-file" > /dev/null; then \
		echo "  $(CYAN)make dist-start$(NC)          # Iniciar etcd"; \
	fi
	@if pgrep -f "etcd.*config-file" > /dev/null && ! curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "  $(CYAN)make dist-reset$(NC)          # Reset completo si hay conflictos"; \
	fi
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "  $(CYAN)make dist-register$(NC)       # Re-registrar servicios"; \
		echo "  $(CYAN)make dist-ui$(NC)             # Iniciar UI web"; \
	fi

dist-clean: dist-reset ## Limpiar datos distribuidos + UI
	@echo "$(YELLOW)🧹 Limpiando datos distribuidos...$(NC)"
	@rm -rf $(ETCD_DATA_DIR)/* $(ETCD_LOG_DIR)/etcd.log 2>/dev/null || true
	@echo "$(GREEN)✅ Limpieza distribuida completada$(NC)"

dist-register: ## Re-registrar servicios V3.1 en etcd
	@echo "$(BLUE)📝 Re-registrando servicios V3.1 en backbone...$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		chmod +x $(SERVICE_DISCOVERY_SCRIPT); \
		echo "  🕵️  Registrando axiom-sniffer..."; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-sniffer localhost 5559 120; \
		echo "  🌍 Registrando axiom-geoip..."; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-geoip localhost 5560 120; \
		echo "  🤖 Registrando axiom-ml..."; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-ml localhost 5561 120; \
		echo "  🎯 Registrando axiom-scheduler..."; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-scheduler localhost 5561 120; \
		echo "  🛡️  Registrando axiom-firewall..."; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-firewall localhost 5562 120; \
		echo "  📊 Registrando axiom-dashboard..."; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-dashboard localhost 8080 120; \
		echo "$(GREEN)✅ Servicios V3.1 re-registrados (incluyendo scheduler)$(NC)"; \
	else \
		echo "$(RED)❌ etcd no disponible$(NC)"; \
		exit 1; \
	fi

dist-quick: dist-setup dist-start ## Setup distribuido completo
	@echo ""
	@echo "$(GREEN)🎉 SETUP DISTRIBUIDO COMPLETADO$(NC)"
	@echo "$(GREEN)================================$(NC)"
	@echo "$(YELLOW)Backbone etcd operativo y listo para servicios$(NC)"
	@echo ""
	@echo "$(CYAN)🔍 Próximos pasos:$(NC)"
	@echo "  $(GREEN)make start_v31$(NC)         # Iniciar pipeline V3.1"
	@echo "  $(CYAN)make dist-discover$(NC)      # Ver servicios"
	@echo "  $(CYAN)make dist-watch$(NC)         # Monitorear en tiempo real"

dist-dev: dist-quick start_v31 ## Setup completo distribuido + V3.1
	@echo ""
	@echo "$(GREEN)🚀 MODO DISTRIBUIDO + V3.1 OPERATIVO$(NC)"
	@echo "$(GREEN)=====================================$(NC)"
	@echo "$(YELLOW)Sistema completo con backbone distribuido$(NC)"
	@sleep 3

	@echo "$(BLUE)🔍 Verificando servicios registrados...$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		make dist-discover; \
	else \
		echo "$(YELLOW)⚠️  Service discovery no disponible$(NC)"; \
		echo "$(BLUE)💡 Para habilitarlo: make dist-reset && make dist-start$(NC)"; \
		echo "$(PURPLE)💡 Para HA: make dist-cluster$(NC)"; \
	fi

	@make show-dashboard

	@echo ""
	@echo "$(BLUE)🌐 Iniciando UI web para etcd...$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		make dist-ui; \
		echo ""; \
		echo "$(GREEN)🎉 ECOSISTEMA COMPLETO OPERATIVO:$(NC)"; \
		echo "$(CYAN)📊 Dashboard V3.1: http://localhost:8080$(NC)"; \
		echo "$(CYAN)🗂️ etcd UI: http://localhost:8081$(NC)"; \
		echo "$(CYAN)🔍 Para info detallada: make dist-info$(NC)"; \
		echo "$(PURPLE)🏛️ Para alta disponibilidad: make dist-cluster$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  UI etcd no disponible (requiere backbone)$(NC)"; \
		echo ""; \
		echo "$(GREEN)🎉 SISTEMA V3.1 OPERATIVO (modo local):$(NC)"; \
		echo "$(CYAN)📊 Dashboard V3.1: http://localhost:8080$(NC)"; \
		echo "$(CYAN)🔧 Para modo distribuido: make dist-reset && make dist-dev$(NC)"; \
		echo "$(PURPLE)🏛️ Para alta disponibilidad: make dist-cluster$(NC)"; \
	fi

dist-ha: dist-cluster start_v31 ## Setup completo HA + V3.1 (3 nodos etcd)
	@echo ""
	@echo "$(PURPLE)🏛️ MODO ALTA DISPONIBILIDAD + V3.1 OPERATIVO$(NC)"
	@echo "$(PURPLE)============================================$(NC)"
	@echo "$(YELLOW)Sistema enterprise con cluster etcd HA$(NC)"
	@sleep 3

	@echo "$(BLUE)🔍 Registrando servicios en cluster HA...$(NC)"
	@make dist-register-cluster

	@echo "$(BLUE)🔍 Verificando servicios distribuidos...$(NC)"
	@make dist-discover

	@make show-dashboard

	@echo ""
	@echo "$(BLUE)🌐 Iniciando UI web para cluster...$(NC)"
	@make dist-ui

	@echo ""
	@echo "$(PURPLE)🎉 ECOSISTEMA HA COMPLETO OPERATIVO:$(NC)"
	@echo "$(CYAN)📊 Dashboard V3.1: http://localhost:8080$(NC)"
	@echo "$(CYAN)🗂️ etcd UI: http://localhost:8081$(NC)"
	@echo "$(CYAN)🏛️ Cluster Status: make dist-cluster-status$(NC)"
	@echo "$(CYAN)💀 Test Failover: make dist-cluster-test$(NC)"

dist-register-cluster: ## Re-registrar servicios V3.1 en cluster HA
	@echo "$(BLUE)📝 Re-registrando servicios V3.1 en cluster HA...$(NC)"
	@if etcdctl --endpoints=$(ETCD_CLUSTER_ENDPOINTS) endpoint health > /dev/null 2>&1; then \
		chmod +x $(SERVICE_DISCOVERY_SCRIPT); \
		echo "  🕵️  Registrando axiom-sniffer en cluster..."; \
		ETCD_ENDPOINTS="$(ETCD_CLUSTER_ENDPOINTS)" $(SERVICE_DISCOVERY_SCRIPT) register axiom-sniffer localhost 5559 120; \
		echo "  🌍 Registrando axiom-geoip en cluster..."; \
		ETCD_ENDPOINTS="$(ETCD_CLUSTER_ENDPOINTS)" $(SERVICE_DISCOVERY_SCRIPT) register axiom-geoip localhost 5560 120; \
		echo "  🤖 Registrando axiom-ml en cluster..."; \
		ETCD_ENDPOINTS="$(ETCD_CLUSTER_ENDPOINTS)" $(SERVICE_DISCOVERY_SCRIPT) register axiom-ml localhost 5561 120; \
		echo "  🎯 Registrando axiom-scheduler en cluster..."; \
		ETCD_ENDPOINTS="$(ETCD_CLUSTER_ENDPOINTS)" $(SERVICE_DISCOVERY_SCRIPT) register axiom-scheduler localhost 5561 120; \
		echo "  🛡️  Registrando axiom-firewall en cluster..."; \
		ETCD_ENDPOINTS="$(ETCD_CLUSTER_ENDPOINTS)" $(SERVICE_DISCOVERY_SCRIPT) register axiom-firewall localhost 5562 120; \
		echo "  📊 Registrando axiom-dashboard en cluster..."; \
		ETCD_ENDPOINTS="$(ETCD_CLUSTER_ENDPOINTS)" $(SERVICE_DISCOVERY_SCRIPT) register axiom-dashboard localhost 8080 120; \
		echo "$(GREEN)✅ Servicios V3.1 registrados en cluster HA$(NC)"; \
	else \
		echo "$(RED)❌ Cluster etcd no disponible$(NC)"; \
		exit 1; \
	fi

# =============================================================================
# SETUP Y CONFIGURACIÓN (Existente pero mejorado)
# =============================================================================
setup:
	@echo "$(BLUE)🔧 Configurando entorno virtual V3.1 + Distribuido...$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "$(YELLOW)⚠️  Entorno virtual ya existe$(NC)"; \
	else \
		$(PYTHON) -m venv $(VENV_NAME); \
		echo "$(GREEN)✅ Entorno virtual creado$(NC)"; \
	fi
	@$(ACTIVATE) && $(PYTHON_VENV) -m pip install --upgrade pip
	@mkdir -p $(PIDS_DIR) $(LOGS_DIR) $(CONFIG_DIR) $(ETCD_CONFIG_DIR) $(ETCD_DATA_DIR)
	@echo "$(GREEN)✅ Setup completado$(NC)"

install: setup
	@echo "$(BLUE)📦 Instalando dependencias V3.1 + Distribuido...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install -r requirements.txt || echo "$(YELLOW)⚠️  requirements.txt no encontrado$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install zmq psutil geoip2 protobuf requests scapy netifaces
	@$(ACTIVATE) && $(PIP_VENV) install joblib scikit-learn xgboost lightgbm pandas numpy
	@$(ACTIVATE) && $(PIP_VENV) install fastapi uvicorn websockets flask
	@$(ACTIVATE) && $(PIP_VENV) install grpcio-tools
	@echo "$(GREEN)✅ Dependencias instaladas$(NC)"

# =============================================================================
# SISTEMA V3.1 EVOLUTIVO (Existente - sin cambios)
# =============================================================================
start_v31: install verify-protobuf-compiled-v31 create-configs-v31 stop
	@echo "$(GREEN)🚀 Iniciando Sistema Autoinmune Digital V3.1 EVOLUTIVO...$(NC)"
	@echo "$(CYAN)========================================================$(NC)"
	@echo "$(PURPLE)Pipeline V3.1: evolutionary_sniffer → geoip → ml_tricapa → scheduler → firewall → dashboard$(NC)"
	@echo ""

	@echo "$(BLUE)1. 🛡️  Firewall Agent V3.1...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT_V31) $(FIREWALL_AGENT_CONFIG_V31) $(FIREWALL_RULES_V31) > $(FIREWALL_LOG_V31) 2>&1 & echo $$! > $(FIREWALL_PID_V31)
	@sleep 3

	@echo "$(BLUE)2. 🕵️  Evolutionary Sniffer V3.1 → Puerto $(CAPTURE_PORT_V31)...$(NC)"
	@sudo bash -c '$(PYTHON_VENV) $(EVOLUTIONARY_SNIFFER_V31) $(EVOLUTIONARY_SNIFFER_CONFIG_V31) > $(EVOLUTIONARY_SNIFFER_LOG_V31) 2>&1 & echo $$! > $(EVOLUTIONARY_SNIFFER_PID_V31)'
	@sleep 3

	@echo "$(BLUE)3. 🌍 GeoIP Enricher V3.1 ($(CAPTURE_PORT_V31) → $(GEOIP_PORT_V31))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER_V31) $(GEOIP_ENRICHER_CONFIG_V31) > $(GEOIP_LOG_V31) 2>&1 & echo $$! > $(GEOIP_PID_V31)
	@sleep 3

	@echo "$(BLUE)4. 🤖 ML Detector Tricapa V3.1 ($(GEOIP_PORT_V31) → $(ML_PORT_V31) + $(DASHBOARD_PORT_V31))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR_TRICAPA_V31) $(ML_DETECTOR_TRICAPA_CONFIG_V31) > $(ML_TRICAPA_LOG_V31) 2>&1 & echo $$! > $(ML_TRICAPA_PID_V31)
	@sleep 3

	@echo "$(BLUE)5. 🎯 Scheduler Firewall ($(ML_PORT_V31) → Orquestación)...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(SCHEDULER_FIREWALL) $(SCHEDULER_FIREWALL_CONFIG) $(FIREWALL_RULES_V31) > $(SCHEDULER_LOG) 2>&1 & echo $$! > $(SCHEDULER_PID)
	@sleep 3

	@echo "$(BLUE)6. 📊 Dashboard V3.1 (Puerto $(DASHBOARD_PORT_V31) → Web $(DASHBOARD_WEB_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD_V31) $(DASHBOARD_CONFIG_V31) $(FIREWALL_RULES_V31) > $(DASHBOARD_LOG_V31) 2>&1 & echo $$! > $(DASHBOARD_PID_V31)
	@sleep 5

	# Registrar servicios en etcd si está disponible
	@echo "$(BLUE)7. 📝 Verificando backbone distribuido...$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "$(GREEN)✅ Backbone disponible, registrando servicios...$(NC)"; \
		chmod +x $(SERVICE_DISCOVERY_SCRIPT); \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-sniffer localhost $(CAPTURE_PORT_V31) 120; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-geoip localhost $(GEOIP_PORT_V31) 120; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-ml localhost $(ML_PORT_V31) 120; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-scheduler localhost $(ML_PORT_V31) 120; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-firewall localhost $(FIREWALL_PORT_V31) 120; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-dashboard localhost $(DASHBOARD_WEB_PORT) 120; \
		echo "$(GREEN)✅ Servicios registrados en backbone (incluyendo scheduler)$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  Backbone distribuido no disponible$(NC)"; \
		echo "$(BLUE)💡 Para habilitar service discovery:$(NC)"; \
		echo "   $(CYAN)make dist-reset && make dist-start$(NC)"; \
		echo "$(YELLOW)   Continuando en modo local...$(NC)"; \
	fi

	@echo ""
	@echo "$(GREEN)🎉 SISTEMA V3.1 EVOLUTIVO OPERACIONAL$(NC)"
	@echo "$(CYAN)=====================================$(NC)"
	@echo "$(YELLOW)📊 Dashboard V3.1: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@echo "$(YELLOW)🔧 Monitor V3.1: make monitor_v31$(NC)"
	@echo "$(YELLOW)📋 Estado V3.1: make status_v31$(NC)"
	@echo "$(YELLOW)🔍 Servicios distribuidos: make dist-discover$(NC)"
	@echo ""
	@$(MAKE) status_v31

# =============================================================================
# PARADAS (NUCLEAR MEJORADO)
# =============================================================================
stop:
	@echo "$(YELLOW)🛑 Deteniendo sistemas (V3.1 + demo + distribuido)...$(NC)"

	# Detener PIDs V3.1
	@-if [ -f $(DASHBOARD_PID_V31) ]; then echo "📊 Deteniendo Dashboard V3.1..."; kill $$(cat $(DASHBOARD_PID_V31)) 2>/dev/null || true; rm -f $(DASHBOARD_PID_V31); fi
	@-if [ -f $(SCHEDULER_PID) ]; then echo "🎯 Deteniendo Scheduler..."; kill $$(cat $(SCHEDULER_PID)) 2>/dev/null || true; rm -f $(SCHEDULER_PID); fi
	@-if [ -f $(ML_TRICAPA_PID_V31) ]; then echo "🤖 Deteniendo ML Tricapa V3.1..."; kill $$(cat $(ML_TRICAPA_PID_V31)) 2>/dev/null || true; rm -f $(ML_TRICAPA_PID_V31); fi
	@-if [ -f $(GEOIP_PID_V31) ]; then echo "🌍 Deteniendo GeoIP V3.1..."; kill $$(cat $(GEOIP_PID_V31)) 2>/dev/null || true; rm -f $(GEOIP_PID_V31); fi
	@-if [ -f $(EVOLUTIONARY_SNIFFER_PID_V31) ]; then echo "🕵️  Deteniendo Evolutionary Sniffer V3.1..."; kill $$(cat $(EVOLUTIONARY_SNIFFER_PID_V31)) 2>/dev/null || true; sudo kill $$(cat $(EVOLUTIONARY_SNIFFER_PID_V31)) 2>/dev/null || true; rm -f $(EVOLUTIONARY_SNIFFER_PID_V31); fi
	@-if [ -f $(FIREWALL_PID_V31) ]; then echo "🛡️  Deteniendo Firewall V3.1..."; kill $$(cat $(FIREWALL_PID_V31)) 2>/dev/null || true; rm -f $(FIREWALL_PID_V31); fi

	# Detener PIDs Demo
	@-if [ -f $(DASHBOARD_PID_DEMO) ]; then echo "📊 Deteniendo Dashboard Demo..."; kill $$(cat $(DASHBOARD_PID_DEMO)) 2>/dev/null || true; rm -f $(DASHBOARD_PID_DEMO); fi
	@-if [ -f $(ML_PID_DEMO) ]; then echo "🤖 Deteniendo ML Demo..."; kill $$(cat $(ML_PID_DEMO)) 2>/dev/null || true; rm -f $(ML_PID_DEMO); fi
	@-if [ -f $(GEOIP_PID_DEMO) ]; then echo "🌍 Deteniendo GeoIP Demo..."; kill $$(cat $(GEOIP_PID_DEMO)) 2>/dev/null || true; rm -f $(GEOIP_PID_DEMO); fi
	@-if [ -f $(PROMISCUOUS_PID_DEMO) ]; then echo "🕵️  Deteniendo Promiscuous Demo..."; kill $$(cat $(PROMISCUOUS_PID_DEMO)) 2>/dev/null || true; sudo kill $$(cat $(PROMISCUOUS_PID_DEMO)) 2>/dev/null || true; rm -f $(PROMISCUOUS_PID_DEMO); fi
	@-if [ -f $(FIREWALL_PID_DEMO) ]; then echo "🛡️  Deteniendo Firewall Demo..."; kill $$(cat $(FIREWALL_PID_DEMO)) 2>/dev/null || true; rm -f $(FIREWALL_PID_DEMO); fi

	# pkill por patrón
	@-pkill -f "dashboard_v31\|evolutionary_sniffer_v31\|geoip_enricher_v31\|ml_detector_tricapa_v31\|scheduler-firewall\|simple_firewall_agent_v31" 2>/dev/null || true
	@-pkill -f "promiscuous_agent\|geoip_enricher\|lightweight_ml_detector\|real_zmq_dashboard\|simple_firewall_agent" 2>/dev/null || true
	@-sudo pkill -f "evolutionary_sniffer_v31\|promiscuous_agent" 2>/dev/null || true

	@echo "$(GREEN)✅ Sistemas V3.1 + demo detenidos$(NC)"
	@echo "$(YELLOW)💡 Para detener backbone distribuido: make dist-stop$(NC)"

stop-nuclear:
	@echo "$(RED)☢️  PARADA NUCLEAR ULTRA - TODO EL ECOSISTEMA ☢️$(NC)"
	@echo "$(RED)================================================$(NC)"
	@echo "$(RED)⚠️  EXTERMINACIÓN: V3.1 + Demo + Distribuido$(NC)"
	@echo ""

	# Detener sistemas normales primero
	@$(MAKE) stop 2>/dev/null || true
	@$(MAKE) dist-stop 2>/dev/null || true

	# Nuclear específico
	@echo "$(YELLOW)💀 Fase Nuclear: Eliminación total...$(NC)"
	@-pkill -9 -f "python.*core/" 2>/dev/null || true
	@-sudo pkill -9 -f "python.*core/" 2>/dev/null || true
	@-pkill -9 -f "etcd" 2>/dev/null || true

	# Liberar puertos
	@for port in $(CAPTURE_PORT_V31) $(GEOIP_PORT_V31) $(ML_PORT_V31) $(FIREWALL_PORT_V31) $(DASHBOARD_PORT_V31) $(DASHBOARD_WEB_PORT) 2379 2380; do \
		PIDS=$$(lsof -ti:$$port 2>/dev/null); \
		if [ ! -z "$$PIDS" ]; then \
			echo "💀 Liberando puerto $$port..."; \
			echo "$$PIDS" | xargs -r kill -9 2>/dev/null || echo "$$PIDS" | xargs -r sudo kill -9 2>/dev/null || true; \
		fi \
	done

	@-rm -rf $(PIDS_DIR)/*.pid
	@echo ""
	@echo "$(GREEN)☢️  PARADA NUCLEAR COMPLETADA ☢️$(NC)"
	@echo "$(GREEN)Todo el ecosistema eliminado - listo para reinicio$(NC)"

# =============================================================================
# MONITORIZACIÓN INTEGRADA
# =============================================================================
status_v31:
	@echo "$(CYAN)📊 Estado Sistema V3.1 Evolutivo$(NC)"
	@echo "$(CYAN)=================================$(NC)"
	@pgrep -f "$(FIREWALL_AGENT_V31)" >/dev/null && echo "  🛡️  Firewall Agent V3.1: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🛡️  Firewall Agent V3.1: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "evolutionary_sniffer_v31" >/dev/null && echo "  🕵️  Evolutionary Sniffer V3.1: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🕵️  Evolutionary Sniffer V3.1: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "geoip_enricher_v31" >/dev/null && echo "  🌍 GeoIP Enricher V3.1: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🌍 GeoIP Enricher V3.1: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "ml_detector_tricapa_v31" >/dev/null && echo "  🤖 ML Detector Tricapa V3.1: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🤖 ML Detector Tricapa V3.1: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "scheduler-firewall" >/dev/null && echo "  🎯 Scheduler Firewall: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🎯 Scheduler Firewall: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "dashboard_v31" >/dev/null && echo "  📊 Dashboard V3.1: $(GREEN)✅ Ejecutándose$(NC) $(YELLOW)(http://localhost:$(DASHBOARD_WEB_PORT))$(NC)" || echo "  📊 Dashboard V3.1: $(RED)⭕ Detenido$(NC)"

	# Mostrar estado distribuido si está disponible
	@echo ""
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "$(CYAN)🌐 Backbone Distribuido:$(NC)"; \
		echo "  🗂️  etcd: $(GREEN)✅ Operativo$(NC) ($(ETCD_ENDPOINT))"; \
		servicios=$$(etcdctl --endpoints=$(ETCD_ENDPOINT) get /services/ --prefix --keys-only | grep -c /services/ || echo 0); \
		echo "  📝 Servicios registrados: $$servicios"; \
	else \
		echo "$(CYAN)🌐 Backbone Distribuido: $(YELLOW)⚠️  No disponible$(NC)"; \
	fi

# =============================================================================
# COMANDOS RÁPIDOS MEJORADOS
# =============================================================================
quick_v31: setup install setup-perms create-configs-v31 compile-protobuf-v31 start_v31 show-dashboard
	@echo ""
	@echo "$(GREEN)🎉 QUICK START V3.1 EVOLUTIVO COMPLETADO$(NC)"
	@echo "$(GREEN)=========================================$(NC)"
	@echo "$(YELLOW)Sistema Autoinmune Digital V3.1 100% operativo!$(NC)"
	@echo ""
	@echo "$(CYAN)📊 Dashboard V3.1: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@echo "$(CYAN)🔧 Monitor V3.1: make monitor_v31$(NC)"
	@echo "$(CYAN)📋 Estado V3.1: make status_v31$(NC)"
	@echo "$(CYAN)🌐 Para modo distribuido: make dist-quick$(NC)"

# =============================================================================
# PROTOBUF V3.1
# =============================================================================
compile-protobuf-v31:
	@echo "$(BLUE)🔧 Compilando Protobuf V3.1...$(NC)"
	@if [ ! -d "$(PROTOBUF_DIR)" ]; then \
		echo "$(RED)❌ Directorio $(PROTOBUF_DIR) no existe$(NC)"; \
		exit 1; \
	fi
	@if [ -f "$(SCHEMA_NETWORK_V31)" ]; then \
		echo "  🔧 Compilando $(SCHEMA_NETWORK_V31)"; \
		$(ACTIVATE) && protoc --python_out=$(PROTOBUF_DIR) --proto_path=$(PROTOBUF_DIR) $(SCHEMA_NETWORK_V31) || exit 1; \
	else \
		echo "$(RED)❌ $(SCHEMA_NETWORK_V31) no encontrado$(NC)"; \
		exit 1; \
	fi
	@if [ -f "$(SCHEMA_FIREWALL_V31)" ]; then \
		echo "  🔧 Compilando $(SCHEMA_FIREWALL_V31)"; \
		$(ACTIVATE) && protoc --python_out=$(PROTOBUF_DIR) --proto_path=$(PROTOBUF_DIR) $(SCHEMA_FIREWALL_V31) || exit 1; \
	else \
		echo "$(YELLOW)⚠️  $(SCHEMA_FIREWALL_V31) no encontrado, usando versión estándar$(NC)"; \
	fi
	@echo "$(GREEN)✅ Compilación Protobuf V3.1 completada$(NC)"

verify-protobuf-compiled-v31:
	@echo "$(BLUE)🔍 Verificando Protobuf V3.1 compilados...$(NC)"
	@if [ -f "$(PROTOBUF_DIR)/network_security_clean_v31_pb2.py" ]; then \
		echo "$(GREEN)✅ network_security_clean_v31_pb2.py$(NC)"; \
	else \
		echo "$(RED)❌ network_security_clean_v31_pb2.py falta - ejecutando compilación$(NC)"; \
		$(MAKE) compile-protobuf-v31; \
	fi

check-protobuf-v31:
	@echo "$(BLUE)🔍 Verificando protobuf V3.1...$(NC)"
	@$(MAKE) verify-protobuf-compiled-v31

# =============================================================================
# CONFIGURACIONES V3.1
# =============================================================================
create-configs-v31:
	@echo "$(BLUE)📁 Creando configuraciones V3.1...$(NC)"
	@mkdir -p $(CONFIG_DIR)

	@echo "$(BLUE)📝 Creando configuración evolutionary_sniffer_v31...$(NC)"
	@test -f $(EVOLUTIONARY_SNIFFER_CONFIG_V31) || echo '{"interface": "en0", "capture_filter": "", "output_port": 5559, "log_level": "INFO", "version": "v3.1", "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-sniffer", "ttl": 120}}' > $(EVOLUTIONARY_SNIFFER_CONFIG_V31)

	@echo "$(BLUE)📝 Creando configuración geoip_enricher_v31...$(NC)"
	@test -f $(GEOIP_ENRICHER_CONFIG_V31) || echo '{"input_port": 5559, "output_port": 5560, "geoip_db_path": "GeoLite2-City.mmdb", "log_level": "INFO", "version": "v3.1", "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-geoip", "ttl": 120}}' > $(GEOIP_ENRICHER_CONFIG_V31)

	@echo "$(BLUE)📝 Creando configuración ml_detector_tricapa_v31...$(NC)"
	@test -f $(ML_DETECTOR_TRICAPA_CONFIG_V31) || echo '{"input_port": 5560, "output_port": 5561, "dashboard_port": 5580, "models_path": "models/production/tricapa/", "tricapa_enabled": true, "ensemble_confidence": true, "log_level": "INFO", "version": "v3.1", "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-ml", "ttl": 120}}' > $(ML_DETECTOR_TRICAPA_CONFIG_V31)

	@echo "$(BLUE)📝 Creando configuración scheduler_firewall...$(NC)"
	@test -f $(SCHEDULER_FIREWALL_CONFIG) || echo '{"input_port": 5561, "firewall_port": 5562, "rules_file": "config/json/firewall_rules_v31.json", "log_level": "INFO", "version": "v3.1", "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-scheduler", "ttl": 120}}' > $(SCHEDULER_FIREWALL_CONFIG)

	@echo "$(BLUE)📝 Creando configuración firewall_agent_v31...$(NC)"
	@test -f $(FIREWALL_AGENT_CONFIG_V31) || echo '{"agent_id": "firewall_v31_001", "port": 5562, "rules_file": "config/json/firewall_rules_v31.json", "enabled": true, "log_level": "INFO", "version": "v3.1", "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-firewall", "ttl": 120}}' > $(FIREWALL_AGENT_CONFIG_V31)

	@echo "$(BLUE)📝 Creando configuración dashboard_v31...$(NC)"
	@test -f $(DASHBOARD_CONFIG_V31) || echo '{"port": 8080, "ml_input_port": 5580, "host": "localhost", "debug": false, "firewall_integration": true, "version": "v3.1", "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-dashboard", "ttl": 120}}' > $(DASHBOARD_CONFIG_V31)

	@echo "$(BLUE)📝 Creando reglas firewall V3.1...$(NC)"
	@test -f $(FIREWALL_RULES_V31) || echo '{"firewall_rules": {"rules": [], "manual_actions": {}, "firewall_agents": {}, "global_settings": {"version": "v3.1", "auto_block": true, "confidence_threshold": 0.8, "distributed_mode": true}}}' > $(FIREWALL_RULES_V31)

	@echo "$(GREEN)✅ Configuraciones V3.1 creadas con soporte distribuido$(NC)"

verify-configs-v31:
	@echo "$(BLUE)🔍 Verificando configuraciones V3.1...$(NC)"
	@for config in $(EVOLUTIONARY_SNIFFER_CONFIG_V31) $(GEOIP_ENRICHER_CONFIG_V31) $(ML_DETECTOR_TRICAPA_CONFIG_V31) $(SCHEDULER_FIREWALL_CONFIG) $(FIREWALL_AGENT_CONFIG_V31) $(DASHBOARD_CONFIG_V31) $(FIREWALL_RULES_V31); do \
		if [ -f "$config" ]; then \
			echo "  ✅ $config"; \
		else \
			echo "  ❌ $config falta"; \
		fi \
	done

# =============================================================================
# SISTEMA DEMO (ENSEÑANZA)
# =============================================================================
start: install create-configs-demo stop
	@echo "$(BLUE)🚀 Iniciando Sistema DEMO (Enseñanza)...$(NC)"
	@echo "$(BLUE)======================================$(NC)"
	@echo "$(YELLOW)💡 Versión estable para demostración y enseñanza$(NC)"
	@echo ""

	@echo "$(BLUE)📁 Verificando configuraciones demo...$(NC)"
	@test -f $(FIREWALL_CONFIG_DEMO) || (mkdir -p $(CONFIG_DIR) && echo '{"agent_id": "firewall_demo_001", "enabled": true, "log_level": "INFO"}' > $(FIREWALL_CONFIG_DEMO))
	@test -f $(DASHBOARD_CONFIG_DEMO) || (mkdir -p $(CONFIG_DIR) && echo '{"port": 8080, "host": "localhost", "debug": false}' > $(DASHBOARD_CONFIG_DEMO))

	@echo "$(BLUE)1. 🛡️  Firewall Agent Demo...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT_DEMO) $(FIREWALL_CONFIG_DEMO) $(FIREWALL_RULES_DEMO) > $(LOGS_DIR)/firewall_demo.log 2>&1 & echo $! > $(FIREWALL_PID_DEMO)
	@sleep 2

	@echo "$(BLUE)2. 🕵️  Promiscuous Agent Demo...$(NC)"
	@sudo bash -c '$(PYTHON_VENV) $(PROMISCUOUS_AGENT_DEMO) $(PROMISCUOUS_CONFIG_DEMO) > $(LOGS_DIR)/promiscuous_demo.log 2>&1 & echo $! > $(PROMISCUOUS_PID_DEMO)'
	@sleep 2

	@echo "$(BLUE)3. 🌍 GeoIP Enricher Demo...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER_DEMO) $(GEOIP_CONFIG_DEMO) > $(LOGS_DIR)/geoip_demo.log 2>&1 & echo $! > $(GEOIP_PID_DEMO)
	@sleep 2

	@echo "$(BLUE)4. 🤖 ML Detector Demo...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR_DEMO) $(ML_CONFIG_DEMO) > $(LOGS_DIR)/ml_demo.log 2>&1 & echo $! > $(ML_PID_DEMO)
	@sleep 2

	@echo "$(BLUE)5. 📊 Dashboard Demo...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD_DEMO) $(DASHBOARD_CONFIG_DEMO) $(FIREWALL_RULES_DEMO) > $(LOGS_DIR)/dashboard_demo.log 2>&1 & echo $! > $(DASHBOARD_PID_DEMO)
	@sleep 3

	@echo ""
	@echo "$(GREEN)✅ Sistema DEMO iniciado$(NC)"
	@echo "$(YELLOW)📊 Dashboard Demo: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@$(MAKE) status

create-configs-demo:
	@echo "$(BLUE)📁 Creando configuraciones demo...$(NC)"
	@mkdir -p $(CONFIG_DIR)
	@test -f $(PROMISCUOUS_CONFIG_DEMO) || echo '{"interface": "en0", "capture_filter": "", "output_port": 5559}' > $(PROMISCUOUS_CONFIG_DEMO)
	@test -f $(GEOIP_CONFIG_DEMO) || echo '{"input_port": 5559, "output_port": 5560}' > $(GEOIP_CONFIG_DEMO)
	@test -f $(ML_CONFIG_DEMO) || echo '{"input_port": 5560, "output_port": 5561, "models_path": "models/production/"}' > $(ML_CONFIG_DEMO)
	@test -f $(DASHBOARD_CONFIG_DEMO) || echo '{"port": 8080, "host": "localhost", "debug": false}' > $(DASHBOARD_CONFIG_DEMO)
	@test -f $(FIREWALL_CONFIG_DEMO) || echo '{"agent_id": "firewall_demo", "enabled": true}' > $(FIREWALL_CONFIG_DEMO)
	@test -f $(FIREWALL_RULES_DEMO) || echo '{"firewall_rules": {"rules": [], "manual_actions": {}}}' > $(FIREWALL_RULES_DEMO)

status:
	@echo "$(BLUE)📊 Estado Sistema Demo$(NC)"
	@echo "$(BLUE)=====================$(NC)"
	@pgrep -f "$(FIREWALL_AGENT_DEMO)" >/dev/null && echo "  🛡️  Firewall Agent Demo: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🛡️  Firewall Agent Demo: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "promiscuous_agent" >/dev/null && echo "  🕵️  Promiscuous Agent Demo: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🕵️  Promiscuous Agent Demo: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "geoip_enricher" >/dev/null && echo "  🌍 GeoIP Enricher Demo: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🌍 GeoIP Enricher Demo: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "lightweight_ml_detector" >/dev/null && echo "  🤖 ML Detector Demo: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🤖 ML Detector Demo: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "real_zmq_dashboard" >/dev/null && echo "  📊 Dashboard Demo: $(GREEN)✅ Ejecutándose$(NC) $(YELLOW)(http://localhost:$(DASHBOARD_WEB_PORT))$(NC)" || echo "  📊 Dashboard Demo: $(RED)⭕ Detenido$(NC)"

# =============================================================================
# MONITORIZACIÓN AVANZADA
# =============================================================================
monitor_v31:
	@echo "$(CYAN)🔄 Iniciando monitor V3.1 avanzado...$(NC)"
	@if [ -f "$(MONITOR_SCRIPT_V31)" ]; then \
		chmod +x $(MONITOR_SCRIPT_V31); \
		$(MONITOR_SCRIPT_V31); \
	else \
		echo "$(YELLOW)⚠️  Monitor V3.1 no encontrado en $(MONITOR_SCRIPT_V31)$(NC)"; \
		echo "$(BLUE)💡 Usando monitor básico integrado...$(NC)"; \
		while true; do \
			clear; \
			echo "$(CYAN)📊 Monitor V3.1 + Distribuido - $(date)$(NC)"; \
			echo "$(CYAN)===========================================$(NC)"; \
			$(MAKE) -s status_v31; \
			echo ""; \
			echo "$(CYAN)📊 Servicios Distribuidos:$(NC)"; \
			if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
				$(SERVICE_DISCOVERY_SCRIPT) discover 2>/dev/null | head -10; \
			else \
				echo "  $(YELLOW)⚠️  Backbone no disponible$(NC)"; \
			fi; \
			echo ""; \
			echo "$(YELLOW)Presiona Ctrl+C para salir$(NC)"; \
			sleep 3; \
		done \
	fi

monitor:
	@echo "$(BLUE)🔄 Iniciando monitor demo...$(NC)"
	@watch -n 3 "$(MAKE) -s status"

logs-v31:
	@echo "$(CYAN)📋 Logs Sistema V3.1$(NC)"
	@echo "$(CYAN)====================$(NC)"
	@if [ -f $(EVOLUTIONARY_SNIFFER_LOG_V31) ]; then echo "$(YELLOW)=== 🕵️  Evolutionary Sniffer V3.1 ===$(NC)"; tail -10 $(EVOLUTIONARY_SNIFFER_LOG_V31); echo ""; fi
	@if [ -f $(GEOIP_LOG_V31) ]; then echo "$(YELLOW)=== 🌍 GeoIP Enricher V3.1 ===$(NC)"; tail -10 $(GEOIP_LOG_V31); echo ""; fi
	@if [ -f $(ML_TRICAPA_LOG_V31) ]; then echo "$(YELLOW)=== 🤖 ML Detector Tricapa V3.1 ===$(NC)"; tail -10 $(ML_TRICAPA_LOG_V31); echo ""; fi
	@if [ -f $(SCHEDULER_LOG) ]; then echo "$(YELLOW)=== 🎯 Scheduler Firewall ===$(NC)"; tail -10 $(SCHEDULER_LOG); echo ""; fi
	@if [ -f $(FIREWALL_LOG_V31) ]; then echo "$(YELLOW)=== 🛡️  Firewall Agent V3.1 ===$(NC)"; tail -10 $(FIREWALL_LOG_V31); echo ""; fi
	@if [ -f $(DASHBOARD_LOG_V31) ]; then echo "$(YELLOW)=== 📊 Dashboard V3.1 ===$(NC)"; tail -10 $(DASHBOARD_LOG_V31); fi

	# Logs distribuidos
	@if [ -f $(ETCD_LOG_DIR)/etcd.log ]; then echo ""; echo "$(YELLOW)=== 🗂️  etcd Backbone ===$(NC)"; tail -5 $(ETCD_LOG_DIR)/etcd.log; fi

logs:
	@echo "$(BLUE)📋 Logs Sistema (Todas las Versiones)$(NC)"
	@echo "$(BLUE)==================================$(NC)"
	@$(MAKE) logs-v31
	@echo ""
	@echo "$(BLUE)📋 Logs Demo:$(NC)"
	@if [ -d "$(LOGS_DIR)" ]; then \
		for log in $(LOGS_DIR)/*demo*.log; do \
			if [ -f "$log" ]; then \
				echo "$(YELLOW)=== $(basename $log) ===$(NC)"; \
				tail -5 $log; \
				echo ""; \
			fi \
		done \
	fi

# =============================================================================
# UTILIDADES Y DASHBOARDS
# =============================================================================
show-dashboard:
	@echo "$(BLUE)🌐 Abriendo dashboard...$(NC)"
	@echo "$(YELLOW)V3.1 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@which open >/dev/null && open http://localhost:$(DASHBOARD_WEB_PORT) || \
       which xdg-open >/dev/null && xdg-open http://localhost:$(DASHBOARD_WEB_PORT) || \
       echo "💡 Abrir manualmente: http://localhost:$(DASHBOARD_WEB_PORT)"

show-architecture-v31:
	@echo "$(CYAN)🏗️ Arquitectura V3.1 Evolutiva + Distribuida + HA$(NC)"
	@echo "$(CYAN)================================================$(NC)"
	@echo ""
	@echo "$(YELLOW)🏛️ BACKBONE DISTRIBUIDO HA:$(NC)"
	@echo "  ┌─────────────────────────────────────────────┐"
	@echo "  │           etcd Cluster HA (Quorum)         │"
	@echo "  │  🗂️ Node1:2379  🗂️ Node2:2389  🗂️ Node3:2399  │"
	@echo "  │         Leader Election + Consensus        │"
	@echo "  └─────────────────┬───────────────────────────┘"
	@echo "                    │ Service Discovery + Config"
	@echo "  ┌─────────────────┴───────────────────────────┐"
	@echo "  │           Load Balancer / Proxy             │"
	@echo "  └─────────────────┬───────────────────────────┘"
	@echo ""
	@echo "$(YELLOW)📡 PIPELINE V3.1:$(NC)"
	@echo "  🕵️  $(EVOLUTIONARY_SNIFFER_V31) → Puerto $(CAPTURE_PORT_V31)"
	@echo "  ↓"
	@echo "  🌍 $(GEOIP_ENRICHER_V31) → Puerto $(GEOIP_PORT_V31)"
	@echo "  ↓"
	@echo "  🤖 $(ML_DETECTOR_TRICAPA_V31) → Puerto $(ML_PORT_V31) + $(DASHBOARD_PORT_V31)"
	@echo "  ↓"
	@echo "  🎯 $(SCHEDULER_FIREWALL) → Orquestación"
	@echo "  ↓"
	@echo "  🛡️  $(FIREWALL_AGENT_V31) → Puerto $(FIREWALL_PORT_V31)"
	@echo "  ↓"
	@echo "  📊 $(DASHBOARD_V31) → Puerto $(DASHBOARD_WEB_PORT)"
	@echo ""
	@echo "$(YELLOW)🔄 FLUJO INTEGRADO HA:$(NC)"
	@echo "  ┌──────────────────────────────────────────┐"
	@echo "  │  etcd Cluster HA ← Service Discovery ←   │"
	@echo "  │  ↓ Auto-registration with TTL           │"
	@echo "  │  ↓ Health checks + Leader election      │"
	@echo "  │  ↓ Consensus + Fault tolerance          │"
	@echo "  └──────────────────────────────────────────┘"
	@echo "               ↓"
	@echo "  Evolutionary Sniffer → GeoIP → ML Tricapa → Scheduler"
	@echo "               ↓                                ↓"
	@echo "         Dashboard V3.1 ←──────────────→ Firewall Agent"
	@echo ""
	@echo "$(YELLOW)🌟 CARACTERÍSTICAS HA:$(NC)"
	@echo "  • Auto-registro de servicios en cluster etcd"
	@echo "  • Health checks con consensus distribuido"
	@echo "  • Leader election automática"
	@echo "  • Tolerancia a fallos (N-1 nodos pueden fallar)"
	@echo "  • Service discovery distribuido y replicado"
	@echo "  • Quorum-based decision making"
	@echo "  • Split-brain protection"
	@echo "  • Auto-recovery de nodos"
	@echo ""
	@echo "$(YELLOW)🌐 PUERTOS DEL CLUSTER:$(NC)"
	@echo "  • Nodo 1: 2379 (client), 2380 (peer)"
	@echo "  • Nodo 2: 2389 (client), 2390 (peer)"
	@echo "  • Nodo 3: 2399 (client), 2400 (peer)"
	@echo "  • Load Balancer: localhost:2379,localhost:2389,localhost:2399"

show-roadmap-v31:
	@echo "$(CYAN)🔮 Roadmap V3.1 Evolutivo + Distribuido + HA$(NC)"
	@echo "$(CYAN)=============================================$(NC)"
	@echo ""
	@echo "$(GREEN)✅ COMPLETADO:$(NC)"
	@echo "  • 🏗️  Pipeline V3.1 completamente funcional"
	@echo "  • 📊 Dashboard V3.1 operativo (1600+ eventos)"
	@echo "  • 🤖 ML Tricapa con ensemble confidence"
	@echo "  • 🔒 Protobuf V3.1 con coordenadas duales"
	@echo "  • 🛡️  Firewall integrado click-to-block"
	@echo "  • 🗂️  etcd backbone para service discovery"
	@echo "  • 📝 Auto-registro de servicios con TTL"
	@echo "  • 👀 Monitoreo distribuido en tiempo real"
	@echo "  • 🌐 UI web para etcd (puerto 8081)"
	@echo "  • 🏛️  Cluster etcd HA con quorum (3 nodos)"
	@echo "  • 💀 Tolerancia a fallos probada"
	@echo ""
	@echo "$(YELLOW)🔄 EN DESARROLLO:$(NC)"
	@echo "  • 🔐 TLS + autenticación para cluster etcd"
	@echo "  • 🎫 Token management con JWT + TTL"
	@echo "  • ⚖️  Load balancing inteligente"
	@echo "  • 📈 Advanced analytics distribuidas"
	@echo "  • 🔄 Auto-scaling basado en carga del cluster"
	@echo ""
	@echo "$(BLUE)🎯 PRÓXIMO:$(NC)"
	@echo "  • 🚀 Kubernetes deployment con Helm"
	@echo "  • 🤖 Auto-reentrenamiento ML distribuido"
	@echo "  • 📱 Mobile dashboard"
	@echo "  • 🔐 Advanced encryption end-to-end"
	@echo "  • 🌍 Multi-region deployment"
	@echo "  • 🎯 Cross-datacenter replication"
	@echo "  • 📊 Observability stack completo (Prometheus + Grafana)"

# =============================================================================
# VERIFICACIONES Y PERMISOS
# =============================================================================
verify:
	@echo "$(BLUE)🔍 Verificando sistema completo...$(NC)"
	@echo ""
	@echo "$(BLUE)📦 Configuraciones V3.1:$(NC)"
	@$(MAKE) verify-configs-v31
	@echo ""
	@echo "$(BLUE)🔧 Protobuf V3.1:$(NC)"
	@$(MAKE) verify-protobuf-compiled-v31
	@echo ""
	@echo "$(BLUE)🗂️  Infraestructura distribuida:$(NC)"
	@if [ -f "$(ETCD_CONFIG_FILE)" ]; then \
		echo "  ✅ $(ETCD_CONFIG_FILE)"; \
	else \
		echo "  ❌ $(ETCD_CONFIG_FILE) falta"; \
	fi
	@if [ -f "$(SERVICE_DISCOVERY_SCRIPT)" ]; then \
		echo "  ✅ $(SERVICE_DISCOVERY_SCRIPT)"; \
	else \
		echo "  ❌ $(SERVICE_DISCOVERY_SCRIPT) falta"; \
	fi
	@if [ -f "$(ETCD_START_SCRIPT)" ]; then \
		echo "  ✅ $(ETCD_START_SCRIPT)"; \
	else \
		echo "  ❌ $(ETCD_START_SCRIPT) falta"; \
	fi
	@echo ""
	@echo "$(BLUE)🔍 Dependencias:$(NC)"
	@$(MAKE) check-deps
	@echo "$(GREEN)✅ Verificación completada$(NC)"

setup-perms:
	@echo "$(BLUE)🔧 Configurando permisos...$(NC)"
	@echo "$(YELLOW)⚠️  Requiere sudo para iptables$(NC)"
	@sudo bash -c 'echo "$(USER) ALL=(ALL) NOPASSWD: /sbin/iptables" >> /etc/sudoers.d/$(USER)-iptables' || true
	@sudo chmod 0440 /etc/sudoers.d/$(USER)-iptables || true
	@echo "$(GREEN)✅ Permisos configurados$(NC)"

check-deps:
	@echo "$(BLUE)🔍 Verificando dependencias...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import zmq; print('✅ ZeroMQ')" 2>/dev/null || echo "❌ ZeroMQ falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import scapy; print('✅ Scapy')" 2>/dev/null || echo "❌ Scapy falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import sklearn; print('✅ Scikit-learn')" 2>/dev/null || echo "❌ Scikit-learn falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import joblib; print('✅ Joblib')" 2>/dev/null || echo "❌ Joblib falta"
	@which protoc >/dev/null && echo "✅ protoc" || echo "❌ protoc falta"
	@which etcd >/dev/null && echo "✅ etcd" || echo "❌ etcd falta (make dist-install-etcd)"
	@which etcdctl >/dev/null && echo "✅ etcdctl" || echo "❌ etcdctl falta"

# =============================================================================
# REINICIO Y LIMPIEZA
# =============================================================================
restart: stop
	@sleep 3
	@$(MAKE) start_v31

restart-distributed: stop-nuclear
	@sleep 3
	@$(MAKE) dist-dev

clean:
	@echo "$(YELLOW)🧹 Limpiando sistema completo...$(NC)"
	@$(MAKE) stop 2>/dev/null || true
	@$(MAKE) dist-stop 2>/dev/null || true
	@rm -rf $(VENV_NAME)
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -f $(PROTOBUF_DIR)/*_pb2.py
	@rm -rf $(PIDS_DIR) $(LOGS_DIR)
	@rm -rf $(ETCD_DATA_DIR)/* $(ETCD_LOG_DIR)/etcd.log 2>/dev/null || true
	@echo "$(GREEN)✅ Limpieza completa completada$(NC)"

# =============================================================================
# COMANDOS RÁPIDOS ADICIONALES
# =============================================================================
quick: setup install setup-perms start show-dashboard
	@echo ""
	@echo "$(BLUE)✅ QUICK START DEMO COMPLETADO$(NC)"
	@echo "$(BLUE)==============================$(NC)"
	@echo "$(YELLOW)Sistema demo para enseñanza listo!$(NC)"

debug:
	@echo "$(PURPLE)🔧 Modo Debug Distribuido$(NC)"
	@echo "$(PURPLE)==========================$(NC)"
	@echo ""
	@echo "$(CYAN)📊 Estado V3.1:$(NC)"
	@$(MAKE) status_v31
	@echo ""
	@echo "$(CYAN)📊 Estado Demo:$(NC)"
	@$(MAKE) status
	@echo ""
	@echo "$(CYAN)🗂️  Estado Distribuido:$(NC)"
	@$(MAKE) dist-status
	@echo ""
	@echo "$(CYAN)📋 Logs Recientes V3.1:$(NC)"
	@$(MAKE) logs-v31 | tail -20
	@echo ""
	@echo "$(CYAN)🔍 Servicios Registrados:$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		servicios=$(etcdctl --endpoints=$(ETCD_ENDPOINT) get /services/ --prefix --keys-only 2>/dev/null | grep -c /services/ || echo 0); \
		if [ "$servicios" -eq 0 ]; then \
			echo "  $(YELLOW)⚠️  Sin servicios registrados (TTL expirado)$(NC)"; \
			echo "  $(BLUE)💡 Ejecuta: make dist-register$(NC)"; \
		else \
			$(SERVICE_DISCOVERY_SCRIPT) discover; \
		fi; \
	else \
		echo "  $(YELLOW)⚠️  Backbone distribuido no disponible$(NC)"; \
	fi

benchmark:
	@echo "$(BLUE)📊 Benchmark sistema distribuido$(NC)"
	@echo "$(BLUE)================================$(NC)"
	@echo ""
	@echo "$(YELLOW)🔍 Procesos activos:$(NC)"
	@ps aux | grep -E "(python.*core/|etcd)" | grep -v grep | awk '{print "  " $11 ": " $3 "% CPU, " $4 "% MEM"}' || echo "  No hay procesos activos"
	@echo ""
	@echo "$(YELLOW)🌐 Puertos en uso:$(NC)"
	@for port in $(CAPTURE_PORT_V31) $(GEOIP_PORT_V31) $(ML_PORT_V31) $(FIREWALL_PORT_V31) $(DASHBOARD_PORT_V31) $(DASHBOARD_WEB_PORT) 2379 2380; do \
		if lsof -i:$port > /dev/null 2>&1; then \
			echo "  Puerto $port: $(GREEN)✅ En uso$(NC)"; \
		else \
			echo "  Puerto $port: $(RED)⭕ Libre$(NC)"; \
		fi \
	done
	@echo ""
	@echo "$(YELLOW)🗂️  Estado etcd:$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "  Salud: $(GREEN)✅ Operativo$(NC)"; \
		echo "  Endpoint: $(ETCD_ENDPOINT)"; \
		echo "  Servicios: $(etcdctl --endpoints=$(ETCD_ENDPOINT) get /services/ --prefix --keys-only | grep -c /services/ || echo 0)"; \
	else \
		echo "  Estado: $(RED)⭕ No disponible$(NC)"; \
	fi

test:
	@echo "$(BLUE)🧪 Tests sistema completo$(NC)"
	@echo "$(BLUE)==========================$(NC)"
	@echo ""
	@echo "$(YELLOW)🔍 Verificación completa:$(NC)"
	@$(MAKE) verify
	@echo ""
	@echo "$(YELLOW)🗂️  Test service discovery:$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		$(MAKE) dist-test; \
	else \
		echo "  $(YELLOW)⚠️  etcd no disponible - saltando tests distribuidos$(NC)"; \
	fi

# =============================================================================
# COMANDOS DE CONTROL ESPECÍFICOS
# =============================================================================
start-bg: start_v31
	@echo "$(GREEN)🚀 Sistema V3.1 iniciado en background$(NC)"

restart-v31:
	@echo "$(YELLOW)🔄 Reiniciando solo V3.1...$(NC)"
	@$(MAKE) stop 2>/dev/null || true
	@sleep 2
	@$(MAKE) start_v31