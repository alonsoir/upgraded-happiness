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
# COMPONENTES V3.1 EVOLUTIVOS - SECUENCIA ETCD ACTUAL
# =============================================================================
# Secuencia actual con etcd
EVOLUTIONARY_SNIFFER_STANDALONE = core/evolutionary_sniffer_standalone.py
ZMQ_PERFORMANCE_OPTIMIZER = zmq_performance_optimizer.py
GEOIP_ENRICHER_ETCD = core/geoip_enricher_v31_etcd.py
ML_DETECTOR_TRICAPA_ETCD = core/lightweight_ml_detector_tricapa_v31_etcd.py
SCHEDULER_FIREWALL_ETCD = core/scheduler_firewall_v31_etcd.py
FIREWALL_AGENT_ETCD = core/simple_firewall_agent_v31_etcd.py
DASHBOARD_ETCD = core/dashboard_v31_etcd.py

# Componentes V3.1 originales (mantener compatibilidad)
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
# CONFIGURACIONES JSON V3.1 - SECUENCIA ETCD ACTUAL
# =============================================================================
CONFIG_DIR = config/json
# Configuraciones etcd (secuencia actual)
EVOLUTIONARY_SNIFFER_ETCD_CONFIG = $(CONFIG_DIR)/evolutionary_sniffer_config_v31_etcd.json
ZMQ_OPTIMIZER_ETCD_CONFIG = $(CONFIG_DIR)/evolutionary_sniffer_config_v31_etcd.json
GEOIP_ENRICHER_ETCD_CONFIG = $(CONFIG_DIR)/geoip_enricher_config_v31_etcd.json
ML_DETECTOR_TRICAPA_ETCD_CONFIG = $(CONFIG_DIR)/lightweight_ml_detector_tricapa_v31_etcd_config_dev.json
SCHEDULER_FIREWALL_ETCD_CONFIG = $(CONFIG_DIR)/scheduler_firewall_etcd_config_dev.json
FIREWALL_AGENT_ETCD_CONFIG = $(CONFIG_DIR)/simple_firewall_agent_v31_etcd.json
DASHBOARD_ETCD_CONFIG = $(CONFIG_DIR)/dashboard_config_v31_etcd.json
FIREWALL_RULES_V31 = $(CONFIG_DIR)/firewall_rules_v31.json

# Configuraciones V3.1 originales (mantener compatibilidad)
EVOLUTIONARY_SNIFFER_CONFIG_V31 = $(CONFIG_DIR)/evolutionary_sniffer_config_v31.json
GEOIP_ENRICHER_CONFIG_V31 = $(CONFIG_DIR)/geoip_enricher_config_v31.json
ML_DETECTOR_TRICAPA_CONFIG_V31 = $(CONFIG_DIR)/lightweight_ml_detector_tricapa_v31_config_dev.json
SCHEDULER_FIREWALL_CONFIG = $(CONFIG_DIR)/scheduler_firewall_config.json
FIREWALL_AGENT_CONFIG_V31 = $(CONFIG_DIR)/simple_firewall_agent_v31_config.json
DASHBOARD_CONFIG_V31 = $(CONFIG_DIR)/dashboard_config_v31.json

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
# GESTIÓN DE PROCESOS - SECUENCIA ETCD
# =============================================================================
PIDS_DIR = .pids
LOGS_DIR = logs

# PIDs secuencia etcd
EVOLUTIONARY_SNIFFER_ETCD_PID = $(PIDS_DIR)/evolutionary_sniffer_standalone.pid
ZMQ_OPTIMIZER_PID = $(PIDS_DIR)/zmq_performance_optimizer.pid
GEOIP_ETCD_PID = $(PIDS_DIR)/geoip_enricher_v31_etcd.pid
ML_TRICAPA_ETCD_PID = $(PIDS_DIR)/ml_detector_tricapa_v31_etcd.pid
SCHEDULER_ETCD_PID = $(PIDS_DIR)/scheduler_firewall_v31_etcd.pid
FIREWALL_ETCD_PID = $(PIDS_DIR)/firewall_agent_v31_etcd.pid
DASHBOARD_ETCD_PID = $(PIDS_DIR)/dashboard_v31_etcd.pid

# PIDs V3.1 originales
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

# Logs secuencia etcd
EVOLUTIONARY_SNIFFER_ETCD_LOG = $(LOGS_DIR)/evolutionary_sniffer_standalone.log
ZMQ_OPTIMIZER_LOG = $(LOGS_DIR)/zmq_performance_optimizer.log
GEOIP_ETCD_LOG = $(LOGS_DIR)/geoip_enricher_v31_etcd.log
ML_TRICAPA_ETCD_LOG = $(LOGS_DIR)/ml_detector_tricapa_v31_etcd.log
SCHEDULER_ETCD_LOG = $(LOGS_DIR)/scheduler_firewall_v31_etcd.log
FIREWALL_ETCD_LOG = $(LOGS_DIR)/firewall_agent_v31_etcd.log
DASHBOARD_ETCD_LOG = $(LOGS_DIR)/dashboard_v31_etcd.log

# Logs V3.1 originales
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
        start-with-etcd-v31 stop-etcd-v31 stop-nuclear-v31 status-etcd-v31 logs-etcd-v31 \
        status status_v31 monitor monitor_v31 logs logs-v31 \
        setup-perms verify check-deps \
        show-dashboard show-architecture-v31 show-roadmap-v31 \
        quick quick_v31 debug benchmark \
        create-configs-v31 create-configs-etcd-v31 verify-configs-v31 \
        etcd-show etcd-show-services etcd-show-all etcd-watch etcd-health \
        dist-setup dist-start dist-stop dist-status dist-test dist-discover dist-watch dist-clean dist-register dist-reset \
        dist-cluster dist-cluster-status dist-cluster-stop dist-cluster-test \
        dist-ha dist-register-cluster \
        dist-ui dist-ui-stop dist-ui-open dist-secure dist-info dist-troubleshoot \
        dist-quick dist-install-etcd dist-dev dist-register-auto dist-healthcheck dist-auto-stop stop-robust

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
	@echo "  $(GREEN)make start-with-etcd-v31$(NC)  - Secuencia completa etcd + V3.1 (NUEVA)"
	@echo "  $(GREEN)make quick_v31$(NC)           - Setup completo V3.1 (original)"
	@echo "  $(GREEN)make dist-quick$(NC)          - Setup distribuido completo (etcd + V3.1)"
	@echo ""
	@echo "$(YELLOW)🔥 SECUENCIA ETCD V3.1 (ACTUAL):$(NC)"
	@echo "  $(GREEN)make start-with-etcd-v31$(NC) - Iniciar secuencia completa etcd + componentes"
	@echo "  $(GREEN)make status-etcd-v31$(NC)     - Estado secuencia etcd V3.1"
	@echo "  $(GREEN)make logs-etcd-v31$(NC)       - Logs secuencia etcd V3.1"
	@echo "  $(RED)make stop-etcd-v31$(NC)       - Detener secuencia etcd V3.1"
	@echo "  $(RED)make stop-nuclear-v31$(NC)    - Parada nuclear etcd V3.1"
	@echo ""
	@echo "$(YELLOW)🗂️  GESTIÓN etcd:$(NC)"
	@echo "  $(CYAN)make etcd-show$(NC)           - Mostrar todo lo cargado en etcd"
	@echo "  $(CYAN)make etcd-show-services$(NC)  - Servicios registrados en etcd"
	@echo "  $(CYAN)make etcd-watch$(NC)          - Monitoreo tiempo real etcd"
	@echo "  $(CYAN)make etcd-health$(NC)         - Estado de salud etcd"
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
	@echo "$(YELLOW)🛡️ SISTEMA V3.1 (Pipeline evolutivo original):$(NC)"
	@echo "  $(GREEN)make start_v31$(NC)           - Iniciar pipeline V3.1 evolutivo original"
	@echo "  $(GREEN)make status_v31$(NC)          - Estado sistema V3.1 original"
	@echo "  $(GREEN)make monitor_v31$(NC)         - Monitor tiempo real V3.1"
	@echo "  $(GREEN)make logs-v31$(NC)            - Logs específicos V3.1"
	@echo ""
	@echo "$(YELLOW)🚀 UI WEB:$(NC)"
	@echo "  $(CYAN)make dist-ui$(NC)             - UI web etcd (puerto 8081)"
	@echo "  $(CYAN)make dist-ui-open$(NC)        - Abrir UI etcd en navegador"
	@echo "  $(CYAN)make dist-ui-stop$(NC)        - Detener UI etcd"
	@echo ""
	@echo "$(YELLOW)🛑 CONTROL SISTEMA:$(NC)"
	@echo "  stop                     - Parada normal (V3.1 + demo)"
	@echo "  stop-nuclear             - Parada nuclear (TODO)"
	@echo "  restart                  - Reiniciar sistema completo"
	@echo ""
	@echo "$(GREEN)💡 FLUJO RECOMENDADO:$(NC)"
	@echo "  $(BLUE)Nueva secuencia:$(NC) $(GREEN)make start-with-etcd-v31$(NC) # Secuencia actual"
	@echo "  $(GREEN)Dashboard:$(NC)       $(GREEN)make show-dashboard$(NC)      # Abrir dashboard"
	@echo "  $(CYAN)etcd info:$(NC)       $(CYAN)make etcd-show$(NC)           # Ver datos etcd"
	@echo "  $(CYAN)UI etcd:$(NC)         $(CYAN)make dist-ui-open$(NC)        # UI web etcd"

# =============================================================================
# NUEVA SECUENCIA ETCD V3.1 - LA ACTUAL
# =============================================================================
start-with-etcd-v31: install create-configs-etcd-v31 stop-etcd-v31 ## Iniciar secuencia completa etcd + V3.1 (ACTUAL)
	@echo "$(GREEN)🚀 Iniciando Secuencia ETCD V3.1 Completa...$(NC)"
	@echo "$(CYAN)==============================================$(NC)"
	@echo "$(PURPLE)Secuencia: etcd → sniffer_standalone → geoip → ml_tricapa → scheduler → firewall → dashboard$(NC)"
	@echo ""

	@echo "$(BLUE)0. 🗂️  Iniciando etcd backbone...$(NC)"
	@$(MAKE) dist-start || (echo "$(RED)❌ Error iniciando etcd$(NC)" && exit 1)
	@sleep 3

	@echo "$(BLUE)1. 🕵️  Evolutionary Sniffer Standalone...$(NC)"
	@sudo -E bash -c '$(ACTIVATE) && $(PYTHON_VENV) $(EVOLUTIONARY_SNIFFER_STANDALONE) $(EVOLUTIONARY_SNIFFER_ETCD_CONFIG) > $(EVOLUTIONARY_SNIFFER_ETCD_LOG) 2>&1 & echo $$! > $(EVOLUTIONARY_SNIFFER_ETCD_PID)'
	@sleep 5

	@echo "$(BLUE)2. 🌍 GeoIP Enricher etcd...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER_ETCD) $(GEOIP_ENRICHER_ETCD_CONFIG) > $(GEOIP_ETCD_LOG) 2>&1 & echo $$! > $(GEOIP_ETCD_PID)
	@sleep 4

	@echo "$(BLUE)3. 🤖 ML Detector Tricapa etcd...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR_TRICAPA_ETCD) $(ML_DETECTOR_TRICAPA_ETCD_CONFIG) > $(ML_TRICAPA_ETCD_LOG) 2>&1 & echo $! > $(ML_TRICAPA_ETCD_PID)
	@sleep 4

	@echo "$(BLUE)4. 🎯 Scheduler Firewall etcd...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(SCHEDULER_FIREWALL_ETCD) $(SCHEDULER_FIREWALL_ETCD_CONFIG) $(FIREWALL_RULES_V31) > $(SCHEDULER_ETCD_LOG) 2>&1 & echo $! > $(SCHEDULER_ETCD_PID)
	@sleep 4

	@echo "$(BLUE)5. 🛡️  Firewall Agent etcd...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT_ETCD) $(FIREWALL_AGENT_ETCD_CONFIG) $(FIREWALL_RULES_V31) > $(FIREWALL_ETCD_LOG) 2>&1 & echo $! > $(FIREWALL_ETCD_PID)
	@sleep 4

	@echo "$(BLUE)6. 📊 Dashboard etcd...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD_ETCD) $(DASHBOARD_ETCD_CONFIG) $(FIREWALL_RULES_V31) > $(DASHBOARD_ETCD_LOG) 2>&1 & echo $! > $(DASHBOARD_ETCD_PID)
	@sleep 5

	@echo "$(BLUE)7. 📝 Registrando servicios en backbone etcd...$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		chmod +x $(SERVICE_DISCOVERY_SCRIPT); \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-sniffer-standalone localhost $(CAPTURE_PORT_V31) 180; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-geoip-etcd localhost $(GEOIP_PORT_V31) 180; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-ml-etcd localhost $(ML_PORT_V31) 180; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-scheduler-etcd localhost $(FIREWALL_PORT_V31) 180; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-firewall-etcd localhost $(FIREWALL_PORT_V31) 180; \
		$(SERVICE_DISCOVERY_SCRIPT) register axiom-dashboard-etcd localhost $(DASHBOARD_WEB_PORT) 180; \
		echo "$(GREEN)✅ Servicios etcd registrados en backbone$(NC)"; \
	else \
		echo "$(RED)❌ No se pudo registrar servicios en etcd$(NC)"; \
	fi

	@echo ""
	@echo "$(GREEN)🎉 SECUENCIA ETCD V3.1 COMPLETAMENTE OPERATIVA$(NC)"
	@echo "$(CYAN)================================================$(NC)"
	@echo "$(YELLOW)📊 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@echo "$(YELLOW)🗂️  etcd UI: make dist-ui-open$(NC)"
	@echo "$(YELLOW)📋 Estado: make status-etcd-v31$(NC)"
	@echo "$(YELLOW)🔍 Ver etcd: make etcd-show$(NC)"
	@echo ""
	@$(MAKE) status-etcd-v31

status-etcd-v31: ## Estado completo secuencia etcd V3.1
	@echo "$(CYAN)📊 Estado Secuencia ETCD V3.1$(NC)"
	@echo "$(CYAN)==============================$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "  🗂️  etcd Backbone: $(GREEN)✅ Operativo$(NC) ($(ETCD_ENDPOINT))"; \
	else \
		echo "  🗂️  etcd Backbone: $(RED)❌ No disponible$(NC)"; \
	fi
	@pgrep -f "$(EVOLUTIONARY_SNIFFER_STANDALONE)" >/dev/null && echo "  🕵️  Sniffer Standalone: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🕵️  Sniffer Standalone: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "geoip_enricher_v31_etcd" >/dev/null && echo "  🌍 GeoIP etcd: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🌍 GeoIP etcd: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "ml_detector_tricapa_v31_etcd" >/dev/null && echo "  🤖 ML Tricapa etcd: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🤖 ML Tricapa etcd: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "scheduler_firewall_v31_etcd" >/dev/null && echo "  🎯 Scheduler etcd: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🎯 Scheduler etcd: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "simple_firewall_agent_v31_etcd" >/dev/null && echo "  🛡️  Firewall etcd: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🛡️  Firewall etcd: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "dashboard_v31_etcd" >/dev/null && echo "  📊 Dashboard etcd: $(GREEN)✅ Ejecutándose$(NC) $(YELLOW)(http://localhost:$(DASHBOARD_WEB_PORT))$(NC)" || echo "  📊 Dashboard etcd: $(RED)⭕ Detenido$(NC)"

	@echo ""
	@echo "$(CYAN)🗂️  Servicios en etcd:$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		servicios=$$(etcdctl --endpoints=$(ETCD_ENDPOINT) get /services/ --prefix --keys-only 2>/dev/null | grep -c /services/ || echo 0); \
		echo "  📝 Total registrados: $$servicios"; \
		if [ "$$servicios" -gt 0 ]; then \
			echo "  $(CYAN)Para detalles: make etcd-show-services$(NC)"; \
		fi; \
	else \
		echo "  $(RED)❌ etcd no disponible$(NC)"; \
	fi

logs-etcd-v31: ## Logs completos secuencia etcd V3.1
	@echo "$(CYAN)📋 Logs Secuencia ETCD V3.1$(NC)"
	@echo "$(CYAN)==============================$(NC)"
	@if [ -f $(EVOLUTIONARY_SNIFFER_ETCD_LOG) ]; then echo "$(YELLOW)=== 🕵️  Sniffer Standalone ===$(NC)"; tail -8 $(EVOLUTIONARY_SNIFFER_ETCD_LOG); echo ""; fi
	@if [ -f $(ZMQ_OPTIMIZER_LOG) ]; then echo "$(YELLOW)=== 📊 ZMQ Optimizer ===$(NC)"; tail -5 $(ZMQ_OPTIMIZER_LOG); echo ""; fi
	@if [ -f $(GEOIP_ETCD_LOG) ]; then echo "$(YELLOW)=== 🌍 GeoIP etcd ===$(NC)"; tail -8 $(GEOIP_ETCD_LOG); echo ""; fi
	@if [ -f $(ML_TRICAPA_ETCD_LOG) ]; then echo "$(YELLOW)=== 🤖 ML Tricapa etcd ===$(NC)"; tail -8 $(ML_TRICAPA_ETCD_LOG); echo ""; fi
	@if [ -f $(SCHEDULER_ETCD_LOG) ]; then echo "$(YELLOW)=== 🎯 Scheduler etcd ===$(NC)"; tail -8 $(SCHEDULER_ETCD_LOG); echo ""; fi
	@if [ -f $(FIREWALL_ETCD_LOG) ]; then echo "$(YELLOW)=== 🛡️  Firewall etcd ===$(NC)"; tail -8 $(FIREWALL_ETCD_LOG); echo ""; fi
	@if [ -f $(DASHBOARD_ETCD_LOG) ]; then echo "$(YELLOW)=== 📊 Dashboard etcd ===$(NC)"; tail -8 $(DASHBOARD_ETCD_LOG); fi
	@if [ -f $(ETCD_LOG_DIR)/etcd.log ]; then echo ""; echo "$(YELLOW)=== 🗂️  etcd Backbone ===$(NC)"; tail -5 $(ETCD_LOG_DIR)/etcd.log; fi

stop-etcd-v31: ## Detener secuencia etcd V3.1
	@echo "$(YELLOW)🛑 Deteniendo Secuencia ETCD V3.1...$(NC)"

	# Detener componentes en orden inverso
	@echo "$(BLUE)📊 Deteniendo Dashboard etcd...$(NC)"
	@-if [ -f $(DASHBOARD_ETCD_PID) ]; then kill $$(cat $(DASHBOARD_ETCD_PID)) 2>/dev/null || true; rm -f $(DASHBOARD_ETCD_PID); fi

	@echo "$(BLUE)🛡️  Deteniendo Firewall etcd...$(NC)"
	@-if [ -f $(FIREWALL_ETCD_PID) ]; then kill $$(cat $(FIREWALL_ETCD_PID)) 2>/dev/null || true; rm -f $(FIREWALL_ETCD_PID); fi

	@echo "$(BLUE)🎯 Deteniendo Scheduler etcd...$(NC)"
	@-if [ -f $(SCHEDULER_ETCD_PID) ]; then kill $$(cat $(SCHEDULER_ETCD_PID)) 2>/dev/null || true; rm -f $(SCHEDULER_ETCD_PID); fi

	@echo "$(BLUE)🤖 Deteniendo ML Tricapa etcd...$(NC)"
	@-if [ -f $(ML_TRICAPA_ETCD_PID) ]; then kill $$(cat $(ML_TRICAPA_ETCD_PID)) 2>/dev/null || true; rm -f $(ML_TRICAPA_ETCD_PID); fi

	@echo "$(BLUE)🌍 Deteniendo GeoIP etcd...$(NC)"
	@-if [ -f $(GEOIP_ETCD_PID) ]; then kill $(cat $(GEOIP_ETCD_PID)) 2>/dev/null || true; rm -f $(GEOIP_ETCD_PID); fi

	@echo "$(BLUE)🕵️  Deteniendo Sniffer Standalone (sudo)...$(NC)"
	@-if [ -f $(EVOLUTIONARY_SNIFFER_ETCD_PID) ]; then \
		PID=$$(cat $(EVOLUTIONARY_SNIFFER_ETCD_PID)); \
		kill $$PID 2>/dev/null || sudo kill $$PID 2>/dev/null || true; \
		rm -f $(EVOLUTIONARY_SNIFFER_ETCD_PID); \
	fi

	# Limpiar por patrones
	@echo "$(BLUE)🔄 Limpieza por patrones etcd...$(NC)"
	@-pkill -f "evolutionary_sniffer_standalone|geoip_enricher_v31_etcd|ml_detector_tricapa_v31_etcd|scheduler_firewall_v31_etcd|simple_firewall_agent_v31_etcd|dashboard_v31_etcd" 2>/dev/null || true
	@-sudo pkill -f "evolutionary_sniffer_standalone" 2>/dev/null || true

	@echo "$(GREEN)✅ Secuencia ETCD V3.1 detenida$(NC)"
	@echo "$(YELLOW)💡 etcd backbone sigue corriendo. Para detenerlo: make dist-stop$(NC)"

stop-nuclear-v31: ## Parada nuclear completa - etcd + V3.1 + limpieza total
	@echo "$(RED)☢️  PARADA NUCLEAR ETCD V3.1 ☢️$(NC)"
	@echo "$(RED)================================$(NC)"

	# Detener secuencia etcd
	@echo "$(YELLOW)💀 Fase 1: Deteniendo secuencia etcd...$(NC)"
	@$(MAKE) stop-etcd-v31 2>/dev/null || true

	# Detener backbone etcd
	@echo "$(YELLOW)💀 Fase 2: Deteniendo backbone etcd...$(NC)"
	@$(MAKE) dist-stop 2>/dev/null || true

	# Nuclear específico para etcd
	@echo "$(YELLOW)💀 Fase 3: Eliminación nuclear...$(NC)"
	@-pkill -9 -f "python.*etcd" 2>/dev/null || true
	@-sudo pkill -9 -f "python.*etcd" 2>/dev/null || true
	@-pkill -9 -f "evolutionary_sniffer_standalone" 2>/dev/null || true
	@-sudo pkill -9 -f "evolutionary_sniffer_standalone" 2>/dev/null || true
	@-pkill -9 -f "zmq_performance_optimizer" 2>/dev/null || true
	@-pkill -9 -f "etcd.*config-file" 2>/dev/null || true

	# Liberar puertos específicos
	@echo "$(YELLOW)💀 Fase 4: Liberando puertos...$(NC)"
	@for port in $(CAPTURE_PORT_V31) $(GEOIP_PORT_V31) $(ML_PORT_V31) $(FIREWALL_PORT_V31) $(DASHBOARD_PORT_V31) $(DASHBOARD_WEB_PORT) 2379 2380; do \
		PIDS=$$(lsof -ti:$$port 2>/dev/null); \
		if [ ! -z "$$PIDS" ]; then \
			echo "💀 Liberando puerto $$port..."; \
			echo "$$PIDS" | xargs -r kill -9 2>/dev/null || echo "$$PIDS" | xargs -r sudo kill -9 2>/dev/null || true; \
		fi \
	done

	# Limpieza total
	@echo "$(YELLOW)💀 Fase 5: Limpieza total...$(NC)"
	@-rm -rf $(PIDS_DIR)/*.pid
	@-rm -rf $(ETCD_DATA_DIR)/* $(ETCD_LOG_DIR)/etcd.log 2>/dev/null || true
	@-docker stop etcd-browser 2>/dev/null || true
	@-docker rm etcd-browser 2>/dev/null || true

	@echo ""
	@echo "$(GREEN)☢️  PARADA NUCLEAR ETCD V3.1 COMPLETADA ☢️$(NC)"
	@echo "$(GREEN)Ecosistema completamente eliminado - listo para reinicio$(NC)"

# =============================================================================
# GESTIÓN Y VISUALIZACIÓN DE etcd
# =============================================================================
etcd-show: ## Mostrar TODO lo cargado en etcd
	@echo "$(CYAN)🗂️  Contenido Completo de etcd$(NC)"
	@echo "$(CYAN)==============================$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "$(BLUE)📊 Información del Cluster:$(NC)"; \
		echo "  Endpoint: $(ETCD_ENDPOINT)"; \
		echo "  Estado: $(GREEN)✅ Operativo$(NC)"; \
		echo ""; \
		echo "$(BLUE)🔑 Todas las Claves:$(NC)"; \
		etcdctl --endpoints=$(ETCD_ENDPOINT) get "" --from-key --keys-only 2>/dev/null | head -20; \
		total=$$(etcdctl --endpoints=$(ETCD_ENDPOINT) get "" --from-key --keys-only 2>/dev/null | wc -l); \
		echo "  💾 Total de claves: $$total"; \
		echo ""; \
		echo "$(BLUE)📝 Servicios Registrados (/services/):$(NC)"; \
		etcdctl --endpoints=$(ETCD_ENDPOINT) get /services/ --prefix 2>/dev/null || echo "  Sin servicios registrados"; \
		echo ""; \
		echo "$(BLUE)⚙️  Configuraciones (/config/):$(NC)"; \
		etcdctl --endpoints=$(ETCD_ENDPOINT) get /config/ --prefix 2>/dev/null || echo "  Sin configuraciones"; \
		echo ""; \
		echo "$(BLUE)📈 Métricas (/metrics/):$(NC)"; \
		etcdctl --endpoints=$(ETCD_ENDPOINT) get /metrics/ --prefix 2>/dev/null || echo "  Sin métricas"; \
	else \
		echo "$(RED)❌ etcd no disponible en $(ETCD_ENDPOINT)$(NC)"; \
		echo "$(YELLOW)💡 Para iniciar etcd: make dist-start$(NC)"; \
	fi

etcd-show-services: ## Mostrar solo servicios registrados
	@echo "$(CYAN)📝 Servicios Registrados en etcd$(NC)"
	@echo "$(CYAN)==================================$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		servicios=$$(etcdctl --endpoints=$(ETCD_ENDPOINT) get /services/ --prefix --keys-only 2>/dev/null | grep -c /services/ || echo 0); \
		if [ "$$servicios" -gt 0 ]; then \
			echo "$(GREEN)📊 Total de servicios: $$servicios$(NC)"; \
			echo ""; \
			echo "$(YELLOW)🔍 Detalles:$(NC)"; \
			etcdctl --endpoints=$(ETCD_ENDPOINT) get /services/ --prefix 2>/dev/null | while read -r key; do \
				if [[ $$key == /services/* ]]; then \
					echo "$(BLUE)  🏷️ $$key$(NC)"; \
					read -r value; \
					echo "    📋 $$value"; \
					echo ""; \
				fi \
			done; \
		else \
			echo "$(YELLOW)⚠️  No hay servicios registrados$(NC)"; \
			echo "$(BLUE)💡 Para registrar: make dist-register$(NC)"; \
		fi; \
	else \
		echo "$(RED)❌ etcd no disponible$(NC)"; \
	fi

etcd-show-all: etcd-show ## Alias para etcd-show

etcd-watch: ## Monitoreo en tiempo real de etcd
	@echo "$(BLUE)👀 Monitoreando etcd en tiempo real...$(NC)"
	@echo "$(YELLOW)💡 Presiona Ctrl+C para salir$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		etcdctl --endpoints=$(ETCD_ENDPOINT) watch "" --prefix; \
	else \
		echo "$(RED)❌ etcd no disponible$(NC)"; \
	fi

etcd-health: ## Estado de salud detallado de etcd
	@echo "$(CYAN)🏥 Estado de Salud etcd$(NC)"
	@echo "$(CYAN)========================$(NC)"
	@if curl -s $(ETCD_ENDPOINT)/health > /dev/null 2>&1; then \
		echo "$(GREEN)✅ etcd está operativo$(NC)"; \
		echo ""; \
		echo "$(BLUE)📊 Información del Endpoint:$(NC)"; \
		etcdctl --endpoints=$(ETCD_ENDPOINT) endpoint health; \
		echo ""; \
		echo "$(BLUE)📈 Estado del Endpoint:$(NC)"; \
		etcdctl --endpoints=$(ETCD_ENDPOINT) endpoint status --write-out=table; \
		echo ""; \
		echo "$(BLUE)👥 Miembros del Cluster:$(NC)"; \
		etcdctl --endpoints=$(ETCD_ENDPOINT) member list; \
	else \
		echo "$(RED)❌ etcd no está disponible$(NC)"; \
		echo "$(YELLOW)💡 Para iniciar etcd: make dist-start$(NC)"; \
		echo ""; \
		echo "$(BLUE)🔧 Diagnóstico:$(NC)"; \
		if lsof -i:2379 > /dev/null 2>&1; then \
			echo "  Puerto 2379: $(GREEN)En uso$(NC)"; \
		else \
			echo "  Puerto 2379: $(RED)Libre$(NC)"; \
		fi; \
		if pgrep -f "etcd.*config-file" > /dev/null; then \
			echo "  Proceso etcd: $(GREEN)Corriendo$(NC)"; \
		else \
			echo "  Proceso etcd: $(RED)No encontrado$(NC)"; \
		fi; \
	fi

# =============================================================================
# CONFIGURACIONES ETCD V3.1
# =============================================================================
create-configs-etcd-v31: ## Crear configuraciones para secuencia etcd V3.1
	@echo "$(BLUE)📁 Creando configuraciones etcd V3.1...$(NC)"
	@mkdir -p $(CONFIG_DIR)

	@echo "$(BLUE)📝 Creando config evolutionary_sniffer_config_v31_etcd.json...$(NC)"
	@test -f $(EVOLUTIONARY_SNIFFER_ETCD_CONFIG) || echo '{"interface": "en0", "capture_filter": "", "output_port": 5559, "log_level": "INFO", "version": "v3.1", "etcd_mode": true, "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-sniffer-standalone", "ttl": 180}}' > $(EVOLUTIONARY_SNIFFER_ETCD_CONFIG)

	@echo "$(BLUE)📝 Creando config geoip_enricher_config_v31_etcd.json...$(NC)"
	@test -f $(GEOIP_ENRICHER_ETCD_CONFIG) || echo '{"input_port": 5559, "output_port": 5560, "geoip_db_path": "GeoLite2-City.mmdb", "log_level": "INFO", "version": "v3.1", "etcd_mode": true, "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-geoip-etcd", "ttl": 180}}' > $(GEOIP_ENRICHER_ETCD_CONFIG)

	@echo "$(BLUE)📝 Creando config lightweight_ml_detector_tricapa_v31_etcd_config_dev.json...$(NC)"
	@test -f $(ML_DETECTOR_TRICAPA_ETCD_CONFIG) || echo '{"input_port": 5560, "output_port": 5561, "dashboard_port": 5580, "models_path": "models/production/tricapa/", "tricapa_enabled": true, "ensemble_confidence": true, "log_level": "INFO", "version": "v3.1", "etcd_mode": true, "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-ml-etcd", "ttl": 180}}' > $(ML_DETECTOR_TRICAPA_ETCD_CONFIG)

	@echo "$(BLUE)📝 Creando config scheduler_firewall_etcd_config_dev.json...$(NC)"
	@test -f $(SCHEDULER_FIREWALL_ETCD_CONFIG) || echo '{"input_port": 5561, "firewall_port": 5562, "rules_file": "config/json/firewall_rules_v31.json", "log_level": "INFO", "version": "v3.1", "etcd_mode": true, "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-scheduler-etcd", "ttl": 180}}' > $(SCHEDULER_FIREWALL_ETCD_CONFIG)

	@echo "$(BLUE)📝 Creando config simple_firewall_agent_v31_etcd.json...$(NC)"
	@test -f $(FIREWALL_AGENT_ETCD_CONFIG) || echo '{"agent_id": "firewall_etcd_001", "port": 5562, "rules_file": "config/json/firewall_rules_v31.json", "enabled": true, "log_level": "INFO", "version": "v3.1", "etcd_mode": true, "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-firewall-etcd", "ttl": 180}}' > $(FIREWALL_AGENT_ETCD_CONFIG)

	@echo "$(BLUE)📝 Creando config dashboard_config_v31_etcd.json...$(NC)"
	@test -f $(DASHBOARD_ETCD_CONFIG) || echo '{"port": 8080, "ml_input_port": 5580, "host": "localhost", "debug": false, "firewall_integration": true, "version": "v3.1", "etcd_mode": true, "distributed_mode": true, "service_discovery": {"enabled": true, "etcd_endpoint": "http://localhost:2379", "service_name": "axiom-dashboard-etcd", "ttl": 180}}' > $(DASHBOARD_ETCD_CONFIG)

	@echo "$(BLUE)📝 Verificando firewall_rules_v31.json...$(NC)"
	@test -f $(FIREWALL_RULES_V31) || echo '{"firewall_rules": {"rules": [], "manual_actions": {}, "firewall_agents": {}, "global_settings": {"version": "v3.1", "auto_block": true, "confidence_threshold": 0.8, "etcd_mode": true, "distributed_mode": true}}}' > $(FIREWALL_RULES_V31)

	@echo "$(GREEN)✅ Configuraciones etcd V3.1 creadas con soporte distribuido completo$(NC)"

# [Resto del Makefile permanece igual - todas las reglas originales...]

# =============================================================================
# MODO DISTRIBUIDO - etcd BACKBONE (mantener reglas originales)
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
	@if [ ! -f "$(ETCD_CONFIG_FILE)" ]; then \
		echo "$(RED)❌ Archivo de configuración no encontrado: $(ETCD_CONFIG_FILE)$(NC)"; \
		echo "$(YELLOW)💡 Asegúrate de que existe: config/etcd/etcd-basic-config.yaml$(NC)"; \
		exit 1; \
	fi
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

# [Resto de reglas dist-* mantener igual...]

# =============================================================================
# SISTEMA V3.1 EVOLUTIVO ORIGINAL (mantener)
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

# [Resto de reglas mantener igual...]

# =============================================================================
# SETUP Y CONFIGURACIÓN (mantener original)
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
	@echo "$(BLUE)📦 Instalando dependencias Sistema Autoinmune V3.1 + etcd...$(NC)"
	@echo "$(YELLOW)🔧 IMPORTANTE: Instalando requirements.txt con dependencias corregidas...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install -r requirements.txt
	@echo "$(BLUE)🔍 Verificando instalación de dependencias críticas...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import google.protobuf; print('✅ Protobuf version:', google.protobuf.__version__)"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import etcd3; print('✅ etcd3 client instalado')"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import zmq; print('✅ ZeroMQ version:', zmq.zmq_version())"
	@echo "$(GREEN)✅ Todas las dependencias instaladas correctamente$(NC)"

# [Todas las demás reglas del Makefile original se mantienen igual...]

# =============================================================================
# PARADAS (actualizar para incluir etcd)
# =============================================================================
stop:
	@echo "$(YELLOW)🛑 Deteniendo sistemas (V3.1 + demo + etcd)...$(NC)"

	# Detener PIDs V3.1 - Con manejo de errores mejorado
	@echo "$(BLUE)📝 Deteniendo servicios V3.1...$(NC)"
	@-if [ -f $(DASHBOARD_PID_V31) ]; then echo "📊 Deteniendo Dashboard V3.1..."; kill $$(cat $(DASHBOARD_PID_V31)) 2>/dev/null || true; rm -f $(DASHBOARD_PID_V31); fi
	@-if [ -f $(SCHEDULER_PID) ]; then echo "🎯 Deteniendo Scheduler..."; kill $$(cat $(SCHEDULER_PID)) 2>/dev/null || true; rm -f $(SCHEDULER_PID); fi
	@-if [ -f $(ML_TRICAPA_PID_V31) ]; then echo "🤖 Deteniendo ML Tricapa V3.1..."; kill $$(cat $(ML_TRICAPA_PID_V31)) 2>/dev/null || true; rm -f $(ML_TRICAPA_PID_V31); fi
	@-if [ -f $(GEOIP_PID_V31) ]; then echo "🌍 Deteniendo GeoIP V3.1..."; kill $$(cat $(GEOIP_PID_V31)) 2>/dev/null || true; rm -f $(GEOIP_PID_V31); fi
	@-if [ -f $(FIREWALL_PID_V31) ]; then echo "🛡️  Deteniendo Firewall V3.1..."; kill $$(cat $(FIREWALL_PID_V31)) 2>/dev/null || true; rm -f $(FIREWALL_PID_V31); fi

	# Detener secuencia etcd
	@echo "$(BLUE)📝 Deteniendo servicios etcd...$(NC)"
	@$(MAKE) stop-etcd-v31 2>/dev/null || true

	# Detener Evolutionary Sniffer con sudo mejorado
	@echo "$(BLUE)🕵️  Deteniendo Evolutionary Sniffer V3.1...$(NC)"
	@-if [ -f $(EVOLUTIONARY_SNIFFER_PID_V31) ]; then \
		PID=$$(cat $(EVOLUTIONARY_SNIFFER_PID_V31)); \
		kill $$PID 2>/dev/null || sudo kill $$PID 2>/dev/null || true; \
		rm -f $(EVOLUTIONARY_SNIFFER_PID_V31); \
	fi

	# pkill por patrón - Con prefijo - para ignorar errores
	@echo "$(BLUE)🔄 Limpieza por patrón...$(NC)"
	@-pkill -f "dashboard_v31|evolutionary_sniffer_v31|geoip_enricher_v31|ml_detector_tricapa_v31|scheduler-firewall|simple_firewall_agent_v31" 2>/dev/null || true
	@-sudo pkill -f "evolutionary_sniffer_v31" 2>/dev/null || true

	@echo "$(GREEN)✅ Sistemas V3.1 detenidos$(NC)"
	@echo "$(YELLOW)💡 Para detener backbone distribuido: make dist-stop$(NC)"

# [Resto de reglas mantener igual...]
# status_v31, monitor_v31, logs-v31, quick_v31, etc.

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

show-dashboard:
	@echo "$(BLUE)🌐 Abriendo dashboard...$(NC)"
	@echo "$(YELLOW)V3.1 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@which open >/dev/null && open http://localhost:$(DASHBOARD_WEB_PORT) || \
       which xdg-open >/dev/null && xdg-open http://localhost:$(DASHBOARD_WEB_PORT) || \
       echo "💡 Abrir manualmente: http://localhost:$(DASHBOARD_WEB_PORT)"

# [Resto de reglas mantener igual: verify, check-deps, clean, etc.]

clean:
	@echo "$(YELLOW)🧹 Limpiando sistema completo...$(NC)"
	@$(MAKE) stop 2>/dev/null || true
	@$(MAKE) dist-stop 2>/dev/null || true
	@$(MAKE) stop-etcd-v31 2>/dev/null || true
	@rm -rf $(VENV_NAME)
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -f $(PROTOBUF_DIR)/*_pb2.py
	@rm -rf $(PIDS_DIR) $(LOGS_DIR)
	@rm -rf $(ETCD_DATA_DIR)/* $(ETCD_LOG_DIR)/etcd.log 2>/dev/null || true
	@echo "$(GREEN)✅ Limpieza completa completada$(NC)"

verify:
	@echo "$(BLUE)🔍 Verificando sistema completo...$(NC)"
	@echo ""
	@echo "$(BLUE)📦 Configuraciones V3.1:$(NC)"
	@$(MAKE) verify-configs-v31
	@echo ""
	@echo "$(BLUE)📦 Configuraciones etcd:$(NC)"
	@for config in $(EVOLUTIONARY_SNIFFER_ETCD_CONFIG) $(GEOIP_ENRICHER_ETCD_CONFIG) $(ML_DETECTOR_TRICAPA_ETCD_CONFIG) $(SCHEDULER_FIREWALL_ETCD_CONFIG) $(FIREWALL_AGENT_ETCD_CONFIG) $(DASHBOARD_ETCD_CONFIG); do \
		if [ -f "$$config" ]; then \
			echo "  ✅ $$config"; \
		else \
			echo "  ❌ $$config falta"; \
		fi \
	done
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

check-deps:
	@echo "$(BLUE)🔍 Verificando dependencias críticas...$(NC)"
	@echo "$(YELLOW)🔧 Dependencias indispensables del sistema:$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import zmq; print('✅ ZeroMQ:', zmq.zmq_version())" 2>/dev/null || echo "❌ ZeroMQ falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import json; print('✅ JSON: nativo Python')" 2>/dev/null || echo "❌ JSON falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import google.protobuf; print('✅ Protobuf:', google.protobuf.__version__)" 2>/dev/null || echo "❌ Protobuf falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import etcd3; print('✅ etcd3')" 2>/dev/null || echo "❌ etcd3 falta"
	@echo "$(YELLOW)🔧 Dependencias de captura y análisis:$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import scapy; print('✅ Scapy')" 2>/dev/null || echo "❌ Scapy falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import psutil; print('✅ PSUtil')" 2>/dev/null || echo "❌ PSUtil falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import geoip2; print('✅ GeoIP2')" 2>/dev/null || echo "❌ GeoIP2 falta"
	@echo "$(YELLOW)🔧 Dependencias ML:$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import sklearn; print('✅ Scikit-learn')" 2>/dev/null || echo "❌ Scikit-learn falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import joblib; print('✅ Joblib')" 2>/dev/null || echo "❌ Joblib falta"
	@echo "$(YELLOW)🔧 Herramientas del sistema:$(NC)"
	@which protoc >/dev/null && echo "✅ protoc (sistema)" || echo "❌ protoc falta - instalar: brew install protobuf"
	@which etcd >/dev/null && echo "✅ etcd" || echo "❌ etcd falta (make dist-install-etcd)"
	@which etcdctl >/dev/null && echo "✅ etcdctl" || echo "❌ etcdctl falta"
	@echo "$(YELLOW)🔧 Verificando compatibilidad protobuf-etcd3...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import google.protobuf; v=google.protobuf.__version__; print('✅ Protobuf compatible:', v) if v.startswith('3.') else print('⚠️  Protobuf puede causar problemas con etcd3:', v)"

# [Mantener todas las demás reglas del Makefile original igual]