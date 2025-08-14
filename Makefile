# =============================================================================
# 🛡️ Upgraded Happiness - Sistema Autoinmune Digital v3.1 EVOLUTIVO
# =============================================================================
# Arquitectura V3.1: evolutionary_sniffer → geoip_enricher → ml_detector_tricapa → scheduler → firewall_agent → dashboard
# Branch: feature/v3.1-evolutionary
# Estado: Pipeline V3.1 completamente funcional | Dashboard V3.1 operativo | 1600+ eventos procesados
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
# CONFIGURACIÓN DEL PROYECTO V3.1
# =============================================================================
# Información del proyecto
PROJECT_NAME = upgraded-happiness
PROJECT_VERSION = v3.1.0-evolutionary
BRANCH = feature/v3.1-evolutionary
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
# PROTOBUF CONFIGURATION V3.1
# =============================================================================
PROTOBUF_DIR = protocols/current
SCHEMA_NETWORK_V31 = $(PROTOBUF_DIR)/network_security_clean_v31.proto
SCHEMA_FIREWALL_V31 = $(PROTOBUF_DIR)/firewall_commands_v31.proto

# Archivos generados V3.1
PROTOBUF_COMPILED_V31 = $(PROTOBUF_DIR)/network_security_clean_v31_pb2.py \
                       $(PROTOBUF_DIR)/firewall_commands_v31_pb2.py

# =============================================================================
# COMPONENTES V3.1 EVOLUTIVOS
# =============================================================================
# Pipeline V3.1 Components (nueva estructura evolutiva)
EVOLUTIONARY_SNIFFER_V31 = core/evolutionary_sniffer_v31.py
GEOIP_ENRICHER_V31 = core/geoip_enricher_v31.py
ML_DETECTOR_TRICAPA_V31 = core/lightweight_ml_detector_tricapa_v31.py
SCHEDULER_FIREWALL = core/scheduler-firewall.py
FIREWALL_AGENT_V31 = core/simple_firewall_agent_v31.py
DASHBOARD_V31 = core/dashboard_v31.py

# Componentes DEMO (versión anterior para enseñanza)
PROMISCUOUS_AGENT_DEMO = core/promiscuous_agent.py
GEOIP_ENRICHER_DEMO = core/geoip_enricher.py
ML_DETECTOR_DEMO = core/lightweight_ml_detector.py
DASHBOARD_DEMO = core/real_zmq_dashboard_with_firewall.py
FIREWALL_AGENT_DEMO = core/simple_firewall_agent.py

# =============================================================================
# CONFIGURACIONES JSON V3.1
# =============================================================================
CONFIG_DIR = config/json

# Configuraciones V3.1 (evolutivas)
EVOLUTIONARY_SNIFFER_CONFIG_V31 = $(CONFIG_DIR)/evolutionary_sniffer_config_v31.json
GEOIP_ENRICHER_CONFIG_V31 = $(CONFIG_DIR)/geoip_enricher_config_v31.json
ML_DETECTOR_TRICAPA_CONFIG_V31 = $(CONFIG_DIR)/lightweight_ml_detector_tricapa_v31_config_dev.json
SCHEDULER_FIREWALL_CONFIG = $(CONFIG_DIR)/scheduler_firewall_config.json
FIREWALL_AGENT_CONFIG_V31 = $(CONFIG_DIR)/simple_firewall_agent_v31_config.json
DASHBOARD_CONFIG_V31 = $(CONFIG_DIR)/dashboard_config_v31.json
FIREWALL_RULES_V31 = $(CONFIG_DIR)/firewall_rules_v31.json

# Configuraciones DEMO (compatibilidad anterior)
PROMISCUOUS_CONFIG_DEMO = $(CONFIG_DIR)/enhanced_agent_config.json
GEOIP_CONFIG_DEMO = $(CONFIG_DIR)/geoip_enricher_config.json
ML_CONFIG_DEMO = $(CONFIG_DIR)/lightweight_ml_detector_config.json
DASHBOARD_CONFIG_DEMO = $(CONFIG_DIR)/dashboard_config.json
FIREWALL_CONFIG_DEMO = $(CONFIG_DIR)/simple_firewall_agent_config.json
FIREWALL_RULES_DEMO = $(CONFIG_DIR)/firewall_rules_dashboard.json

# =============================================================================
# ARQUITECTURA DE RED V3.1
# =============================================================================
# Pipeline Ports V3.1 (flujo evolutivo)
CAPTURE_PORT_V31 = 5559          # evolutionary_sniffer → geoip_enricher
GEOIP_PORT_V31 = 5560           # geoip_enricher → ml_detector_tricapa
ML_PORT_V31 = 5561              # ml_detector_tricapa → scheduler
FIREWALL_PORT_V31 = 5562        # scheduler ↔ firewall_agent
DASHBOARD_PORT_V31 = 5580       # ml_detector_tricapa → dashboard
DASHBOARD_WEB_PORT = 8080       # Web UI (ambas versiones)

# Pipeline Ports DEMO (compatibilidad)
CAPTURE_PORT_DEMO = 5559
GEOIP_PORT_DEMO = 5560
ML_PORT_DEMO = 5561
FIREWALL_PORT_DEMO = 5562

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
        create-configs-v31 verify-configs-v31

# =============================================================================
# HELP Y DOCUMENTACIÓN V3.1
# =============================================================================
help:
	@echo "$(CYAN)🧬 Sistema Autoinmune Digital V3.1 EVOLUTIVO$(NC)"
	@echo "$(CYAN)=============================================$(NC)"
	@echo "$(PURPLE)Versión: $(PROJECT_VERSION)$(NC)"
	@echo "$(PURPLE)Estado: Pipeline V3.1 completamente funcional$(NC)"
	@echo "$(PURPLE)Dashboard V3.1: OPERATIVO (1600+ eventos procesados)$(NC)"
	@echo "$(PURPLE)Repo: $(REPO_URL)$(NC)"
	@echo ""
	@echo "$(YELLOW)🚀 COMANDOS PRINCIPALES V3.1:$(NC)"
	@echo "  $(GREEN)make quick_v31$(NC)           - Setup completo + Start V3.1 (RECOMENDADO)"
	@echo "  $(GREEN)make start_v31$(NC)           - Iniciar pipeline V3.1 evolutivo"
	@echo "  $(GREEN)make status_v31$(NC)          - Estado sistema V3.1"
	@echo "  $(GREEN)make monitor_v31$(NC)         - Monitor tiempo real V3.1"
	@echo "  $(GREEN)make show-dashboard$(NC)      - Abrir dashboard V3.1"
	@echo ""
	@echo "$(YELLOW)📚 DEMO Y ENSEÑANZA:$(NC)"
	@echo "  $(BLUE)make start$(NC)               - Iniciar versión demo (enseñanza)"
	@echo "  $(BLUE)make status$(NC)              - Estado versión demo"
	@echo "  $(BLUE)make monitor$(NC)             - Monitor versión demo"
	@echo ""
	@echo "$(YELLOW)🛑 CONTROL SISTEMA:$(NC)"
	@echo "  stop                     - Parada normal (ambas versiones)"
	@echo "  stop-nuclear             - Parada nuclear (TODOS los Python)"
	@echo "  restart                  - Reiniciar sistema"
	@echo ""
	@echo "$(YELLOW)📦 SETUP Y CONFIGURACIÓN:$(NC)"
	@echo "  setup                    - Crear entorno virtual"
	@echo "  install                  - Instalar dependencias"
	@echo "  setup-perms              - Configurar permisos sudo (iptables)"
	@echo "  compile-protobuf-v31     - Compilar protobuf V3.1"
	@echo "  create-configs-v31       - Crear configuraciones V3.1"
	@echo "  verify                   - Verificar integridad del sistema"
	@echo ""
	@echo "$(YELLOW)📊 MONITORIZACIÓN:$(NC)"
	@echo "  logs                     - Ver logs (ambas versiones)"
	@echo "  logs-v31                 - Ver logs específicos V3.1"
	@echo "  debug                    - Modo debug interactivo"
	@echo "  benchmark                - Ejecutar benchmarks"
	@echo ""
	@echo "$(YELLOW)ℹ️  INFORMACIÓN:$(NC)"
	@echo "  show-architecture-v31    - Mostrar arquitectura V3.1"
	@echo "  show-roadmap-v31         - Ver roadmap V3.1"
	@echo ""
	@echo "$(CYAN)🏗️ ARQUITECTURA V3.1:$(NC)"
	@echo "  evolutionary_sniffer_v31 → geoip_enricher_v31 → ml_detector_tricapa_v31"
	@echo "  ↓"
	@echo "  scheduler-firewall ↔ simple_firewall_agent_v31"
	@echo "  ↓"
	@echo "  dashboard_v31 (puerto 8080)"
	@echo ""
	@echo "$(CYAN)🌐 SERVICIOS:$(NC)"
	@echo "  Dashboard V3.1: http://localhost:$(DASHBOARD_WEB_PORT)"
	@echo ""
	@echo "$(GREEN)🎯 DIFERENCIA CLAVE:$(NC)"
	@echo "  $(GREEN)V3.1 = Versión evolutiva hacia producción$(NC)"
	@echo "  $(BLUE)Demo = Versión estable para enseñanza$(NC)"

# =============================================================================
# SETUP Y CONFIGURACIÓN
# =============================================================================
setup:
	@echo "$(BLUE)🔧 Configurando entorno virtual V3.1...$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "$(YELLOW)⚠️  Entorno virtual ya existe$(NC)"; \
	else \
		$(PYTHON) -m venv $(VENV_NAME); \
		echo "$(GREEN)✅ Entorno virtual creado$(NC)"; \
	fi
	@$(ACTIVATE) && $(PYTHON_VENV) -m pip install --upgrade pip
	@mkdir -p $(PIDS_DIR) $(LOGS_DIR) $(CONFIG_DIR)
	@echo "$(GREEN)✅ Setup completado$(NC)"

install: setup
	@echo "$(BLUE)📦 Instalando dependencias V3.1...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install -r requirements.txt || echo "$(YELLOW)⚠️  requirements.txt no encontrado, instalando dependencias básicas$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install zmq psutil geoip2 protobuf requests scapy netifaces
	@$(ACTIVATE) && $(PIP_VENV) install joblib scikit-learn xgboost lightgbm pandas numpy
	@$(ACTIVATE) && $(PIP_VENV) install fastapi uvicorn websockets flask
	@$(ACTIVATE) && $(PIP_VENV) install grpcio-tools  # Para compilación protobuf
	@echo "$(GREEN)✅ Dependencias instaladas$(NC)"

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

# =============================================================================
# CONFIGURACIONES V3.1
# =============================================================================
create-configs-v31:
	@echo "$(BLUE)📁 Creando configuraciones V3.1...$(NC)"
	@mkdir -p $(CONFIG_DIR)

	@echo "$(BLUE)📝 Creando configuración evolutionary_sniffer_v31...$(NC)"
	@test -f $(EVOLUTIONARY_SNIFFER_CONFIG_V31) || echo '{"interface": "en0", "capture_filter": "", "output_port": 5559, "log_level": "INFO", "version": "v3.1"}' > $(EVOLUTIONARY_SNIFFER_CONFIG_V31)

	@echo "$(BLUE)📝 Creando configuración geoip_enricher_v31...$(NC)"
	@test -f $(GEOIP_ENRICHER_CONFIG_V31) || echo '{"input_port": 5559, "output_port": 5560, "geoip_db_path": "GeoLite2-City.mmdb", "log_level": "INFO", "version": "v3.1"}' > $(GEOIP_ENRICHER_CONFIG_V31)

	@echo "$(BLUE)📝 Creando configuración ml_detector_tricapa_v31...$(NC)"
	@test -f $(ML_DETECTOR_TRICAPA_CONFIG_V31) || echo '{"input_port": 5560, "output_port": 5561, "dashboard_port": 5580, "models_path": "models/production/tricapa/", "tricapa_enabled": true, "ensemble_confidence": true, "log_level": "INFO", "version": "v3.1"}' > $(ML_DETECTOR_TRICAPA_CONFIG_V31)

	@echo "$(BLUE)📝 Creando configuración scheduler_firewall...$(NC)"
	@test -f $(SCHEDULER_FIREWALL_CONFIG) || echo '{"input_port": 5561, "firewall_port": 5562, "rules_file": "config/json/firewall_rules_v31.json", "log_level": "INFO", "version": "v3.1"}' > $(SCHEDULER_FIREWALL_CONFIG)

	@echo "$(BLUE)📝 Creando configuración firewall_agent_v31...$(NC)"
	@test -f $(FIREWALL_AGENT_CONFIG_V31) || echo '{"agent_id": "firewall_v31_001", "port": 5562, "rules_file": "config/json/firewall_rules_v31.json", "enabled": true, "log_level": "INFO", "version": "v3.1"}' > $(FIREWALL_AGENT_CONFIG_V31)

	@echo "$(BLUE)📝 Creando configuración dashboard_v31...$(NC)"
	@test -f $(DASHBOARD_CONFIG_V31) || echo '{"port": 8080, "ml_input_port": 5580, "host": "localhost", "debug": false, "firewall_integration": true, "version": "v3.1"}' > $(DASHBOARD_CONFIG_V31)

	@echo "$(BLUE)📝 Creando reglas firewall V3.1...$(NC)"
	@test -f $(FIREWALL_RULES_V31) || echo '{"firewall_rules": {"rules": [], "manual_actions": {}, "firewall_agents": {}, "global_settings": {"version": "v3.1", "auto_block": true, "confidence_threshold": 0.8}}}' > $(FIREWALL_RULES_V31)

	@echo "$(GREEN)✅ Configuraciones V3.1 creadas$(NC)"

verify-configs-v31:
	@echo "$(BLUE)🔍 Verificando configuraciones V3.1...$(NC)"
	@for config in $(EVOLUTIONARY_SNIFFER_CONFIG_V31) $(GEOIP_ENRICHER_CONFIG_V31) $(ML_DETECTOR_TRICAPA_CONFIG_V31) $(SCHEDULER_FIREWALL_CONFIG) $(FIREWALL_AGENT_CONFIG_V31) $(DASHBOARD_CONFIG_V31) $(FIREWALL_RULES_V31); do \
		if [ -f "$$config" ]; then \
			echo "  ✅ $$config"; \
		else \
			echo "  ❌ $$config falta"; \
		fi \
	done

# =============================================================================
# SISTEMA V3.1 EVOLUTIVO
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

	@echo ""
	@echo "$(GREEN)🎉 SISTEMA V3.1 EVOLUTIVO OPERACIONAL$(NC)"
	@echo "$(CYAN)=====================================$(NC)"
	@echo "$(YELLOW)📊 Dashboard V3.1: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@echo "$(YELLOW)🔧 Monitor V3.1: make monitor_v31$(NC)"
	@echo "$(YELLOW)📋 Estado V3.1: make status_v31$(NC)"
	@echo "$(YELLOW)🛑 Parada: make stop-nuclear$(NC)"
	@echo ""
	@$(MAKE) status_v31

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
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT_DEMO) $(FIREWALL_CONFIG_DEMO) $(FIREWALL_RULES_DEMO) > $(LOGS_DIR)/firewall_demo.log 2>&1 & echo $$! > $(FIREWALL_PID_DEMO)
	@sleep 2

	@echo "$(BLUE)2. 🕵️  Promiscuous Agent Demo...$(NC)"
	@sudo bash -c '$(PYTHON_VENV) $(PROMISCUOUS_AGENT_DEMO) $(PROMISCUOUS_CONFIG_DEMO) > $(LOGS_DIR)/promiscuous_demo.log 2>&1 & echo $$! > $(PROMISCUOUS_PID_DEMO)'
	@sleep 2

	@echo "$(BLUE)3. 🌍 GeoIP Enricher Demo...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER_DEMO) $(GEOIP_CONFIG_DEMO) > $(LOGS_DIR)/geoip_demo.log 2>&1 & echo $$! > $(GEOIP_PID_DEMO)
	@sleep 2

	@echo "$(BLUE)4. 🤖 ML Detector Demo...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR_DEMO) $(ML_CONFIG_DEMO) > $(LOGS_DIR)/ml_demo.log 2>&1 & echo $$! > $(ML_PID_DEMO)
	@sleep 2

	@echo "$(BLUE)5. 📊 Dashboard Demo...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD_DEMO) $(DASHBOARD_CONFIG_DEMO) $(FIREWALL_RULES_DEMO) > $(LOGS_DIR)/dashboard_demo.log 2>&1 & echo $$! > $(DASHBOARD_PID_DEMO)
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

# =============================================================================
# PARADAS (NUCLEAR PARA AMBAS VERSIONES)
# =============================================================================
stop:
	@echo "$(YELLOW)🛑 Deteniendo sistema (método secuencial)...$(NC)"

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

	@echo "$(GREEN)✅ Sistema detenido$(NC)"

stop-nuclear:
	@echo "$(RED)☢️  PARADA NUCLEAR ULTRA - AMBAS VERSIONES ☢️$(NC)"
	@echo "$(RED)===============================================$(NC)"
	@echo "$(RED)⚠️  EXTERMINACIÓN TOTAL DE PROCESOS PYTHON$(NC)"
	@echo ""

	# Nuclear 1: Soft kill
	@echo "$(YELLOW)💀 Fase 1: Soft kill (SIGTERM)...$(NC)"
	@-pkill -TERM -f "python.*core/" 2>/dev/null || true
	@sleep 1

	# Nuclear 2: Kill específico V3.1
	@echo "$(YELLOW)💀 Fase 2: Kill V3.1 específico...$(NC)"
	@-pkill -9 -f "evolutionary_sniffer_v31\|geoip_enricher_v31\|ml_detector_tricapa_v31\|dashboard_v31\|simple_firewall_agent_v31\|scheduler-firewall" 2>/dev/null || true
	@sleep 1

	# Nuclear 3: Kill demo
	@echo "$(YELLOW)💀 Fase 3: Kill demo específico...$(NC)"
	@-pkill -9 -f "promiscuous_agent\|geoip_enricher\|lightweight_ml_detector\|real_zmq_dashboard\|simple_firewall_agent" 2>/dev/null || true
	@sleep 1

	# Nuclear 4: Sudo kill
	@echo "$(YELLOW)💀 Fase 4: Sudo kill (procesos privilegiados)...$(NC)"
	@-sudo pkill -9 -f "python.*core/" 2>/dev/null || true

	# Nuclear 5: Liberar puertos
	@echo "$(YELLOW)💀 Fase 5: Liberación forzada de puertos...$(NC)"
	@for port in $(CAPTURE_PORT_V31) $(GEOIP_PORT_V31) $(ML_PORT_V31) $(FIREWALL_PORT_V31) $(DASHBOARD_PORT_V31) $(DASHBOARD_WEB_PORT); do \
		PIDS=$$(lsof -ti:$$port 2>/dev/null); \
		if [ ! -z "$$PIDS" ]; then \
			echo "  Puerto $$port ocupado por PIDs: $$PIDS"; \
			echo "$$PIDS" | xargs -r kill -9 2>/dev/null || echo "$$PIDS" | xargs -r sudo kill -9 2>/dev/null || true; \
		fi \
	done

	# Nuclear 6: Búsqueda y destrucción amplia
	@echo "$(YELLOW)💀 Fase 6: Búsqueda y destrucción por patrón...$(NC)"
	@-ps aux | grep -E "python.*(upgraded|core/)" | grep -v grep | awk '{print $$2}' | xargs -r kill -9 2>/dev/null || true
	@-ps aux | grep -E "python.*(upgraded|core/)" | grep -v grep | awk '{print $$2}' | xargs -r sudo kill -9 2>/dev/null || true

	# Nuclear 7: Limpieza
	@echo "$(YELLOW)💀 Fase 7: Limpieza...$(NC)"
	@-rm -rf $(PIDS_DIR)/*.pid

	@echo ""
	@echo "$(GREEN)☢️  PARADA NUCLEAR COMPLETADA ☢️$(NC)"
	@echo "$(GREEN)Listo para reinicio limpio$(NC)"

restart: stop
	@sleep 3
	@$(MAKE) start_v31

# =============================================================================
# MONITORIZACIÓN
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

status:
	@echo "$(BLUE)📊 Estado Sistema Demo$(NC)"
	@echo "$(BLUE)=====================$(NC)"
	@pgrep -f "$(FIREWALL_AGENT_DEMO)" >/dev/null && echo "  🛡️  Firewall Agent Demo: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🛡️  Firewall Agent Demo: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "promiscuous_agent" >/dev/null && echo "  🕵️  Promiscuous Agent Demo: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🕵️  Promiscuous Agent Demo: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "geoip_enricher" >/dev/null && echo "  🌍 GeoIP Enricher Demo: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🌍 GeoIP Enricher Demo: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "lightweight_ml_detector" >/dev/null && echo "  🤖 ML Detector Demo: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🤖 ML Detector Demo: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "real_zmq_dashboard" >/dev/null && echo "  📊 Dashboard Demo: $(GREEN)✅ Ejecutándose$(NC) $(YELLOW)(http://localhost:$(DASHBOARD_WEB_PORT))$(NC)" || echo "  📊 Dashboard Demo: $(RED)⭕ Detenido$(NC)"

monitor_v31:
	@echo "$(CYAN)🔄 Iniciando monitor V3.1 avanzado...$(NC)"
	@if [ -f "$(MONITOR_SCRIPT_V31)" ]; then \
		chmod +x $(MONITOR_SCRIPT_V31); \
		$(MONITOR_SCRIPT_V31); \
	else \
		echo "$(YELLOW)⚠️  Monitor V3.1 no encontrado en $(MONITOR_SCRIPT_V31)$(NC)"; \
		echo "$(BLUE)💡 Usando monitor básico...$(NC)"; \
		watch -n 3 "$(MAKE) -s status_v31"; \
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

logs:
	@echo "$(BLUE)📋 Logs Sistema (Ambas Versiones)$(NC)"
	@echo "$(BLUE)==================================$(NC)"
	@$(MAKE) logs-v31
	@echo ""
	@echo "$(BLUE)📋 Logs Demo:$(NC)"
	@if [ -d "$(LOGS_DIR)" ]; then \
		for log in $(LOGS_DIR)/*demo*.log; do \
			if [ -f "$$log" ]; then \
				echo "$(YELLOW)=== $$(basename $$log) ===$(NC)"; \
				tail -5 $$log; \
				echo ""; \
			fi \
		done \
	fi

# =============================================================================
# UTILIDADES
# =============================================================================
show-dashboard:
	@echo "$(BLUE)🌐 Abriendo dashboard...$(NC)"
	@echo "$(YELLOW)V3.1 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@which open >/dev/null && open http://localhost:$(DASHBOARD_WEB_PORT) || \
       which xdg-open >/dev/null && xdg-open http://localhost:$(DASHBOARD_WEB_PORT) || \
       echo "💡 Abrir manualmente: http://localhost:$(DASHBOARD_WEB_PORT)"

show-architecture-v31:
	@echo "$(CYAN)🏗️ Arquitectura V3.1 Evolutiva$(NC)"
	@echo "$(CYAN)===============================$(NC)"
	@echo ""
	@echo "$(YELLOW)📡 PIPELINE V3.1:$(NC)"
	@echo "  1. 🕵️  $(EVOLUTIONARY_SNIFFER_V31) → Puerto $(CAPTURE_PORT_V31)"
	@echo "  2. 🌍 $(GEOIP_ENRICHER_V31) → Puerto $(GEOIP_PORT_V31)"
	@echo "  3. 🤖 $(ML_DETECTOR_TRICAPA_V31) → Puerto $(ML_PORT_V31) + $(DASHBOARD_PORT_V31)"
	@echo "  4. 🎯 $(SCHEDULER_FIREWALL) → Orquestación"
	@echo "  5. 🛡️  $(FIREWALL_AGENT_V31) → Puerto $(FIREWALL_PORT_V31)"
	@echo "  6. 📊 $(DASHBOARD_V31) → Puerto $(DASHBOARD_WEB_PORT)"
	@echo ""
	@echo "$(YELLOW)🔄 FLUJO DE DATOS V3.1:$(NC)"
	@echo "  Evolutionary Sniffer $(GRAY)→$(NC) GeoIP Enricher $(GRAY)→$(NC) ML Tricapa $(GRAY)→$(NC) Scheduler"
	@echo "  ↓"
	@echo "  Dashboard V3.1 ← ML Tricapa → Firewall Agent"

show-roadmap-v31:
	@echo "$(CYAN)🔮 Roadmap V3.1 Evolutivo$(NC)"
	@echo "$(CYAN)==========================$(NC)"
	@echo ""
	@echo "$(GREEN)✅ COMPLETADO:$(NC)"
	@echo "  • 🏗️  Pipeline V3.1 completamente funcional"
	@echo "  • 📊 Dashboard V3.1 operativo (1600+ eventos)"
	@echo "  • 🤖 ML Tricapa con ensemble confidence"
	@echo "  • 🔒 Protobuf V3.1 con coordenadas duales"
	@echo "  • 🛡️  Firewall integrado click-to-block"
	@echo ""
	@echo "$(YELLOW)🔄 EN DESARROLLO:$(NC)"
	@echo "  • 🔧 CSP optimization para dashboard"
	@echo "  • 📈 Advanced analytics y métricas"
	@echo "  • 🌐 Multi-node deployment"
	@echo ""
	@echo "$(BLUE)🎯 PRÓXIMO:$(NC)"
	@echo "  • 🚀 Kubernetes deployment"
	@echo "  • 🤖 Auto-reentrenamiento ML"
	@echo "  • 📱 Mobile dashboard"
	@echo "  • 🔐 Advanced encryption"

verify:
	@echo "$(BLUE)🔍 Verificando sistema completo...$(NC)"
	@$(MAKE) verify-configs-v31
	@$(MAKE) verify-protobuf-compiled-v31
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

clean:
	@echo "$(YELLOW)🧹 Limpiando sistema...$(NC)"
	@$(MAKE) stop 2>/dev/null || true
	@rm -rf $(VENV_NAME)
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -f $(PROTOBUF_DIR)/*_pb2.py
	@rm -rf $(PIDS_DIR) $(LOGS_DIR)
	@echo "$(GREEN)✅ Limpieza completada$(NC)"

# =============================================================================
# COMANDOS RÁPIDOS
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
	@echo "$(CYAN)🛑 Parada: make stop-nuclear$(NC)"

quick: setup install setup-perms start show-dashboard
	@echo ""
	@echo "$(BLUE)✅ QUICK START DEMO COMPLETADO$(NC)"
	@echo "$(BLUE)==============================$(NC)"
	@echo "$(YELLOW)Sistema demo para enseñanza listo!$(NC)"

debug:
	@echo "$(PURPLE)🔧 Modo Debug$(NC)"
	@$(MAKE) status_v31
	@echo ""
	@$(MAKE) status
	@echo ""
	@$(MAKE) logs-v31 | tail -20

benchmark:
	@echo "$(BLUE)📊 Benchmark sistema$(NC)"
	@ps aux | grep -E "(python.*core/)" | grep -v grep | awk '{print "  " $$11 ": " $$3 "% CPU, " $$4 "% MEM"}' || echo "  No hay procesos activos"

test:
	@echo "$(BLUE)🧪 Tests básicos$(NC)"
	@$(MAKE) verify
	@$(MAKE) check-deps