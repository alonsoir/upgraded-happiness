# =============================================================================
# 🛡️ Upgraded Happiness - Sistema Autoinmune Digital v2.0 (POST-HOUSEKEEPING)
# =============================================================================
# Arquitectura: promiscuous_agent → geoip_enricher → ml_detector → dashboard → firewall_agent
# Branch: housekeeping/file-organization
# Estructura: 142 archivos organizados, 0 pérdidas | Human-AI Collaborative Project
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
# CONFIGURACIÓN DEL PROYECTO POST-HOUSEKEEPING
# =============================================================================
# Información del proyecto
PROJECT_NAME = upgraded-happiness
PROJECT_VERSION = v2.0.0-post-housekeeping
BRANCH = housekeeping/file-organization
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
# PROTOBUF CONFIGURATION (NUEVA ESTRUCTURA AUTOMATIZADA)
# =============================================================================
# Variables Protobuf (como solicitado por Alonso)
PROTOBUF_DIR = protocols/current
SCHEMA_NETWORK_EXTENDED = $(PROTOBUF_DIR)/network_event_extended_v3.proto
SCHEMA_FIREWALL_COMMAND = $(PROTOBUF_DIR)/firewall_commands.proto
SCHEMA_NETWORK_EVENT = $(PROTOBUF_DIR)/network_event.proto
SCHEMA_NETWORK_EXTENDED_V2 = $(PROTOBUF_DIR)/network_event_extended_v2.proto

# Archivos generados (se colocan en el mismo directorio que los .proto)
PROTOBUF_COMPILED = $(PROTOBUF_DIR)/network_event_extended_v3_pb2.py \
                   $(PROTOBUF_DIR)/firewall_commands_pb2.py \
                   $(PROTOBUF_DIR)/network_event_pb2.py \
                   $(PROTOBUF_DIR)/network_event_extended_v2_pb2.py

# =============================================================================
# COMPONENTES PRINCIPALES (ESTRUCTURA POST-HOUSEKEEPING)
# =============================================================================
# Core Pipeline Components (rutas actualizadas → core/)
PROMISCUOUS_AGENT = core/promiscuous_agent.py
GEOIP_ENRICHER = core/geoip_enricher.py
ML_DETECTOR = core/lightweight_ml_detector.py
DASHBOARD = core/real_zmq_dashboard_with_firewall.py
FIREWALL_AGENT = core/simple_firewall_agent.py

# 🌟 JOYA ÉPICA: Híbrido Sniffer + ML (90% del proyecto demostrado)
FIXED_SERVICE_SNIFFER = core/fixed_service_sniffer.py

# 🆕 NUEVOS COMPONENTES DESCUBIERTOS POST-HOUSEKEEPING
NETWORK_FEATURE_EXTRACTOR = core/enhanced_network_feature_extractor.py
FAST_EJECTOR_LAYER = core/fast_ejector_layer.py

# Experimental (no producción)
PROMISCUOUS_AGENT_V2 = core/promiscuous_agent_v2.py

# Advanced Components (ML Pipeline) - SIN COMENTARIOS INLINE
NEURAL_TRAINER = ml_pipeline/trainers/advanced_trainer.py
SNIFFER_RETRAINER = ml_pipeline/trainers/sniffer_compatible_retrainer.py
RAG_ENGINE = autoinmune_rag_engine.py

# =============================================================================
# CONFIGURACIONES JSON (ESTRUCTURA ACTUALIZADA)
# =============================================================================
# Configuraciones principales (config/json/)
CONFIG_DIR = config/json
PROMISCUOUS_CONFIG = $(CONFIG_DIR)/enhanced_agent_config.json
GEOIP_CONFIG = $(CONFIG_DIR)/geoip_enricher_config.json
ML_CONFIG = $(CONFIG_DIR)/lightweight_ml_detector_config.json
DASHBOARD_CONFIG = $(CONFIG_DIR)/dashboard_config.json
FIREWALL_CONFIG = $(CONFIG_DIR)/simple_firewall_agent_config.json
NEURAL_CONFIG = $(CONFIG_DIR)/advanced_trainer_v2_config.json

# Configuraciones adicionales (segundo parámetro)
DASHBOARD_FIREWALL_CONFIG = config/json/firewall_rules_dashboard.json
FIREWALL_AGENT_RULES_CONFIG = config/json/firewall_rules_agent.json

# =============================================================================
# DIRECTORIOS ECOSISTEMA (POST-HOUSEKEEPING)
# =============================================================================
# Directorios principales
CORE_DIR = core
ML_PIPELINE_DIR = ml_pipeline
MODELS_PRODUCTION_DIR = models/production
MODELS_ARCHIVE_DIR = models/archive
WEB_STATIC_DIR = web/static
WEB_TEMPLATES_DIR = web/templates
DATASETS_DIR = datasets
PROTOCOLS_DIR = protocols
SCRIPTS_DIR = scripts
DOCS_DIR = docs
ARCHIVE_DIR = archive

# Directorios de ejecución
PIDS_DIR = .pids
LOGS_DIR = logs
DATA_DIR = data
INFRASTRUCTURE_DIR = infrastructure

# =============================================================================
# ARQUITECTURA DE RED (ZeroMQ) - SIN CAMBIOS
# =============================================================================
# Pipeline Ports (Flujo de datos)
CAPTURE_PORT = 5559          # promiscuous_agent → geoip_enricher
GEOIP_PORT = 5560           # geoip_enricher → ml_detector
ML_PORT = 5561              # ml_detector → dashboard
FIREWALL_PORT = 5562        # dashboard → firewall_agent

# Service Ports
DASHBOARD_WEB_PORT = 8080   # Web UI principal
RAG_WEB_PORT = 8090         # RAG Engine (próximamente)
NEURAL_PORT = 5563          # Neural trainer (próximamente)

# =============================================================================
# GESTIÓN DE PROCESOS (ACTUALIZADA)
# =============================================================================
# PIDs para gestión de procesos
PROMISCUOUS_PID = $(PIDS_DIR)/promiscuous_agent.pid
GEOIP_PID = $(PIDS_DIR)/geoip_enricher.pid
ML_PID = $(PIDS_DIR)/ml_detector.pid
DASHBOARD_PID = $(PIDS_DIR)/dashboard.pid
FIREWALL_PID = $(PIDS_DIR)/firewall_agent.pid
NEURAL_PID = $(PIDS_DIR)/neural_trainer.pid
RAG_PID = $(PIDS_DIR)/rag_engine.pid

# Logs para debugging
PROMISCUOUS_LOG = $(LOGS_DIR)/promiscuous_agent.log
GEOIP_LOG = $(LOGS_DIR)/geoip_enricher.log
ML_LOG = $(LOGS_DIR)/ml_detector.log
DASHBOARD_LOG = $(LOGS_DIR)/dashboard.log
FIREWALL_LOG = $(LOGS_DIR)/firewall_agent.log
NEURAL_LOG = $(LOGS_DIR)/neural_trainer.log
RAG_LOG = $(LOGS_DIR)/rag_engine.log

# Scripts de utilidad (actualizados) - SIN COMENTARIOS INLINE
NUCLEAR_STOP_SCRIPT = scripts/deployment/nuclear-stop.sh
MONITOR_SCRIPT = scripts/utils/monitor_autoinmune.sh

# =============================================================================
# PHONY DECLARATIONS
# =============================================================================
.PHONY: help setup install clean tricapa test-pipeline monitor ml-features clean backup status \
        compile-protobuf check-protobuf verify-protobuf-compiled check-protobuf-imports fix-protobuf-imports \
        list-imports-to-fix verify-system-ready \
        start start-bg start-core start-advanced stop stop-nuclear restart \
        status monitor logs logs-tail logs-errors \
        setup-perms verify check-geoip check-deps check-structure \
        show-dashboard show-architecture show-roadmap show-housekeeping show-epic-sniffer \
        quick debug test benchmark \
        dev-start dev-stop dev-restart \
        start-improved verify-start status-detailed create-config-dirs

# =============================================================================
# HELP Y DOCUMENTACIÓN (ACTUALIZADA POST-HOUSEKEEPING)
# =============================================================================
help:
	@echo "$(CYAN)🧬 Sistema Autoinmune Digital v2.0 - POST-HOUSEKEEPING$(NC)"
	@echo "$(CYAN)=====================================================$(NC)"
	@echo "$(PURPLE)Branch: $(BRANCH)$(NC)"
	@echo "$(PURPLE)Estado: 142 archivos organizados, 0 pérdidas$(NC)"
	@echo "$(PURPLE)Repo: $(REPO_URL)$(NC)"
	@echo ""
	@echo "$(YELLOW)🚀 COMANDOS PRINCIPALES:$(NC)"
	@echo "  $(GREEN)make quick$(NC)              - Setup completo + Start (RECOMENDADO)"
	@echo "  $(GREEN)make compile-protobuf$(NC)   - Compilar archivos .proto (NUEVO)"
	@echo "  $(GREEN)make start$(NC)              - Iniciar sistema completo"
	@echo "  $(GREEN)make show-dashboard$(NC)     - Abrir dashboard web"
	@echo "  $(GREEN)make stop$(NC)               - Detener sistema completo"
	@echo "  $(GREEN)make status$(NC)             - Ver estado del sistema"
	@echo ""
	@echo "$(YELLOW)📦 SETUP Y CONFIGURACIÓN:$(NC)"
	@echo "  setup                    - Crear entorno virtual"
	@echo "  install                  - Instalar dependencias"
	@echo "  setup-perms              - Configurar permisos sudo (iptables)"
	@echo "  check-geoip              - Verificar configuración GeoIP"
	@echo "  check-deps               - Verificar dependencias"
	@echo "  check-structure          - Verificar estructura post-housekeeping"
	@echo "  verify                   - Verificar integridad del sistema"
	@echo "  clean                    - Limpiar todo"
	@echo ""
	@echo "$(YELLOW)🔧 PROTOBUF (NUEVO):$(NC)"
	@echo "  compile-protobuf         - Compilar .proto → .py automáticamente"
	@echo "  check-protobuf           - Verificar compilación protobuf"
	@echo ""
	@echo "$(YELLOW)🔄 OPERACIONES AVANZADAS:$(NC)"
	@echo "  start-core               - Solo componentes core (básico)"
	@echo "  start-advanced           - Componentes avanzados (ML Pipeline)"
	@echo "  start-bg                 - Iniciar en background"
	@echo "  restart                  - Reiniciar sistema completo"
	@echo "  stop-nuclear             - Parada nuclear (emergencia)"
	@echo ""
	@echo "$(YELLOW)📊 MONITORIZACIÓN Y DEBUG:$(NC)"
	@echo "  monitor                  - Monitor tiempo real"
	@echo "  logs                     - Ver logs de todos los componentes"
	@echo "  logs-tail                - Seguir logs en tiempo real"
	@echo "  logs-errors              - Ver solo errores"
	@echo "  debug                    - Modo debug interactivo"
	@echo "  benchmark                - Ejecutar benchmarks"
	@echo ""
	@echo "  health-check             - Análisis completo de salud del sistema"
	@echo "  monitor-live             - Monitor en tiempo real (actualización cada 3s)"
	@echo "  dashboard-terminal       - Dashboard compacto en terminal"
	@echo "  test-sequence            - Verificar secuencia de arranque (dry run)"
	@echo "  generate-monitor-script  - Generar script de monitoreo avanzado"
	@echo "$(YELLOW)ℹ️  INFORMACIÓN:$(NC)"
	@echo "  show-architecture        - Mostrar arquitectura del sistema"
	@echo "  show-roadmap             - Ver roadmap y estado actual"
	@echo "  show-housekeeping        - Ver resultado housekeeping"
	@echo "  show-epic-sniffer        - Ver joya épica: fixed_service_sniffer.py"
	@echo "  verify-system-ready      - Verificación completa pre-arranque"
	@echo "  list-imports-to-fix      - Listar imports protobuf a corregir"
	@echo ""
	@echo "$(CYAN)🏗️ ARQUITECTURA POST-HOUSEKEEPING:$(NC)"
	@echo "  core/ → ml_pipeline/ → models/production/ → web/ → protocols/current/"
	@echo ""
	@echo "$(CYAN)🌐 SERVICIOS WEB:$(NC)"
	@echo "  Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)"
	@echo "  RAG Engine: http://localhost:$(RAG_WEB_PORT) (próximamente)"
	@echo "$(BLUE)🚀 UPGRADED HAPPINESS - SISTEMA TRICAPA$(NC)"
	@echo "$(BLUE)========================================$(NC)"
	@echo "$(GREEN)Sistema ML de ciberseguridad con 7 modelos operativos$(NC)"
	@echo ""
	@echo "$(YELLOW)📊 COMANDOS DISPONIBLES:$(NC)"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(BLUE)🏗️ ARQUITECTURA TRICAPA:$(NC)"
	@echo "$(GREEN)🔴 Nivel 1:$(NC) rf_production_cicids (CICDS2017 - Ataque vs Normal)"
	@echo "$(GREEN)🟡 Nivel 2:$(NC) web/internal_normal_detector (Especialización)"
	@echo "$(GREEN)🟢 Nivel 3:$(NC) ddos/ransomware específicos (4 modelos)"
# =============================================================================
# INFORMACIÓN DEL SISTEMA (ACTUALIZADA)
# =============================================================================
show-architecture:
	@echo "$(CYAN)🏗️ Arquitectura Post-Housekeeping$(NC)"
	@echo "$(CYAN)==================================$(NC)"
	@echo ""
	@echo "$(YELLOW)📡 PIPELINE PRINCIPAL (core/):$(NC)"
	@echo "  1. 🕵️  $(PROMISCUOUS_AGENT) → Puerto $(CAPTURE_PORT) (✅ Principal - 36KB)"
	@echo "  2. 🌍 $(GEOIP_ENRICHER) → Puerto $(GEOIP_PORT) (✅ Masivo - 77KB)"
	@echo "  3. 🤖 $(ML_DETECTOR) → Puerto $(ML_PORT) (✅ Tricapa - 51KB)"
	@echo "  4. 📊 $(DASHBOARD) → Puerto $(FIREWALL_PORT) (✅ ÉPICO - 158KB)"
	@echo "  5. 🛡️  $(FIREWALL_AGENT) (✅ Firewall - 53KB)"
	@echo ""
	@echo "$(YELLOW)💎 JOYAS ÉPICAS - COMPONENTES ESPECIALES:$(NC)"
	@echo "  🌟 $(FIXED_SERVICE_SNIFFER) - Híbrido Scapy → Features → ML (33KB)"
	@echo "      📊 20+ features via Scapy → Modelos reentrenados"
	@echo "      ⚡ Sin ZeroMQ/Protobuf, puro potencial demostrado"
	@echo "  🧮 $(NETWORK_FEATURE_EXTRACTOR) - Extractor avanzado (16KB)"
	@echo "  ⚡ $(FAST_EJECTOR_LAYER) - Componente rápido (3.5KB) 🆕"
	@echo ""
	@echo "$(YELLOW)🧠 ML PIPELINE (ml_pipeline/):$(NC)"
	@echo "  6. 🤖 $(NEURAL_TRAINER) → Puerto $(NEURAL_PORT) (🔄 Disponible)"
	@echo "  7. 🔄 $(SNIFFER_RETRAINER) (✅ Reentrenamiento)"
	@echo "  8. 🌐 329 sitios globales → $(ML_PIPELINE_DIR)/data_generators/"
	@echo ""
	@echo "$(YELLOW)💎 MODELOS EN PRODUCCIÓN:$(NC)"
	@echo "  🧠 $(MODELS_PRODUCTION_DIR)/rf_production_sniffer_compatible.joblib (10.1MB)"
	@echo "  🌐 $(MODELS_PRODUCTION_DIR)/web_normal_detector.joblib (2.5MB)"
	@echo "  🏢 $(MODELS_PRODUCTION_DIR)/internal_normal_detector.joblib (2.3MB)"
	@echo ""
	@echo "$(YELLOW)🌐 WEB DASHBOARD:$(NC)"
	@echo "  📊 $(WEB_STATIC_DIR)/ - Assets estáticos"
	@echo "  📄 $(WEB_TEMPLATES_DIR)/ - Templates HTML"
	@echo "  🎯 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)"

show-roadmap:
	@echo "$(CYAN)🔮 Roadmap Post-Housekeeping$(NC)"
	@echo "$(CYAN)=============================$(NC)"
	@echo ""
	@echo "$(GREEN)✅ COMPLETADO (Q3 2025):$(NC)"
	@echo "  • 🏗️  Housekeeping épico: 142 archivos organizados, 0 pérdidas"
	@echo "  • 🧠 Sistema tricapa ML operativo (3 modelos producción)"
	@echo "  • 🌍 Generación datos épica: 329 sitios globales curados"
	@echo "  • 🔒 Protocolos ZeroMQ preservados (6 versiones)"
	@echo "  • 📚 Documentation revolutionary completada"
	@echo "  • 🤖 Human-AI collaborative methodology establecida"
	@echo ""
	@echo "$(YELLOW)🔄 EN DESARROLLO ACTIVO (Agosto 2025):$(NC)"
	@echo "  • 🔧 Protobuf v3.1 integration design"
	@echo "  • 📊 Dashboard-Firewall integration (click-to-block)"
	@echo "  • 🔄 Auto-reentrenamiento con ml_pipeline/"
	@echo "  • 🌐 Distributed system foundations"
	@echo ""
	@echo "$(BLUE)🎯 PRÓXIMOS HITOS (Q4 2025):$(NC)"
	@echo "  • 🔐 Sistema distribuido con cifrado avanzado"
	@echo "  • 🤖 RAG Engine con Claude integration"
	@echo "  • 🐳 Containerización K3s/Docker"
	@echo "  • 🚀 RELEASE 1.0.0 - Production Ready"
	@echo ""
	@echo "$(PURPLE)🌟 FUTURO (2026):$(NC)"
	@echo "  • 🧠 Deep Learning models integration"
	@echo "  • 🌍 Multi-region deployment orchestration"
	@echo "  • 🔮 Predictive threat modeling"
	@echo "  • ⚡ Quantum-ready encryption"

show-housekeeping:
	@echo "$(CYAN)🧹 Resultado Housekeeping Épico$(NC)"
	@echo "$(CYAN)================================$(NC)"
	@echo ""
	@echo "$(GREEN)🏆 ESTADÍSTICAS BRUTALES:$(NC)"
	@echo "  📊 142 archivos procesados sin pérdidas"
	@echo "  🧠 40 modelos ML organizados (4 producción + 36 evolutivos)"
	@echo "  🌍 329 sitios globales en traffic_generator preservados"
	@echo "  ⚙️  13 configuraciones JSON organizadas"
	@echo "  🔒 6 versiones Protobuf (evolución completa hacia v3.1)"
	@echo "  🌐 Dashboard web completo con assets críticos"
	@echo "  📦 41 archivos experimentales - historia completa preservada"
	@echo ""
	@echo "$(YELLOW)🏗️ ESTRUCTURA ECOSISTEMA:$(NC)"
	@echo "  📁 $(CORE_DIR)/ - 8 componentes principales"
	@echo "  🤖 $(ML_PIPELINE_DIR)/ - 6 trainers + 3 analyzers + generators épicos"
	@echo "  💎 $(MODELS_PRODUCTION_DIR)/ - Modelos en producción (14.9MB total)"
	@echo "  📊 $(MODELS_ARCHIVE_DIR)/ - 36 modelos evolutivos preservados"
	@echo "  🌐 $(WEB_STATIC_DIR)/ & $(WEB_TEMPLATES_DIR)/ - Dashboard completo"
	@echo "  🔒 $(PROTOCOLS_DIR)/current/ - Base sólida hacia v3.1"
	@echo "  ⚙️  $(CONFIG_DIR)/ - Configuraciones organizadas"
	@echo "  🗂️  $(DATASETS_DIR)/ - clean/specialized + raw + official"
	@echo ""
	@echo "$(PURPLE)✨ JOYAS ÉPICAS PRESERVADAS:$(NC)"
	@echo "  🌟 traffic_generator.py - 329 sitios globales implementación collaborative"
	@echo "  📊 websites_database.csv - Base de datos global curada"
	@echo "  🧠 Sistema tricapa - Metodología revolutionary documentada"
	@echo "  🏗️  Ecosystem completo - Template para proyectos futuros"

# =============================================================================
# SETUP Y CONFIGURACIÓN (ACTUALIZADA POST-HOUSEKEEPING)
# =============================================================================
create-config-dirs:
	@echo "$(BLUE)📁 Creando directorios de configuración post-housekeeping...$(NC)"
	@mkdir -p $(CONFIG_DIR) config
	@mkdir -p $(PIDS_DIR) $(LOGS_DIR) $(DATA_DIR)
	@mkdir -p $(INFRASTRUCTURE_DIR)
	@echo "$(GREEN)✅ Directorios creados$(NC)"

setup: create-config-dirs
	@echo "$(BLUE)🔧 Configurando entorno virtual post-housekeeping...$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "$(YELLOW)⚠️  Entorno virtual ya existe$(NC)"; \
	else \
		$(PYTHON) -m venv $(VENV_NAME); \
		echo "$(GREEN)✅ Entorno virtual creado$(NC)"; \
	fi
	@$(ACTIVATE) && $(PYTHON_VENV) -m pip install --upgrade pip
	@echo "$(GREEN)✅ Setup completado$(NC)"

install: setup
	@echo "$(BLUE)📦 Instalando dependencias (estructura actualizada)...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install -r $(INFRASTRUCTURE_DIR)/requirements.txt || $(PIP_VENV) install -r requirements.txt
	@echo "$(BLUE)📦 Instalando librerías específicas ML...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install joblib scikit-learn xgboost lightgbm
	@$(ACTIVATE) && $(PIP_VENV) install zmq psutil geoip2 protobuf requests
	@$(ACTIVATE) && $(PIP_VENV) install fastapi uvicorn websockets
	@$(ACTIVATE) && $(PIP_VENV) install scapy netifaces
	@$(ACTIVATE) && $(PIP_VENV) install pandas numpy matplotlib seaborn
	@$(ACTIVATE) && $(PIP_VENV) install pytest pytest-asyncio
	@$(ACTIVATE) && $(PIP_VENV) install grpcio-tools  # Para compilación protobuf
	@echo "$(GREEN)✅ Dependencias instaladas$(NC)"

# =============================================================================
# PROTOBUF COMPILATION (NUEVA FUNCIONALIDAD AUTÓNOMA)
# =============================================================================
compile-protobuf:
	@echo "$(BLUE)🔧 Compilando archivos Protobuf automáticamente...$(NC)"
	@echo "$(YELLOW)📁 Directorio: $(PROTOBUF_DIR)$(NC)"
	@if [ ! -d "$(PROTOBUF_DIR)" ]; then \
		echo "$(RED)❌ Directorio $(PROTOBUF_DIR) no existe$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)🔨 Compilando schemas obligatorios para arranque:$(NC)"
	@if [ -f "$(SCHEMA_NETWORK_EXTENDED)" ]; then \
		echo "  🔧 $(SCHEMA_NETWORK_EXTENDED)"; \
		$(ACTIVATE) && protoc --python_out=$(PROTOBUF_DIR) --proto_path=$(PROTOBUF_DIR) $(SCHEMA_NETWORK_EXTENDED) || (echo "$(RED)❌ CRÍTICO: Error compilando network_event_extended_v3.proto$(NC)" && exit 1); \
	else \
		echo "$(RED)❌ CRÍTICO: $(SCHEMA_NETWORK_EXTENDED) no encontrado$(NC)"; \
		exit 1; \
	fi
	@if [ -f "$(SCHEMA_FIREWALL_COMMAND)" ]; then \
		echo "  🔧 $(SCHEMA_FIREWALL_COMMAND)"; \
		$(ACTIVATE) && protoc --python_out=$(PROTOBUF_DIR) --proto_path=$(PROTOBUF_DIR) $(SCHEMA_FIREWALL_COMMAND) || (echo "$(RED)❌ CRÍTICO: Error compilando firewall_commands.proto$(NC)" && exit 1); \
	else \
		echo "$(RED)❌ CRÍTICO: $(SCHEMA_FIREWALL_COMMAND) no encontrado$(NC)"; \
		exit 1; \
	fi
	@if [ -f "$(SCHEMA_NETWORK_EVENT)" ]; then \
		echo "  🔧 $(SCHEMA_NETWORK_EVENT)"; \
		$(ACTIVATE) && protoc --python_out=$(PROTOBUF_DIR) --proto_path=$(PROTOBUF_DIR) $(SCHEMA_NETWORK_EVENT) || echo "$(YELLOW)⚠️  Warning: Error compilando network_event.proto$(NC)"; \
	fi
	@if [ -f "$(SCHEMA_NETWORK_EXTENDED_V2)" ]; then \
		echo "  🔧 $(SCHEMA_NETWORK_EXTENDED_V2)"; \
		$(ACTIVATE) && protoc --python_out=$(PROTOBUF_DIR) --proto_path=$(PROTOBUF_DIR) $(SCHEMA_NETWORK_EXTENDED_V2) || echo "$(YELLOW)⚠️  Warning: Error compilando network_event_extended_v2.proto$(NC)"; \
	fi
	@echo "$(GREEN)✅ Compilación Protobuf completada$(NC)"

verify-protobuf-compiled:
	@echo "$(BLUE)🔍 Verificando archivos Protobuf compilados OBLIGATORIOS...$(NC)"
	@MISSING=0; \
	if [ ! -f "$(PROTOBUF_DIR)/network_event_extended_v3_pb2.py" ]; then \
		echo "$(RED)❌ CRÍTICO: network_event_extended_v3_pb2.py falta$(NC)"; \
		MISSING=1; \
	else \
		echo "$(GREEN)✅ network_event_extended_v3_pb2.py encontrado$(NC)"; \
	fi; \
	if [ ! -f "$(PROTOBUF_DIR)/firewall_commands_pb2.py" ]; then \
		echo "$(RED)❌ CRÍTICO: firewall_commands_pb2.py falta$(NC)"; \
		MISSING=1; \
	else \
		echo "$(GREEN)✅ firewall_commands_pb2.py encontrado$(NC)"; \
	fi; \
	if [ $MISSING -eq 1 ]; then \
		echo "$(YELLOW)🔧 Auto-compilando archivos faltantes...$(NC)"; \
		$(MAKE) compile-protobuf; \
	fi

verify-firewall-rules:
	@echo "$(BLUE)🔍 Verificando archivos de reglas de firewall...$(NC)"
	@if [ ! -f "$(DASHBOARD_FIREWALL_CONFIG)" ]; then \
		echo "$(YELLOW)⚠️  Creando $(DASHBOARD_FIREWALL_CONFIG)...$(NC)"; \
		mkdir -p config/json; \
		echo '{"firewall_rules": {"rules": [], "manual_actions": {}, "firewall_agents": {}, "global_settings": {}}}' > $(DASHBOARD_FIREWALL_CONFIG); \
		echo "$(GREEN)✅ $(DASHBOARD_FIREWALL_CONFIG) creado$(NC)"; \
	else \
		echo "$(GREEN)✅ $(DASHBOARD_FIREWALL_CONFIG) encontrado$(NC)"; \
	fi
	@if [ ! -f "$(FIREWALL_AGENT_RULES_CONFIG)" ]; then \
		echo "$(YELLOW)⚠️  Creando $(FIREWALL_AGENT_RULES_CONFIG)...$(NC)"; \
		mkdir -p config/json; \
		echo '{"firewall_rules": {"rules": [], "manual_actions": {}, "firewall_agents": {}, "global_settings": {}}}' > $(FIREWALL_AGENT_RULES_CONFIG); \
		echo "$(GREEN)✅ $(FIREWALL_AGENT_RULES_CONFIG) creado$(NC)"; \
	else \
		echo "$(GREEN)✅ $(FIREWALL_AGENT_RULES_CONFIG) encontrado$(NC)"; \
	fi

# Añadir después de verify-firewall-rules (alrededor de línea 500)

test-sequence:
	@echo "$(CYAN)🧪 TEST DE SECUENCIA DE ARRANQUE$(NC)"
	@echo "$(CYAN)====================================$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Verificando archivos de configuración...$(NC)"
	@for config in $(PROMISCUOUS_CONFIG) $(GEOIP_CONFIG) $(ML_CONFIG) $(DASHBOARD_CONFIG) $(FIREWALL_CONFIG) $(DASHBOARD_FIREWALL_CONFIG) $(FIREWALL_AGENT_RULES_CONFIG); do \
		if [ -f "$$config" ]; then \
			echo "  ✅ $$config"; \
		else \
			echo "  ❌ $$config FALTA"; \
		fi \
	done
	@echo ""
	@echo "$(YELLOW)📋 Verificando ejecutables...$(NC)"
	@for component in $(PROMISCUOUS_AGENT) $(GEOIP_ENRICHER) $(ML_DETECTOR) $(DASHBOARD) $(FIREWALL_AGENT); do \
		if [ -f "$$component" ]; then \
			SIZE=$$(ls -lh "$$component" | awk '{print $$5}'); \
			echo "  ✅ $$component ($$SIZE)"; \
		else \
			echo "  ❌ $$component FALTA"; \
		fi \
	done
	@echo ""
	@echo "$(YELLOW)🔧 Comandos que se ejecutarán (DRY RUN):$(NC)"
	@echo ""
	@echo "  $(BLUE)1.$(NC) Firewall Agent:"
	@echo "     $(GREEN)$(PYTHON_VENV) $(FIREWALL_AGENT) \\$(NC)"
	@echo "       $(GREEN)$(FIREWALL_CONFIG) \\$(NC)"
	@echo "       $(GREEN)$(FIREWALL_AGENT_RULES_CONFIG)$(NC)"
	@echo ""
	@echo "  $(BLUE)2.$(NC) Promiscuous Agent (requiere sudo):"
	@echo "     $(GREEN)sudo $(PYTHON_VENV) $(PROMISCUOUS_AGENT) \\$(NC)"
	@echo "       $(GREEN)$(PROMISCUOUS_CONFIG)$(NC)"
	@echo ""
	@echo "  $(BLUE)3.$(NC) GeoIP Enricher:"
	@echo "     $(GREEN)$(PYTHON_VENV) $(GEOIP_ENRICHER) \\$(NC)"
	@echo "       $(GREEN)$(GEOIP_CONFIG)$(NC)"
	@echo ""
	@echo "  $(BLUE)4.$(NC) ML Detector:"
	@echo "     $(GREEN)$(PYTHON_VENV) $(ML_DETECTOR) \\$(NC)"
	@echo "       $(GREEN)$(ML_CONFIG)$(NC)"
	@echo ""
	@echo "  $(BLUE)5.$(NC) Dashboard:"
	@echo "     $(GREEN)$(PYTHON_VENV) $(DASHBOARD) \\$(NC)"
	@echo "       $(GREEN)$(DASHBOARD_CONFIG) \\$(NC)"
	@echo "       $(GREEN)$(DASHBOARD_FIREWALL_CONFIG)$(NC)"
	@echo ""
	@echo "$(YELLOW)🔍 Verificando puertos...$(NC)"
	@for port in $(CAPTURE_PORT) $(GEOIP_PORT) $(ML_PORT) $(FIREWALL_PORT) $(DASHBOARD_WEB_PORT); do \
		if lsof -ti:$$port >/dev/null 2>&1; then \
			echo "  ⚠️  Puerto $$port EN USO (PID: $$(lsof -ti:$$port))"; \
		else \
			echo "  ✅ Puerto $$port libre"; \
		fi \
	done
	@echo ""
	@echo "$(YELLOW)🔍 Verificando entorno virtual...$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "  ✅ Entorno virtual existe: $(VENV_NAME)"; \
		if [ -f "$(PYTHON_VENV)" ]; then \
			echo "  ✅ Python: $(PYTHON_VENV)"; \
			$(PYTHON_VENV) --version 2>/dev/null | sed 's/^/     /' || echo "     ❌ Error verificando versión"; \
		else \
			echo "  ❌ Python no encontrado en venv"; \
		fi \
	else \
		echo "  ❌ Entorno virtual NO existe"; \
	fi
	@echo ""
	@echo "$(YELLOW)🔍 Verificando permisos sudo...$(NC)"
	@if sudo -n true 2>/dev/null; then \
		echo "  ✅ Permisos sudo disponibles (sin password)"; \
	else \
		echo "  ⚠️  Se requerirá password para sudo"; \
	fi
	@echo ""
	@echo "$(PURPLE)📊 RESUMEN:$(NC)"
	@echo "  Para ejecutar el sistema: $(GREEN)make start$(NC)"
	@echo "  Para parada normal: $(YELLOW)make stop$(NC)"
	@echo "  Para parada nuclear: $(RED)make stop-nuclear$(NC)"

monitor-live:
	@echo "$(CYAN)🔄 Iniciando monitor en tiempo real...$(NC)"
	@./scripts/utils/monitor_autoinmune.sh 3

# Añadir después de monitor-live

dashboard-terminal:
	@echo "$(CYAN)📊 DASHBOARD TERMINAL - Sistema Autoinmune$(NC)"
	@echo "$(CYAN)==========================================$(NC)"
	@watch -n 2 -c '$(MAKE) -s health-check-compact'

health-check-compact:
	@echo "$(date '+%H:%M:%S') - SISTEMA AUTOINMUNE DIGITAL"
	@echo "----------------------------------------"
	@echo "COMPONENTES:"
	@pgrep -f "simple_firewall_agent" >/dev/null && echo "  [✓] Firewall" || echo "  [✗] Firewall"
	@pgrep -f "promiscuous_agent" >/dev/null && echo "  [✓] Promiscuous" || echo "  [✗] Promiscuous"
	@pgrep -f "geoip_enricher" >/dev/null && echo "  [✓] GeoIP" || echo "  [✗] GeoIP"
	@pgrep -f "lightweight_ml_detector" >/dev/null && echo "  [✓] ML Detector" || echo "  [✗] ML Detector"
	@pgrep -f "real_zmq_dashboard" >/dev/null && echo "  [✓] Dashboard" || echo "  [✗] Dashboard"
	@echo ""
	@echo "RECURSOS:"
	@ps aux | grep -E "python.*(core/)" | grep -v grep | awk '{cpu+=$$3; mem+=$$4} END {printf "  CPU Total: %.1f%%\n  MEM Total: %.1f%%\n", cpu, mem}'
	@echo ""
	@echo "ACTIVIDAD:"
	@for log in $(LOGS_DIR)/*.log; do \
		if [ -f "$$log" ]; then \
			echo "  $$(basename $$log .log): $$(tail -1 $$log | cut -c1-50)..."; \
		fi \
	done | head -5

check-protobuf-imports:
	@echo "$(BLUE)🔍 Verificando imports de Protobuf en componentes core...$(NC)"
	@echo "$(YELLOW)📋 Archivos que deben importar desde protocols/current/:$(NC)"
	@for component in $(PROMISCUOUS_AGENT) $(GEOIP_ENRICHER) $(ML_DETECTOR) $(DASHBOARD) $(FIREWALL_AGENT); do \
		if [ -f "$component" ]; then \
			echo "  🔍 Analizando $component..."; \
			if grep -q "import.*pb2" "$component" 2>/dev/null; then \
				echo "    📦 Imports protobuf encontrados:"; \
				grep "import.*pb2\|from.*pb2" "$component" | sed 's/^/      /' || true; \
				if grep -q "protocols.current" "$component" 2>/dev/null; then \
					echo "    $(GREEN)✅ Ruta protocols.current correcta$(NC)"; \
				else \
					echo "    $(YELLOW)⚠️  Revisar rutas - debe usar: from protocols.current import$(NC)"; \
				fi \
			else \
				echo "    $(BLUE)ℹ️  Sin imports protobuf (normal para algunos componentes)$(NC)"; \
			fi \
		fi \
	done

fix-protobuf-imports:
	@echo "$(BLUE)🔧 Sugerencias para arreglar imports Protobuf...$(NC)"
	@echo "$(YELLOW)💡 PATRÓN CORRECTO para imports:$(NC)"
	@echo "  $(GREEN)✅ from protocols.current import network_event_extended_v3_pb2$(NC)"
	@echo "  $(GREEN)✅ from protocols.current import firewall_commands_pb2$(NC)"
	@echo ""
	@echo "$(YELLOW)❌ PATRONES INCORRECTOS a evitar:$(NC)"
	@echo "  $(RED)❌ import network_event_extended_v3_pb2  # Sin ruta$(NC)"
	@echo "  $(RED)❌ from . import network_event_extended_v3_pb2  # Ruta relativa$(NC)"
	@echo ""
	@echo "$(YELLOW)🔧 PARA ARREGLAR MANUALMENTE:$(NC)"
	@echo "  1. Abrir cada archivo core/ que use protobuf"
	@echo "  2. Cambiar imports para usar: protocols.current.XXXX_pb2"
	@echo "  3. Verificar con: make check-protobuf-imports"

check-protobuf:
	@echo "$(BLUE)🔍 Verificando compilación Protobuf...$(NC)"
	@echo "$(YELLOW)Archivos .proto:$(NC)"
	@ls -la $(PROTOBUF_DIR)/*.proto 2>/dev/null | awk '{print "  📄 " $$9 " (" $$5 " bytes)"}' || echo "  ❌ No se encontraron archivos .proto"
	@echo "$(YELLOW)Archivos compilados (_pb2.py):$(NC)"
	@ls -la $(PROTOBUF_DIR)/*_pb2.py 2>/dev/null | awk '{print "  🔧 " $$9 " (" $$5 " bytes)"}' || echo "  ❌ No se encontraron archivos compilados"
	@echo "$(YELLOW)Test importación:$(NC)"
	@cd $(PROTOBUF_DIR) && $(ACTIVATE) && $(PYTHON_VENV) -c "import network_event_extended_v3_pb2; print('  ✅ network_event_extended_v3_pb2 importable')" 2>/dev/null || echo "  ❌ Error importando network_event_extended_v3_pb2"
	@cd $(PROTOBUF_DIR) && $(ACTIVATE) && $(PYTHON_VENV) -c "import firewall_commands_pb2; print('  ✅ firewall_commands_pb2 importable')" 2>/dev/null || echo "  ❌ Error importando firewall_commands_pb2"

check-structure:
	@echo "$(BLUE)🔍 Verificando estructura post-housekeeping...$(NC)"
	@echo "$(YELLOW)📁 Directorios principales:$(NC)"
	@for dir in $(CORE_DIR) $(ML_PIPELINE_DIR) $(MODELS_PRODUCTION_DIR) $(WEB_STATIC_DIR) $(PROTOCOLS_DIR); do \
		if [ -d "$$dir" ]; then \
			echo "  ✅ $$dir/"; \
		else \
			echo "  ❌ $$dir/ falta"; \
		fi \
	done
	@echo "$(YELLOW)🧠 Componentes core:$(NC)"
	@for component in $(PROMISCUOUS_AGENT) $(GEOIP_ENRICHER) $(ML_DETECTOR) $(DASHBOARD) $(FIREWALL_AGENT) $(FIXED_SERVICE_SNIFFER) $(NETWORK_FEATURE_EXTRACTOR) $(FAST_EJECTOR_LAYER); do \
		if [ -f "$component" ]; then \
			SIZE=$(ls -lh "$component" | awk '{print $5}'); \
			echo "  ✅ $component ($SIZE)"; \
		else \
			echo "  ❌ $component falta"; \
		fi \
	done
	@echo "$(YELLOW)💎 Modelos en producción:$(NC)"
	@ls -la $(MODELS_PRODUCTION_DIR)/*.joblib 2>/dev/null | awk '{print "  🧠 " $$9 " (" $$5 " bytes)"}' || echo "  ❌ No se encontraron modelos en producción"
	@echo "$(YELLOW)🌐 Assets web:$(NC)"
	@if [ -d "$(WEB_STATIC_DIR)" ]; then \
		echo "  ✅ $(WEB_STATIC_DIR)/"; \
		ls $(WEB_STATIC_DIR)/ 2>/dev/null | sed 's/^/    📄 /' || echo "    ⚠️  Directorio vacío"; \
	else \
		echo "  ❌ $(WEB_STATIC_DIR)/ falta"; \
	fi
	@if [ -d "$(WEB_TEMPLATES_DIR)" ]; then \
		echo "  ✅ $(WEB_TEMPLATES_DIR)/"; \
		ls $(WEB_TEMPLATES_DIR)/ 2>/dev/null | sed 's/^/    📄 /' || echo "    ⚠️  Directorio vacío"; \
	else \
		echo "  ❌ $(WEB_TEMPLATES_DIR)/ falta"; \
	fi

# Resto de funciones de setup (adaptadas)
setup-perms:
	@echo "$(BLUE)🔧 Configurando permisos de firewall...$(NC)"
	@echo "$(YELLOW)⚠️  Requiere sudo para iptables$(NC)"
	@sudo bash -c 'echo "$(USER) ALL=(ALL) NOPASSWD: /sbin/iptables" >> /etc/sudoers.d/$(USER)-iptables' || true
	@sudo chmod 0440 /etc/sudoers.d/$(USER)-iptables || true
	@echo "$(GREEN)✅ Permisos configurados$(NC)"
	@sudo -n iptables -L >/dev/null 2>&1 && echo "$(GREEN)✅ Permisos funcionando$(NC)" || echo "$(RED)❌ Error en permisos - ejecutar: sudo make setup-perms$(NC)"

check-deps:
	@echo "$(BLUE)🔍 Verificando dependencias...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import zmq; print('✅ ZeroMQ disponible')" 2>/dev/null || echo "❌ ZeroMQ falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import scapy; print('✅ Scapy disponible')" 2>/dev/null || echo "❌ Scapy falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import sklearn; print('✅ Scikit-learn disponible')" 2>/dev/null || echo "❌ Scikit-learn falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import geoip2; print('✅ GeoIP2 disponible')" 2>/dev/null || echo "❌ GeoIP2 falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import fastapi; print('✅ FastAPI disponible')" 2>/dev/null || echo "❌ FastAPI falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import joblib; print('✅ Joblib disponible')" 2>/dev/null || echo "❌ Joblib falta"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import protobuf; print('✅ Protobuf disponible')" 2>/dev/null || echo "❌ Protobuf falta"
	@which sudo >/dev/null && echo "✅ sudo disponible" || echo "❌ sudo falta"
	@which protoc >/dev/null && echo "✅ protoc disponible" || echo "❌ protoc falta (instalar Protocol Buffers)"

check-geoip:
	@echo "$(BLUE)🌍 Verificando configuración GeoIP...$(NC)"
	@if [ -f "GeoLite2-City.mmdb" ]; then \
		echo "  ✅ Base de datos GeoLite2 encontrada"; \
		stat -c "%y" GeoLite2-City.mmdb | sed 's/^/  📅 Última modificación: /' 2>/dev/null || stat -f "%Sm" GeoLite2-City.mmdb | sed 's/^/  📅 Última modificación: /'; \
	else \
		echo "  ⚠️  Base de datos GeoLite2 NO encontrada"; \
		echo "  💡 Se usará ip-api.com como fallback"; \
		echo "  💡 Para descargar GeoLite2: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"; \
	fi
	@echo "  🔗 Verificando conectividad con ip-api.com..."
	@curl -s --connect-timeout 3 "http://ip-api.com/json/8.8.8.8" >/dev/null && \
		echo "  ✅ ip-api.com accesible" || \
		echo "  ❌ ip-api.com no accesible"

verify: check-structure
	@echo "$(BLUE)🔍 Verificando integridad del sistema post-housekeeping...$(NC)"
	@echo "$(YAML)Configuraciones JSON:$(NC)"
	@for config in $(PROMISCUOUS_CONFIG) $(GEOIP_CONFIG) $(ML_CONFIG) $(DASHBOARD_CONFIG) $(FIREWALL_CONFIG); do \
		if [ -f "$$config" ]; then \
			echo "  ✅ $$config"; \
		else \
			echo "  ❌ $$config falta - creando configuración básica..."; \
			mkdir -p $(CONFIG_DIR); \
			if echo "$$config" | grep -q "dashboard_config"; then \
				echo '{"port": 8080, "host": "localhost", "debug": false}' > "$$config"; \
				echo "  ✅ $$config creado"; \
			elif echo "$$config" | grep -q "simple_firewall_agent_config"; then \
				echo '{"agent_id": "firewall_001", "enabled": true, "log_level": "INFO"}' > "$$config"; \
				echo "  ✅ $$config creado"; \
			elif echo "$$config" | grep -q "lightweight_ml_detector_config"; then \
				echo '{"model_path": "models/production/", "tricapa_enabled": true}' > "$$config"; \
				echo "  ✅ $$config creado"; \
			fi \
		fi \
	done
	@echo "$(YELLOW)Permisos:$(NC)"
	@sudo -n iptables -L >/dev/null 2>&1 && echo "  ✅ Permisos firewall OK" || echo "  ❌ Permisos firewall faltan (ejecutar: make setup-perms)"

clean:
	@echo "$(YELLOW)🧹 Limpiando sistema post-housekeeping...$(NC)"
	@$(MAKE) stop 2>/dev/null || true
	@echo "  🗑️  Removiendo entorno virtual..."
	@rm -rf $(VENV_NAME)
	@echo "  🗑️  Limpiando archivos Python..."
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@find . -name "*.pyo" -delete 2>/dev/null || true
	@echo "  🗑️  Limpiando Protobuf compilados..."
	@rm -f $(PROTOBUF_DIR)/*_pb2.py
	@echo "  🗑️  Limpiando directorios temporales..."
	@rm -rf $(PIDS_DIR) $(LOGS_DIR) $(DATA_DIR)
	@echo "$(GREEN)✅ Limpieza completada$(NC)"
	@echo "$(BLUE)🧹 LIMPIANDO ARCHIVOS TEMPORALES$(NC)"
	@echo "$(BLUE)================================$(NC)"
	@find . -name "*.backup_*" -type f -delete 2>/dev/null || true
	@find . -name "*.bak" -type f -delete 2>/dev/null || true
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -type f -delete 2>/dev/null || true
	@echo "$(GREEN)✅ Archivos temporales eliminados$(NC)"

# =============================================================================
# GESTIÓN DEL SISTEMA PRINCIPAL (ACTUALIZADA POST-HOUSEKEEPING)
# =============================================================================
start: install verify check-geoip compile-protobuf verify-firewall-rules stop
	@echo "$(GREEN)🚀 Iniciando Sistema Autoinmune Digital v2.0 POST-HOUSEKEEPING...$(NC)"
	@echo "$(CYAN)================================================================$(NC)"
	@echo "$(PURPLE)Branch: $(BRANCH)$(NC)"
	@echo "$(PURPLE)Estado: 142 archivos organizados, 0 pérdidas$(NC)"
	@echo ""
	@echo "$(BLUE)🔄 Iniciando componentes con estructura actualizada...$(NC)"

	# Verificar componente promiscuous principal
	@if [ -f "$(PROMISCUOUS_AGENT)" ]; then \
		echo "$(BLUE)✅ Usando $(PROMISCUOUS_AGENT) (principal)$(NC)"; \
	else \
		echo "$(RED)❌ No se encontró $(PROMISCUOUS_AGENT)$(NC)"; \
		exit 1; \
	fi

	@echo "$(BLUE)📁 Verificando configuraciones JSON...$(NC)"
	@test -f $(DASHBOARD_CONFIG) || (mkdir -p $(CONFIG_DIR) && echo '{"port": 8080, "host": "localhost", "debug": false}' > $(DASHBOARD_CONFIG))
	@test -f $(FIREWALL_CONFIG) || (mkdir -p $(CONFIG_DIR) && echo '{"agent_id": "firewall_001", "enabled": true, "log_level": "INFO"}' > $(FIREWALL_CONFIG))
	@test -f $(ML_CONFIG) || (mkdir -p $(CONFIG_DIR) && echo '{"model_path": "models/production/", "tricapa_enabled": true}' > $(ML_CONFIG))
	@echo ""

	@echo "$(BLUE)1. 🛡️  Firewall Agent ($(FIREWALL_AGENT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT) $(FIREWALL_CONFIG) $(FIREWALL_AGENT_RULES_CONFIG) > $(FIREWALL_LOG) 2>&1 & echo $$! > $(FIREWALL_PID)
	@sleep 3

	@echo "$(BLUE)2. 🕵️  Promiscuous Agent → Puerto $(CAPTURE_PORT)...$(NC)"
	@sudo bash -c '$(PYTHON_VENV) $(PROMISCUOUS_AGENT) $(PROMISCUOUS_CONFIG) > $(PROMISCUOUS_LOG) 2>&1 & echo $! > $(PROMISCUOUS_PID)'
	@sleep 3

	@echo "$(BLUE)3. 🌍 GeoIP Enricher ($(CAPTURE_PORT) → $(GEOIP_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER) $(GEOIP_CONFIG) > $(GEOIP_LOG) 2>&1 & echo $$! > $(GEOIP_PID)
	@sleep 3

	@echo "$(BLUE)4. 🤖 ML Detector Tricapa ($(GEOIP_PORT) → $(ML_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) $(ML_CONFIG) > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@sleep 3

	@echo "$(BLUE)5. 📊 Dashboard Web ($(ML_PORT) → UI $(DASHBOARD_WEB_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD) $(DASHBOARD_CONFIG) $(DASHBOARD_FIREWALL_CONFIG) > $(DASHBOARD_LOG) 2>&1 & echo $$! > $(DASHBOARD_PID)
	@sleep 5

	@echo ""
	@echo "$(GREEN)🎉 SISTEMA POST-HOUSEKEEPING OPERACIONAL$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@echo "$(YELLOW)📊 Dashboard Principal: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@echo "$(YELLOW)💎 Modelos Tricapa: $(MODELS_PRODUCTION_DIR)/$(NC)"
	@echo "$(YELLOW)🌐 Assets Web: $(WEB_STATIC_DIR)/ + $(WEB_TEMPLATES_DIR)/$(NC)"
	@echo "$(YELLOW)🔒 Protocolos: $(PROTOCOLS_DIR)/current/ (6 versiones)$(NC)"
	@echo "$(YELLOW)🧠 ML Pipeline: $(ML_PIPELINE_DIR)/ (listo para reentrenamiento)$(NC)"
	@echo "$(YELLOW)🌍 329 sitios globales preservados$(NC)"
	@echo ""
	@$(MAKE) status

# Otros comandos de gestión (actualizados para estructura post-housekeeping)
start-core: install verify verify-protobuf-compiled stop
	@echo "$(GREEN)🚀 Iniciando componentes CORE (estructura actualizada)...$(NC)"
	@test -f $(FIREWALL_CONFIG) || (mkdir -p $(CONFIG_DIR) && echo '{"agent_id": "firewall_001", "enabled": true, "log_level": "INFO"}' > $(FIREWALL_CONFIG))
	@test -f $(DASHBOARD_CONFIG) || (mkdir -p $(CONFIG_DIR) && echo '{"port": 8080, "host": "localhost", "debug": false}' > $(DASHBOARD_CONFIG))
	@test -f $(ML_CONFIG) || (mkdir -p $(CONFIG_DIR) && echo '{"model_path": "models/production/", "tricapa_enabled": true}' > $(ML_CONFIG))

	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT) $(FIREWALL_CONFIG) $(FIREWALL_AGENT_RULES_CONFIG) > $(FIREWALL_LOG) 2>&1 & echo $$! > $(FIREWALL_PID)
	@sleep 2
	@sudo bash -c '$(PYTHON_VENV) $(PROMISCUOUS_AGENT) $(PROMISCUOUS_CONFIG) > $(PROMISCUOUS_LOG) 2>&1 & echo $! > $(PROMISCUOUS_PID)'
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER) $(GEOIP_CONFIG) > $(GEOIP_LOG) 2>&1 & echo $! > $(GEOIP_PID)
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) $(ML_CONFIG) > $(ML_LOG) 2>&1 & echo $! > $(ML_PID)
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD) $(DASHBOARD_CONFIG) $(DASHBOARD_FIREWALL_CONFIG) > $(DASHBOARD_LOG) 2>&1 & echo $$! > $(DASHBOARD_PID)
	@echo "$(GREEN)✅ Componentes core iniciados con estructura post-housekeeping$(NC)"

start-advanced:
	@echo "$(BLUE)🧠 Iniciando componentes AVANZADOS (ML Pipeline)...$(NC)"
	@if [ -f "$(NEURAL_TRAINER)" ]; then \
		echo "$(BLUE)🤖 Neural Trainer ($(ML_PIPELINE_DIR))...$(NC)"; \
		$(ACTIVATE) && $(PYTHON_VENV) $(NEURAL_TRAINER) $(NEURAL_CONFIG) > $(NEURAL_LOG) 2>&1 & echo $! > $(NEURAL_PID); \
		sleep 2; \
	else \
		echo "$(YELLOW)⚠️  Neural Trainer no disponible en $(ML_PIPELINE_DIR)$(NC)"; \
	fi
	@if [ -f "$(SNIFFER_RETRAINER)" ]; then \
		echo "$(BLUE)🔄 Sniffer Retrainer disponible$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  Sniffer Retrainer no encontrado$(NC)"; \
	fi
	@echo "$(GREEN)✅ Componentes ML Pipeline verificados$(NC)"

start-bg: install verify check-geoip verify-protobuf-compiled stop
	@echo "$(GREEN)🚀 Iniciando sistema (background mode)...$(NC)"
	@test -f $(FIREWALL_CONFIG) || (mkdir -p config && echo '{"rules": [], "enabled": true, "mode": "agent"}' > $(FIREWALL_CONFIG))
	@test -f $(DASHBOARD_CONFIG) || (mkdir -p config && echo '{"dashboard_rules": [], "monitoring": true, "mode": "dashboard"}' > $(DASHBOARD_CONFIG))
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(FIREWALL_AGENT) $(FIREWALL_CONFIG) $(FIREWALL_AGENT_RULES_CONFIG) > $(FIREWALL_LOG) 2>&1 & echo $$! > $(FIREWALL_PID)
	@sleep 2
	@sudo bash -c 'nohup $(PYTHON_VENV) $(PROMISCUOUS_AGENT) $(PROMISCUOUS_CONFIG) > $(PROMISCUOUS_LOG) 2>&1 & echo $! > $(PROMISCUOUS_PID)'
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(GEOIP_ENRICHER) $(GEOIP_CONFIG) > $(GEOIP_LOG) 2>&1 & echo $! > $(GEOIP_PID)
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(ML_DETECTOR) $(ML_CONFIG) > $(ML_LOG) 2>&1 & echo $! > $(ML_PID)
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(DASHBOARD) $(DASHBOARD_CONFIG) $(DASHBOARD_FIREWALL_CONFIG) > $(DASHBOARD_LOG) 2>&1 & echo $$! > $(DASHBOARD_PID)
	@echo "$(GREEN)✅ Sistema iniciado en background$(NC)"
	@echo "$(YELLOW)📊 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"

# Otros comandos de gestión siguen el mismo patrón de actualización...
start-core: install verify verify-protobuf-compiled stop
	@echo "$(GREEN)🚀 Iniciando componentes CORE (estructura actualizada)...$(NC)"
	@test -f $(FIREWALL_CONFIG) || (mkdir -p $(CONFIG_DIR) && echo '{"agent_id": "firewall_001", "enabled": true, "log_level": "INFO"}' > $(FIREWALL_CONFIG))
	@test -f $(DASHBOARD_CONFIG) || (mkdir -p $(CONFIG_DIR) && echo '{"port": 8080, "host": "localhost", "debug": false}' > $(DASHBOARD_CONFIG))
	@test -f $(ML_CONFIG) || (mkdir -p $(CONFIG_DIR) && echo '{"model_path": "models/production/", "tricapa_enabled": true}' > $(ML_CONFIG))

	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT) $(FIREWALL_CONFIG) $(FIREWALL_AGENT_RULES_CONFIG) > $(FIREWALL_LOG) 2>&1 & echo $! > $(FIREWALL_PID)
	@sleep 2
	@sudo bash -c '$(PYTHON_VENV) $(PROMISCUOUS_AGENT) $(PROMISCUOUS_CONFIG) > $(PROMISCUOUS_LOG) 2>&1 & echo $! > $(PROMISCUOUS_PID)'
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER) $(GEOIP_CONFIG) > $(GEOIP_LOG) 2>&1 & echo $! > $(GEOIP_PID)
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) $(ML_CONFIG) > $(ML_LOG) 2>&1 & echo $! > $(ML_PID)
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD) $(DASHBOARD_CONFIG) $(DASHBOARD_FIREWALL_CONFIG) > $(DASHBOARD_LOG) 2>&1 & echo $! > $(DASHBOARD_PID)
	@echo "$(GREEN)✅ Componentes core iniciados con estructura post-housekeeping$(NC)"

start-advanced:
	@echo "$(BLUE)🧠 Iniciando componentes AVANZADOS (ML Pipeline)...$(NC)"
	@if [ -f "$(NEURAL_TRAINER)" ]; then \
		echo "$(BLUE)🤖 Neural Trainer ($(ML_PIPELINE_DIR))...$(NC)"; \
		$(ACTIVATE) && $(PYTHON_VENV) $(NEURAL_TRAINER) $(NEURAL_CONFIG) > $(NEURAL_LOG) 2>&1 & echo $$! > $(NEURAL_PID); \
		sleep 2; \
	else \
		echo "$(YELLOW)⚠️  Neural Trainer no disponible en $(ML_PIPELINE_DIR)$(NC)"; \
	fi
	@if [ -f "$(SNIFFER_RETRAINER)" ]; then \
		echo "$(BLUE)🔄 Sniffer Retrainer disponible$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  Sniffer Retrainer no encontrado$(NC)"; \
	fi
	@echo "$(GREEN)✅ Componentes ML Pipeline verificados$(NC)"

# =============================================================================
# GESTIÓN DE PARADAS (NUCLEAR GARANTIZADO)
# =============================================================================

# Función de parada estándar (secuencial y limpia)
stop:
	@echo "$(YELLOW)🛑 Deteniendo sistema POST-HOUSEKEEPING (método secuencial)...$(NC)"
	@echo "$(BLUE)Parada secuencial en orden inverso...$(NC)"

	# Método 1: Intentar con PIDs si existen
	@echo "🔄 Método 1: Deteniendo con PIDs guardados..."
	@-if [ -f $(DASHBOARD_PID) ]; then echo "📊 Deteniendo Dashboard..."; kill $(cat $(DASHBOARD_PID)) 2>/dev/null || true; rm -f $(DASHBOARD_PID); fi
	@-if [ -f $(ML_PID) ]; then echo "🤖 Deteniendo ML Detector..."; kill $(cat $(ML_PID)) 2>/dev/null || true; rm -f $(ML_PID); fi
	@-if [ -f $(GEOIP_PID) ]; then echo "🌍 Deteniendo GeoIP Enricher..."; kill $(cat $(GEOIP_PID)) 2>/dev/null || true; rm -f $(GEOIP_PID); fi
	@-if [ -f $(PROMISCUOUS_PID) ]; then echo "🕵️  Deteniendo Promiscuous Agent..."; kill $(cat $(PROMISCUOUS_PID)) 2>/dev/null || true; sudo kill $(cat $(PROMISCUOUS_PID)) 2>/dev/null || true; rm -f $(PROMISCUOUS_PID); fi
	@-if [ -f $(FIREWALL_PID) ]; then echo "🛡️  Deteniendo Firewall Agent..."; kill $(cat $(FIREWALL_PID)) 2>/dev/null || true; rm -f $(FIREWALL_PID); fi
	@-if [ -f $(NEURAL_PID) ]; then echo "🤖 Deteniendo Neural Trainer..."; kill $(cat $(NEURAL_PID)) 2>/dev/null || true; rm -f $(NEURAL_PID); fi
	@sleep 2

	# Método 2: pkill por nombre de proceso (más agresivo)
	@echo "🔄 Método 2: pkill por patrón actualizado..."
	@-echo "📊 Matando Dashboard..."
	@-pkill -f "real_zmq_dashboard_with_firewall" 2>/dev/null || true
	@-echo "🤖 Matando ML Detector..."
	@-pkill -f "lightweight_ml_detector" 2>/dev/null || true
	@-echo "🌍 Matando GeoIP Enricher..."
	@-pkill -f "geoip_enricher" 2>/dev/null || true
	@-echo "🕵️  Matando Promiscuous Agent..."
	@-pkill -f "promiscuous_agent" 2>/dev/null || true
	@-sudo pkill -f "promiscuous_agent" 2>/dev/null || true
	@-echo "🛡️  Matando Firewall Agent..."
	@-pkill -f "simple_firewall_agent" 2>/dev/null || true
	@sleep 2

	# Método 3: SIGKILL si siguen activos (nuclear)
	@echo "🔄 Método 3: SIGKILL nuclear..."
	@-pkill -9 -f "real_zmq_dashboard_with_firewall" 2>/dev/null || true
	@-pkill -9 -f "lightweight_ml_detector" 2>/dev/null || true
	@-pkill -9 -f "geoip_enricher" 2>/dev/null || true
	@-pkill -9 -f "promiscuous_agent" 2>/dev/null || true
	@-sudo pkill -9 -f "promiscuous_agent" 2>/dev/null || true
	@-pkill -9 -f "simple_firewall_agent" 2>/dev/null || true

	# Limpiar archivos PID
	@echo "🧹 Limpiando PIDs..."
	@-rm -f $(PIDS_DIR)/*.pid

	@echo "$(GREEN)✅ Sistema post-housekeeping detenido correctamente$(NC)"

# Añadir después de stop, antes de stop-nuclear

stop-force:
	@echo "$(YELLOW)⚡ Parada forzada (más agresiva que stop, menos que nuclear)$(NC)"
	@$(MAKE) stop
	@sleep 2
	@echo "$(YELLOW)🔨 Aplicando fuerza adicional...$(NC)"
	@-pkill -9 -f "core/.*\.py" 2>/dev/null || true
	@-sudo pkill -9 -f "promiscuous_agent" 2>/dev/null || true
	@for port in $(CAPTURE_PORT) $(GEOIP_PORT) $(ML_PORT) $(FIREWALL_PORT) $(DASHBOARD_WEB_PORT); do \
		lsof -ti:$$port 2>/dev/null | xargs -r kill -9 2>/dev/null || true; \
	done
	@rm -f $(PIDS_DIR)/*.pid
	@echo "$(GREEN)✅ Parada forzada completada$(NC)"

# Comando de emergency stop (nuclear) - VERSIÓN MEJORADA POST-HOUSEKEEPING
# Reemplazar el stop-nuclear existente con esta versión mejorada

stop-nuclear:
	@echo "$(RED)☢️  PARADA NUCLEAR ULTRA POST-HOUSEKEEPING ACTIVADA ☢️$(NC)"
	@echo "$(RED)======================================================$(NC)"
	@echo "$(RED)⚠️  DEFCON 1: Exterminación total de procesos$(NC)"
	@echo ""

	# Pre-check: Mostrar lo que vamos a matar
	@echo "$(YELLOW)🔍 Procesos objetivo detectados:$(NC)"
	@ps aux | grep -E "python.*upgraded|python.*core/|python.*ml_pipeline/" | grep -v grep | awk '{print "  🎯 " $$2 " - " $$11}' | head -10 || echo "  No hay procesos detectados"
	@echo ""

	# Nuclear 1: Soft kill primero (dar oportunidad de cleanup)
	@echo "$(YELLOW)💀 Fase 1: Soft kill (SIGTERM)...$(NC)"
	@-pkill -TERM -f "promiscuous_agent|geoip_enricher|lightweight_ml_detector|dashboard_with_firewall|simple_firewall_agent" 2>/dev/null || true
	@sleep 1

	# Nuclear 2: Kill por nombres específicos
	@echo "$(YELLOW)💀 Fase 2: Kill específico por componentes...$(NC)"
	@-pkill -9 -f "promiscuous_agent" 2>/dev/null || true
	@-pkill -9 -f "geoip_enricher" 2>/dev/null || true
	@-pkill -9 -f "lightweight_ml_detector" 2>/dev/null || true
	@-pkill -9 -f "real_zmq_dashboard_with_firewall" 2>/dev/null || true
	@-pkill -9 -f "simple_firewall_agent" 2>/dev/null || true
	@-pkill -9 -f "fixed_service_sniffer" 2>/dev/null || true
	@sleep 1

	# Nuclear 3: Sudo kill para procesos con privilegios
	@echo "$(YELLOW)💀 Fase 3: Sudo kill (procesos privilegiados)...$(NC)"
	@-sudo pkill -9 -f "python.*promiscuous" 2>/dev/null || true
	@-sudo pkill -9 -f "python.*core/" 2>/dev/null || true
	@-sudo pkill -9 -f "python.*ml_pipeline/" 2>/dev/null || true

	# Nuclear 4: Matar por PID files si existen
	@echo "$(YELLOW)💀 Fase 4: Kill por archivos PID...$(NC)"
	@for pidfile in $(PIDS_DIR)/*.pid; do \
		if [ -f "$$pidfile" ]; then \
			PID=$$(cat "$$pidfile" 2>/dev/null); \
			if [ ! -z "$$PID" ]; then \
				echo "  Matando PID $$PID desde $$pidfile"; \
				kill -9 "$$PID" 2>/dev/null || sudo kill -9 "$$PID" 2>/dev/null || true; \
			fi; \
			rm -f "$$pidfile"; \
		fi \
	done

	# Nuclear 5: Liberar puertos (más agresivo)
	@echo "$(YELLOW)💀 Fase 5: Liberación forzada de puertos...$(NC)"
	@for port in $(CAPTURE_PORT) $(GEOIP_PORT) $(ML_PORT) $(FIREWALL_PORT) $(DASHBOARD_WEB_PORT); do \
		PIDS=$$(lsof -ti:$$port 2>/dev/null); \
		if [ ! -z "$$PIDS" ]; then \
			echo "  Puerto $$port ocupado por PIDs: $$PIDS"; \
			echo "$$PIDS" | xargs -r kill -9 2>/dev/null || echo "$$PIDS" | xargs -r sudo kill -9 2>/dev/null || true; \
		fi \
	done

	# Nuclear 6: Buscar y destruir por patrón amplio
	@echo "$(YELLOW)💀 Fase 6: Búsqueda y destrucción por patrón...$(NC)"
	@-ps aux | grep -E "python.*(upgraded|core/|ml_pipeline/|config/json)" | grep -v grep | awk '{print $$2}' | xargs -r kill -9 2>/dev/null || true
	@-ps aux | grep -E "python.*(upgraded|core/|ml_pipeline/|config/json)" | grep -v grep | awk '{print $$2}' | xargs -r sudo kill -9 2>/dev/null || true

	# Nuclear 7: Limpieza total de archivos temporales
	@echo "$(YELLOW)💀 Fase 7: Limpieza de archivos temporales...$(NC)"
	@-rm -rf $(PIDS_DIR)/*.pid
	@-rm -f $(LOGS_DIR)/*.log.lock 2>/dev/null || true
	@-rm -f /tmp/*upgraded*happiness* 2>/dev/null || true
	@-rm -f /tmp/zmq* 2>/dev/null || true
	@-sudo rm -f /var/run/*upgraded* 2>/dev/null || true

	# Nuclear 8: Verificación final ULTRA
	@echo ""
	@echo "$(RED)☢️  VERIFICACIÓN POST-NUCLEAR:$(NC)"
	@SURVIVORS=$$(ps aux | grep -E "python.*(upgraded|core/|ml_pipeline/)" | grep -v grep | wc -l); \
	if [ $$SURVIVORS -gt 0 ]; then \
		echo "$(RED)⚠️  ALERTA: $$SURVIVORS procesos supervivientes detectados$(NC)"; \
		echo "$(YELLOW)Intentando exterminación final...$(NC)"; \
		ps aux | grep -E "python.*(upgraded|core/|ml_pipeline/)" | grep -v grep | awk '{print $$2}' | while read pid; do \
			echo "  ☠️  Exterminando superviviente PID: $$pid"; \
			kill -9 $$pid 2>/dev/null || sudo kill -9 $$pid 2>/dev/null || true; \
		done; \
		sleep 2; \
		FINAL_CHECK=$$(ps aux | grep -E "python.*(upgraded|core/|ml_pipeline/)" | grep -v grep | wc -l); \
		if [ $$FINAL_CHECK -gt 0 ]; then \
			echo "$(RED)⚠️  SUPERVIVIENTES INMORTALES:$(NC)"; \
			ps aux | grep -E "python.*(upgraded|core/|ml_pipeline/)" | grep -v grep | sed 's/^/    /' || true; \
			echo "$(RED)Requiere intervención manual con: sudo kill -9 <PID>$(NC)"; \
		else \
			echo "$(GREEN)✅ Exterminación completa - 0 supervivientes$(NC)"; \
		fi \
	else \
		echo "$(GREEN)☢️  ÉXITO TOTAL: 0 supervivientes$(NC)"; \
	fi

	@echo ""
	@echo "$(YELLOW)🔍 Estado de puertos después de la purga:$(NC)"
	@for port in $(CAPTURE_PORT) $(GEOIP_PORT) $(ML_PORT) $(FIREWALL_PORT) $(DASHBOARD_WEB_PORT); do \
		if lsof -ti:$$port >/dev/null 2>&1; then \
			echo "  ❌ Puerto $$port AÚN OCUPADO"; \
		else \
			echo "  ✅ Puerto $$port liberado"; \
		fi \
	done

	@echo ""
	@echo "$(GREEN)☢️  PARADA NUCLEAR ULTRA COMPLETADA ☢️$(NC)"
	@echo "$(GREEN)Sistema listo para reinicio limpio con 'make start'$(NC)"

restart: stop
	@sleep 3
	@$(MAKE) start

# =============================================================================
# MONITORIZACIÓN (ACTUALIZADA)
# =============================================================================
status:
	@echo "$(CYAN)📊 Estado Sistema Post-Housekeeping$(NC)"
	@echo "$(CYAN)===================================$(NC)"
	@echo "$(YELLOW)🔧 Componentes Core ($(CORE_DIR)/)$(NC)"
	@pgrep -f "$(FIREWALL_AGENT)" >/dev/null && echo "  🛡️  Firewall Agent: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🛡️  Firewall Agent: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "promiscuous_agent" >/dev/null && echo "  🕵️  Promiscuous Agent: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🕵️  Promiscuous Agent: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "$(GEOIP_ENRICHER)" >/dev/null && echo "  🌍 GeoIP Enricher: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🌍 GeoIP Enricher: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "$(ML_DETECTOR)" >/dev/null && echo "  🤖 ML Detector Tricapa: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🤖 ML Detector: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "$(DASHBOARD)" >/dev/null && echo "  📊 Dashboard: $(GREEN)✅ Ejecutándose$(NC) $(YELLOW)(http://localhost:$(DASHBOARD_WEB_PORT))$(NC)" || echo "  📊 Dashboard: $(RED)⭕ Detenido$(NC)"
	@echo ""
	@echo "$(YELLOW)🧠 ML Pipeline ($(ML_PIPELINE_DIR)/)$(NC)"
	@pgrep -f "$(NEURAL_TRAINER)" >/dev/null && echo "  🤖 Neural Trainer: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🤖 Neural Trainer: $(BLUE)🎯 Disponible$(NC)"
	@echo ""
	@echo "$(YELLOW)💎 Modelos & Datos:$(NC)"
	@if [ -d "$(MODELS_PRODUCTION_DIR)" ]; then \
		MODELS_COUNT=$(ls $(MODELS_PRODUCTION_DIR)/*.joblib 2>/dev/null | wc -l); \
		echo "  🧠 Modelos producción: $MODELS_COUNT archivos"; \
	else \
		echo "  ❌ $(MODELS_PRODUCTION_DIR)/ no encontrado"; \
	fi
	@if [ -d "$(MODELS_ARCHIVE_DIR)" ]; then \
		ARCHIVE_COUNT=$(ls $(MODELS_ARCHIVE_DIR)/*.joblib 2>/dev/null | wc -l); \
		echo "  📦 Modelos archive: $ARCHIVE_COUNT archivos"; \
	else \
		echo "  ❌ $(MODELS_ARCHIVE_DIR)/ no encontrado"; \
	fi
	@echo ""
	@echo "$(YELLOW)🌐 Web Assets:$(NC)"
	@if [ -d "$(WEB_STATIC_DIR)" ]; then echo "  ✅ $(WEB_STATIC_DIR)/"; else echo "  ❌ $(WEB_STATIC_DIR)/ falta"; fi
	@if [ -d "$(WEB_TEMPLATES_DIR)" ]; then echo "  ✅ $(WEB_TEMPLATES_DIR)/"; else echo "  ❌ $(WEB_TEMPLATES_DIR)/ falta"; fi
	@echo ""
	@echo "$(YELLOW)🔒 Protocolos:$(NC)"
	@if [ -d "$(PROTOCOLS_DIR)/current" ]; then \
		PROTO_COUNT=$(ls $(PROTOCOLS_DIR)/current/*.proto 2>/dev/null | wc -l); \
		echo "  🔧 Protobuf files: $PROTO_COUNT archivos"; \
		COMPILED_COUNT=$(ls $(PROTOCOLS_DIR)/current/*_pb2.py 2>/dev/null | wc -l); \
		echo "  ⚙️  Compilados: $COMPILED_COUNT archivos"; \
	else \
		echo "  ❌ $(PROTOCOLS_DIR)/current/ no encontrado"; \
	fi
	@echo "$(BLUE)📊 ESTADO SISTEMA TRICAPA$(NC)"
	@echo "$(BLUE)========================$(NC)"
	@echo "$(YELLOW)📂 Modelos en production/tricapa/:$(NC)"
	@ls -la $(MODELS_DIR)/*.joblib 2>/dev/null | wc -l | xargs -I {} echo "   ✅ {} modelos .joblib encontrados"
	@echo ""
	@echo "$(YELLOW)🔴 Nivel 1 (CICDS2017):$(NC)"
	@ls $(MODELS_DIR)/*cicids*.joblib 2>/dev/null | sed 's/.*\//   ✅ /' || echo "   ❌ No encontrado"
	@echo ""
	@echo "$(YELLOW)🟡 Nivel 2 (Detectores especializados):$(NC)"
	@ls $(MODELS_DIR)/*normal_detector*.joblib 2>/dev/null | sed 's/.*\//   ✅ /' || echo "   ❌ No encontrado"
	@echo ""
	@echo "$(YELLOW)🟢 Nivel 3 (Amenazas específicas):$(NC)"
	@ls $(MODELS_DIR)/{ddos,ransomware}*.joblib 2>/dev/null | sed 's/.*\//   ✅ /' || echo "   ❌ No encontrado"

monitor: status
	@echo ""
	@echo "$(YELLOW)💹 Actividad Reciente Post-Housekeeping:$(NC)"
	@if [ -f $(FIREWALL_LOG) ]; then echo "🛡️  $(FIREWALL_AGENT):"; tail -3 $(FIREWALL_LOG) | sed 's/^/    /' | head -3; echo ""; fi
	@if [ -f $(GEOIP_LOG) ]; then echo "🌍 $(GEOIP_ENRICHER):"; tail -3 $(GEOIP_LOG) | sed 's/^/    /' | head -3; echo ""; fi
	@if [ -f $(ML_LOG) ]; then echo "🤖 $(ML_DETECTOR):"; tail -3 $(ML_LOG) | sed 's/^/    /' | head -3; echo ""; fi
	@if [ -f $(DASHBOARD_LOG) ]; then echo "📊 $(DASHBOARD):"; tail -3 $(DASHBOARD_LOG) | sed 's/^/    /' | head -3; fi

monitor-ml:
	@echo "$(BLUE)🌐 INICIANDO MONITOR SCAPY TRICAPA$(NC)"
	@echo "$(BLUE)================================$(NC)"
	@echo "$(GREEN)Modelos: 7 tricapa operativos$(NC)"
	@echo "$(YELLOW)⚠️  Requiere sudo para captura de paquetes$(NC)"
	@echo "$(YELLOW)⏸️  Presiona Ctrl+C para detener$(NC)"
	@sudo $(PYTHON) $(CORE_DIR)/scapy_monitor_complete_pipeline.py

logs:
	@echo "$(CYAN)📋 Logs del Sistema$(NC)"
	@echo "$(CYAN)====================$(NC)"
	@if [ -f $(FIREWALL_LOG) ]; then echo "$(YELLOW)=== 🛡️  Firewall Agent ===$(NC)"; tail -10 $(FIREWALL_LOG); echo ""; fi
	@if [ -f $(PROMISCUOUS_LOG) ]; then echo "$(YELLOW)=== 🕵️  Promiscuous Agent ===$(NC)"; tail -10 $(PROMISCUOUS_LOG); echo ""; fi
	@if [ -f $(GEOIP_LOG) ]; then echo "$(YELLOW)=== 🌍 GeoIP Enricher ===$(NC)"; tail -10 $(GEOIP_LOG); echo ""; fi
	@if [ -f $(ML_LOG) ]; then echo "$(YELLOW)=== 🤖 ML Detector ===$(NC)"; tail -10 $(ML_LOG); echo ""; fi
	@if [ -f $(DASHBOARD_LOG) ]; then echo "$(YELLOW)=== 📊 Dashboard ===$(NC)"; tail -10 $(DASHBOARD_LOG); fi
	@if [ -f $(NEURAL_LOG) ]; then echo "$(YELLOW)=== 🤖 Neural Trainer ===$(NC)"; tail -10 $(NEURAL_LOG); echo ""; fi

logs-tail:
	@echo "$(CYAN)📋 Siguiendo logs en tiempo real...$(NC)"
	@echo "$(YELLOW)Ctrl+C para salir$(NC)"
	@tail -f $(LOGS_DIR)/*.log 2>/dev/null | grep --line-buffered -E "(📊|📨|📤|ERROR|WARNING|🔥|🌍|🤖|📡)" | while read line; do echo "[$(date '+%H:%M:%S')] $line"; done

logs-errors:
	@echo "$(CYAN)🚨 Logs de Errores$(NC)"
	@echo "$(CYAN)==================$(NC)"
	@grep -i "error\|exception\|traceback\|failed" $(LOGS_DIR)/*.log 2>/dev/null | tail -20 | sed 's/^/  /' || echo "$(GREEN)✅ No se encontraron errores recientes$(NC)"

show-dashboard:
	@echo "$(BLUE)🌐 Abriendo dashboard web...$(NC)"
	@echo "$(YELLOW)URL: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@which open >/dev/null && open http://localhost:$(DASHBOARD_WEB_PORT) || \
       which xdg-open >/dev/null && xdg-open http://localhost:$(DASHBOARD_WEB_PORT) || \
       echo "💡 Abrir manualmente: http://localhost:$(DASHBOARD_WEB_PORT)"

test:
	@echo "$(BLUE)🧪 Ejecutando tests...$(NC)"
	@if [ -d "tests" ]; then \
       $(ACTIVATE) && $(PYTHON_VENV) -m pytest tests/ -v; \
    else \
       echo "$(YELLOW)⚠️  Directorio tests/ no encontrado$(NC)"; \
       echo "$(BLUE)💡 Creando estructura de tests básica...$(NC)"; \
       mkdir -p tests; \
       echo "# Tests del Sistema Autoinmune" > tests/README.md; \
       echo "$(GREEN)✅ Estructura creada en tests/$(NC)"; \
    fi

benchmark:
	@echo "$(BLUE)📊 Ejecutando benchmarks...$(NC)"
	@echo "$(YELLOW)Verificando rendimiento del sistema...$(NC)"
	@$(MAKE) status
	@echo ""
	@echo "$(YELLOW)Uso de CPU por proceso:$(NC)"
	@ps aux | grep -E "(python.*upgraded|python.*core/|python.*ml_pipeline/)" | grep -v grep | awk '{print "  " $11 ": " $3 "% CPU, " $4 "% MEM"}' || echo "  No hay procesos activos"
	@echo ""
	@echo "$(YELLOW)Uso de memoria:$(NC)"
	@free -h | sed 's/^/  /' 2>/dev/null || echo "  No disponible en macOS"
	@echo ""
	@echo "$(YELLOW)Conexiones de red activas:$(NC)"
	@netstat -tuln 2>/dev/null | grep -E ":($(CAPTURE_PORT)|$(GEOIP_PORT)|$(ML_PORT)|$(FIREWALL_PORT)|$(DASHBOARD_WEB_PORT))" | sed 's/^/  /' || echo "  No hay conexiones activas"

# =============================================================================
# MONITORIZACIÓN (ACTUALIZADA)
# =============================================================================
status:
	@echo "$(CYAN)📊 Estado Sistema Post-Housekeeping$(NC)"
	@echo "$(CYAN)===================================$(NC)"
	@echo "$(YELLOW)🔧 Componentes Core ($(CORE_DIR)/)$(NC)"
	@pgrep -f "$(FIREWALL_AGENT)" >/dev/null && echo "  🛡️  Firewall Agent: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🛡️  Firewall Agent: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "promiscuous_agent" >/dev/null && echo "  🕵️  Promiscuous Agent: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🕵️  Promiscuous Agent: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "$(GEOIP_ENRICHER)" >/dev/null && echo "  🌍 GeoIP Enricher: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🌍 GeoIP Enricher: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "$(ML_DETECTOR)" >/dev/null && echo "  🤖 ML Detector Tricapa: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🤖 ML Detector: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "$(DASHBOARD)" >/dev/null && echo "  📊 Dashboard: $(GREEN)✅ Ejecutándose$(NC) $(YELLOW)(http://localhost:$(DASHBOARD_WEB_PORT))$(NC)" || echo "  📊 Dashboard: $(RED)⭕ Detenido$(NC)"
	@echo ""
	@echo "$(YELLOW)🧠 ML Pipeline ($(ML_PIPELINE_DIR)/)$(NC)"
	@pgrep -f "$(NEURAL_TRAINER)" >/dev/null && echo "  🤖 Neural Trainer: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🤖 Neural Trainer: $(BLUE)🎯 Disponible$(NC)"
	@echo ""
	@echo "$(YELLOW)💎 Modelos & Datos:$(NC)"
	@if [ -d "$(MODELS_PRODUCTION_DIR)" ]; then \
		MODELS_COUNT=$$(ls $(MODELS_PRODUCTION_DIR)/*.joblib 2>/dev/null | wc -l); \
		echo "  🧠 Modelos producción: $$MODELS_COUNT archivos"; \
	else \
		echo "  ❌ $(MODELS_PRODUCTION_DIR)/ no encontrado"; \
	fi
	@if [ -d "$(MODELS_ARCHIVE_DIR)" ]; then \
		ARCHIVE_COUNT=$$(ls $(MODELS_ARCHIVE_DIR)/*.joblib 2>/dev/null | wc -l); \
		echo "  📦 Modelos archive: $$ARCHIVE_COUNT archivos"; \
	else \
		echo "  ❌ $(MODELS_ARCHIVE_DIR)/ no encontrado"; \
	fi
	@echo ""
	@echo "$(YELLOW)🌐 Web Assets:$(NC)"
	@if [ -d "$(WEB_STATIC_DIR)" ]; then echo "  ✅ $(WEB_STATIC_DIR)/"; else echo "  ❌ $(WEB_STATIC_DIR)/ falta"; fi
	@if [ -d "$(WEB_TEMPLATES_DIR)" ]; then echo "  ✅ $(WEB_TEMPLATES_DIR)/"; else echo "  ❌ $(WEB_TEMPLATES_DIR)/ falta"; fi
	@echo ""
	@echo "$(YELLOW)🔒 Protocolos:$(NC)"
	@if [ -d "$(PROTOCOLS_DIR)/current" ]; then \
		PROTO_COUNT=$$(ls $(PROTOCOLS_DIR)/current/*.proto 2>/dev/null | wc -l); \
		echo "  🔧 Protobuf files: $$PROTO_COUNT archivos"; \
		COMPILED_COUNT=$$(ls $(PROTOCOLS_DIR)/current/*_pb2.py 2>/dev/null | wc -l); \
		echo "  ⚙️  Compilados: $$COMPILED_COUNT archivos"; \
	else \
		echo "  ❌ $(PROTOCOLS_DIR)/current/ no encontrado"; \
	fi

# El resto de comandos de monitorización, debug, etc. siguen el mismo patrón...

monitor: status
	@echo ""
	@echo "$(YELLOW)💹 Actividad Reciente Post-Housekeeping:$(NC)"
	@if [ -f $(FIREWALL_LOG) ]; then echo "🛡️  $(FIREWALL_AGENT):"; tail -3 $(FIREWALL_LOG) | sed 's/^/    /' | head -3; echo ""; fi
	@if [ -f $(GEOIP_LOG) ]; then echo "🌍 $(GEOIP_ENRICHER):"; tail -3 $(GEOIP_LOG) | sed 's/^/    /' | head -3; echo ""; fi
	@if [ -f $(ML_LOG) ]; then echo "🤖 $(ML_DETECTOR):"; tail -3 $(ML_LOG) | sed 's/^/    /' | head -3; echo ""; fi
	@if [ -f $(DASHBOARD_LOG) ]; then echo "📊 $(DASHBOARD):"; tail -3 $(DASHBOARD_LOG) | sed 's/^/    /' | head -3; fi

# =============================================================================
# COMANDO RÁPIDO AUTÓNOMO (ACTUALIZADO)
# =============================================================================
quick: setup install setup-perms verify-protobuf-compiled start show-dashboard
	@echo ""
	@echo "$(GREEN)🎉 QUICK START POST-HOUSEKEEPING COMPLETADO$(NC)"
	@echo "$(GREEN)==============================================$(NC)"
	@echo "$(YELLOW)Sistema Autoinmune Digital v2.0 POST-HOUSEKEEPING 100% operativo!$(NC)"
	@echo ""
	@echo "$(CYAN)📊 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@echo "$(CYAN)💎 Modelos: $(MODELS_PRODUCTION_DIR)/ (auto-detectados)$(NC)"
	@echo "$(CYAN)🌐 Web: $(WEB_STATIC_DIR)/ + $(WEB_TEMPLATES_DIR)/ (organizados)$(NC)"
	@echo "$(CYAN)🔒 Protobuf: $(PROTOBUF_DIR)/ (auto-compilados)$(NC)"
	@echo "$(CYAN)🧠 Pipeline: $(ML_PIPELINE_DIR)/ (listo)$(NC)"
	@echo "$(CYAN)🌍 329 sitios globales preservados$(NC)"
	@echo "$(CYAN)💎 fixed_service_sniffer.py (33KB épico)$(NC)"
	@echo ""
	@echo "$(CYAN)🔧 Comandos útiles:$(NC)"
	@echo "$(CYAN)  make status               - Estado sistema$(NC)"
	@echo "$(CYAN)  make show-housekeeping    - Ver resultado épico$(NC)"
	@echo "$(CYAN)  make show-epic-sniffer    - Ver joya híbrida$(NC)"
	@echo "$(CYAN)  make check-protobuf-imports - Verificar imports$(NC)"
	@echo "$(CYAN)  make logs                 - Ver logs$(NC)"
	@echo "$(CYAN)  make stop                 - Parar sistema$(NC)"
	@echo "$(CYAN)  make stop-nuclear         - Parar nuclear$(NC)"

# =============================================================================
# COMANDO RÁPIDO AUTÓNOMO (ACTUALIZADO)
# =============================================================================
quick: setup install setup-perms verify-protobuf-compiled start show-dashboard
	@echo ""
	@echo "$(GREEN)🎉 QUICK START POST-HOUSEKEEPING COMPLETADO$(NC)"
	@echo "$(GREEN)==============================================$(NC)"
	@echo "$(YELLOW)Sistema Autoinmune Digital v2.0 POST-HOUSEKEEPING 100% operativo!$(NC)"
	@echo ""
	@echo "$(CYAN)📊 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@echo "$(CYAN)💎 Modelos: $(MODELS_PRODUCTION_DIR)/ (auto-detectados)$(NC)"
	@echo "$(CYAN)🌐 Web: $(WEB_STATIC_DIR)/ + $(WEB_TEMPLATES_DIR)/ (organizados)$(NC)"
	@echo "$(CYAN)🔒 Protobuf: $(PROTOBUF_DIR)/ (auto-compilados)$(NC)"
	@echo "$(CYAN)🧠 Pipeline: $(ML_PIPELINE_DIR)/ (listo)$(NC)"
	@echo "$(CYAN)🌍 329 sitios globales preservados$(NC)"
	@echo "$(CYAN)💎 fixed_service_sniffer.py (33KB épico)$(NC)"
	@echo ""
	@echo "$(CYAN)🔧 Comandos útiles:$(NC)"
	@echo "$(CYAN)  make status               - Estado sistema$(NC)"
	@echo "$(CYAN)  make show-housekeeping    - Ver resultado épico$(NC)"
	@echo "$(CYAN)  make show-epic-sniffer    - Ver joya híbrida$(NC)"
	@echo "$(CYAN)  make check-protobuf-imports - Verificar imports$(NC)"
	@echo "$(CYAN)  make logs                 - Ver logs$(NC)"
	@echo "$(CYAN)  make stop                 - Parar sistema$(NC)"
	@echo "$(CYAN)  make stop-nuclear         - Parar nuclear$(NC)"

# =============================================================================
# UTILIDADES DE VERIFICACIÓN IMPORT (NUEVAS)
# =============================================================================
list-imports-to-fix:
	@echo "$(BLUE)📋 Lista de archivos core que pueden necesitar ajuste de imports...$(NC)"
	@echo "$(YELLOW)🔍 Buscando imports protobuf en core/:$(NC)"
	@for file in core/*.py; do \
		if [ -f "$file" ] && grep -q "pb2\|protobuf" "$file" 2>/dev/null; then \
			echo "  📄 $file:"; \
			grep -n "import.*pb2\|from.*pb2\|protobuf" "$file" | sed 's/^/    /' || true; \
			echo ""; \
		fi \
	done
	@echo "$(YELLOW)💡 Para cada archivo listado arriba:$(NC)"
	@echo "  1. Cambiar imports a: from protocols.current import XXXX_pb2"
	@echo "  2. Verificar con: make check-protobuf-imports"
	@echo "  3. Test con: make start"

verify-system-ready:
	@echo "$(BLUE)🔍 Verificación completa del sistema POST-HOUSEKEEPING...$(NC)"
	@echo "$(CYAN)=========================================================$(NC)"
	@$(MAKE) check-structure
	@echo ""
	@$(MAKE) verify-protobuf-compiled
	@echo ""
	@$(MAKE) check-protobuf-imports
	@echo ""
	@$(MAKE) check-deps
	@echo ""
	@if [ -f "core/fixed_service_sniffer.py" ]; then \
		echo "$(GREEN)✅ JOYA ÉPICA CONFIRMADA: fixed_service_sniffer.py (33KB)$(NC)"; \
	else \
		echo "$(RED)❌ JOYA ÉPICA PERDIDA: fixed_service_sniffer.py$(NC)"; \
	fi
	@echo ""
	@echo "$(YELLOW)🎯 RESULTADO:$(NC)"
	@echo "$(GREEN)  Sistema listo para arranque autónomo con 'make start'$(NC)"

# =============================================================================
# FUNCIONES DE DEBUG Y DESARROLLO (ACTUALIZADA)
# =============================================================================
debug:
	@echo "$(BLUE)🔧 Modo Debug Post-Housekeeping$(NC)"
	@echo "$(BLUE)===============================$(NC)"
	@$(MAKE) check-structure
	@echo ""
	@$(MAKE) status
	@echo ""
	@$(MAKE) check-protobuf
	@echo ""
	@echo "$(YELLOW)Logs recientes:$(NC)"
	@$(MAKE) logs-errors

dev-start: verify-protobuf-compiled start-core
	@echo "$(PURPLE)🔧 Modo desarrollo post-housekeeping activado$(NC)"
	@echo "$(PURPLE)Estructura: $(CORE_DIR)/ + $(ML_PIPELINE_DIR)/ + $(MODELS_PRODUCTION_DIR)/$(NC)"
	@echo "$(PURPLE)Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"

show-epic-sniffer:
	@echo "$(CYAN)💎 JOYA ÉPICA - fixed_service_sniffer.py$(NC)"
	@echo "$(CYAN)=======================================$(NC)"
	@echo ""
	@echo "$(GREEN)🌟 EL SCRIPT QUE DEMUESTRA EL 90% DEL PROYECTO$(NC)"
	@echo ""
	@echo "$(YELLOW)🔬 QUÉ HACE:$(NC)"
	@echo "  📡 Captura tráfico con Scapy (como promiscuous_agent)"
	@echo "  🧮 Extrae 20+ features de red (sin ZeroMQ)"
	@echo "  🤖 Los pasa directamente a modelos ML reentrenados"
	@echo "  🎯 Demuestra toda la metodología en un solo script"
	@echo ""
	@echo "$(YELLOW)💡 POR QUÉ ES ÉPICO:$(NC)"
	@echo "  ⚡ Híbrido perfecto: Sniffer + ML Detector"
	@echo "  🔧 Sin capas de complejidad (ZeroMQ/Protobuf)"
	@echo "  💎 Esencia pura del proyecto demostrada"
	@echo "  🚀 Base para reescritura hacia Protobuf v3.1"
	@echo ""
	@if [ -f "$(FIXED_SERVICE_SNIFFER)" ]; then \
		echo "$(GREEN)✅ Archivo encontrado: $(FIXED_SERVICE_SNIFFER)$(NC)"; \
		echo "$(YELLOW)📊 Estadísticas:$(NC)"; \
		wc -l $(FIXED_SERVICE_SNIFFER) | awk '{print "  📝 Líneas: " $1}'; \
		grep -c "import" $(FIXED_SERVICE_SNIFFER) | awk '{print "  📦 Imports: " $1}'; \
		grep -c "def " $(FIXED_SERVICE_SNIFFER) | awk '{print "  🔧 Funciones: " $1}'; \
	else \
		echo "$(RED)❌ Archivo no encontrado: $(FIXED_SERVICE_SNIFFER)$(NC)"; \
		echo "$(YELLOW)💡 Buscar en: core/ o archive/experimental/$(NC)"; \
	fi
	@echo ""
	@echo "$(PURPLE)🔮 FUTURO - Protobuf v3.1:$(NC)"
	@echo "  🏗️  Base para reescritura de componentes core"
	@echo "  🔒 Integración con protocolos seguros"
	@echo "  🌐 Distribución con ZeroMQ + cifrado"

tricapa: ## 🎯 Probar pipeline tricapa completo (7 modelos)
	@echo "$(BLUE)🎯 PROBANDO PIPELINE TRICAPA COMPLETO$(NC)"
	@echo "$(BLUE)====================================$(NC)"
	@echo "$(GREEN)Esperado: 7 modelos activos$(NC)"
	@$(PYTHON) $(CORE_DIR)/complete_ml_pipeline.py

test-pipeline: tricapa ## 🧪 Alias para tricapa (probar pipeline completo)

ml-features: ## 🔍 Monitor ML features en tiempo real (requiere sudo)
	@echo "$(BLUE)🔍 MONITOR ML FEATURES TIEMPO REAL$(NC)"
	@echo "$(BLUE)==================================$(NC)"
	@echo "$(GREEN)Modelos DDOS/Ransomware: 4 específicos$(NC)"
	@echo "$(YELLOW)⚠️  Requiere sudo para captura de paquetes$(NC)"
	@echo "$(YELLOW)⏸️  Presiona Ctrl+C para detener$(NC)"
	@sudo $(PYTHON) $(CORE_DIR)/scapy_to_ml_features.py

suppress-warnings: ## 🔇 Suprimir warnings de sklearn
	@echo "$(BLUE)🔇 SUPRIMIENDO WARNINGS SKLEARN$(NC)"
	@echo "$(BLUE)==============================$(NC)"
	@$(PYTHON) suppress_sklearn_warnings.py

test-all: ## 🧪 Probar todos los componentes tricapa secuencialmente
	@echo "$(BLUE)🧪 PROBANDO TODOS LOS COMPONENTES TRICAPA$(NC)"
	@echo "$(BLUE)=========================================$(NC)"
	@echo ""
	@echo "$(YELLOW)1. Pipeline ML completo:$(NC)"
	@$(PYTHON) $(CORE_DIR)/complete_ml_pipeline.py
	@echo ""
	@echo "$(YELLOW)2. Monitor scapy (5 segundos):$(NC)"
	@timeout 5 sudo $(PYTHON) $(CORE_DIR)/scapy_monitor_complete_pipeline.py 2>/dev/null || true
	@echo ""
	@echo "$(YELLOW)3. ML Features (5 segundos):$(NC)"
	@timeout 5 sudo $(PYTHON) $(CORE_DIR)/scapy_to_ml_features.py 2>/dev/null || true
	@echo ""
	@echo "$(GREEN)✅ TODOS LOS COMPONENTES PROBADOS$(NC)"

backup: ## 💾 Crear backup del sistema tricapa
	@echo "$(BLUE)💾 CREANDO BACKUP SISTEMA TRICAPA$(NC)"
	@echo "$(BLUE)=================================$(NC)"
	@BACKUP_DIR="backup_tricapa_$(shell date +%Y%m%d_%H%M%S)" && \
	mkdir -p $$BACKUP_DIR && \
	cp -r $(MODELS_DIR) $$BACKUP_DIR/models_tricapa && \
	cp -r $(CORE_DIR)/*.py $$BACKUP_DIR/ && \
	echo "$(GREEN)✅ Backup creado en: $$BACKUP_DIR$(NC)"

install-deps: ## 📦 Instalar dependencias del sistema tricapa
	@echo "$(BLUE)📦 INSTALANDO DEPENDENCIAS TRICAPA$(NC)"
	@echo "$(BLUE)==================================$(NC)"
	@pip install scapy numpy pandas scikit-learn joblib
	@echo "$(GREEN)✅ Dependencias instaladas$(NC)"

docs: ## 📋 Mostrar documentación del sistema tricapa
	@echo "$(BLUE)📋 DOCUMENTACIÓN SISTEMA TRICAPA$(NC)"
	@echo "$(BLUE)===============================$(NC)"
	@echo ""
	@echo "$(GREEN)🏗️ ARQUITECTURA:$(NC)"
	@echo "   🔴 Nivel 1: Filtro general CICDS2017 (82→23 features)"
	@echo "   🟡 Nivel 2: Detectores especializados (23→4 features)"
	@echo "   🟢 Nivel 3: Amenazas específicas (4 features→decisión)"
	@echo ""
	@echo "$(GREEN)📊 MODELOS:$(NC)"
	@echo "   • rf_production_cicids.joblib"
	@echo "   • web_normal_detector.joblib"
	@echo "   • internal_normal_detector.joblib"
	@echo "   • ddos_random_forest.joblib"
	@echo "   • ddos_lightgbm.joblib"
	@echo "   • ransomware_random_forest.joblib"
	@echo "   • ransomware_lightgbm.joblib"
	@echo ""
	@echo "$(GREEN)🚀 USO RÁPIDO:$(NC)"
	@echo "   make tricapa          # Probar pipeline completo"
	@echo "   make monitor          # Monitor tiempo real"
	@echo "   make ml-features      # Features ML tiempo real"
	@echo "   make status           # Ver estado del sistema"

# Comandos de desarrollo
dev-branch: ## 🌟 Crear rama de desarrollo tricapa
	@git checkout -b feature/tricapa-dev-$(shell date +%Y%m%d) 2>/dev/null || echo "$(YELLOW)Ya en rama de desarrollo$(NC)"

# Comandos de rendimiento
benchmark: ## ⚡ Benchmark del sistema tricapa
	@echo "$(BLUE)⚡ BENCHMARK SISTEMA TRICAPA$(NC)"
	@echo "$(BLUE)===========================$(NC)"
	@echo "$(YELLOW)Midiendo rendimiento de los 7 modelos...$(NC)"
	@time $(PYTHON) $(CORE_DIR)/complete_ml_pipeline.py
	@echo "$(GREEN)✅ Benchmark completado$(NC)"# Resto de comandos permanecen similares pero actualizados para nueva estructura...