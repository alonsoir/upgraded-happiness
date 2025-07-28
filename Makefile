# =============================================================================
# 🛡️ Upgraded Happiness - Sistema Autoinmune Digital v2.0 (PRODUCTION)
# =============================================================================
# Arquitectura: promiscuous_agent → geoip_enricher → ml_detector → dashboard → firewall_agent
# Branch: feature/claude-integration
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
# CONFIGURACIÓN DEL PROYECTO
# =============================================================================
# Información del proyecto
PROJECT_NAME = upgraded-happiness
PROJECT_VERSION = v2.0.0
BRANCH = feature/claude-integration
REPO_URL = https://github.com/alonsoir/upgraded-happiness

# Python y Entorno
PYTHON = python3
VENV_NAME = upgraded_happiness_venv
VENV_BIN = $(VENV_NAME)/bin
PYTHON_VENV = $(VENV_BIN)/python
PIP_VENV = $(VENV_BIN)/pip
ACTIVATE = source $(VENV_BIN)/activate

# =============================================================================
# COMPONENTES PRINCIPALES (ARQUITECTURA DISTRIBUIDA)
# =============================================================================
# Core Pipeline Components (✅ = Operativo, 🔄 = En desarrollo, 🎯 = Planificado)
PROMISCUOUS_AGENT = promiscuous_agent.py              # ✅ Captura promiscua
GEOIP_ENRICHER = geoip_enricher.py                   # ✅ Enriquecimiento GeoIP
ML_DETECTOR = lightweight_ml_detector.py             # ✅ Detección ML (refinando)
DASHBOARD = real_zmq_dashboard_with_firewall.py      # 🔄 Dashboard principal (mejorando)
FIREWALL_AGENT = simple_firewall_agent.py            # ✅ Agente firewall (integrando)

# Advanced Components (Próximas fases)
NEURAL_TRAINER = advanced_trainer.py         # 🎯 Entrenamiento continuo
RAG_ENGINE = autoinmune_rag_engine.py               # 🎯 Interfaz conversacional

# Configuraciones JSON
PROMISCUOUS_CONFIG = enhanced_agent_config.json
GEOIP_CONFIG = geoip_enricher_config.json
ML_CONFIG = lightweight_ml_detector_config.json
DASHBOARD_CONFIG = dashboard_config.json                    # ✅ Primer parámetro (original)
FIREWALL_CONFIG = simple_firewall_agent_config.json       # ✅ Primer parámetro (original)
NEURAL_CONFIG = config-advanced-trainer.json
RAG_CONFIG = rag_engine_config.json

# Configuraciones JSON adicionales (segundos parámetros)
DASHBOARD_FIREWALL_CONFIG = config/firewall_rules_dashboard.json  # ✅ Segundo parámetro dashboard
FIREWALL_AGENT_RULES_CONFIG = config/firewall_rules_agent.json   # ✅ Segundo parámetro firewall agent

# =============================================================================
# ARQUITECTURA DE RED (ZeroMQ)
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
# GESTIÓN DE PROCESOS
# =============================================================================
# Directorios
PIDS_DIR = .pids
LOGS_DIR = logs
DATA_DIR = data
MODELS_DIR = models

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

# Scripts de utilidad
NUCLEAR_STOP_SCRIPT = nuclear-stop.sh
MONITOR_SCRIPT = monitor_autoinmune.sh

# =============================================================================
# PHONY DECLARATIONS
# =============================================================================
.PHONY: help setup install clean \
        start start-bg start-core start-advanced stop stop-nuclear restart \
        status monitor logs logs-tail logs-errors \
        setup-perms verify check-geoip check-deps \
        show-dashboard show-architecture show-roadmap \
        quick debug test benchmark \
        dev-start dev-stop dev-restart \
        start-improved verify-start status-detailed create-config-dirs

# =============================================================================
# HELP Y DOCUMENTACIÓN
# =============================================================================
help:
	@echo "$(CYAN)🧬 Sistema Autoinmune Digital v2.0$(NC)"
	@echo "$(CYAN)=====================================$(NC)"
	@echo "$(PURPLE)Branch: $(BRANCH)$(NC)"
	@echo "$(PURPLE)Repo: $(REPO_URL)$(NC)"
	@echo ""
	@echo "$(YELLOW)🚀 COMANDOS PRINCIPALES:$(NC)"
	@echo "  $(GREEN)make quick$(NC)            - Setup completo + Start (RECOMENDADO)"
	@echo "  $(GREEN)make start$(NC)            - Iniciar sistema completo"
	@echo "  $(GREEN)make show-dashboard$(NC)   - Abrir dashboard web"
	@echo "  $(GREEN)make stop$(NC)             - Detener sistema completo"
	@echo "  $(GREEN)make status$(NC)           - Ver estado del sistema"
	@echo ""
	@echo "$(YELLOW)📦 SETUP Y CONFIGURACIÓN:$(NC)"
	@echo "  setup                  - Crear entorno virtual"
	@echo "  install                - Instalar dependencias"
	@echo "  setup-perms            - Configurar permisos sudo (iptables)"
	@echo "  check-geoip            - Verificar configuración GeoIP"
	@echo "  check-deps             - Verificar dependencias"
	@echo "  verify                 - Verificar integridad del sistema"
	@echo "  clean                  - Limpiar todo"
	@echo ""
	@echo "$(YELLOW)🔄 OPERACIONES AVANZADAS:$(NC)"
	@echo "  start-core             - Solo componentes core (básico)"
	@echo "  start-advanced         - Componentes avanzados (RAG, Neural)"
	@echo "  start-bg               - Iniciar en background"
	@echo "  restart                - Reiniciar sistema completo"
	@echo "  stop-nuclear           - Parada nuclear (emergencia)"
	@echo ""
	@echo "$(YELLOW)📊 MONITORIZACIÓN Y DEBUG:$(NC)"
	@echo "  monitor                - Monitor tiempo real"
	@echo "  logs                   - Ver logs de todos los componentes"
	@echo "  logs-tail              - Seguir logs en tiempo real"
	@echo "  logs-errors            - Ver solo errores"
	@echo "  debug                  - Modo debug interactivo"
	@echo "  benchmark              - Ejecutar benchmarks"
	@echo ""
	@echo "$(YELLOW)🔧 DESARROLLO:$(NC)"
	@echo "  dev-start              - Iniciar en modo desarrollo"
	@echo "  dev-stop               - Parar modo desarrollo"
	@echo "  test                   - Ejecutar tests"
	@echo ""
	@echo "$(YELLOW)ℹ️  INFORMACIÓN:$(NC)"
	@echo "  show-architecture      - Mostrar arquitectura del sistema"
	@echo "  show-roadmap           - Ver roadmap y estado actual"
	@echo ""
	@echo "$(CYAN)🏗️ ARQUITECTURA ACTUAL:$(NC)"
	@echo "  promiscuous_agent ($(CAPTURE_PORT)) → geoip_enricher ($(GEOIP_PORT)) → ml_detector ($(ML_PORT)) → dashboard ($(FIREWALL_PORT)) → firewall_agent"
	@echo ""
	@echo "$(CYAN)🌐 SERVICIOS WEB:$(NC)"
	@echo "  Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)"
	@echo "  RAG Engine: http://localhost:$(RAG_WEB_PORT) (próximamente)"

# =============================================================================
# INFORMACIÓN DEL SISTEMA
# =============================================================================
show-architecture:
	@echo "$(CYAN)🏗️ Arquitectura del Sistema$(NC)"
	@echo "$(CYAN)==============================$(NC)"
	@echo ""
	@echo "$(YELLOW)📡 PIPELINE PRINCIPAL:$(NC)"
	@echo "  1. 🕵️  $(PROMISCUOUS_AGENT) → Puerto $(CAPTURE_PORT) (✅ Operativo)"
	@echo "  2. 🌍 $(GEOIP_ENRICHER) → Puerto $(GEOIP_PORT) (✅ Operativo)"
	@echo "  3. 🤖 $(ML_DETECTOR) → Puerto $(ML_PORT) (⚠️ Refinando)"
	@echo "  4. 📊 $(DASHBOARD) → Puerto $(FIREWALL_PORT) (🔄 Mejorando)"
	@echo "  5. 🛡️  $(FIREWALL_AGENT) (✅ Integrando)"
	@echo ""
	@echo "$(YELLOW)🧠 COMPONENTES AVANZADOS:$(NC)"
	@echo "  6. 🤖 $(NEURAL_TRAINER) → Puerto $(NEURAL_PORT) (🎯 Planificado)"
	@echo "  7. 🗣️  $(RAG_ENGINE) → Puerto $(RAG_WEB_PORT) (🎯 En diseño)"
	@echo ""
	@echo "$(YELLOW)🌐 SERVICIOS WEB:$(NC)"
	@echo "  📊 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)"
	@echo "  🗣️  RAG Chat: http://localhost:$(RAG_WEB_PORT)"

show-roadmap:
	@echo "$(CYAN)🔮 Roadmap del Proyecto$(NC)"
	@echo "$(CYAN)========================$(NC)"
	@echo ""
	@echo "$(GREEN)✅ COMPLETADO (Q3 2025):$(NC)"
	@echo "  • Pipeline distribuido ZeroMQ/Protobuf"
	@echo "  • Captura promiscua con Scapy"
	@echo "  • Enriquecimiento GeoIP"
	@echo "  • Detección ML básica"
	@echo "  • Dashboard web"
	@echo "  • Cifrado AES-256-GCM"
	@echo ""
	@echo "$(YELLOW)🔄 EN DESARROLLO ACTIVO:$(NC)"
	@echo "  • Dashboard-Firewall integration (click-to-block)"
	@echo "  • ML classification tuning"
	@echo "  • Auto-respuesta automática"
	@echo "  • RAG Engine con Claude"
	@echo ""
	@echo "$(BLUE)🎯 PRÓXIMOS HITOS (Q4 2025):$(NC)"
	@echo "  • Neural trainer operativo"
	@echo "  • Threat intelligence feeds"
	@echo "  • Advanced correlation"
	@echo "  • Multi-region deployment"
	@echo ""
	@echo "$(PURPLE)🚀 FUTURO (2026):$(NC)"
	@echo "  • Auto-scaling inteligente"
	@echo "  • Kubernetes integration"
	@echo "  • Quantum-ready encryption"
	@echo "  • Self-healing infrastructure"

# =============================================================================
# SETUP Y CONFIGURACIÓN
# =============================================================================
create-config-dirs:
	@echo "$(BLUE)📁 Creando directorios de configuración...$(NC)"
	@mkdir -p config
	@mkdir -p $(PIDS_DIR) $(LOGS_DIR) $(DATA_DIR) $(MODELS_DIR)
	@echo "$(GREEN)✅ Directorios creados$(NC)"

setup: create-config-dirs
	@echo "$(BLUE)🔧 Configurando entorno virtual...$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "$(YELLOW)⚠️  Entorno virtual ya existe$(NC)"; \
	else \
		$(PYTHON) -m venv $(VENV_NAME); \
		echo "$(GREEN)✅ Entorno virtual creado$(NC)"; \
	fi
	@$(ACTIVATE) && $(PYTHON_VENV) -m pip install --upgrade pip
	@echo "$(GREEN)✅ Setup completado$(NC)"

install: setup
	@echo "$(BLUE)📦 Instalando dependencias...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install -r requirements.txt
	@echo "$(BLUE)📦 Instalando librerías específicas...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install joblib scikit-learn xgboost lightgbm
	@$(ACTIVATE) && $(PIP_VENV) install zmq psutil geoip2 protobuf requests
	@$(ACTIVATE) && $(PIP_VENV) install fastapi uvicorn websockets
	@$(ACTIVATE) && $(PIP_VENV) install scapy netifaces
	@$(ACTIVATE) && $(PIP_VENV) install pandas numpy matplotlib seaborn
	@$(ACTIVATE) && $(PIP_VENV) install pytest pytest-asyncio
	@echo "$(GREEN)✅ Dependencias instaladas$(NC)"

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
	@which sudo >/dev/null && echo "✅ sudo disponible" || echo "❌ sudo falta"

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

verify:
	@echo "$(BLUE)🔍 Verificando integridad del sistema...$(NC)"
	@echo "$(YELLOW)Archivos principales:$(NC)"
	@for file in $(PROMISCUOUS_AGENT) $(GEOIP_ENRICHER) $(ML_DETECTOR) $(DASHBOARD) $(FIREWALL_AGENT); do \
		if [ -f "$$file" ]; then \
			echo "  ✅ $$file"; \
		else \
			echo "  ❌ $$file falta"; \
		fi \
	done
	@echo "$(YELLOW)Configuraciones:$(NC)"
	@for config in $(PROMISCUOUS_CONFIG) $(GEOIP_CONFIG) $(ML_CONFIG) $(DASHBOARD_CONFIG) $(FIREWALL_CONFIG) $(DASHBOARD_FIREWALL_CONFIG) $(FIREWALL_AGENT_RULES_CONFIG); do \
		if [ -f "$config" ]; then \
			echo "  ✅ $config"; \
		else \
			echo "  ❌ $config falta - creando configuración básica..."; \
			if echo "$config" | grep -q "firewall_rules_agent"; then \
				mkdir -p config; \
				echo '{"rules": [], "enabled": true, "mode": "agent"}' > "$config"; \
				echo "  ✅ $config creado"; \
			elif echo "$config" | grep -q "firewall_rules_dashboard"; then \
				mkdir -p config; \
				echo '{"dashboard_rules": [], "monitoring": true, "mode": "dashboard"}' > "$config"; \
				echo "  ✅ $config creado"; \
			elif echo "$config" | grep -q "dashboard_config"; then \
				echo '{"port": 8080, "host": "localhost", "debug": false}' > "$config"; \
				echo "  ✅ $config creado"; \
			elif echo "$config" | grep -q "simple_firewall_agent_config"; then \
				echo '{"agent_id": "firewall_001", "enabled": true, "log_level": "INFO"}' > "$config"; \
				echo "  ✅ $config creado"; \
			fi \
		fi \
	done
	@echo "$(YELLOW)Permisos:$(NC)"
	@sudo -n iptables -L >/dev/null 2>&1 && echo "  ✅ Permisos firewall OK" || echo "  ❌ Permisos firewall faltan (ejecutar: make setup-perms)"
	@echo "$(YELLOW)Dependencias:$(NC)"
	@$(MAKE) check-deps 2>/dev/null | grep -E "(✅|❌)" | sed 's/^/  /'

clean:
	@echo "$(YELLOW)🧹 Limpiando sistema...$(NC)"
	@$(MAKE) stop 2>/dev/null || true
	@echo "  🗑️  Removiendo entorno virtual..."
	@rm -rf $(VENV_NAME)
	@echo "  🗑️  Limpiando archivos Python..."
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@find . -name "*.pyo" -delete 2>/dev/null || true
	@echo "  🗑️  Limpiando directorios temporales..."
	@rm -rf $(PIDS_DIR) $(LOGS_DIR) $(DATA_DIR) $(MODELS_DIR)
	@echo "$(GREEN)✅ Limpieza completada$(NC)"

# =============================================================================
# GESTIÓN DEL SISTEMA PRINCIPAL
# =============================================================================
start: install verify check-geoip stop
	@echo "$(GREEN)🚀 Iniciando Sistema Autoinmune Digital v2.0...$(NC)"
	@echo "$(CYAN)================================================$(NC)"
	@echo "$(PURPLE)Branch: $(BRANCH)$(NC)"
	@echo ""
	@echo "$(BLUE)🔄 Iniciando componentes en orden secuencial...$(NC)"
	@echo "$(BLUE)📁 Verificando archivos de configuración JSON...$(NC)"
	@test -f $(DASHBOARD_CONFIG) || (echo "$(YELLOW)⚠️  Creando $(DASHBOARD_CONFIG)...$(NC)" && echo '{"port": 8080, "host": "localhost", "debug": false}' > $(DASHBOARD_CONFIG))
	@test -f $(DASHBOARD_FIREWALL_CONFIG) || (echo "$(YELLOW)⚠️  Creando $(DASHBOARD_FIREWALL_CONFIG)...$(NC)" && mkdir -p config && echo '{"dashboard_rules": [], "monitoring": true, "mode": "dashboard"}' > $(DASHBOARD_FIREWALL_CONFIG))
	@test -f $(FIREWALL_CONFIG) || (echo "$(YELLOW)⚠️  Creando $(FIREWALL_CONFIG)...$(NC)" && echo '{"agent_id": "firewall_001", "enabled": true, "log_level": "INFO"}' > $(FIREWALL_CONFIG))
	@test -f $(FIREWALL_AGENT_RULES_CONFIG) || (echo "$(YELLOW)⚠️  Creando $(FIREWALL_AGENT_RULES_CONFIG)...$(NC)" && mkdir -p config && echo '{"rules": [], "enabled": true, "mode": "agent"}' > $(FIREWALL_AGENT_RULES_CONFIG))
	@echo ""

	@echo "$(BLUE)1. 🛡️  Firewall Agent (Puerto $(FIREWALL_PORT)) con $(FIREWALL_CONFIG) $(FIREWALL_AGENT_RULES_CONFIG)...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT) $(FIREWALL_CONFIG) $(FIREWALL_AGENT_RULES_CONFIG) > $(FIREWALL_LOG) 2>&1 & echo $! > $(FIREWALL_PID)
	@sleep 3

	@echo "$(BLUE)2. 🕵️  Promiscuous Agent → Puerto $(CAPTURE_PORT)...$(NC)"
	@sudo bash -c '$(PYTHON_VENV) $(PROMISCUOUS_AGENT) $(PROMISCUOUS_CONFIG) > $(PROMISCUOUS_LOG) 2>&1 & echo $$! > $(PROMISCUOUS_PID)'
	@sleep 3
	@echo "🔍 Verificando PID promiscuous_agent..."
	@if [ -f $(PROMISCUOUS_PID) ]; then \
		PID=$$(cat $(PROMISCUOUS_PID)); \
		if ps -p $$PID > /dev/null 2>&1; then \
			echo "✅ Promiscuous Agent iniciado (PID: $$PID)"; \
		else \
			echo "🔄 Buscando PID real..."; \
			REAL_PID=$$(pgrep -f "$(PROMISCUOUS_AGENT)" | head -1); \
			if [ -n "$$REAL_PID" ]; then \
				echo "✅ PID real encontrado: $$REAL_PID"; \
				echo $$REAL_PID > $(PROMISCUOUS_PID); \
			else \
				echo "❌ Promiscuous Agent no encontrado"; \
			fi \
		fi \
	fi

	@echo "$(BLUE)3. 🌍 GeoIP Enricher ($(CAPTURE_PORT) → $(GEOIP_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER) $(GEOIP_CONFIG) > $(GEOIP_LOG) 2>&1 & echo $$! > $(GEOIP_PID)
	@sleep 3

	@echo "$(BLUE)4. 🤖 ML Detector ($(GEOIP_PORT) → $(ML_PORT)) [⚠️ Refinando]...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) $(ML_CONFIG) > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@sleep 3

	@echo "$(BLUE)5. 📊 Dashboard ($(ML_PORT) → UI $(DASHBOARD_WEB_PORT) → $(FIREWALL_PORT)) con $(DASHBOARD_CONFIG) $(DASHBOARD_FIREWALL_CONFIG) [🔄 Mejorando]...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD) $(DASHBOARD_CONFIG) $(DASHBOARD_FIREWALL_CONFIG) > $(DASHBOARD_LOG) 2>&1 & echo $! > $(DASHBOARD_PID)
	@sleep 5

	@echo ""
	@echo "$(GREEN)🎉 SISTEMA OPERACIONAL$(NC)"
	@echo "$(CYAN)========================$(NC)"
	@echo "$(YELLOW)📊 Dashboard Principal: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@echo "$(YELLOW)🛡️  Pipeline: promiscuous → geoip → ml → dashboard → firewall$(NC)"
	@echo "$(YELLOW)🔐 Cifrado: AES-256-GCM activo$(NC)"
	@echo "$(YELLOW)📡 Captura: Modo promiscuo activo$(NC)"
	@echo "$(YELLOW)🌍 GeoIP: Enriquecimiento geográfico$(NC)"
	@echo "$(YELLOW)🤖 ML: Detección de anomalías$(NC)"
	@echo "$(YELLOW)⚙️  Configuraciones JSON:$(NC)"
	@echo "$(YELLOW)   • Firewall Agent: $(FIREWALL_CONFIG)$(NC)"
	@echo "$(YELLOW)   • Dashboard: $(DASHBOARD_CONFIG)$(NC)"
	@echo ""
	@echo "$(PURPLE)💡 Issues conocidos en desarrollo:$(NC)"
	@echo "$(PURPLE)   • Click-to-block en dashboard (próxima semana)$(NC)"
	@echo "$(PURPLE)   • ML classification tuning (sprint actual)$(NC)"
	@echo "$(PURPLE)   • Auto-respuesta firewall (próximo sprint)$(NC)"
	@echo ""
	@echo "$(PURPLE)   • Recomendacion. Arrancar el script monitor_autoinmune.sh después de darle permisos de ejecución.$(NC)"
	@$(MAKE) status

start-core: install verify stop
	@echo "$(GREEN)🚀 Iniciando componentes CORE...$(NC)"
	@test -f $(FIREWALL_CONFIG) || echo '{"agent_id": "firewall_001", "enabled": true, "log_level": "INFO"}' > $(FIREWALL_CONFIG)
	@test -f $(FIREWALL_AGENT_RULES_CONFIG) || (mkdir -p config && echo '{"rules": [], "enabled": true, "mode": "agent"}' > $(FIREWALL_AGENT_RULES_CONFIG))
	@test -f $(DASHBOARD_CONFIG) || echo '{"port": 8080, "host": "localhost", "debug": false}' > $(DASHBOARD_CONFIG)
	@test -f $(DASHBOARD_FIREWALL_CONFIG) || (mkdir -p config && echo '{"dashboard_rules": [], "monitoring": true, "mode": "dashboard"}' > $(DASHBOARD_FIREWALL_CONFIG))
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT) $(FIREWALL_CONFIG) $(FIREWALL_AGENT_RULES_CONFIG) > $(FIREWALL_LOG) 2>&1 & echo $! > $(FIREWALL_PID)
	@sleep 2
	@sudo bash -c '$(PYTHON_VENV) $(PROMISCUOUS_AGENT) $(PROMISCUOUS_CONFIG) > $(PROMISCUOUS_LOG) 2>&1 & echo $! > $(PROMISCUOUS_PID)'
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER) $(GEOIP_CONFIG) > $(GEOIP_LOG) 2>&1 & echo $! > $(GEOIP_PID)
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) $(ML_CONFIG) > $(ML_LOG) 2>&1 & echo $! > $(ML_PID)
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD) $(DASHBOARD_CONFIG) $(DASHBOARD_FIREWALL_CONFIG) > $(DASHBOARD_LOG) 2>&1 & echo $! > $(DASHBOARD_PID)
	@echo "$(GREEN)✅ Componentes core iniciados$(NC)"

start-advanced:
	@echo "$(BLUE)🧠 Iniciando componentes AVANZADOS...$(NC)"
	@if [ -f "$(NEURAL_TRAINER)" ]; then \
		echo "$(BLUE)🤖 Neural Trainer...$(NC)"; \
		$(ACTIVATE) && $(PYTHON_VENV) $(NEURAL_TRAINER) $(NEURAL_CONFIG) > $(NEURAL_LOG) 2>&1 & echo $$! > $(NEURAL_PID); \
		sleep 2; \
	else \
		echo "$(YELLOW)⚠️  Neural Trainer no disponible (🎯 planificado)$(NC)"; \
	fi
	@if [ -f "$(RAG_ENGINE)" ]; then \
		echo "$(BLUE)🗣️  RAG Engine...$(NC)"; \
		$(ACTIVATE) && $(PYTHON_VENV) $(RAG_ENGINE) $(RAG_CONFIG) > $(RAG_LOG) 2>&1 & echo $$! > $(RAG_PID); \
		sleep 2; \
	else \
		echo "$(YELLOW)⚠️  RAG Engine no disponible (🎯 en diseño)$(NC)"; \
	fi
	@echo "$(GREEN)✅ Componentes avanzados iniciados$(NC)"

start-bg: install verify check-geoip stop
	@echo "$(GREEN)🚀 Iniciando sistema (background mode)...$(NC)"
	@test -f $(FIREWALL_CONFIG) || (mkdir -p config && echo '{"rules": [], "enabled": true, "mode": "agent"}' > $(FIREWALL_CONFIG))
	@test -f $(DASHBOARD_CONFIG) || (mkdir -p config && echo '{"dashboard_rules": [], "monitoring": true, "mode": "dashboard"}' > $(DASHBOARD_CONFIG))
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(FIREWALL_AGENT) $(FIREWALL_CONFIG) > $(FIREWALL_LOG) 2>&1 & echo $$! > $(FIREWALL_PID)
	@sleep 2
	@sudo bash -c 'nohup $(PYTHON_VENV) $(PROMISCUOUS_AGENT) $(PROMISCUOUS_CONFIG) > $(PROMISCUOUS_LOG) 2>&1 & echo $$! > $(PROMISCUOUS_PID)'
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(GEOIP_ENRICHER) $(GEOIP_CONFIG) > $(GEOIP_LOG) 2>&1 & echo $$! > $(GEOIP_PID)
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(ML_DETECTOR) $(ML_CONFIG) > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(DASHBOARD) $(DASHBOARD_CONFIG) > $(DASHBOARD_LOG) 2>&1 & echo $$! > $(DASHBOARD_PID)
	@echo "$(GREEN)✅ Sistema iniciado en background$(NC)"
	@echo "$(YELLOW)📊 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"

# =============================================================================
# GESTIÓN DE PARADAS (UNIFICADA)
# =============================================================================

# Función de parada estándar (secuencial y limpia)
stop:
	@echo "$(YELLOW)🛑 Deteniendo sistema...$(NC)"
	@echo "$(BLUE)Parada secuencial en orden inverso...$(NC)"

	# Metodo 1: Intentar con PIDs si existen
	@echo "🔄 Método 1: Deteniendo con PIDs..."
	@-if [ -f $(RAG_PID) ]; then echo "🗣️  Deteniendo RAG Engine..."; kill $$(cat $(RAG_PID)) 2>/dev/null || true; rm -f $(RAG_PID); fi
	@-if [ -f $(NEURAL_PID) ]; then echo "🤖 Deteniendo Neural Trainer..."; kill $$(cat $(NEURAL_PID)) 2>/dev/null || true; rm -f $(NEURAL_PID); fi
	@-if [ -f $(DASHBOARD_PID) ]; then echo "📊 Deteniendo Dashboard..."; kill $$(cat $(DASHBOARD_PID)) 2>/dev/null || true; rm -f $(DASHBOARD_PID); fi
	@-if [ -f $(ML_PID) ]; then echo "🤖 Deteniendo ML Detector..."; kill $$(cat $(ML_PID)) 2>/dev/null || true; rm -f $(ML_PID); fi
	@-if [ -f $(GEOIP_PID) ]; then echo "🌍 Deteniendo GeoIP Enricher..."; kill $$(cat $(GEOIP_PID)) 2>/dev/null || true; rm -f $(GEOIP_PID); fi
	@-if [ -f $(PROMISCUOUS_PID) ]; then echo "🕵️  Deteniendo Promiscuous Agent..."; kill $$(cat $(PROMISCUOUS_PID)) 2>/dev/null || true; sudo kill $$(cat $(PROMISCUOUS_PID)) 2>/dev/null || true; rm -f $(PROMISCUOUS_PID); fi
	@-if [ -f $(FIREWALL_PID) ]; then echo "🛡️  Deteniendo Firewall Agent..."; kill $$(cat $(FIREWALL_PID)) 2>/dev/null || true; rm -f $(FIREWALL_PID); fi
	@sleep 2

	# Método 2: pkill por nombre de proceso (más agresivo)
	@echo "🔄 Método 2: pkill por patrón..."
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

	@echo "$(GREEN)✅ Sistema detenido correctamente$(NC)"

# Comando de emergency stop (nuclear) - VERSIÓN ÚNICA Y MEJORADA
stop-nuclear:
	@echo "$(RED)🚨 PARADA NUCLEAR ACTIVADA$(NC)"
	@echo "$(RED)==============================$(NC)"

	# Matar TODOS los procesos Python relacionados
	@echo "💀 Matando todos los procesos Python del sistema..."
	@-ps aux | grep -E "python.*upgraded|python.*promiscuous|python.*geoip|python.*ml_detector|python.*dashboard|python.*firewall" | grep -v grep | awk '{print $$2}' | xargs -r kill -9 2>/dev/null || true
	@-ps aux | grep -E "python.*upgraded|python.*promiscuous|python.*geoip|python.*ml_detector|python.*dashboard|python.*firewall" | grep -v grep | awk '{print $$2}' | xargs -r sudo kill -9 2>/dev/null || true

	# Limpiar procesos sudo colgados
	@echo "🧹 Limpiando procesos sudo..."
	@-sudo pkill -9 -f "python.*promiscuous" 2>/dev/null || true

	# Limpiar PIDs
	@echo "🗑️  Limpiando archivos PID..."
	@-rm -f $(PIDS_DIR)/*.pid

	# Limpiar puertos ZeroMQ colgados
	@echo "🔌 Liberando puertos ZeroMQ..."
	@-lsof -ti:5559,5560,5561,5562,8080 2>/dev/null | xargs -r kill -9 2>/dev/null || true

	@echo "$(GREEN)✅ Parada nuclear completada$(NC)"

restart: stop
	@sleep 3
	@$(MAKE) start

# =============================================================================
# FUNCIONES DE INICIO MEJORADAS
# =============================================================================

# Start mejorado con PIDs robustos
start-improved: install verify check-geoip stop
	@echo "$(GREEN)🚀 Iniciando Sistema Autoinmune Digital v2.0 (Mejorado)...$(NC)"
	@echo "$(CYAN)========================================================$(NC)"

	@echo "$(BLUE)1. 🛡️  Firewall Agent...$(NC)"
	@test -f $(FIREWALL_CONFIG) || (mkdir -p config && echo '{"rules": [], "enabled": true, "mode": "agent"}' > $(FIREWALL_CONFIG))
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT) $(FIREWALL_CONFIG) > $(FIREWALL_LOG) 2>&1 & echo $$! > $(FIREWALL_PID)
	@sleep 3

	@echo "$(BLUE)2. 🕵️  Promiscuous Agent (con sudo)...$(NC)"
	@sudo bash -c '$(PYTHON_VENV) $(PROMISCUOUS_AGENT) $(PROMISCUOUS_CONFIG) > $(PROMISCUOUS_LOG) 2>&1 & echo $$! > $(PROMISCUOUS_PID)'
	@sleep 3

	@echo "$(BLUE)3. 🌍 GeoIP Enricher...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER) $(GEOIP_CONFIG) > $(GEOIP_LOG) 2>&1 & echo $$! > $(GEOIP_PID)
	@sleep 3

	@echo "$(BLUE)4. 🤖 ML Detector...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) $(ML_CONFIG) > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@sleep 3

	@echo "$(BLUE)5. 📊 Dashboard...$(NC)"
	@test -f $(DASHBOARD_CONFIG) || (mkdir -p config && echo '{"dashboard_rules": [], "monitoring": true, "mode": "dashboard"}' > $(DASHBOARD_CONFIG))
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD) $(DASHBOARD_CONFIG) > $(DASHBOARD_LOG) 2>&1 & echo $$! > $(DASHBOARD_PID)
	@sleep 5

	@echo ""
	@echo "$(GREEN)🎉 VERIFICANDO ESTADO...$(NC)"
	@$(MAKE) verify-start

# Verificador de inicio
verify-start:
	@echo "$(CYAN)🔍 Verificando componentes iniciados...$(NC)"
	@components_ok=0; \
	total_components=5; \
	for pidfile in $(FIREWALL_PID) $(PROMISCUOUS_PID) $(GEOIP_PID) $(ML_PID) $(DASHBOARD_PID); do \
		if [ -f "$$pidfile" ]; then \
			PID=$$(cat $$pidfile); \
			if ps -p $$PID > /dev/null 2>&1; then \
				components_ok=$$((components_ok + 1)); \
				echo "  ✅ $$(basename $$pidfile .pid): PID $$PID activo"; \
			else \
				echo "  ❌ $$(basename $$pidfile .pid): PID $$PID muerto"; \
			fi \
		else \
			echo "  ❌ $$(basename $$pidfile .pid): Sin PID file"; \
		fi \
	done; \
	echo ""; \
	echo "📊 Estado: $$components_ok/$$total_components componentes activos"; \
	if [ "$$components_ok" -eq "$$total_components" ]; then \
		echo "$(GREEN)🎉 SISTEMA COMPLETAMENTE OPERACIONAL$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  Sistema parcialmente operacional$(NC)"; \
	fi

# =============================================================================
# MONITORIZACIÓN Y DEBUGGING
# =============================================================================
status:
	@echo "$(CYAN)📊 Estado del Sistema Autoinmune$(NC)"
	@echo "$(CYAN)===================================$(NC)"
	@echo "$(YELLOW)🔧 Componentes Core:$(NC)"
	@pgrep -f "$(FIREWALL_AGENT)" >/dev/null && echo "  🛡️  Firewall Agent: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🛡️  Firewall Agent: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "$(PROMISCUOUS_AGENT)" >/dev/null && echo "  🕵️  Promiscuous Agent: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🕵️  Promiscuous Agent: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "$(GEOIP_ENRICHER)" >/dev/null && echo "  🌍 GeoIP Enricher: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🌍 GeoIP Enricher: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "$(ML_DETECTOR)" >/dev/null && echo "  🤖 ML Detector: $(GREEN)✅ Ejecutándose$(NC) $(YELLOW)(refinando)$(NC)" || echo "  🤖 ML Detector: $(RED)⭕ Detenido$(NC)"
	@pgrep -f "$(DASHBOARD)" >/dev/null && echo "  📊 Dashboard: $(GREEN)✅ Ejecutándose$(NC) $(YELLOW)(http://localhost:$(DASHBOARD_WEB_PORT))$(NC)" || echo "  📊 Dashboard: $(RED)⭕ Detenido$(NC)"
	@echo ""
	@echo "$(YELLOW)🧠 Componentes Avanzados:$(NC)"
	@pgrep -f "$(NEURAL_TRAINER)" >/dev/null && echo "  🤖 Neural Trainer: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🤖 Neural Trainer: $(BLUE)🎯 No disponible$(NC)"
	@pgrep -f "$(RAG_ENGINE)" >/dev/null && echo "  🗣️  RAG Engine: $(GREEN)✅ Ejecutándose$(NC)" || echo "  🗣️  RAG Engine: $(BLUE)🎯 No disponible$(NC)"
	@echo ""
	@echo "$(YELLOW)⚙️  Configuraciones JSON:$(NC)"
	@test -f $(FIREWALL_CONFIG) && echo "  ✅ Firewall Agent Config: $(FIREWALL_CONFIG)" || echo "  ❌ Firewall Agent Config: $(FIREWALL_CONFIG) falta"
	@test -f $(DASHBOARD_CONFIG) && echo "  ✅ Dashboard Config: $(DASHBOARD_CONFIG)" || echo "  ❌ Dashboard Config: $(DASHBOARD_CONFIG) falta"
	@echo ""
	@echo "$(YELLOW)🌐 Puertos de Red:$(NC)"
	@lsof -i :$(CAPTURE_PORT) >/dev/null 2>&1 && echo "  📡 Captura ($(CAPTURE_PORT)): $(GREEN)ACTIVO$(NC)" || echo "  📡 Captura ($(CAPTURE_PORT)): $(RED)INACTIVO$(NC)"
	@lsof -i :$(GEOIP_PORT) >/dev/null 2>&1 && echo "  🌍 GeoIP ($(GEOIP_PORT)): $(GREEN)ACTIVO$(NC)" || echo "  🌍 GeoIP ($(GEOIP_PORT)): $(RED)INACTIVO$(NC)"
	@lsof -i :$(ML_PORT) >/dev/null 2>&1 && echo "  🤖 ML ($(ML_PORT)): $(GREEN)ACTIVO$(NC)" || echo "  🤖 ML ($(ML_PORT)): $(RED)INACTIVO$(NC)"
	@lsof -i :$(FIREWALL_PORT) >/dev/null 2>&1 && echo "  🛡️  Firewall ($(FIREWALL_PORT)): $(GREEN)ACTIVO$(NC)" || echo "  🛡️  Firewall ($(FIREWALL_PORT)): $(RED)INACTIVO$(NC)"
	@lsof -i :$(DASHBOARD_WEB_PORT) >/dev/null 2>&1 && echo "  📊 Dashboard Web ($(DASHBOARD_WEB_PORT)): $(GREEN)ACTIVO$(NC)" || echo "  📊 Dashboard Web ($(DASHBOARD_WEB_PORT)): $(RED)INACTIVO$(NC)"
	@lsof -i :$(RAG_WEB_PORT) >/dev/null 2>&1 && echo "  🗣️  RAG Web ($(RAG_WEB_PORT)): $(GREEN)ACTIVO$(NC)" || echo "  🗣️  RAG Web ($(RAG_WEB_PORT)): $(BLUE)🎯 Planificado$(NC)"

# Status mejorado con PIDs
status-detailed:
	@echo "$(CYAN)📊 Estado Detallado del Sistema$(NC)"
	@echo "$(CYAN)================================$(NC)"
	@echo ""

	@echo "$(YELLOW)🔧 PIDs guardados:$(NC)"
	@if [ -d "$(PIDS_DIR)" ]; then \
		ls -la $(PIDS_DIR)/*.pid 2>/dev/null | awk '{print "  📄 " $$9 ": " $$5 " bytes"}' || echo "  ⚠️  No hay PIDs guardados"; \
	else \
		echo "  ❌ Directorio PIDs no existe"; \
	fi
	@echo ""

	@echo "$(YELLOW)🏃 Procesos activos:$(NC)"
	@ps aux | grep -E "python.*upgraded|python.*promiscuous|python.*geoip|python.*ml_detector|python.*dashboard|python.*firewall" | grep -v grep | awk '{print "  🆔 PID " $$2 " (" $$3 "% CPU): " $$11 " " $$12}' || echo "  ⚠️  No hay procesos activos"
	@echo ""

	@echo "$(YELLOW)🌐 Puertos en uso:$(NC)"
	@lsof -i :5559,5560,5561,5562,8080 2>/dev/null | grep LISTEN | awk '{print "  🔌 Puerto " $$9 ": " $$1 " (PID " $$2 ")"}' || echo "  ⚠️  No hay puertos activos"

monitor:
	@echo "$(CYAN)📊 Monitor del Sistema$(NC)"
	@echo "$(CYAN)=======================$(NC)"
	@$(MAKE) status
	@echo ""
	@echo "$(YELLOW)💹 Actividad Reciente (últimas 3 líneas):$(NC)"
	@if [ -f $(FIREWALL_LOG) ]; then echo "🛡️  $(FIREWALL_AGENT):"; tail -3 $(FIREWALL_LOG) | sed 's/^/    /' | head -3; echo ""; fi
	@if [ -f $(GEOIP_LOG) ]; then echo "🌍 $(GEOIP_ENRICHER):"; tail -3 $(GEOIP_LOG) | sed 's/^/    /' | head -3; echo ""; fi
	@if [ -f $(ML_LOG) ]; then echo "🤖 $(ML_DETECTOR):"; tail -3 $(ML_LOG) | sed 's/^/    /' | head -3; echo ""; fi
	@if [ -f $(DASHBOARD_LOG) ]; then echo "📊 $(DASHBOARD):"; tail -3 $(DASHBOARD_LOG) | sed 's/^/    /' | head -3; fi

logs:
	@echo "$(CYAN)📋 Logs del Sistema$(NC)"
	@echo "$(CYAN)====================$(NC)"
	@if [ -f $(FIREWALL_LOG) ]; then echo "$(YELLOW)=== 🛡️  Firewall Agent ===$(NC)"; tail -10 $(FIREWALL_LOG); echo ""; fi
	@if [ -f $(PROMISCUOUS_LOG) ]; then echo "$(YELLOW)=== 🕵️  Promiscuous Agent ===$(NC)"; tail -10 $(PROMISCUOUS_LOG); echo ""; fi
	@if [ -f $(GEOIP_LOG) ]; then echo "$(YELLOW)=== 🌍 GeoIP Enricher ===$(NC)"; tail -10 $(GEOIP_LOG); echo ""; fi
	@if [ -f $(ML_LOG) ]; then echo "$(YELLOW)=== 🤖 ML Detector ===$(NC)"; tail -10 $(ML_LOG); echo ""; fi
	@if [ -f $(DASHBOARD_LOG) ]; then echo "$(YELLOW)=== 📊 Dashboard ===$(NC)"; tail -10 $(DASHBOARD_LOG); fi
	@if [ -f $(NEURAL_LOG) ]; then echo "$(YELLOW)=== 🤖 Neural Trainer ===$(NC)"; tail -10 $(NEURAL_LOG); echo ""; fi
	@if [ -f $(RAG_LOG) ]; then echo "$(YELLOW)=== 🗣️  RAG Engine ===$(NC)"; tail -10 $(RAG_LOG); fi

logs-tail:
	@echo "$(CYAN)📋 Siguiendo logs en tiempo real...$(NC)"
	@echo "$(YELLOW)Ctrl+C para salir$(NC)"
	@tail -f $(LOGS_DIR)/*.log 2>/dev/null | grep --line-buffered -E "(📊|📨|📤|ERROR|WARNING|🔥|🌍|🤖|📡)" | while read line; do echo "[$(date '+%H:%M:%S')] $$line"; done

logs-errors:
	@echo "$(CYAN)🚨 Logs de Errores$(NC)"
	@echo "$(CYAN)==================$(NC)"
	@grep -i "error\|exception\|traceback\|failed" $(LOGS_DIR)/*.log 2>/dev/null | tail -20 | sed 's/^/  /' || echo "$(GREEN)✅ No se encontraron errores recientes$(NC)"

# =============================================================================
# UTILIDADES Y DESARROLLO
# =============================================================================
show-dashboard:
	@echo "$(BLUE)🌐 Abriendo dashboard web...$(NC)"
	@echo "$(YELLOW)URL: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@which open >/dev/null && open http://localhost:$(DASHBOARD_WEB_PORT) || \
		which xdg-open >/dev/null && xdg-open http://localhost:$(DASHBOARD_WEB_PORT) || \
		echo "💡 Abrir manualmente: http://localhost:$(DASHBOARD_WEB_PORT)"

debug:
	@echo "$(BLUE)🔧 Modo Debug Interactivo$(NC)"
	@echo "$(BLUE)============================$(NC)"
	@echo "$(YELLOW)Sistema:$(NC)"
	@$(MAKE) status
	@echo ""
	@echo "$(YELLOW)Logs recientes:$(NC)"
	@$(MAKE) logs-errors
	@echo ""
	@echo "$(YELLOW)Puertos en uso:$(NC)"
	@lsof -i :$(CAPTURE_PORT),$(GEOIP_PORT),$(ML_PORT),$(FIREWALL_PORT),$(DASHBOARD_WEB_PORT) 2>/dev/null || echo "  No hay puertos activos"
	@echo ""
	@echo "$(YELLOW)Procesos Python:$(NC)"
	@ps aux | grep -E "(python.*upgraded|python.*$(PROMISCUOUS_AGENT)|python.*$(DASHBOARD))" | grep -v grep || echo "  No hay procesos activos"

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
	@ps aux | grep -E "(python.*upgraded|python.*promiscuous|python.*geoip|python.*ml_detector|python.*dashboard)" | grep -v grep | awk '{print "  " $$11 ": " $$3 "% CPU, " $$4 "% MEM"}' || echo "  No hay procesos activos"
	@echo ""
	@echo "$(YELLOW)Uso de memoria:$(NC)"
	@free -h | sed 's/^/  /' 2>/dev/null || echo "  No disponible en macOS"
	@echo ""
	@echo "$(YELLOW)Conexiones de red activas:$(NC)"
	@netstat -tuln 2>/dev/null | grep -E ":($(CAPTURE_PORT)|$(GEOIP_PORT)|$(ML_PORT)|$(FIREWALL_PORT)|$(DASHBOARD_WEB_PORT))" | sed 's/^/  /' || echo "  No hay conexiones activas"

# =============================================================================
# COMANDOS DE DESARROLLO
# =============================================================================
dev-start: start-core
	@echo "$(PURPLE)🔧 Modo desarrollo activado$(NC)"
	@echo "$(PURPLE)Core components iniciados$(NC)"
	@echo "$(PURPLE)Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"

dev-stop: stop
	@echo "$(PURPLE)🔧 Modo desarrollo detenido$(NC)"

dev-restart: dev-stop dev-start

# =============================================================================
# COMANDO RÁPIDO
# =============================================================================
quick: setup install setup-perms start show-dashboard
	@echo ""
	@echo "$(GREEN)🎉 QUICK START COMPLETADO$(NC)"
	@echo "$(GREEN)============================$(NC)"
	@echo "$(YELLOW)El Sistema Autoinmune Digital está operativo!$(NC)"
	@echo ""
	@echo "$(CYAN)📊 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@echo "$(CYAN)🔧 Estado: make status$(NC)"
	@echo "$(CYAN)📋 Logs: make logs$(NC)"
	@echo "$(CYAN)🛑 Parar: make stop$(NC)"