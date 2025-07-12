# =============================================================================
# 🛡️ Upgraded Happiness - SCADA Security Platform (PRODUCTION)
# =============================================================================
# Arquitectura: promiscuous_agent → geoip_enricher → ml_detector → dashboard → firewall_agent
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# =============================================================================
# COLORES
# =============================================================================
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
PURPLE = \033[0;35m
CYAN = \033[0;36m
NC = \033[0m # No Color

# =============================================================================
# CONFIGURACIÓN
# =============================================================================
# Python y Entorno
PYTHON = python3
VENV_NAME = upgraded_happiness_venv
VENV_BIN = $(VENV_NAME)/bin
PYTHON_VENV = $(VENV_BIN)/python
PIP_VENV = $(VENV_BIN)/pip
ACTIVATE = source $(VENV_BIN)/activate

# Scripts de Producción (ARQUITECTURA NUEVA)
PROMISCUOUS_AGENT = promiscuous_agent.py
GEOIP_ENRICHER = geoip_enricher.py
ML_DETECTOR = lightweight_ml_detector.py
DASHBOARD = real_zmq_dashboard_with_firewall.py
FIREWALL_AGENT = simple_firewall_agent.py

# Configuraciones JSON
PROMISCUOUS_CONFIG = enhanced_agent_config.json
GEOIP_CONFIG = geoip_enricher_config.json
ML_CONFIG = lightweight_ml_detector_config.json
DASHBOARD_CONFIG = dashboard_config.json
FIREWALL_CONFIG = simple_firewall_agent_config.json

# Directorios
PIDS_DIR = .pids
LOGS_DIR = logs

# Puertos (NUEVA ARQUITECTURA)
CAPTURE_PORT = 5559          # promiscuous_agent → geoip_enricher
GEOIP_PORT = 5560           # geoip_enricher → ml_detector
ML_PORT = 5561              # ml_detector → dashboard
FIREWALL_PORT = 5562        # dashboard → firewall_agent
DASHBOARD_WEB_PORT = 8000   # Web UI

# PIDs
PROMISCUOUS_PID = $(PIDS_DIR)/promiscuous_agent.pid
GEOIP_PID = $(PIDS_DIR)/geoip_enricher.pid
ML_PID = $(PIDS_DIR)/ml_detector.pid
DASHBOARD_PID = $(PIDS_DIR)/dashboard.pid
FIREWALL_PID = $(PIDS_DIR)/firewall_agent.pid

# Logs
PROMISCUOUS_LOG = $(LOGS_DIR)/promiscuous_agent.log
GEOIP_LOG = $(LOGS_DIR)/geoip_enricher.log
ML_LOG = $(LOGS_DIR)/ml_detector.log
DASHBOARD_LOG = $(LOGS_DIR)/dashboard.log
FIREWALL_LOG = $(LOGS_DIR)/firewall_agent.log

# Nuclear stop script
NUCLEAR_STOP_SCRIPT = nuclear-stop.sh

# =============================================================================
# PHONY DECLARATIONS
# =============================================================================
.PHONY: help setup install clean \
        start start-bg stop stop-nuclear restart \
        status monitor logs \
        setup-perms verify \
        show-dashboard \
        quick check-geoip

# =============================================================================
# HELP
# =============================================================================
help:
	@echo "$(CYAN)🛡️ Upgraded Happiness - SCADA Security Platform$(NC)"
	@echo "$(CYAN)================================================$(NC)"
	@echo ""
	@echo "$(YELLOW)🚀 COMANDOS PRINCIPALES:$(NC)"
	@echo "  $(GREEN)make start$(NC)           - Iniciar sistema completo (RECOMENDADO)"
	@echo "  $(GREEN)make show-dashboard$(NC)  - Abrir dashboard web"
	@echo "  $(GREEN)make stop$(NC)            - Detener sistema completo"
	@echo "  $(GREEN)make status$(NC)          - Ver estado del sistema"
	@echo ""
	@echo "$(YELLOW)📦 SETUP:$(NC)"
	@echo "  setup                 - Crear entorno virtual"
	@echo "  install               - Instalar dependencias"
	@echo "  setup-perms           - Configurar permisos (sudo)"
	@echo "  check-geoip           - Verificar configuración GeoIP"
	@echo "  clean                 - Limpiar todo"
	@echo ""
	@echo "$(YELLOW)🔄 OPERACIONES:$(NC)"
	@echo "  start-bg              - Iniciar en background"
	@echo "  restart               - Reiniciar sistema"
	@echo "  stop-nuclear          - Parada nuclear (máxima agresividad)"
	@echo "  monitor               - Monitorizar en tiempo real"
	@echo "  logs                  - Ver logs"
	@echo "  verify                - Verificar integridad"
	@echo ""
	@echo "$(YELLOW)⚡ QUICK:$(NC)"
	@echo "  quick                 - Setup + Install + Start"
	@echo ""
	@echo "$(CYAN)🏗️ ARQUITECTURA:$(NC)"
	@echo "  promiscuous_agent ($(CAPTURE_PORT)) → geoip_enricher ($(GEOIP_PORT)) → ml_detector ($(ML_PORT)) → dashboard ($(FIREWALL_PORT)) → firewall_agent"
	@echo ""
	@echo "$(CYAN)🌐 URL: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"

# =============================================================================
# SETUP
# =============================================================================
setup:
	@echo "$(BLUE)🔧 Configurando entorno virtual...$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "$(YELLOW)⚠️  Entorno virtual ya existe$(NC)"; \
	else \
		$(PYTHON) -m venv $(VENV_NAME); \
		echo "$(GREEN)✅ Entorno virtual creado$(NC)"; \
	fi
	@$(ACTIVATE) && $(PYTHON_VENV) -m pip install --upgrade pip
	@mkdir -p $(PIDS_DIR) $(LOGS_DIR)
	@echo "$(GREEN)✅ Setup completado$(NC)"

install: setup
	@echo "$(BLUE)📦 Instalando dependencias...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install -r requirements.txt
	@$(ACTIVATE) && $(PIP_VENV) install joblib scikit-learn xgboost lightgbm
	@$(ACTIVATE) && $(PIP_VENV) install zmq psutil geoip2 protobuf requests
	@$(ACTIVATE) && $(PIP_VENV) install fastapi uvicorn websockets
	@echo "$(GREEN)✅ Dependencias instaladas$(NC)"

setup-perms:
	@echo "$(BLUE)🔧 Configurando permisos de firewall...$(NC)"
	@echo "$(YELLOW)Requiere sudo para iptables$(NC)"
	@sudo bash -c 'echo "$(USER) ALL=(ALL) NOPASSWD: /sbin/iptables" >> /etc/sudoers.d/$(USER)-iptables'
	@sudo chmod 0440 /etc/sudoers.d/$(USER)-iptables
	@echo "$(GREEN)✅ Permisos configurados$(NC)"
	@sudo -n iptables -L >/dev/null && echo "$(GREEN)✅ Permisos funcionando$(NC)" || echo "$(RED)❌ Error en permisos$(NC)"

check-geoip:
	@echo "$(BLUE)🌍 Verificando configuración GeoIP...$(NC)"
	@if [ -f "GeoLite2-City.mmdb" ]; then \
		echo "  ✅ Base de datos GeoLite2 encontrada"; \
		stat -c "%y" GeoLite2-City.mmdb | sed 's/^/  📅 Última modificación: /'; \
	else \
		echo "  ⚠️  Base de datos GeoLite2 NO encontrada"; \
		echo "  💡 Se usará ip-api.com como fallback"; \
		echo "  💡 Para descargar GeoLite2: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"; \
	fi
	@echo "  🔗 Verificando conectividad con ip-api.com..."
	@curl -s --connect-timeout 3 "http://ip-api.com/json/8.8.8.8" >/dev/null && \
		echo "  ✅ ip-api.com accesible" || \
		echo "  ❌ ip-api.com no accesible"

clean:
	@echo "$(YELLOW)🧹 Limpiando...$(NC)"
	@$(MAKE) stop 2>/dev/null || true
	@rm -rf $(VENV_NAME) __pycache__ $(PIDS_DIR) $(LOGS_DIR)
	@find . -name "*.pyc" -delete
	@find . -name "*.pyo" -delete
	@echo "$(GREEN)✅ Limpieza completada$(NC)"

# =============================================================================
# SISTEMA PRINCIPAL
# =============================================================================
start: install verify check-geoip stop
	@echo "$(GREEN)🚀 Iniciando Upgraded Happiness...$(NC)"
	@echo "$(CYAN)====================================$(NC)"
	@echo ""
	@echo "$(BLUE)Iniciando componentes en orden:$(NC)"
	@echo ""

	@echo "$(BLUE)1. 🔥 Firewall Agent (Puerto $(FIREWALL_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT) $(FIREWALL_CONFIG) > $(FIREWALL_LOG) 2>&1 & echo $$! > $(FIREWALL_PID)
	@sleep 3

	@echo "$(BLUE)2. 🕵️  Promiscuous Agent (Captura → Puerto $(CAPTURE_PORT))...$(NC)"
	@sudo $(PYTHON_VENV) $(PROMISCUOUS_AGENT) $(PROMISCUOUS_CONFIG) > $(PROMISCUOUS_LOG) 2>&1 & echo $$! > $(PROMISCUOUS_PID)
	@sleep 3

	@echo "$(BLUE)3. 🌍 GeoIP Enricher (Puerto $(CAPTURE_PORT) → $(GEOIP_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(GEOIP_ENRICHER) $(GEOIP_CONFIG) > $(GEOIP_LOG) 2>&1 & echo $$! > $(GEOIP_PID)
	@sleep 3

	@echo "$(BLUE)4. 🤖 ML Detector (Puerto $(GEOIP_PORT) → $(ML_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) $(ML_CONFIG) > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@sleep 3

	@echo "$(BLUE)5. 📊 Dashboard (Puerto $(ML_PORT) → UI → $(FIREWALL_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD) $(DASHBOARD_CONFIG) > $(DASHBOARD_LOG) 2>&1 & echo $$! > $(DASHBOARD_PID)
	@sleep 3

	@echo ""
	@echo "$(GREEN)🎉 SISTEMA OPERACIONAL$(NC)"
	@echo "$(CYAN)========================$(NC)"
	@echo "$(YELLOW)📊 Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"
	@echo "$(YELLOW)🔥 Firewall: Puerto $(FIREWALL_PORT)$(NC)"
	@echo "$(YELLOW)📡 Captura: Activa$(NC)"
	@echo "$(YELLOW)🌍 GeoIP: Activo$(NC)"
	@echo "$(YELLOW)🤖 ML: Activo$(NC)"
	@echo "$(YELLOW)🛡️  Auto-respuesta: Activa$(NC)"
	@echo ""
	@echo "$(PURPLE)💡 Haz click en eventos de alto riesgo para bloquear IPs$(NC)"
	@$(MAKE) status

start-bg: install verify check-geoip stop
	@echo "$(GREEN)🚀 Iniciando sistema (background)...$(NC)"
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(FIREWALL_AGENT) $(FIREWALL_CONFIG) > $(FIREWALL_LOG) 2>&1 & echo $$! > $(FIREWALL_PID)
	@sleep 2
	@sudo nohup $(PYTHON_VENV) $(PROMISCUOUS_AGENT) $(PROMISCUOUS_CONFIG) > $(PROMISCUOUS_LOG) 2>&1 & echo $$! > $(PROMISCUOUS_PID)
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(GEOIP_ENRICHER) $(GEOIP_CONFIG) > $(GEOIP_LOG) 2>&1 & echo $$! > $(GEOIP_PID)
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(ML_DETECTOR) $(ML_CONFIG) > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(DASHBOARD) $(DASHBOARD_CONFIG) > $(DASHBOARD_LOG) 2>&1 & echo $$! > $(DASHBOARD_PID)
	@echo "$(GREEN)✅ Sistema iniciado en background$(NC)"
	@echo "$(YELLOW)Dashboard: http://localhost:$(DASHBOARD_WEB_PORT)$(NC)"

stop:
	@echo "$(YELLOW)🛑 Deteniendo sistema...$(NC)"
	@echo "$(BLUE)Deteniendo en orden inverso...$(NC)"

	# 5. Dashboard (último en iniciar, primero en parar)
	@-pkill -f "$(DASHBOARD)" 2>/dev/null || true
	@-if [ -f $(DASHBOARD_PID) ]; then kill $$(cat $(DASHBOARD_PID)) 2>/dev/null || true; rm -f $(DASHBOARD_PID); fi
	@sleep 1

	# 4. ML Detector
	@-pkill -f "$(ML_DETECTOR)" 2>/dev/null || true
	@-if [ -f $(ML_PID) ]; then kill $$(cat $(ML_PID)) 2>/dev/null || true; rm -f $(ML_PID); fi
	@sleep 1

	# 3. GeoIP Enricher
	@-pkill -f "$(GEOIP_ENRICHER)" 2>/dev/null || true
	@-if [ -f $(GEOIP_PID) ]; then kill $$(cat $(GEOIP_PID)) 2>/dev/null || true; rm -f $(GEOIP_PID); fi
	@sleep 1

	# 2. Promiscuous Agent (needs sudo)
	@-pkill -f "$(PROMISCUOUS_AGENT)" 2>/dev/null || true
	@-sudo pkill -f "$(PROMISCUOUS_AGENT)" 2>/dev/null || true
	@-if [ -f $(PROMISCUOUS_PID) ]; then kill $$(cat $(PROMISCUOUS_PID)) 2>/dev/null || true; rm -f $(PROMISCUOUS_PID); fi
	@sleep 1

	# 1. Firewall Agent (primero en iniciar, último en parar)
	@-pkill -f "$(FIREWALL_AGENT)" 2>/dev/null || true
	@-if [ -f $(FIREWALL_PID) ]; then kill $$(cat $(FIREWALL_PID)) 2>/dev/null || true; rm -f $(FIREWALL_PID); fi

	@echo "$(GREEN)✅ Sistema detenido$(NC)"

stop-nuclear:
	@echo "$(RED)🚨 Ejecutando parada nuclear...$(NC)"
	@if [ -f $(NUCLEAR_STOP_SCRIPT) ]; then \
		chmod +x $(NUCLEAR_STOP_SCRIPT); \
		./$(NUCLEAR_STOP_SCRIPT); \
	else \
		echo "$(YELLOW)⚠️ nuclear-stop.sh no encontrado, usando parada básica$(NC)"; \
		pkill -f "python.*upgraded_happiness" 2>/dev/null || true; \
		pkill -f "python.*$(PROMISCUOUS_AGENT)" 2>/dev/null || true; \
		pkill -f "python.*$(GEOIP_ENRICHER)" 2>/dev/null || true; \
		pkill -f "python.*$(ML_DETECTOR)" 2>/dev/null || true; \
		pkill -f "python.*$(DASHBOARD)" 2>/dev/null || true; \
		pkill -f "python.*$(FIREWALL_AGENT)" 2>/dev/null || true; \
		sudo pkill -f "python.*$(PROMISCUOUS_AGENT)" 2>/dev/null || true; \
		rm -f $(PIDS_DIR)/*.pid; \
		echo "$(GREEN)✅ Parada nuclear completada$(NC)"; \
	fi

restart: stop
	@sleep 3
	@$(MAKE) start

# =============================================================================
# MONITORIZACIÓN
# =============================================================================
status:
	@echo "$(CYAN)📊 Estado del Sistema$(NC)"
	@echo "$(CYAN)=====================$(NC)"
	@echo "$(YELLOW)Componentes:$(NC)"
	@pgrep -f "$(FIREWALL_AGENT)" >/dev/null && echo "  🔥 Firewall Agent: Ejecutándose" || echo "  ⭕ Firewall Agent: Detenido"
	@pgrep -f "$(PROMISCUOUS_AGENT)" >/dev/null && echo "  🕵️  Promiscuous Agent: Ejecutándose" || echo "  ⭕ Promiscuous Agent: Detenido"
	@pgrep -f "$(GEOIP_ENRICHER)" >/dev/null && echo "  🌍 GeoIP Enricher: Ejecutándose" || echo "  ⭕ GeoIP Enricher: Detenido"
	@pgrep -f "$(ML_DETECTOR)" >/dev/null && echo "  🤖 ML Detector: Ejecutándose" || echo "  ⭕ ML Detector: Detenido"
	@pgrep -f "$(DASHBOARD)" >/dev/null && echo "  📊 Dashboard: Ejecutándose (http://localhost:$(DASHBOARD_WEB_PORT))" || echo "  ⭕ Dashboard: Detenido"
	@echo ""
	@echo "$(YELLOW)Puertos:$(NC)"
	@lsof -i :$(CAPTURE_PORT) >/dev/null 2>&1 && echo "  📡 Puerto Captura ($(CAPTURE_PORT)): ACTIVO" || echo "  ⭕ Puerto Captura ($(CAPTURE_PORT)): INACTIVO"
	@lsof -i :$(GEOIP_PORT) >/dev/null 2>&1 && echo "  🌍 Puerto GeoIP ($(GEOIP_PORT)): ACTIVO" || echo "  ⭕ Puerto GeoIP ($(GEOIP_PORT)): INACTIVO"
	@lsof -i :$(ML_PORT) >/dev/null 2>&1 && echo "  🤖 Puerto ML ($(ML_PORT)): ACTIVO" || echo "  ⭕ Puerto ML ($(ML_PORT)): INACTIVO"
	@lsof -i :$(FIREWALL_PORT) >/dev/null 2>&1 && echo "  🔥 Puerto Firewall ($(FIREWALL_PORT)): ACTIVO" || echo "  ⭕ Puerto Firewall ($(FIREWALL_PORT)): INACTIVO"
	@lsof -i :$(DASHBOARD_WEB_PORT) >/dev/null 2>&1 && echo "  📊 Puerto Dashboard ($(DASHBOARD_WEB_PORT)): ACTIVO" || echo "  ⭕ Puerto Dashboard ($(DASHBOARD_WEB_PORT)): INACTIVO"

monitor:
	@echo "$(CYAN)📊 Monitor del Sistema$(NC)"
	@echo "$(CYAN)=======================$(NC)"
	@$(MAKE) status
	@echo ""
	@echo "$(YELLOW)Actividad Reciente:$(NC)"
	@if [ -f $(FIREWALL_LOG) ]; then echo "🔥 Firewall:"; tail -3 $(FIREWALL_LOG) | sed 's/^/  /'; echo ""; fi
	@if [ -f $(GEOIP_LOG) ]; then echo "🌍 GeoIP:"; tail -3 $(GEOIP_LOG) | sed 's/^/  /'; echo ""; fi
	@if [ -f $(ML_LOG) ]; then echo "🤖 ML:"; tail -3 $(ML_LOG) | sed 's/^/  /'; echo ""; fi
	@if [ -f $(DASHBOARD_LOG) ]; then echo "📊 Dashboard:"; tail -3 $(DASHBOARD_LOG) | sed 's/^/  /'; fi

logs:
	@echo "$(CYAN)📋 Logs del Sistema$(NC)"
	@echo "$(CYAN)====================$(NC)"
	@if [ -f $(FIREWALL_LOG) ]; then echo "=== 🔥 Firewall Agent ==="; tail -10 $(FIREWALL_LOG); echo ""; fi
	@if [ -f $(PROMISCUOUS_LOG) ]; then echo "=== 🕵️  Promiscuous Agent ==="; tail -10 $(PROMISCUOUS_LOG); echo ""; fi
	@if [ -f $(GEOIP_LOG) ]; then echo "=== 🌍 GeoIP Enricher ==="; tail -10 $(GEOIP_LOG); echo ""; fi
	@if [ -f $(ML_LOG) ]; then echo "=== 🤖 ML Detector ==="; tail -10 $(ML_LOG); echo ""; fi
	@if [ -f $(DASHBOARD_LOG) ]; then echo "=== 📊 Dashboard ==="; tail -10 $(DASHBOARD_LOG); fi

# =============================================================================
# VERIFICACIÓN Y UTILIDADES
# =============================================================================
verify:
	@echo "$(BLUE)🔍 Verificando integridad del sistema...$(NC)"
	@for file in $(PROMISCUOUS_AGENT) $(GEOIP_ENRICHER) $(ML_DETECTOR) $(DASHBOARD) $(FIREWALL_AGENT); do \
		if [ -f "$$file" ]; then \
			echo "  ✅ $$file"; \
		else \
			echo "  ❌ $$file falta"; \
		fi \
	done
	@echo "$(BLUE)Verificando configuraciones...$(NC)"
	@for config in $(PROMISCUOUS_CONFIG) $(GEOIP_CONFIG) $(ML_CONFIG) $(DASHBOARD_CONFIG) $(FIREWALL_CONFIG); do \
		if [ -f "$$config" ]; then \
			echo "  ✅ $$config"; \
		else \
			echo "  ❌ $$config falta"; \
		fi \
	done
	@echo "$(BLUE)Verificando permisos...$(NC)"
	@sudo -n iptables -L >/dev/null 2>&1 && echo "  ✅ Permisos firewall OK" || echo "  ❌ Permisos firewall faltan (ejecutar: make setup-perms)"

show-dashboard:
	@echo "$(BLUE)🌐 Abriendo dashboard...$(NC)"
	@which open >/dev/null && open http://localhost:$(DASHBOARD_WEB_PORT) || \
	 which xdg-open >/dev/null && xdg-open http://localhost:$(DASHBOARD_WEB_PORT) || \
	 echo "💡 Abrir manualmente: http://localhost:$(DASHBOARD_WEB_PORT)"

# =============================================================================
# COMANDOS RÁPIDOS
# =============================================================================
quick: setup install start show-dashboard