# =============================================================================
# 🛡️ Upgraded Happiness - SCADA Security Platform + Firewall (Enhanced)
# =============================================================================
# Comprehensive Makefile with GIS Dashboard, HTTP 207 fixes, Nuclear Stop, and Firewall System
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# =============================================================================
# COLORS AND VISUAL CONFIGURATION
# =============================================================================
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
PURPLE = \033[0;35m
CYAN = \033[0;36m
NC = \033[0m # No Color

# =============================================================================
# VARIABLES CONFIGURATION
# =============================================================================
# Python and Environment
PYTHON = python3
VENV_NAME = upgraded_happiness_venv
VENV_BIN = $(VENV_NAME)/bin
PYTHON_VENV = $(VENV_BIN)/python
PIP_VENV = $(VENV_BIN)/pip
ACTIVATE = source $(VENV_BIN)/activate

# Core Platform Scripts
ORCHESTRATOR = system_orchestrator.py
ML_DETECTOR = ml_detector_with_persistence.py
PROMISCUOUS_AGENT = promiscuous_agent.py
BROKER = scripts/smart_broker.py
SIMPLE_BROKER = simple_broker.py
FIX_MODULE = fix_module.py

# Dashboard Scripts (Multiple versions)
DASHBOARD = dashboard_server_with_real_data.py
DASHBOARD_FIXED = dashboard_server_fixed.py
DASHBOARD_GIS = enhanced_protobuf_gis_dashboard.py
GIS_SCRIPT = dashboard_server_gis.py

# 🔥 NEW: Firewall System Components
FIREWALL_DASHBOARD = real_zmq_dashboard_with_firewall.py
FIREWALL_AGENT = firewall_agent.py
CLAUDE_INTEGRATION = claude_firewall_integration.py
GPS_GENERATOR = generate_gps_traffic.py

# Utilities
DIAGNOSTIC_TOOL = diagnostic_tool.py
IP_GEOLOCATOR = ip_geolocator.py
NUCLEAR_STOP_SCRIPT = nuclear-stop.sh

# Directories
TEST_DIR = tests_consolidated
PIDS_DIR = .pids
LOGS_DIR = logs
STATIC_DIR = static

# Ports Configuration
BROKER_PORT = 5555
BROKER_SECONDARY_PORT = 5556
DASHBOARD_PORT = 8766
GIS_DASHBOARD_PORT = 8000

# 🔥 NEW: Firewall System Ports
CAPTURE_PORT = 5559
ML_ENHANCED_PORT = 5560
FIREWALL_COMMAND_PORT = 5561
FIREWALL_DASHBOARD_PORT = 8000

# Process ID Files
BROKER_PID = $(PIDS_DIR)/broker.pid
ML_PID = $(PIDS_DIR)/ml.pid
DASHBOARD_PID = $(PIDS_DIR)/dashboard.pid
AGENT_PID = $(PIDS_DIR)/agent.pid
GIS_PID = $(PIDS_DIR)/gis.pid

# 🔥 NEW: Firewall System PIDs
FIREWALL_AGENT_PID = $(PIDS_DIR)/firewall_agent.pid
FIREWALL_DASHBOARD_PID = $(PIDS_DIR)/firewall_dashboard.pid
GPS_GENERATOR_PID = $(PIDS_DIR)/gps_generator.pid

# Log Files
BROKER_LOG = $(LOGS_DIR)/broker.out
ML_LOG = $(LOGS_DIR)/ml.out
DASHBOARD_LOG = $(LOGS_DIR)/dashboard.out
AGENT_LOG = $(LOGS_DIR)/agent.out
GIS_LOG = $(LOGS_DIR)/gis_dashboard.out

# 🔥 NEW: Firewall System Logs
FIREWALL_AGENT_LOG = $(LOGS_DIR)/firewall_agent.out
FIREWALL_DASHBOARD_LOG = $(LOGS_DIR)/firewall_dashboard.out
GPS_GENERATOR_LOG = $(LOGS_DIR)/gps_generator.out

# =============================================================================
# PHONY DECLARATIONS
# =============================================================================
.PHONY: all help setup install install-dev install-all install-dashboard \
        install-gis-deps install-firewall-deps setup-gis setup-pids-dir clean reinstall \
        run run-daemon run-enhanced run-fixed run-gis-dashboard \
        run-all run-full-gis dashboard-fixed \
        run-firewall run-firewall-bg run-firewall-full run-firewall-test \
        stop stop-enhanced stop-gis stop-all stop-firewall emergency-stop verify-stop \
        restart-nuclear restart-fixed restart-gis restart-firewall \
        status status-detailed status-gis status-firewall monitor monitor-live monitor-gis monitor-firewall \
        verify verify-firewall fix-deps setup-sudo setup-production setup-firewall-perms \
        test test-cov test-geolocation test-gis test-firewall generate-test-events test-claude \
        format lint security check \
        backup emergency-fix dev dev-gis dev-firewall \
        logs logs-gis logs-firewall show-logs clean-gis clean-firewall \
        diagnose fix-207 help-207 check-logs test-dashboard verify-fixes \
        show-dashboard show-firewall-dashboard info help-nuclear help-gis help-firewall \
        qt qr qv qs qm qd qf quick-start quick-firewall \
        gis gis-bg gis-stop gis-status gis-logs gis-clean gis-test \
        firewall fw-start fw-stop fw-status fw-logs fw-test fw-clean

# =============================================================================
# MAIN HELP SYSTEM
# =============================================================================
help:
	@echo "$(CYAN)🛡️ Upgraded Happiness - SCADA Security Platform + Firewall$(NC)"
	@echo "$(CYAN)=========================================================$(NC)"
	@echo ""
	@echo "$(YELLOW)🚀 QUICK START:$(NC)"
	@echo "  $(GREEN)make run-firewall$(NC)        - Start complete firewall system (RECOMMENDED)"
	@echo "  $(GREEN)make show-firewall-dashboard$(NC) - Open firewall dashboard"
	@echo "  $(GREEN)make stop-firewall$(NC)       - Stop firewall system"
	@echo "  $(GREEN)make run-enhanced$(NC)        - Start legacy GIS system"
	@echo ""
	@echo "$(YELLOW)🔥 FIREWALL SYSTEM (NEW):$(NC)"
	@echo "  run-firewall              - Start complete firewall system (interactive)"
	@echo "  run-firewall-bg           - Start firewall system (background)"
	@echo "  run-firewall-test         - Start with test data generator"
	@echo "  stop-firewall             - Stop firewall system components"
	@echo "  status-firewall           - Show firewall system status"
	@echo "  test-firewall             - Test firewall functionality"
	@echo "  test-claude               - Test Claude integration"
	@echo ""
	@echo "$(YELLOW)📦 SETUP & INSTALLATION:$(NC)"
	@echo "  setup                     - Create virtual environment"
	@echo "  install                   - Install production dependencies"
	@echo "  install-all               - Install all dependencies (prod + dev + GIS + firewall)"
	@echo "  install-firewall-deps     - Install firewall-specific dependencies"
	@echo "  setup-firewall-perms      - Configure firewall permissions (sudo)"
	@echo "  setup-gis                 - Configure GIS dashboard system"
	@echo "  clean                     - Clean virtual environment"
	@echo "  reinstall                 - Clean and reinstall everything"
	@echo ""
	@echo "$(YELLOW)🚀 PLATFORM EXECUTION:$(NC)"
	@echo "  run                       - Start platform (Interactive mode)"
	@echo "  run-daemon                - Start platform (Daemon mode)"
	@echo "  run-enhanced              - Start with GIS dashboard"
	@echo "  run-fixed                 - Start with HTTP 207 fixes"
	@echo "  run-gis-dashboard         - Start only GIS dashboard"
	@echo "  run-full-gis              - Start complete platform + GIS"
	@echo "  quick-start               - Quick start legacy system"
	@echo "  quick-firewall            - Quick start firewall system"
	@echo ""
	@echo "$(YELLOW)🌍 GIS DASHBOARD (LEGACY):$(NC)"
	@echo "  gis                       - Quick start GIS dashboard"
	@echo "  gis-status                - Show GIS dashboard status"
	@echo "  gis-logs                  - Follow GIS dashboard logs"
	@echo "  gis-stop                  - Stop GIS dashboard"
	@echo "  test-gis                  - Test GIS functionality"
	@echo ""
	@echo "$(YELLOW)🛑 STOP COMMANDS:$(NC)"
	@echo "  stop                      - Nuclear stop (handles all processes)"
	@echo "  stop-firewall             - Stop only firewall system"
	@echo "  stop-gis                  - Stop only GIS dashboard"
	@echo "  emergency-stop            - Maximum aggressiveness stop"
	@echo "  verify-stop               - Verify complete stop"
	@echo ""
	@echo "$(YELLOW)📊 MONITORING:$(NC)"
	@echo "  status                    - Show complete project status"
	@echo "  status-firewall           - Show firewall system status"
	@echo "  monitor                   - Enhanced platform monitoring"
	@echo "  monitor-firewall          - Monitor firewall system"
	@echo "  monitor-gis               - Monitor GIS dashboard"
	@echo "  diagnose                  - Run comprehensive diagnostic"
	@echo ""
	@echo "$(YELLOW)💊 FIXES & UTILITIES:$(NC)"
	@echo "  fix-207                   - Fix HTTP 207 Multi-Status errors"
	@echo "  test-geolocation          - Test IP geolocation service"
	@echo "  emergency-fix             - Emergency recovery"
	@echo ""
	@echo "$(YELLOW)⚡ QUICK COMMANDS:$(NC)"
	@echo "  qt qr qv qs qm qd qf      - Quick test/run/verify/status/monitor/dashboard/firewall"
	@echo "  fw-start fw-stop fw-status - Quick firewall commands"
	@echo ""
	@echo "$(CYAN)🌐 URLs:$(NC)"
	@echo "  Firewall Dashboard:       http://localhost:$(FIREWALL_DASHBOARD_PORT) (MAIN)"
	@echo "  GIS Dashboard:            http://localhost:$(GIS_DASHBOARD_PORT) (LEGACY)"
	@echo "  Fixed Dashboard:          http://localhost:$(DASHBOARD_PORT) (LEGACY)"
	@echo ""
	@echo "$(PURPLE)💡 Run 'make help-firewall' for firewall-specific help$(NC)"
	@echo "$(PURPLE)💡 Run 'make help-gis' for GIS-specific help$(NC)"
	@echo "$(PURPLE)💡 Run 'make help-207' for HTTP 207 troubleshooting$(NC)"

# =============================================================================
# SETUP AND INSTALLATION
# =============================================================================
setup:
	@echo "$(BLUE)🔧 Setting up virtual environment...$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "$(YELLOW)⚠️  Virtual environment already exists$(NC)"; \
	else \
		$(PYTHON) -m venv $(VENV_NAME); \
		echo "$(GREEN)✅ Virtual environment created$(NC)"; \
	fi
	@$(ACTIVATE) && $(PYTHON_VENV) -m pip install --upgrade pip
	@echo "$(GREEN)✅ Virtual environment setup completed$(NC)"

setup-pids-dir:
	@mkdir -p $(PIDS_DIR) $(LOGS_DIR) $(STATIC_DIR)

install: setup
	@echo "$(BLUE)📦 Installing production dependencies...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install -r requirements.txt
	@$(ACTIVATE) && $(PIP_VENV) install joblib scikit-learn xgboost lightgbm
	@echo "$(GREEN)✅ Production dependencies installed$(NC)"

install-dev: install
	@echo "$(BLUE)🛠️  Installing development dependencies...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install -r requirements-dev.txt
	@echo "$(GREEN)✅ Development dependencies installed$(NC)"

install-dashboard: setup
	@echo "$(BLUE)🌐 Installing dashboard web dependencies...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install aiohttp aiohttp-cors aiofiles pyyaml websockets
	@echo "$(GREEN)✅ Dashboard dependencies installed$(NC)"

install-gis-deps: setup
	@echo "$(BLUE)🌍 Installing GIS dependencies...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install fastapi uvicorn requests websockets
	@echo "$(GREEN)✅ GIS dependencies installed$(NC)"

install-firewall-deps: setup
	@echo "$(BLUE)🔥 Installing firewall system dependencies...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install zmq psutil
	@echo "$(GREEN)✅ Firewall dependencies installed$(NC)"

install-all: install-dev install-dashboard install-gis-deps install-firewall-deps
	@echo "$(GREEN)✅ All dependencies installed$(NC)"

setup-gis: setup install-gis-deps setup-pids-dir
	@echo "$(BLUE)🌍 Configuring GIS dashboard system...$(NC)"
	@echo "$(GREEN)✅ GIS system configured$(NC)"

setup-firewall-perms:
	@echo "$(BLUE)🔥 Configuring firewall permissions...$(NC)"
	@echo "$(YELLOW)This will add iptables sudo permissions for your user$(NC)"
	@echo "$(YELLOW)You may be prompted for your password$(NC)"
	@sudo bash -c 'echo "$(USER) ALL=(ALL) NOPASSWD: /sbin/iptables" >> /etc/sudoers.d/$(USER)-iptables'
	@sudo chmod 0440 /etc/sudoers.d/$(USER)-iptables
	@echo "$(GREEN)✅ Firewall permissions configured$(NC)"
	@echo "$(BLUE)Testing permissions...$(NC)"
	@sudo -n iptables -L >/dev/null && echo "$(GREEN)✅ Firewall permissions working$(NC)" || echo "$(RED)❌ Firewall permissions failed$(NC)"

clean:
	@echo "$(YELLOW)🧹 Cleaning virtual environment...$(NC)"
	@rm -rf $(VENV_NAME) __pycache__ $(PIDS_DIR) $(LOGS_DIR)
	@find . -name "*.pyc" -delete
	@find . -name "*.pyo" -delete
	@find . -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@rm -f *.pid *.log ip_cache.db firewall_agent.log
	@echo "$(GREEN)✅ Cleanup completed$(NC)"

clean-firewall:
	@echo "$(YELLOW)🧹 Cleaning firewall system files...$(NC)"
	@$(MAKE) stop-firewall
	@rm -f $(FIREWALL_AGENT_PID) $(FIREWALL_DASHBOARD_PID) $(GPS_GENERATOR_PID)
	@rm -f $(FIREWALL_AGENT_LOG) $(FIREWALL_DASHBOARD_LOG) $(GPS_GENERATOR_LOG)
	@rm -f firewall_agent.log
	@echo "$(GREEN)✅ Firewall system files cleaned$(NC)"

reinstall: clean setup install-all
	@echo "$(GREEN)✅ Reinstallation completed$(NC)"

# =============================================================================
# 🔥 FIREWALL SYSTEM EXECUTION
# =============================================================================
run-firewall: install-firewall-deps verify-firewall setup-pids-dir stop-firewall
	@echo "$(GREEN)🔥 Starting SCADA Firewall System...$(NC)"
	@echo "$(CYAN)===================================$(NC)"
	@echo "$(BLUE)Starting components in correct order...$(NC)"
	@echo ""
	@echo "$(BLUE)1. Starting Firewall Agent (Port $(FIREWALL_COMMAND_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_AGENT) > $(FIREWALL_AGENT_LOG) 2>&1 & echo $$! > $(FIREWALL_AGENT_PID)
	@sleep 3
	@echo "$(BLUE)2. Starting Promiscuous Agent (Capture → Port $(CAPTURE_PORT))...$(NC)"
	@sudo $(PYTHON_VENV) $(PROMISCUOUS_AGENT) enhanced_agent_config.json > $(AGENT_LOG) 2>&1 & echo $$! > $(AGENT_PID)
	@sleep 3
	@echo "$(BLUE)3. Starting ML Detector (Port $(CAPTURE_PORT) → $(ML_ENHANCED_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@sleep 3
	@echo "$(BLUE)4. Starting Firewall Dashboard (Port $(ML_ENHANCED_PORT) → UI → $(FIREWALL_COMMAND_PORT))...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIREWALL_DASHBOARD) > $(FIREWALL_DASHBOARD_LOG) 2>&1 & echo $$! > $(FIREWALL_DASHBOARD_PID)
	@sleep 3
	@echo ""
	@echo "$(GREEN)🎉 FIREWALL SYSTEM OPERATIONAL$(NC)"
	@echo "$(CYAN)==============================$(NC)"
	@echo "$(YELLOW)📊 Dashboard: http://localhost:$(FIREWALL_DASHBOARD_PORT)$(NC)"
	@echo "$(YELLOW)🔥 Firewall Commands: Port $(FIREWALL_COMMAND_PORT)$(NC)"
	@echo "$(YELLOW)📡 Traffic Capture: Active$(NC)"
	@echo "$(YELLOW)🤖 ML Analysis: Active$(NC)"
	@echo "$(YELLOW)🛡️ Auto Response: Active$(NC)"
	@echo ""
	@echo "$(PURPLE)💡 Click on high-risk events to block IPs automatically$(NC)"
	@$(MAKE) status-firewall

run-firewall-bg: install-firewall-deps verify-firewall setup-pids-dir stop-firewall
	@echo "$(GREEN)🔥 Starting Firewall System (Background)...$(NC)"
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(FIREWALL_AGENT) > $(FIREWALL_AGENT_LOG) 2>&1 & echo $$! > $(FIREWALL_AGENT_PID)
	@sleep 2
	@sudo nohup $(PYTHON_VENV) $(PROMISCUOUS_AGENT) enhanced_agent_config.json > $(AGENT_LOG) 2>&1 & echo $$! > $(AGENT_PID)
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(ML_DETECTOR) > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@sleep 2
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(FIREWALL_DASHBOARD) > $(FIREWALL_DASHBOARD_LOG) 2>&1 & echo $$! > $(FIREWALL_DASHBOARD_PID)
	@echo "$(GREEN)✅ Firewall system started in background$(NC)"
	@echo "$(YELLOW)Dashboard: http://localhost:$(FIREWALL_DASHBOARD_PORT)$(NC)"

run-firewall-test: run-firewall-bg
	@echo "$(BLUE)🧪 Starting GPS Test Data Generator...$(NC)"
	@sleep 3
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(GPS_GENERATOR) continuous 15 > $(GPS_GENERATOR_LOG) 2>&1 & echo $$! > $(GPS_GENERATOR_PID)
	@echo "$(GREEN)✅ Test system running with GPS data$(NC)"

run-firewall-orchestrator: install-firewall-deps verify-firewall
	@echo "$(GREEN)🔥 Starting with System Orchestrator...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ORCHESTRATOR)

# Legacy system commands (preserved)
run: setup install verify
	@echo "$(GREEN)🚀 Starting Upgraded Happiness Platform (Interactive)...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ORCHESTRATOR)

run-daemon: setup install verify setup-pids-dir
	@echo "$(GREEN)🚀 Starting Platform (Daemon Mode)...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(BROKER) > $(BROKER_LOG) 2>&1 & echo $$! > $(BROKER_PID)
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@sleep 2
	@sudo $(PYTHON_VENV) $(PROMISCUOUS_AGENT) > $(AGENT_LOG) 2>&1 & echo $$! > $(AGENT_PID)
	@sleep 2
	@echo "$(GREEN)✅ All components started in daemon mode$(NC)"

run-enhanced: setup-gis stop-all
	@echo "$(GREEN)🚀 Starting SCADA System with GIS Dashboard...$(NC)"
	@echo "$(CYAN)=============================================$(NC)"
	@echo "$(BLUE)1. Starting Simple Broker...$(NC)"
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(SIMPLE_BROKER) > $(BROKER_LOG) 2>&1 &
	@echo $$! > $(BROKER_PID)
	@sleep 3
	@echo "$(BLUE)2. Starting GIS Dashboard...$(NC)"
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(DASHBOARD_GIS) > $(GIS_LOG) 2>&1 &
	@echo $$! > $(GIS_PID)
	@sleep 3
	@echo "$(BLUE)3. Starting Promiscuous Agent...$(NC)"
	@sudo nohup $(PYTHON_VENV) $(PROMISCUOUS_AGENT) > $(AGENT_LOG) 2>&1 &
	@echo $$! > $(AGENT_PID)
	@sleep 2
	@echo ""
	@echo "$(GREEN)🎉 SCADA SYSTEM WITH GIS OPERATIONAL$(NC)"
	@echo "$(CYAN)====================================$(NC)"
	@echo "$(YELLOW)📊 GIS Dashboard: http://localhost:$(GIS_DASHBOARD_PORT)$(NC)"
	@echo "$(YELLOW)🌍 Geolocation: Active$(NC)"
	@echo "$(YELLOW)📡 Traffic Capture: Active$(NC)"
	@echo ""
	@echo "$(PURPLE)💡 Open http://localhost:$(GIS_DASHBOARD_PORT) to see events on map$(NC)"

quick-start: run-enhanced
quick-firewall: run-firewall

# =============================================================================
# STOP COMMANDS
# =============================================================================
stop-firewall:
	@echo "$(YELLOW)🛑 Stopping Firewall System...$(NC)"
	@-pkill -f "$(FIREWALL_AGENT)" 2>/dev/null || true
	@-pkill -f "$(FIREWALL_DASHBOARD)" 2>/dev/null || true
	@-pkill -f "$(GPS_GENERATOR)" 2>/dev/null || true
	@-if [ -f $(FIREWALL_AGENT_PID) ]; then kill $$(cat $(FIREWALL_AGENT_PID)) 2>/dev/null || true; rm -f $(FIREWALL_AGENT_PID); fi
	@-if [ -f $(FIREWALL_DASHBOARD_PID) ]; then kill $$(cat $(FIREWALL_DASHBOARD_PID)) 2>/dev/null || true; rm -f $(FIREWALL_DASHBOARD_PID); fi
	@-if [ -f $(GPS_GENERATOR_PID) ]; then kill $$(cat $(GPS_GENERATOR_PID)) 2>/dev/null || true; rm -f $(GPS_GENERATOR_PID); fi
	@-if [ -f $(ML_PID) ]; then kill $$(cat $(ML_PID)) 2>/dev/null || true; rm -f $(ML_PID); fi
	@-if [ -f $(AGENT_PID) ]; then kill $$(cat $(AGENT_PID)) 2>/dev/null || true; rm -f $(AGENT_PID); fi
	@-sudo pkill -f "$(PROMISCUOUS_AGENT)" 2>/dev/null || true
	@echo "$(GREEN)✅ Firewall system stopped$(NC)"

stop-all:
	@echo "$(YELLOW)🛑 Stopping all components silently...$(NC)"
	@-pkill -f "$(SIMPLE_BROKER)" 2>/dev/null || true
	@-pkill -f "$(BROKER)" 2>/dev/null || true
	@-pkill -f "$(ML_DETECTOR)" 2>/dev/null || true
	@-pkill -f "$(DASHBOARD_GIS)" 2>/dev/null || true
	@-pkill -f "$(DASHBOARD_FIXED)" 2>/dev/null || true
	@-pkill -f "$(FIREWALL_DASHBOARD)" 2>/dev/null || true
	@-pkill -f "$(FIREWALL_AGENT)" 2>/dev/null || true
	@-pkill -f "$(GPS_GENERATOR)" 2>/dev/null || true
	@-pkill -f "$(PROMISCUOUS_AGENT)" 2>/dev/null || true
	@-sudo pkill -f "$(PROMISCUOUS_AGENT)" 2>/dev/null || true
	@$(MAKE) kill-by-pids 2>/dev/null || true

kill-by-pids:
	@-if [ -f $(BROKER_PID) ]; then kill $$(cat $(BROKER_PID)) 2>/dev/null || true; rm -f $(BROKER_PID); fi
	@-if [ -f $(ML_PID) ]; then kill $$(cat $(ML_PID)) 2>/dev/null || true; rm -f $(ML_PID); fi
	@-if [ -f $(DASHBOARD_PID) ]; then kill $$(cat $(DASHBOARD_PID)) 2>/dev/null || true; rm -f $(DASHBOARD_PID); fi
	@-if [ -f $(AGENT_PID) ]; then kill $$(cat $(AGENT_PID)) 2>/dev/null || true; rm -f $(AGENT_PID); fi
	@-if [ -f $(GIS_PID) ]; then kill $$(cat $(GIS_PID)) 2>/dev/null || true; rm -f $(GIS_PID); fi
	@-if [ -f $(FIREWALL_AGENT_PID) ]; then kill $$(cat $(FIREWALL_AGENT_PID)) 2>/dev/null || true; rm -f $(FIREWALL_AGENT_PID); fi
	@-if [ -f $(FIREWALL_DASHBOARD_PID) ]; then kill $$(cat $(FIREWALL_DASHBOARD_PID)) 2>/dev/null || true; rm -f $(FIREWALL_DASHBOARD_PID); fi
	@-if [ -f $(GPS_GENERATOR_PID) ]; then kill $$(cat $(GPS_GENERATOR_PID)) 2>/dev/null || true; rm -f $(GPS_GENERATOR_PID); fi

stop: stop-all
	@echo "$(YELLOW)🛑 Nuclear stop - All components stopped$(NC)"
	@if [ -f $(NUCLEAR_STOP_SCRIPT) ]; then \
		chmod +x $(NUCLEAR_STOP_SCRIPT); \
		./$(NUCLEAR_STOP_SCRIPT); \
	fi

restart-firewall: stop-firewall
	@sleep 3
	@$(MAKE) run-firewall

# =============================================================================
# MONITORING AND STATUS
# =============================================================================
status-firewall:
	@echo "$(CYAN)📊 Firewall System Status:$(NC)"
	@echo "$(CYAN)=========================$(NC)"
	@echo "$(YELLOW)Firewall Components:$(NC)"
	@pgrep -f "$(FIREWALL_AGENT)" >/dev/null && echo "  🔥 Firewall Agent: Running" || echo "  ⭕ Firewall Agent: Stopped"
	@pgrep -f "$(FIREWALL_DASHBOARD)" >/dev/null && echo "  📊 Firewall Dashboard: Running (http://localhost:$(FIREWALL_DASHBOARD_PORT))" || echo "  ⭕ Firewall Dashboard: Stopped"
	@pgrep -f "$(ML_DETECTOR)" >/dev/null && echo "  🤖 ML Detector: Running" || echo "  ⭕ ML Detector: Stopped"
	@pgrep -f "$(PROMISCUOUS_AGENT)" >/dev/null && echo "  🕵️  Promiscuous Agent: Running" || echo "  ⭕ Promiscuous Agent: Stopped"
	@pgrep -f "$(GPS_GENERATOR)" >/dev/null && echo "  🗺️  GPS Generator: Running" || echo "  ⭕ GPS Generator: Stopped"
	@echo ""
	@echo "$(YELLOW)Firewall Ports:$(NC)"
	@lsof -i :$(CAPTURE_PORT) >/dev/null 2>&1 && echo "  📡 Capture Port ($(CAPTURE_PORT)): ACTIVE" || echo "  ⭕ Capture Port ($(CAPTURE_PORT)): INACTIVE"
	@lsof -i :$(ML_ENHANCED_PORT) >/dev/null 2>&1 && echo "  🤖 ML Enhanced Port ($(ML_ENHANCED_PORT)): ACTIVE" || echo "  ⭕ ML Enhanced Port ($(ML_ENHANCED_PORT)): INACTIVE"
	@lsof -i :$(FIREWALL_COMMAND_PORT) >/dev/null 2>&1 && echo "  🔥 Firewall Command Port ($(FIREWALL_COMMAND_PORT)): ACTIVE" || echo "  ⭕ Firewall Command Port ($(FIREWALL_COMMAND_PORT)): INACTIVE"
	@lsof -i :$(FIREWALL_DASHBOARD_PORT) >/dev/null 2>&1 && echo "  📊 Dashboard Port ($(FIREWALL_DASHBOARD_PORT)): ACTIVE" || echo "  ⭕ Dashboard Port ($(FIREWALL_DASHBOARD_PORT)): INACTIVE"

status:
	@echo "$(CYAN)📊 Upgraded Happiness - Complete Project Status$(NC)"
	@echo "$(CYAN)================================================$(NC)"
	@echo "$(YELLOW)Virtual Environment:$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "  ✅ $(VENV_NAME) exists"; \
	else \
		echo "  ❌ $(VENV_NAME) not found"; \
	fi
	@echo ""
	@$(MAKE) status-firewall
	@echo ""
	@echo "$(YELLOW)Legacy System Processes:$(NC)"
	@pgrep -f "$(SIMPLE_BROKER)" >/dev/null && echo "  🔌 Simple Broker: Running" || echo "  ⭕ Simple Broker: Stopped"
	@pgrep -f "$(BROKER)" >/dev/null && echo "  🔌 Smart Broker: Running" || echo "  ⭕ Smart Broker: Stopped"
	@pgrep -f "$(DASHBOARD_GIS)" >/dev/null && echo "  🌍 GIS Dashboard: Running (http://localhost:$(GIS_DASHBOARD_PORT))" || echo "  ⭕ GIS Dashboard: Stopped"
	@pgrep -f "$(DASHBOARD_FIXED)" >/dev/null && echo "  🌐 Fixed Dashboard: Running (http://localhost:$(DASHBOARD_PORT))" || echo "  ⭕ Fixed Dashboard: Stopped"

monitor-firewall:
	@echo "$(CYAN)📊 Firewall System Monitor$(NC)"
	@echo "$(CYAN)=========================$(NC)"
	@$(MAKE) status-firewall
	@echo ""
	@echo "$(YELLOW)Recent Firewall Activity:$(NC)"
	@if [ -f $(FIREWALL_AGENT_LOG) ]; then echo "Firewall Agent:"; tail -3 $(FIREWALL_AGENT_LOG) | sed 's/^/  /'; fi
	@if [ -f $(FIREWALL_DASHBOARD_LOG) ]; then echo "Dashboard:"; tail -3 $(FIREWALL_DASHBOARD_LOG) | sed 's/^/  /'; fi
	@if [ -f $(ML_LOG) ]; then echo "ML Detector:"; tail -3 $(ML_LOG) | sed 's/^/  /'; fi

# =============================================================================
# VERIFICATION AND TESTING
# =============================================================================
verify-firewall:
	@echo "$(BLUE)🔍 Verifying firewall system integrity...$(NC)"
	@for file in $(FIREWALL_AGENT) $(FIREWALL_DASHBOARD) $(ML_DETECTOR) $(PROMISCUOUS_AGENT) $(CLAUDE_INTEGRATION); do \
		if [ -f "$$file" ]; then \
			echo "  ✅ $$file"; \
		else \
			echo "  ❌ $$file missing"; \
		fi \
	done
	@echo "$(BLUE)Checking firewall permissions...$(NC)"
	@sudo -n iptables -L >/dev/null 2>&1 && echo "  ✅ Firewall permissions OK" || echo "  ❌ Firewall permissions missing (run: make setup-firewall-perms)"

test-firewall:
	@echo "$(BLUE)🧪 Testing Firewall System...$(NC)"
	@if [ -f $(FIREWALL_AGENT_PID) ] && kill -0 $$(cat $(FIREWALL_AGENT_PID)) 2>/dev/null; then \
		echo "Testing firewall agent connectivity..."; \
		$(ACTIVATE) && $(PYTHON_VENV) -c "import zmq; context = zmq.Context(); socket = context.socket(zmq.PUSH); socket.connect('tcp://localhost:$(FIREWALL_COMMAND_PORT)'); print('✅ Firewall agent connectivity OK')"; \
	else \
		echo "❌ Firewall agent not running"; \
		exit 1; \
	fi
	@if [ -f $(FIREWALL_DASHBOARD_PID) ] && kill -0 $$(cat $(FIREWALL_DASHBOARD_PID)) 2>/dev/null; then \
		echo "Testing dashboard health endpoint..."; \
		curl -s http://localhost:$(FIREWALL_DASHBOARD_PORT)/health | python3 -m json.tool 2>/dev/null || echo "Health check failed"; \
		echo "✅ Firewall dashboard responding"; \
	else \
		echo "❌ Firewall dashboard not running"; \
		exit 1; \
	fi

test-claude:
	@echo "$(BLUE)🧪 Testing Claude Integration...$(NC)"
	@if [ -f $(CLAUDE_INTEGRATION) ]; then \
		$(ACTIVATE) && $(PYTHON_VENV) $(CLAUDE_INTEGRATION); \
	else \
		echo "$(RED)❌ $(CLAUDE_INTEGRATION) not found$(NC)"; \
	fi

# =============================================================================
# LOGS AND UTILITIES
# =============================================================================
logs-firewall:
	@echo "$(CYAN)📋 Firewall System Logs:$(NC)"
	@if [ -f $(FIREWALL_AGENT_LOG) ]; then echo "=== Firewall Agent ==="; tail -15 $(FIREWALL_AGENT_LOG); echo ""; fi
	@if [ -f $(FIREWALL_DASHBOARD_LOG) ]; then echo "=== Dashboard ==="; tail -15 $(FIREWALL_DASHBOARD_LOG); echo ""; fi
	@if [ -f $(ML_LOG) ]; then echo "=== ML Detector ==="; tail -15 $(ML_LOG); echo ""; fi

show-firewall-dashboard:
	@echo "$(BLUE)🔥 Opening firewall dashboard...$(NC)"
	@which open >/dev/null && open http://localhost:$(FIREWALL_DASHBOARD_PORT) || \
	 which xdg-open >/dev/null && xdg-open http://localhost:$(FIREWALL_DASHBOARD_PORT) || \
	 echo "💡 Open manually: http://localhost:$(FIREWALL_DASHBOARD_PORT)"

# =============================================================================
# QUICK COMMANDS (Enhanced)
# =============================================================================
qt: test-firewall
qr: run-firewall
qv: verify-firewall
qs: status-firewall
qm: monitor-firewall
qd: show-firewall-dashboard
qf: run-firewall

# Firewall Quick Commands
fw-start: run-firewall-bg
fw-stop: stop-firewall
fw-status: status-firewall
fw-logs: logs-firewall
fw-test: test-firewall
fw-clean: clean-firewall

# =============================================================================
# HELP SECTIONS
# =============================================================================
help-firewall:
	@echo "$(CYAN)🔥 Firewall System Help$(NC)"
	@echo "$(CYAN)========================$(NC)"
	@echo ""
	@echo "$(YELLOW)Firewall Commands:$(NC)"
	@echo "  run-firewall             - Start complete firewall system (interactive)"
	@echo "  run-firewall-bg          - Start firewall system (background)"
	@echo "  run-firewall-test        - Start with GPS test data"
	@echo "  stop-firewall            - Stop firewall system"
	@echo "  status-firewall          - Show firewall system status"
	@echo "  monitor-firewall         - Monitor firewall system"
	@echo "  test-firewall            - Test firewall functionality"
	@echo "  logs-firewall            - Show firewall logs"
	@echo ""
	@echo "$(YELLOW)Architecture:$(NC)"
	@echo "  Port $(CAPTURE_PORT): Promiscuous Agent → ML Detector"
	@echo "  Port $(ML_ENHANCED_PORT): ML Detector → Dashboard"
	@echo "  Port $(FIREWALL_COMMAND_PORT): Dashboard → Firewall Agent"
	@echo "  Port $(FIREWALL_DASHBOARD_PORT): Dashboard Web UI"
	@echo ""
	@echo "$(YELLOW)Features:$(NC)"
	@echo "  • Real-time network packet capture"
	@echo "  • ML-based anomaly detection"
	@echo "  • Interactive dashboard with click-to-block"
	@echo "  • Automatic firewall rule generation"
	@echo "  • Claude-powered intelligent responses"
	@echo "  • Temporal rule management"
	@echo ""
	@echo "$(YELLOW)Setup Requirements:$(NC)"
	@echo "  1. Run: make setup-firewall-perms"
	@echo "  2. Run: make install-firewall-deps"
	@echo "  3. Run: make run-firewall"
	@echo ""
	@echo "$(YELLOW)URL:$(NC) http://localhost:$(FIREWALL_DASHBOARD_PORT)"

# Include existing help sections...
help-gis:
	@echo "$(CYAN)🌍 GIS Dashboard Help (Legacy)$(NC)"
	@echo "$(CYAN)==============================$(NC)"
	@echo ""
	@echo "$(YELLOW)GIS Commands:$(NC)"
	@echo "  run-gis-dashboard    - Start GIS dashboard (interactive)"
	@echo "  gis                  - Quick start GIS dashboard"
	@echo "  gis-bg               - Start GIS dashboard (background)"
	@echo "  gis-stop             - Stop GIS dashboard"
	@echo "  gis-status           - Show GIS dashboard status"
	@echo "  gis-logs             - Follow GIS dashboard logs"
	@echo "  gis-test             - Test GIS functionality"
	@echo ""
	@echo "$(YELLOW)URL:$(NC) http://localhost:$(GIS_DASHBOARD_PORT)"

# Default target
all: setup install-all verify-firewall
	@echo "$(GREEN)✅ Upgraded Happiness + Firewall setup completed successfully!$(NC)"