# Makefile for Upgraded Happiness - ENHANCED with HTTP 207 Fixes
# ===================================================================
# Mantiene el sistema nuclear-stop + añade correcciones HTTP 207
# ===================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
PURPLE = \033[0;35m
CYAN = \033[0;36m
NC = \033[0m # No Color

# Variables (mantener compatibilidad)
PYTHON = python3
VENV_NAME = upgraded_happiness_venv
VENV_BIN = $(VENV_NAME)/bin
PYTHON_VENV = $(VENV_BIN)/python
PIP_VENV = $(VENV_BIN)/pip
ACTIVATE = source $(VENV_BIN)/activate

# Main scripts (existentes)
ORCHESTRATOR = system_orchestrator.py
ML_DETECTOR = lightweight_ml_detector.py
PROMISCUOUS_AGENT = promiscuous_agent.py
BROKER = scripts/smart_broker.py
FIX_MODULE = fix_module.py
DASHBOARD = dashboard_server_with_real_data.py

# NUEVOS: Scripts con correcciones HTTP 207
DASHBOARD_FIXED = dashboard_server_fixed.py
DIAGNOSTIC_TOOL = diagnostic_tool.py

# Test directory
TEST_DIR = tests_consolidated

# Nuclear stop (MANTENER)
NUCLEAR_STOP_SCRIPT := nuclear-stop.sh

# Process IDs storage (NUEVO pero compatible)
PIDS_DIR := .pids
BROKER_PID := $(PIDS_DIR)/broker.pid
ML_PID := $(PIDS_DIR)/ml.pid
DASHBOARD_PID := $(PIDS_DIR)/dashboard.pid
AGENT_PID := $(PIDS_DIR)/agent.pid

# Ports configuration
BROKER_PORT := 5555
BROKER_SECONDARY_PORT := 5556
DASHBOARD_PORT := 8766

.PHONY: all help setup install install-dev install-all install-dashboard test test-cov format lint security check clean verify run run-daemon run-orchestrator run-broker run-detector run-agent run-dashboard run-all fix-deps setup-sudo setup-production backup dev status monitor monitor-live test-traffic logs docs profile benchmark memory emergency-fix stop qt qr qv qs qm qd quick-start reinstall setup-nuclear-stop emergency-stop verify-stop status-detailed restart-nuclear maintenance-cycle help-nuclear fix-207 diagnose run-fixed dashboard-fixed help-207

# Default target
all: setup install-all verify test
	@echo "$(GREEN)✅ Upgraded Happiness setup completed successfully!$(NC)"

# =============================================================================
# HELP SECTIONS - Enhanced with HTTP 207 fixes
# =============================================================================

help:
	@echo "$(CYAN)🚀 Upgraded Happiness - Available Commands (WITH HTTP 207 FIXES):$(NC)"
	@echo ""
	@echo "$(YELLOW)Setup & Installation:$(NC)"
	@echo "  make setup          - Create virtual environment"
	@echo "  make install        - Install production dependencies"
	@echo "  make install-dev    - Install development dependencies"
	@echo "  make install-all    - Install all dependencies (prod + dev)"
	@echo "  make install-dashboard - Install dashboard web dependencies"
	@echo "  make clean          - Clean virtual environment"
	@echo "  make reinstall      - Clean and reinstall everything"
	@echo ""
	@echo "$(YELLOW)Platform Execution:$(NC)"
	@echo "  make run            - Start platform (Interactive mode)"
	@echo "  make run-daemon     - Start platform (Daemon mode)"
	@echo "  make run-fixed      - 🆕 Start with HTTP 207 fixes (RECOMMENDED)"
	@echo "  make run-dashboard  - Start web dashboard (port 8766)"
	@echo "  make dashboard-fixed- 🆕 Start FIXED dashboard"
	@echo "  make run-all        - Start platform + dashboard"
	@echo "  make quick-start    - Quick start with proper initialization order"
	@echo ""
	@echo "$(YELLOW)💊 HTTP 207 FIXES:$(NC)"
	@echo "  make fix-207        - 🆕 Fix HTTP 207 Multi-Status errors"
	@echo "  make diagnose       - 🆕 Run comprehensive diagnostic"
	@echo "  make help-207       - 🆕 Help for HTTP 207 issues"
	@echo ""
	@echo "$(YELLOW)🛑 NUCLEAR STOP SYSTEM (PROVEN):$(NC)"
	@echo "  make stop           - Nuclear stop (handles root processes)"
	@echo "  make emergency-stop - Maximum aggressiveness stop"
	@echo "  make verify-stop    - Verify complete stop"
	@echo "  make restart-nuclear- Nuclear stop + clean restart"
	@echo ""
	@echo "$(YELLOW)Development & Code Quality:$(NC)"
	@echo "  make verify         - Verify system integrity"
	@echo "  make test           - Run all tests"
	@echo "  make check          - Run all checks (format + lint + test)"
	@echo "  make fix-deps       - Fix circular imports and dependencies"
	@echo "  make dev            - Development mode"
	@echo ""
	@echo "$(YELLOW)Monitoring:$(NC)"
	@echo "  make status         - Show project status"
	@echo "  make status-detailed- Enhanced status with process details"
	@echo "  make monitor        - Enhanced platform monitoring"
	@echo "  make monitor-live   - Continuous monitoring (real-time)"
	@echo ""
	@echo "$(YELLOW)Quick Commands:$(NC)"
	@echo "  make qt qr qv qs qm qd - Quick test/run/verify/status/monitor/dashboard"
	@echo ""
	@echo "$(CYAN)🌐 Complete Workflow (RECOMMENDED):$(NC)"
	@echo "  make run-fixed      - Start everything with HTTP 207 fixes"

# =============================================================================
# SETUP AND INSTALLATION (Original functionality)
# =============================================================================

# Setup virtual environment
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

# Create directory for storing process IDs
setup-pids-dir:
	@mkdir -p $(PIDS_DIR)

# Install production dependencies
install: setup
	@echo "$(BLUE)📦 Installing production dependencies...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install -r requirements.txt
	@echo "$(BLUE)🧠 Installing ML dependencies...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install joblib scikit-learn xgboost lightgbm
	@echo "$(GREEN)✅ Production dependencies installed$(NC)"

# Install development dependencies
install-dev: install
	@echo "$(BLUE)🛠️  Installing development dependencies...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install -r requirements-dev.txt
	@echo "$(GREEN)✅ Development dependencies installed$(NC)"

# Install dashboard dependencies
install-dashboard: setup
	@echo "$(BLUE)🌐 Installing dashboard web dependencies...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install aiohttp aiohttp-cors aiofiles pyyaml websockets
	@echo "$(GREEN)✅ Dashboard dependencies installed$(NC)"

# Install all dependencies (prod + dev + dashboard)
install-all: install-dev install-dashboard
	@echo "$(GREEN)✅ All dependencies installed$(NC)"

# Clean virtual environment
clean:
	@echo "$(YELLOW)🧹 Cleaning virtual environment...$(NC)"
	@rm -rf $(VENV_NAME)
	@rm -rf __pycache__
	@find . -name "*.pyc" -delete
	@find . -name "*.pyo" -delete
	@find . -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf $(PIDS_DIR)
	@rm -f *.pid *.log
	@echo "$(GREEN)✅ Cleanup completed$(NC)"

# Reinstall everything
reinstall: clean setup install-all
	@echo "$(GREEN)✅ Reinstallation completed$(NC)"

# ==== FIXED RUNNING COMMANDS ====

run-daemon-fixed: ## Start all components with HTTP 207 fixes
	@echo -e "$(GREEN)🚀 Starting SCADA system with HTTP 207 fixes...$(NC)"
	$(MAKE) stop-all-silent
	$(MAKE) setup-pids-dir
	@echo -e "$(BLUE)Starting ZeroMQ Broker...$(NC)"
	$(PYTHON) scripts/smart_broker.py & echo $$! > $(BROKER_PID)
	@sleep 3
	@echo -e "$(BLUE)Starting ML Detector...$(NC)"
	$(PYTHON) lightweight_ml_detector.py & echo $$! > $(ML_PID)
	@sleep 2
	@echo -e "$(BLUE)Starting Fixed Dashboard...$(NC)"
	$(PYTHON) dashboard_server_fixed.py & echo $$! > $(DASHBOARD_PID)
	@sleep 2
	@echo -e "$(BLUE)Starting Promiscuous Agent...$(NC)"
	sudo $(PYTHON) promiscuous_agent.py & echo $$! > $(AGENT_PID)
	@sleep 1
	@echo -e "$(GREEN)✅ All components started!$(NC)"
	@echo -e "$(YELLOW)Dashboard: http://localhost:$(DASHBOARD_PORT)$(NC)"
	@$(MAKE) status

run-daemon: run-daemon-fixed ## Alias for run-daemon-fixed

start-fixed: run-daemon-fixed ## Alias for run-daemon-fixed

# =============================================================================
# PLATFORM EXECUTION (Original + Enhanced with HTTP 207 fixes)
# =============================================================================

# Run complete platform (interactive mode)
run: setup install verify
	@echo "$(GREEN)🚀 Starting Upgraded Happiness Platform (Interactive)...$(NC)"
	@echo "$(YELLOW)⚠️  This will start interactive orchestrator. Use Ctrl+C to stop.$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ORCHESTRATOR)

# Run platform components individually (daemon mode) - ORIGINAL
run-daemon: setup install verify
	@echo "$(GREEN)🚀 Starting Upgraded Happiness Platform (Daemon Mode)...$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@echo "$(PURPLE)🔌 ZeroMQ Broker$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(BROKER) &
	@sleep 2
	@echo "$(PURPLE)🤖 ML Detector$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) &
	@sleep 2
	@echo "$(PURPLE)🕵️  Promiscuous Agent$(NC)"
	@sudo $(PYTHON_VENV) $(PROMISCUOUS_AGENT) &
	@sleep 2
	@echo "$(GREEN)✅ All components started in daemon mode$(NC)"
	@echo "$(YELLOW)💡 Use 'make stop' to stop all components$(NC)"

# 🆕 NEW: Run with HTTP 207 fixes (RECOMMENDED)
run-fixed: setup install-all verify setup-pids-dir
	@echo "$(GREEN)🚀 Starting SCADA system with HTTP 207 fixes...$(NC)"
	$(MAKE) stop-all-silent
	@echo "$(BLUE)Starting ZeroMQ Broker...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(BROKER) & echo $! > $(BROKER_PID)
	@sleep 3
	@echo "$(BLUE)Starting ML Detector...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) & echo $! > $(ML_PID)
	@sleep 2
	@echo "$(BLUE)Starting Fixed Dashboard...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD_FIXED) & echo $! > $(DASHBOARD_PID)
	@sleep 2
	@echo "$(BLUE)Starting Promiscuous Agent...$(NC)"
	@sudo $(PYTHON_VENV) $(PROMISCUOUS_AGENT) & echo $! > $(AGENT_PID)
	@sleep 1
	@echo "$(GREEN)✅ All components started with HTTP 207 fixes!$(NC)"
	@echo "$(YELLOW)Dashboard: http://localhost:$(DASHBOARD_PORT)$(NC)"
	@$(MAKE) status

# Run web dashboard - ORIGINAL
run-dashboard: setup install-dashboard
	@echo "$(BLUE)🌐 Starting Web Dashboard...$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@echo "$(PURPLE)📱 Dashboard URL: http://localhost:8766$(NC)"
	@echo "$(PURPLE)🔌 WebSocket: ws://localhost:8766/ws$(NC)"
	@echo "$(YELLOW)⚠️  Make sure the platform is running first!$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD)

# 🆕 NEW: Run FIXED dashboard
dashboard-fixed: setup install-dashboard
	@echo "$(BLUE)🌐 Starting FIXED Web Dashboard...$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@echo "$(PURPLE)📱 Dashboard URL: http://localhost:8766$(NC)"
	@echo "$(PURPLE)🔌 WebSocket: ws://localhost:8766/ws$(NC)"
	@echo "$(GREEN)✅ Using HTTP 207 fixes$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD_FIXED)

# Run everything: platform + dashboard (ENHANCED)
run-all: setup install-all verify
	@echo "$(GREEN)🚀 Starting COMPLETE Platform + Dashboard...$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@echo "$(PURPLE)🔌 Starting ZeroMQ Broker...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(BROKER) &
	@sleep 3
	@echo "$(PURPLE)🤖 Starting ML Detector...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) &
	@sleep 3
	@echo "$(PURPLE)🕵️  Starting Promiscuous Agent...$(NC)"
	@sudo $(PYTHON_VENV) $(PROMISCUOUS_AGENT) &
	@sleep 3
	@echo "$(PURPLE)🌐 Starting Web Dashboard...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD) &
	@sleep 2
	@echo ""
	@echo "$(GREEN)✅ EVERYTHING STARTED!$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@echo "$(YELLOW)📱 Dashboard: http://localhost:8766$(NC)"
	@echo "$(YELLOW)🔌 ZeroMQ Broker: tcp://localhost:5555$(NC)"
	@echo "$(YELLOW)📊 Monitor: ./platform_monitor.sh$(NC)"
	@echo ""
	@echo "$(RED)⏹️  Use 'make stop' to stop everything$(NC)"

# Run individual components
run-orchestrator: setup install
	@echo "$(BLUE)🎯 Starting System Orchestrator...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ORCHESTRATOR)

run-detector: setup install
	@echo "$(BLUE)🤖 Starting ML Detector...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR)

run-agent: setup install
	@echo "$(BLUE)🕵️  Starting Promiscuous Agent...$(NC)"
	@sudo $(PYTHON_VENV) $(PROMISCUOUS_AGENT)

run-broker: setup install
	@echo "$(BLUE)🔌 Starting ZeroMQ Broker...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(BROKER)

# Dashboard utilities
dashboard-only: run-dashboard

dashboard-debug: setup install-dashboard
	@echo "$(BLUE)🌐 Starting Dashboard with DEBUG output...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import logging; logging.basicConfig(level=logging.DEBUG)" && $(PYTHON_VENV) $(DASHBOARD)

# Quick start with proper order (reproduces manual setup)
quick-start: setup install verify
	@echo "$(GREEN)🚀 Quick Start - Proper Order Initialization$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(BROKER) &
	@sleep 3
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) &
	@sleep 3
	@sudo $(PYTHON_VENV) $(PROMISCUOUS_AGENT) &
	@sleep 2
	@echo "$(GREEN)✅ Platform started with proper initialization order$(NC)"
	@./platform_monitor.sh 2>/dev/null || make status

# =============================================================================
# NUCLEAR STOP SYSTEM (MANTENER - Funciona con procesos root)
# =============================================================================

# Setup nuclear stop (ORIGINAL)
setup-nuclear-stop:
	@if [ ! -f $(NUCLEAR_STOP_SCRIPT) ]; then \
		echo "❌ $(NUCLEAR_STOP_SCRIPT) requerido para parada efectiva"; \
		exit 1; \
	fi
	@chmod +x $(NUCLEAR_STOP_SCRIPT)

# NUCLEAR STOP - Regla principal (ORIGINAL)
stop: setup-nuclear-stop
	@echo "🛑 Ejecutando parada nuclear completa..."
	@./$(NUCLEAR_STOP_SCRIPT)

# Stop original (respaldo)
stop-original:
	@echo "$(YELLOW)🛑 Stopping all platform components...$(NC)"
	@pkill -f "$(ORCHESTRATOR)" 2>/dev/null || echo "$(YELLOW)⚠️  Orchestrator not running$(NC)"
	@pkill -f "$(ML_DETECTOR)" 2>/dev/null || echo "$(YELLOW)⚠️  ML Detector not running$(NC)"
	@pkill -f "$(PROMISCUOUS_AGENT)" 2>/dev/null || echo "$(YELLOW)⚠️  Promiscuous Agent not running$(NC)"
	@pkill -f "$(BROKER)" 2>/dev/null || echo "$(YELLOW)⚠️  Broker not running$(NC)"
	@pkill -f "$(DASHBOARD)" 2>/dev/null || echo "$(YELLOW)⚠️  Dashboard not running$(NC)"
	@pkill -f "$(DASHBOARD_FIXED)" 2>/dev/null || echo "$(YELLOW)⚠️  Fixed Dashboard not running$(NC)"
	@sudo pkill -f "$(PROMISCUOUS_AGENT)" 2>/dev/null || true
	@pkill -f "lightweight_ml_detector" 2>/dev/null || true
	@pkill -f "promiscuous_agent" 2>/dev/null || true
	@pkill -f "system_orchestrator" 2>/dev/null || true
	@pkill -f "smart_broker" 2>/dev/null || true
	@pkill -f "dashboard_server" 2>/dev/null || true
	@echo "$(GREEN)✅ All components stopped$(NC)"

# Stop silently (para uso interno)
stop-all-silent:
	@-pkill -f "smart_broker.py" 2>/dev/null || true
	@-pkill -f "lightweight_ml_detector.py" 2>/dev/null || true
	@-pkill -f "dashboard_server" 2>/dev/null || true
	@-pkill -f "promiscuous_agent.py" 2>/dev/null || true
	@-$(MAKE) kill-by-pids 2>/dev/null || true
	@rm -f $(PIDS_DIR)/*.pid 2>/dev/null || true

# Kill by PIDs (NUEVO)
kill-by-pids:
	@if [ -f $(BROKER_PID) ]; then kill $(cat $(BROKER_PID)) 2>/dev/null || true; rm -f $(BROKER_PID); fi
	@if [ -f $(ML_PID) ]; then kill $(cat $(ML_PID)) 2>/dev/null || true; rm -f $(ML_PID); fi
	@if [ -f $(DASHBOARD_PID) ]; then kill $(cat $(DASHBOARD_PID)) 2>/dev/null || true; rm -f $(DASHBOARD_PID); fi
	@if [ -f $(AGENT_PID) ]; then kill $(cat $(AGENT_PID)) 2>/dev/null || true; rm -f $(AGENT_PID); fi

# Emergency stop (ORIGINAL)
emergency-stop:
	@echo "🚨 EMERGENCY STOP - Máxima agresividad"
	@sudo pkill -9 -f "python.*promiscuous" 2>/dev/null || true
	@sudo pkill -9 -f "python.*broker" 2>/dev/null || true
	@sudo pkill -9 -f "python.*detector" 2>/dev/null || true
	@sudo pkill -9 -f "uvicorn" 2>/dev/null || true
	@sudo lsof -ti :5555,5556,8766,8080 | xargs sudo kill -9 2>/dev/null || true
	@sudo rm -f *.pid /tmp/*scada* /tmp/*broker* /tmp/*zmq* 2>/dev/null || true
	@echo "💀 Emergency stop completed"

# Verify stop (ORIGINAL)
verify-stop:
	@echo "🔍 Verificando estado de parada..."
	@echo "Procesos SCADA activos:"
	@ps aux | grep -E "(smart_broker|ml_detector|promiscuous_agent|uvicorn)" | grep -v grep || echo "✅ Sin procesos SCADA activos"
	@echo "Puertos SCADA ocupados:"
	@lsof -i :5555,5556,8766,8080 2>/dev/null || echo "✅ Todos los puertos SCADA libres"

# Restart nuclear (ORIGINAL)
restart-nuclear: stop
	@echo "🔄 Esperando estabilización..."
	@sleep 3
	@echo "🚀 Iniciando sistema limpio..."
	$(MAKE) quick-start

# Restart with fixes (NUEVO)
restart-fixed: stop
	@echo "🔄 Restarting with HTTP 207 fixes..."
	@sleep 3
	$(MAKE) run-fixed

# Maintenance cycle (ORIGINAL)
maintenance-cycle:
	@echo "🔧 Ejecutando ciclo de mantenimiento completo..."
	$(MAKE) stop
	$(MAKE) verify-stop
	$(MAKE) fix-deps 2>/dev/null || true
	$(MAKE) quick-start
	@sleep 8
	$(MAKE) status-detailed

# =============================================================================
# MONITORING AND STATUS (Enhanced)
# =============================================================================

# Show project status (ENHANCED)
status:
	@echo "$(CYAN)📊 Upgraded Happiness - Project Status$(NC)"
	@echo "$(CYAN)======================================$(NC)"
	@echo "$(YELLOW)Virtual Environment:$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "  ✅ $(VENV_NAME) exists"; \
		echo "  📍 Python: $($(ACTIVATE) && $(PYTHON_VENV) --version)"; \
	else \
		echo "  ❌ $(VENV_NAME) not found"; \
	fi
	@echo ""
	@echo "$(YELLOW)Core Files:$(NC)"
	@for file in $(ORCHESTRATOR) $(BROKER) $(ML_DETECTOR) $(PROMISCUOUS_AGENT) $(FIX_MODULE) $(DASHBOARD) $(DASHBOARD_FIXED) $(DIAGNOSTIC_TOOL); do \
		if [ -f "$file" ]; then \
			echo "  ✅ $file"; \
		else \
			echo "  ❌ $file"; \
		fi \
	done
	@echo ""
	@echo "$(YELLOW)Running Processes:$(NC)"
	@pgrep -f "$(ORCHESTRATOR)" >/dev/null && echo "  🎯 System Orchestrator: Running" || echo "  ⭕ System Orchestrator: Stopped"
	@pgrep -f "$(BROKER)" >/dev/null && echo "  🔌 ZeroMQ Broker: Running" || echo "  ⭕ ZeroMQ Broker: Stopped"
	@pgrep -f "$(ML_DETECTOR)" >/dev/null && echo "  🤖 ML Detector: Running" || echo "  ⭕ ML Detector: Stopped"
	@pgrep -f "$(PROMISCUOUS_AGENT)" >/dev/null && echo "  🕵️  Promiscuous Agent: Running" || echo "  ⭕ Promiscuous Agent: Stopped"
	@pgrep -f "$(DASHBOARD)" >/dev/null && echo "  🌐 Web Dashboard: Running (http://localhost:8766)" || echo "  ⭕ Web Dashboard: Stopped"
	@pgrep -f "$(DASHBOARD_FIXED)" >/dev/null && echo "  🌐 FIXED Dashboard: Running (http://localhost:8766)" || echo "  ⭕ FIXED Dashboard: Stopped"
	@echo ""
	@echo "$(YELLOW)Network Ports:$(NC)"
	@lsof -i :5555 >/dev/null 2>&1 && echo "  🔌 ZeroMQ (5555): LISTENING" || echo "  ⭕ ZeroMQ (5555): NOT LISTENING"
	@lsof -i :8766 >/dev/null 2>&1 && echo "  🌐 Dashboard (8766): LISTENING" || echo "  ⭕ Dashboard (8766): NOT LISTENING"

# Enhanced status (ORIGINAL)
status-detailed:
	@echo "📊 Estado detallado del sistema..."
	@echo "=== PROCESOS ==="
	@ps aux | grep -E "(smart_broker|ml_detector|promiscuous_agent|uvicorn)" | grep -v grep || echo "Sin procesos SCADA"
	@echo "=== PUERTOS ==="
	@for port in 5555 5556 8766 8080; do \
		echo "Puerto $port:"; \
		lsof -i :$port 2>/dev/null || echo "  Libre ✅"; \
	done

# Enhanced monitoring
monitor:
	@if [ -f "platform_monitor.sh" ]; then \
		chmod +x platform_monitor.sh; \
		./platform_monitor.sh; \
	else \
		echo "$(RED)❌ platform_monitor.sh not found$(NC)"; \
		echo "$(YELLOW)💡 Run basic monitoring instead...$(NC)"; \
		make status; \
	fi

# Continuous monitoring
monitor-live:
	@if [ -f "platform_monitor.sh" ]; then \
		chmod +x platform_monitor.sh; \
		./platform_monitor.sh --continuous; \
	else \
		echo "$(RED)❌ platform_monitor.sh not found$(NC)"; \
		echo "$(YELLOW)💡 Use 'watch make status' instead$(NC)"; \
	fi

# Generate test traffic
test-traffic:
	@if [ -f "platform_monitor.sh" ]; then \
		chmod +x platform_monitor.sh; \
		./platform_monitor.sh --test-traffic; \
	else \
		echo "$(YELLOW)⚠️  Generating basic test traffic...$(NC)"; \
		curl -s https://httpbin.org/get > /dev/null 2>&1 && echo "$(GREEN)✅ HTTP test completed$(NC)"; \
		ping -c 3 8.8.8.8 > /dev/null 2>&1 && echo "$(GREEN)✅ ICMP test completed$(NC)"; \
	fi

# Show recent logs (if log files exist)
logs:
	@echo "$(CYAN)📋 Recent Logs$(NC)"
	@echo "$(CYAN)==============$(NC)"
	@if [ -f "logs/system.log" ]; then \
		echo "$(YELLOW)System Log (last 20 lines):$(NC)"; \
		tail -20 logs/system.log; \
	else \
		echo "$(YELLOW)⚠️  No system logs found$(NC)"; \
	fi

# =============================================================================
# 🆕 HTTP 207 FIXES AND DIAGNOSTICS (NEW)
# =============================================================================

# 🆕 Fix HTTP 207 Multi-Status errors
fix-207:
	@echo "$(YELLOW)🔧 Fixing HTTP 207 Multi-Status errors...$(NC)"
	@echo "$(BLUE)Step 1: Stopping all processes...$(NC)"
	$(MAKE) stop-all-silent
	@sleep 2
	@echo "$(BLUE)Step 2: Checking for stuck connections...$(NC)"
	@-netstat -an | grep :$(DASHBOARD_PORT) || true
	@echo "$(BLUE)Step 3: Clearing any WebSocket connections...$(NC)"
	@-fuser -k $(DASHBOARD_PORT)/tcp 2>/dev/null || true
	@sleep 1
	@echo "$(BLUE)Step 4: Starting with fixed configuration...$(NC)"
	$(MAKE) run-fixed
	@echo "$(GREEN)✅ HTTP 207 fix applied!$(NC)"

# 🆕 Run comprehensive diagnostic
diagnose:
	@echo "$(GREEN)🔍 Running SCADA diagnostic...$(NC)"
	@if [ -f "$(DIAGNOSTIC_TOOL)" ]; then \
		$(ACTIVATE) && $(PYTHON_VENV) $(DIAGNOSTIC_TOOL); \
	else \
		echo "$(RED)❌ $(DIAGNOSTIC_TOOL) not found$(NC)"; \
		echo "$(YELLOW)💡 Running basic diagnostic...$(NC)"; \
		$(MAKE) status-detailed; \
		$(MAKE) check-logs; \
	fi

# 🆕 Check for HTTP 207 errors in logs
check-logs:
	@echo "$(YELLOW)🔍 Checking for HTTP 207 errors...$(NC)"
	@echo "$(BLUE)System logs:$(NC)"
	@-tail -50 /var/log/system.log 2>/dev/null | grep -E "(207|Multi-Status|UNKNOWN|HTTP/1.0.*400)" || echo "No system log errors found"
	@echo "$(BLUE)Application logs:$(NC)"
	@-find . -name "*.log" -exec tail -20 {} \; 2>/dev/null | grep -E "(207|Multi-Status|UNKNOWN|HTTP/1.0.*400)" || echo "No application log errors found"

# 🆕 Test dashboard connectivity
test-dashboard:
	@echo "$(YELLOW)🧪 Testing dashboard connectivity...$(NC)"
	@echo "$(BLUE)HTTP Test:$(NC)"
	@-curl -s -w "Status: %{http_code}\nTime: %{time_total}s\n" http://localhost:$(DASHBOARD_PORT) -o /dev/null || echo "HTTP test failed"
	@echo "$(BLUE)WebSocket Test:$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -c "import asyncio, websockets, json; asyncio.run(websockets.connect('ws://localhost:$(DASHBOARD_PORT)/ws').__aenter__().send(json.dumps({'test': True})))" 2>/dev/null && echo "WebSocket OK" || echo "WebSocket test failed"

# 🆕 Verify that all fixes are in place
verify-fixes:
	@echo "$(YELLOW)🔍 Verifying fixes...$(NC)"
	@echo "$(BLUE)Checking fixed dashboard server...$(NC)"
	@test -f $(DASHBOARD_FIXED) && echo "  $(GREEN)✅ $(DASHBOARD_FIXED) exists$(NC)" || echo "  $(RED)❌ $(DASHBOARD_FIXED) missing$(NC)"
	@echo "$(BLUE)Checking diagnostic tool...$(NC)"
	@test -f $(DIAGNOSTIC_TOOL) && echo "  $(GREEN)✅ $(DIAGNOSTIC_TOOL) exists$(NC)" || echo "  $(RED)❌ $(DIAGNOSTIC_TOOL) missing$(NC)"
	@echo "$(BLUE)Checking virtual environment...$(NC)"
	@test -d $(VENV_NAME) && echo "  $(GREEN)✅ Virtual environment exists$(NC)" || echo "  $(RED)❌ Virtual environment missing$(NC)"
	@echo "$(BLUE)Checking port availability...$(NC)"
	@-nc -z localhost $(DASHBOARD_PORT) && echo "  $(YELLOW)⚠️  Port $(DASHBOARD_PORT) in use$(NC)" || echo "  $(GREEN)✅ Port $(DASHBOARD_PORT) available$(NC)"

# 🆕 Help for HTTP 207 Multi-Status issues
help-207:
	@echo "$(BLUE)HTTP 207 Multi-Status Issue Help$(NC)"
	@echo "$(BLUE)================================$(NC)"
	@echo ""
	@echo "$(YELLOW)What is HTTP 207?$(NC)"
	@echo "HTTP 207 Multi-Status is a WebDAV-specific response code that indicates"
	@echo "multiple resources were processed, each with potentially different status codes."
	@echo ""
	@echo "$(YELLOW)Why am I seeing this error?$(NC)"
	@echo "1. Your dashboard server is receiving malformed HTTP requests"
	@echo "2. WebSocket connections are being interpreted as WebDAV requests"
	@echo "3. aiohttp server configuration issues"
	@echo ""
	@echo "$(YELLOW)How to fix:$(NC)"
	@echo "  $(GREEN)make fix-207$(NC)     - Apply automatic fixes"
	@echo "  $(GREEN)make diagnose$(NC)    - Run comprehensive diagnostic"
	@echo "  $(GREEN)make emergency-stop$(NC) - Force restart everything"
	@echo ""
	@echo "$(YELLOW)Manual steps:$(NC)"
	@echo "1. Stop all processes: make stop"
	@echo "2. Use fixed dashboard: make dashboard-fixed"
	@echo "3. Start in order: make run-fixed"

# =============================================================================
# UTILITIES AND MAINTENANCE (Original functionality)
# =============================================================================

# Create backup
backup:
	@echo "$(BLUE)💾 Creating project backup...$(NC)"
	@mkdir -p backups
	@tar -czf backups/upgraded_happiness_backup_$(shell date +%Y%m%d_%H%M%S).tar.gz \
		--exclude=$(VENV_NAME) \
		--exclude=backups \
		--exclude=__pycache__ \
		--exclude=.git \
		.
	@echo "$(GREEN)✅ Backup created in backups/$(NC)"

# Emergency recovery (ENHANCED)
emergency-fix: clean setup install-all fix-deps verify
	@echo "$(GREEN)🚑 Emergency recovery completed!$(NC)"

# =============================================================================
# QUICK COMMANDS (Enhanced)
# =============================================================================

# Quick commands for common tasks
qt: test
qr: run-fixed     # 🆕 CHANGED: Now uses fixed version
qv: verify
qs: status
qm: monitor
qd: dashboard-fixed  # 🆕 CHANGED: Now uses fixed version

# =============================================================================
# NUCLEAR HELP SYSTEM (ORIGINAL)
# =============================================================================

# Help nuclear actualizado
help-nuclear:
	@echo "🛑 COMANDOS DE PARADA NUCLEAR:"
	@echo "  stop              - Parada nuclear completa (NUEVO, RECOMENDADO)"
	@echo "  stop-original     - Método original (puede fallar con procesos root)"
	@echo "  emergency-stop    - Parada de emergencia máxima"
	@echo "  verify-stop       - Verificar parada completa"
	@echo ""
	@echo "🔄 REINICIO MEJORADO:"
	@echo "  restart-nuclear   - Parada nuclear + inicio limpio"
	@echo "  restart-fixed     - Parada nuclear + inicio con HTTP 207 fixes"
	@echo "  maintenance-cycle - Mantenimiento completo"
	@echo ""
	@echo "📊 MONITOREO:"
	@echo "  status-detailed   - Estado completo del sistema"
	@echo ""
	@echo "💡 NOTA: 'make stop' ahora usa parada nuclear efectiva"

# =============================================================================
# DEVELOPMENT UTILITIES (Enhanced)
# =============================================================================

# Development mode with fixes
dev-setup-fixed: setup install-all verify-fixes
	@echo "$(GREEN)Creating fixed dashboard server...$(NC)"
	@if [ ! -f $(DASHBOARD_FIXED) ]; then \
		echo "Please ensure $(DASHBOARD_FIXED) exists"; \
		exit 1; \
	fi
	@echo "$(GREEN)Creating diagnostic tool...$(NC)"
	@if [ ! -f $(DIAGNOSTIC_TOOL) ]; then \
		echo "Please ensure $(DIAGNOSTIC_TOOL) exists"; \
		exit 1; \
	fi
	@echo "$(GREEN)✅ Development environment ready with HTTP 207 fixes!$(NC)"

# =============================================================================
# LEGACY COMMANDS (redirected to fixed versions)
# =============================================================================

# Legacy commands that now use fixed versions
run-daemon-original: run-daemon  # Keep original behavior available
dashboard-only: dashboard-fixed   # Redirect to fixed version