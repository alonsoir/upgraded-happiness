# =============================================================================
# 🛡️ Upgraded Happiness - SCADA Security Platform (Refactored Makefile)
# =============================================================================
# Comprehensive Makefile with GIS Dashboard, HTTP 207 fixes, and Nuclear Stop
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
ML_DETECTOR = lightweight_ml_detector.py
PROMISCUOUS_AGENT = promiscuous_agent.py
BROKER = scripts/smart_broker.py
SIMPLE_BROKER = simple_broker.py
FIX_MODULE = fix_module.py

# Dashboard Scripts (Multiple versions)
DASHBOARD = dashboard_server_with_real_data.py
DASHBOARD_FIXED = dashboard_server_fixed.py
DASHBOARD_GIS = enhanced_protobuf_gis_dashboard.py
GIS_SCRIPT = dashboard_server_gis.py

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
BROKER_SIMPLE_PORT_IN = 5559
BROKER_SIMPLE_PORT_OUT = 5560

# Process ID Files
BROKER_PID = $(PIDS_DIR)/broker.pid
ML_PID = $(PIDS_DIR)/ml.pid
DASHBOARD_PID = $(PIDS_DIR)/dashboard.pid
AGENT_PID = $(PIDS_DIR)/agent.pid
GIS_PID = $(PIDS_DIR)/gis.pid

# Log Files
BROKER_LOG = $(LOGS_DIR)/broker.out
ML_LOG = $(LOGS_DIR)/ml.out
DASHBOARD_LOG = $(LOGS_DIR)/dashboard.out
AGENT_LOG = $(LOGS_DIR)/agent.out
GIS_LOG = $(LOGS_DIR)/gis_dashboard.out

# =============================================================================
# PHONY DECLARATIONS
# =============================================================================
.PHONY: all help setup install install-dev install-all install-dashboard \
        install-gis-deps setup-gis setup-pids-dir clean reinstall \
        run run-daemon run-enhanced run-fixed run-gis-dashboard \
        run-all run-full-gis dashboard-fixed \
        stop stop-enhanced stop-gis stop-all emergency-stop verify-stop \
        restart-nuclear restart-fixed restart-gis \
        status status-detailed status-gis monitor monitor-live monitor-gis \
        verify fix-deps setup-sudo setup-production \
        test test-cov test-geolocation test-gis generate-test-events \
        format lint security check \
        backup emergency-fix dev dev-gis \
        logs logs-gis show-logs clean-gis \
        diagnose fix-207 help-207 check-logs test-dashboard verify-fixes \
        show-dashboard info help-nuclear help-gis \
        qt qr qv qs qm qd quick-start \
        gis gis-bg gis-stop gis-status gis-logs gis-clean gis-test

# =============================================================================
# MAIN HELP SYSTEM
# =============================================================================
help:
	@echo "$(CYAN)🛡️ Upgraded Happiness - SCADA Security Platform$(NC)"
	@echo "$(CYAN)===============================================$(NC)"
	@echo ""
	@echo "$(YELLOW)🚀 QUICK START:$(NC)"
	@echo "  $(GREEN)make run-enhanced$(NC)    - Start complete system with GIS (RECOMMENDED)"
	@echo "  $(GREEN)make show-dashboard$(NC)  - Open dashboard in browser"
	@echo "  $(GREEN)make stop$(NC)            - Nuclear stop (all components)"
	@echo ""
	@echo "$(YELLOW)📦 SETUP & INSTALLATION:$(NC)"
	@echo "  setup                 - Create virtual environment"
	@echo "  install               - Install production dependencies"
	@echo "  install-all           - Install all dependencies (prod + dev + GIS)"
	@echo "  setup-gis             - Configure GIS dashboard system"
	@echo "  clean                 - Clean virtual environment"
	@echo "  reinstall             - Clean and reinstall everything"
	@echo ""
	@echo "$(YELLOW)🚀 PLATFORM EXECUTION:$(NC)"
	@echo "  run                   - Start platform (Interactive mode)"
	@echo "  run-daemon            - Start platform (Daemon mode)"
	@echo "  run-enhanced          - Start with GIS dashboard (RECOMMENDED)"
	@echo "  run-fixed             - Start with HTTP 207 fixes"
	@echo "  run-gis-dashboard     - Start only GIS dashboard"
	@echo "  run-full-gis          - Start complete platform + GIS"
	@echo "  quick-start           - Quick start with proper order"
	@echo ""
	@echo "$(YELLOW)🌍 GIS DASHBOARD:$(NC)"
	@echo "  gis                   - Quick start GIS dashboard"
	@echo "  gis-status            - Show GIS dashboard status"
	@echo "  gis-logs              - Follow GIS dashboard logs"
	@echo "  gis-stop              - Stop GIS dashboard"
	@echo "  test-gis              - Test GIS functionality"
	@echo ""
	@echo "$(YELLOW)🛑 STOP COMMANDS:$(NC)"
	@echo "  stop                  - Nuclear stop (handles all processes)"
	@echo "  stop-gis              - Stop only GIS dashboard"
	@echo "  emergency-stop        - Maximum aggressiveness stop"
	@echo "  verify-stop           - Verify complete stop"
	@echo ""
	@echo "$(YELLOW)📊 MONITORING:$(NC)"
	@echo "  status                - Show project status"
	@echo "  monitor               - Enhanced platform monitoring"
	@echo "  monitor-gis           - Monitor GIS dashboard"
	@echo "  diagnose              - Run comprehensive diagnostic"
	@echo ""
	@echo "$(YELLOW)💊 FIXES & UTILITIES:$(NC)"
	@echo "  fix-207               - Fix HTTP 207 Multi-Status errors"
	@echo "  test-geolocation      - Test IP geolocation service"
	@echo "  emergency-fix         - Emergency recovery"
	@echo ""
	@echo "$(YELLOW)⚡ QUICK COMMANDS:$(NC)"
	@echo "  qt qr qv qs qm qd     - Quick test/run/verify/status/monitor/dashboard"
	@echo ""
	@echo "$(CYAN)🌐 URLs:$(NC)"
	@echo "  GIS Dashboard:        http://localhost:$(GIS_DASHBOARD_PORT)"
	@echo "  Fixed Dashboard:      http://localhost:$(DASHBOARD_PORT)"
	@echo ""
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

install-all: install-dev install-dashboard install-gis-deps
	@echo "$(GREEN)✅ All dependencies installed$(NC)"

setup-gis: setup install-gis-deps setup-pids-dir
	@echo "$(BLUE)🌍 Configuring GIS dashboard system...$(NC)"
	@echo "$(GREEN)✅ GIS system configured$(NC)"

clean:
	@echo "$(YELLOW)🧹 Cleaning virtual environment...$(NC)"
	@rm -rf $(VENV_NAME) __pycache__ $(PIDS_DIR) $(LOGS_DIR)
	@find . -name "*.pyc" -delete
	@find . -name "*.pyo" -delete
	@find . -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@rm -f *.pid *.log ip_cache.db
	@echo "$(GREEN)✅ Cleanup completed$(NC)"

reinstall: clean setup install-all
	@echo "$(GREEN)✅ Reinstallation completed$(NC)"

# =============================================================================
# PLATFORM EXECUTION
# =============================================================================
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

run-fixed: setup install-all verify setup-pids-dir stop-all
	@echo "$(GREEN)🚀 Starting with HTTP 207 fixes...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(BROKER) > $(BROKER_LOG) 2>&1 & echo $$! > $(BROKER_PID)
	@sleep 3
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@sleep 2
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD_FIXED) > $(DASHBOARD_LOG) 2>&1 & echo $$! > $(DASHBOARD_PID)
	@sleep 2
	@sudo $(PYTHON_VENV) $(PROMISCUOUS_AGENT) > $(AGENT_LOG) 2>&1 & echo $$! > $(AGENT_PID)
	@echo "$(GREEN)✅ System started with HTTP 207 fixes$(NC)"
	@echo "$(YELLOW)Dashboard: http://localhost:$(DASHBOARD_PORT)$(NC)"

run-gis-dashboard: setup-gis
	@echo "$(BLUE)🌍 Starting GIS Dashboard only...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD_GIS)

dashboard-fixed: setup install-dashboard
	@echo "$(BLUE)🌐 Starting FIXED Web Dashboard...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(DASHBOARD_FIXED)

run-full-gis: run-daemon run-gis-dashboard
	@echo "$(GREEN)🚀 Full SCADA platform with GIS Dashboard running$(NC)"

quick-start: run-enhanced

# =============================================================================
# STOP COMMANDS
# =============================================================================
stop-all:
	@echo "$(YELLOW)🛑 Stopping all components silently...$(NC)"
	@-pkill -f "$(SIMPLE_BROKER)" 2>/dev/null || true
	@-pkill -f "$(BROKER)" 2>/dev/null || true
	@-pkill -f "$(ML_DETECTOR)" 2>/dev/null || true
	@-pkill -f "$(DASHBOARD_GIS)" 2>/dev/null || true
	@-pkill -f "$(DASHBOARD_FIXED)" 2>/dev/null || true
	@-pkill -f "$(PROMISCUOUS_AGENT)" 2>/dev/null || true
	@-sudo pkill -f "$(PROMISCUOUS_AGENT)" 2>/dev/null || true
	@$(MAKE) kill-by-pids 2>/dev/null || true

kill-by-pids:
	@-if [ -f $(BROKER_PID) ]; then kill $$(cat $(BROKER_PID)) 2>/dev/null || true; rm -f $(BROKER_PID); fi
	@-if [ -f $(ML_PID) ]; then kill $$(cat $(ML_PID)) 2>/dev/null || true; rm -f $(ML_PID); fi
	@-if [ -f $(DASHBOARD_PID) ]; then kill $$(cat $(DASHBOARD_PID)) 2>/dev/null || true; rm -f $(DASHBOARD_PID); fi
	@-if [ -f $(AGENT_PID) ]; then kill $$(cat $(AGENT_PID)) 2>/dev/null || true; rm -f $(AGENT_PID); fi
	@-if [ -f $(GIS_PID) ]; then kill $$(cat $(GIS_PID)) 2>/dev/null || true; rm -f $(GIS_PID); fi

stop: stop-all
	@echo "$(YELLOW)🛑 Nuclear stop - All components stopped$(NC)"
	@if [ -f $(NUCLEAR_STOP_SCRIPT) ]; then \
		chmod +x $(NUCLEAR_STOP_SCRIPT); \
		./$(NUCLEAR_STOP_SCRIPT); \
	fi

stop-gis:
	@echo "$(YELLOW)🛑 Stopping GIS Dashboard...$(NC)"
	@-pkill -f "$(DASHBOARD_GIS)" 2>/dev/null || true
	@-if [ -f $(GIS_PID) ]; then kill $$(cat $(GIS_PID)) 2>/dev/null || true; rm -f $(GIS_PID); fi
	@echo "$(GREEN)✅ GIS Dashboard stopped$(NC)"

emergency-stop:
	@echo "$(RED)🚨 EMERGENCY STOP - Maximum aggressiveness$(NC)"
	@sudo pkill -9 -f "python.*promiscuous" 2>/dev/null || true
	@sudo pkill -9 -f "python.*broker" 2>/dev/null || true
	@sudo pkill -9 -f "python.*detector" 2>/dev/null || true
	@sudo pkill -9 -f "python.*dashboard" 2>/dev/null || true
	@sudo pkill -9 -f "uvicorn" 2>/dev/null || true
	@sudo lsof -ti :$(BROKER_PORT),$(BROKER_SECONDARY_PORT),$(DASHBOARD_PORT),$(GIS_DASHBOARD_PORT) | xargs sudo kill -9 2>/dev/null || true
	@echo "$(RED)💀 Emergency stop completed$(NC)"

verify-stop:
	@echo "$(BLUE)🔍 Verifying stop status...$(NC)"
	@echo "Active SCADA processes:"
	@ps aux | grep -E "(broker|detector|promiscuous|dashboard)" | grep -v grep || echo "✅ No SCADA processes active"
	@echo "Occupied SCADA ports:"
	@lsof -i :$(BROKER_PORT),$(BROKER_SECONDARY_PORT),$(DASHBOARD_PORT),$(GIS_DASHBOARD_PORT) 2>/dev/null || echo "✅ All SCADA ports free"

restart-nuclear: stop
	@sleep 3
	@$(MAKE) run-enhanced

restart-fixed: stop
	@sleep 3
	@$(MAKE) run-fixed

restart-gis: stop-gis
	@sleep 2
	@$(MAKE) run-gis-dashboard

# =============================================================================
# MONITORING AND STATUS
# =============================================================================
status:
	@echo "$(CYAN)📊 Upgraded Happiness - Project Status$(NC)"
	@echo "$(CYAN)======================================$(NC)"
	@echo "$(YELLOW)Virtual Environment:$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "  ✅ $(VENV_NAME) exists"; \
	else \
		echo "  ❌ $(VENV_NAME) not found"; \
	fi
	@echo ""
	@echo "$(YELLOW)Running Processes:$(NC)"
	@pgrep -f "$(SIMPLE_BROKER)" >/dev/null && echo "  🔌 Simple Broker: Running" || echo "  ⭕ Simple Broker: Stopped"
	@pgrep -f "$(BROKER)" >/dev/null && echo "  🔌 Smart Broker: Running" || echo "  ⭕ Smart Broker: Stopped"
	@pgrep -f "$(ML_DETECTOR)" >/dev/null && echo "  🤖 ML Detector: Running" || echo "  ⭕ ML Detector: Stopped"
	@pgrep -f "$(PROMISCUOUS_AGENT)" >/dev/null && echo "  🕵️  Promiscuous Agent: Running" || echo "  ⭕ Promiscuous Agent: Stopped"
	@pgrep -f "$(DASHBOARD_GIS)" >/dev/null && echo "  🌍 GIS Dashboard: Running (http://localhost:$(GIS_DASHBOARD_PORT))" || echo "  ⭕ GIS Dashboard: Stopped"
	@pgrep -f "$(DASHBOARD_FIXED)" >/dev/null && echo "  🌐 Fixed Dashboard: Running (http://localhost:$(DASHBOARD_PORT))" || echo "  ⭕ Fixed Dashboard: Stopped"
	@echo ""
	@echo "$(YELLOW)Network Ports:$(NC)"
	@lsof -i :$(BROKER_PORT) >/dev/null 2>&1 && echo "  🔌 Smart Broker ($(BROKER_PORT)): LISTENING" || echo "  ⭕ Smart Broker ($(BROKER_PORT)): NOT LISTENING"
	@lsof -i :$(BROKER_SIMPLE_PORT_OUT) >/dev/null 2>&1 && echo "  🔌 Simple Broker ($(BROKER_SIMPLE_PORT_OUT)): LISTENING" || echo "  ⭕ Simple Broker ($(BROKER_SIMPLE_PORT_OUT)): NOT LISTENING"
	@lsof -i :$(DASHBOARD_PORT) >/dev/null 2>&1 && echo "  🌐 Fixed Dashboard ($(DASHBOARD_PORT)): LISTENING" || echo "  ⭕ Fixed Dashboard ($(DASHBOARD_PORT)): NOT LISTENING"
	@lsof -i :$(GIS_DASHBOARD_PORT) >/dev/null 2>&1 && echo "  🌍 GIS Dashboard ($(GIS_DASHBOARD_PORT)): LISTENING" || echo "  ⭕ GIS Dashboard ($(GIS_DASHBOARD_PORT)): NOT LISTENING"

status-gis:
	@echo "$(CYAN)📊 GIS Dashboard Status:$(NC)"
	@if [ -f $(GIS_PID) ]; then \
		pid=$$(cat $(GIS_PID)); \
		if kill -0 $$pid 2>/dev/null; then \
			echo "✅ Running (PID: $$pid)"; \
			echo "🌐 URL: http://localhost:$(GIS_DASHBOARD_PORT)"; \
		else \
			echo "❌ Not running (stale PID)"; \
			rm -f $(GIS_PID); \
		fi; \
	else \
		echo "❌ Not running"; \
	fi
	@if [ -f $(GIS_LOG) ]; then \
		echo "📋 Recent logs:"; \
		tail -3 $(GIS_LOG) 2>/dev/null | sed 's/^/  /'; \
	fi

monitor:
	@echo "$(CYAN)📊 Platform Monitor$(NC)"
	@echo "$(CYAN)==================$(NC)"
	@$(MAKE) status
	@echo ""
	@echo "$(YELLOW)Recent Activity:$(NC)"
	@if [ -f $(BROKER_LOG) ]; then echo "Broker:"; tail -3 $(BROKER_LOG) | sed 's/^/  /'; fi
	@if [ -f $(GIS_LOG) ]; then echo "GIS:"; tail -3 $(GIS_LOG) | sed 's/^/  /'; fi

monitor-gis:
	@echo "$(CYAN)📊 GIS Dashboard Monitor$(NC)"
	@echo "$(CYAN)========================$(NC)"
	@$(MAKE) status-gis
	@echo ""
	@curl -s http://localhost:$(GIS_DASHBOARD_PORT)/api/stats 2>/dev/null | python3 -m json.tool || echo "   ❌ Dashboard API not available"

monitor-live:
	@echo "$(CYAN)📊 Live Monitor (Ctrl+C to exit)$(NC)"
	@watch -n 2 "make status"

# =============================================================================
# TESTING AND VALIDATION
# =============================================================================
verify:
	@echo "$(BLUE)🔍 Verifying system integrity...$(NC)"
	@for file in $(SIMPLE_BROKER) $(BROKER) $(ML_DETECTOR) $(PROMISCUOUS_AGENT) $(DASHBOARD_GIS); do \
		if [ -f "$$file" ]; then \
			echo "  ✅ $$file"; \
		else \
			echo "  ❌ $$file missing"; \
		fi \
	done

test-geolocation:
	@echo "$(BLUE)🧪 Testing IP geolocation...$(NC)"
	@if [ -f $(IP_GEOLOCATOR) ]; then \
		$(ACTIVATE) && $(PYTHON_VENV) $(IP_GEOLOCATOR); \
	else \
		echo "$(RED)❌ $(IP_GEOLOCATOR) not found$(NC)"; \
	fi

test-gis:
	@echo "$(BLUE)🧪 Testing GIS Dashboard...$(NC)"
	@if [ -f $(GIS_PID) ] && kill -0 $$(cat $(GIS_PID)) 2>/dev/null; then \
		echo "Testing health endpoint..."; \
		curl -s http://localhost:$(GIS_DASHBOARD_PORT)/health | python3 -m json.tool 2>/dev/null || echo "Health check failed"; \
		echo "✅ GIS Dashboard responding"; \
	else \
		echo "❌ GIS Dashboard not running"; \
		exit 1; \
	fi

test: verify
	@echo "$(BLUE)🧪 Running tests...$(NC)"
	@if [ -d "$(TEST_DIR)" ]; then \
		$(ACTIVATE) && $(PYTHON_VENV) -m pytest $(TEST_DIR); \
	else \
		echo "$(YELLOW)⚠️  No test directory found$(NC)"; \
	fi

# =============================================================================
# UTILITIES AND FIXES
# =============================================================================
fix-207:
	@echo "$(YELLOW)🔧 Fixing HTTP 207 Multi-Status errors...$(NC)"
	@$(MAKE) stop-all
	@sleep 2
	@-fuser -k $(DASHBOARD_PORT)/tcp 2>/dev/null || true
	@sleep 1
	@$(MAKE) run-fixed
	@echo "$(GREEN)✅ HTTP 207 fix applied!$(NC)"

diagnose:
	@echo "$(BLUE)🔍 Running comprehensive diagnostic...$(NC)"
	@if [ -f "$(DIAGNOSTIC_TOOL)" ]; then \
		$(ACTIVATE) && $(PYTHON_VENV) $(DIAGNOSTIC_TOOL); \
	else \
		echo "$(YELLOW)💡 Running basic diagnostic...$(NC)"; \
		$(MAKE) status; \
		$(MAKE) verify; \
	fi

fix-deps:
	@echo "$(BLUE)🔧 Fixing dependencies...$(NC)"
	@$(ACTIVATE) && $(PIP_VENV) install --upgrade pip
	@$(ACTIVATE) && $(PIP_VENV) install --force-reinstall -r requirements.txt

emergency-fix: clean setup install-all
	@echo "$(GREEN)🚑 Emergency recovery completed!$(NC)"

show-dashboard:
	@echo "$(BLUE)🌐 Opening dashboard...$(NC)"
	@which open >/dev/null && open http://localhost:$(GIS_DASHBOARD_PORT) || \
	 which xdg-open >/dev/null && xdg-open http://localhost:$(GIS_DASHBOARD_PORT) || \
	 echo "💡 Open manually: http://localhost:$(GIS_DASHBOARD_PORT)"

# =============================================================================
# LOGS AND MAINTENANCE
# =============================================================================
logs:
	@echo "$(CYAN)📋 Recent Logs$(NC)"
	@if [ -f $(BROKER_LOG) ]; then echo "Broker:"; tail -10 $(BROKER_LOG); fi
	@if [ -f $(GIS_LOG) ]; then echo "GIS:"; tail -10 $(GIS_LOG); fi

logs-gis:
	@echo "$(CYAN)📋 GIS Dashboard Logs:$(NC)"
	@if [ -f $(GIS_LOG) ]; then \
		tail -f $(GIS_LOG); \
	else \
		echo "❌ No GIS log file found"; \
	fi

show-logs:
	@echo "$(CYAN)📄 Live logs (Ctrl+C to exit):$(NC)"
	@tail -f $(LOGS_DIR)/*.out 2>/dev/null || echo "No log files found"

clean-gis:
	@echo "$(YELLOW)🧹 Cleaning GIS files...$(NC)"
	@$(MAKE) stop-gis
	@rm -f ip_cache.db $(GIS_LOG) $(GIS_PID)
	@echo "$(GREEN)✅ GIS files cleaned$(NC)"

backup:
	@echo "$(BLUE)💾 Creating backup...$(NC)"
	@mkdir -p backups
	@tar -czf backups/upgraded_happiness_backup_$$(date +%Y%m%d_%H%M%S).tar.gz \
		--exclude=$(VENV_NAME) --exclude=backups --exclude=__pycache__ --exclude=.git .
	@echo "$(GREEN)✅ Backup created$(NC)"

# =============================================================================
# QUICK COMMANDS
# =============================================================================
qt: test
qr: run-enhanced
qv: verify
qs: status
qm: monitor
qd: show-dashboard

# GIS Quick Commands
gis: run-gis-dashboard
gis-bg:
	@$(ACTIVATE) && nohup $(PYTHON_VENV) $(DASHBOARD_GIS) > $(GIS_LOG) 2>&1 & echo $$! > $(GIS_PID)
	@echo "$(GREEN)✅ GIS Dashboard started in background$(NC)"
gis-stop: stop-gis
gis-status: status-gis
gis-logs: logs-gis
gis-clean: clean-gis
gis-test: test-gis

# =============================================================================
# ADDITIONAL HELP SECTIONS
# =============================================================================
help-gis:
	@echo "$(CYAN)🌍 GIS Dashboard Help$(NC)"
	@echo "$(CYAN)=====================$(NC)"
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
	@echo "$(YELLOW)Features:$(NC)"
	@echo "  • Geographic visualization of security events"
	@echo "  • Real-time IP geolocation"
	@echo "  • Interactive Leaflet maps"
	@echo "  • WebSocket real-time updates"
	@echo "  • ZeroMQ integration"
	@echo ""
	@echo "$(YELLOW)URL:$(NC) http://localhost:$(GIS_DASHBOARD_PORT)"

help-207:
	@echo "$(CYAN)💊 HTTP 207 Multi-Status Help$(NC)"
	@echo "$(CYAN)==============================$(NC)"
	@echo ""
	@echo "$(YELLOW)What is HTTP 207?$(NC)"
	@echo "HTTP 207 Multi-Status is a WebDAV response indicating"
	@echo "multiple resources were processed with different statuses."
	@echo ""
	@echo "$(YELLOW)Quick Fix:$(NC)"
	@echo "  $(GREEN)make fix-207$(NC)        - Apply automatic fixes"
	@echo "  $(GREEN)make emergency-stop$(NC) - Force restart everything"
	@echo "  $(GREEN)make run-fixed$(NC)      - Start with fixes applied"

info:
	@echo "$(CYAN)🛡️ Upgraded Happiness - System Information$(NC)"
	@echo "$(CYAN)===========================================$(NC)"
	@echo ""
	@echo "$(YELLOW)Features:$(NC)"
	@echo "  🌍 IP Geolocation with interactive maps"
	@echo "  📡 Real-time network traffic capture"
	@echo "  🤖 Machine Learning anomaly detection"
	@echo "  🔌 ZeroMQ high-performance messaging"
	@echo "  🌐 WebSocket real-time dashboard"
	@echo "  💾 Local cache for geolocation data"
	@echo ""
	@echo "$(YELLOW)Endpoints:$(NC)"
	@echo "  GIS Dashboard:    http://localhost:$(GIS_DASHBOARD_PORT)"
	@echo "  Fixed Dashboard:  http://localhost:$(DASHBOARD_PORT)"
	@echo "  API Stats:        http://localhost:$(GIS_DASHBOARD_PORT)/api/stats"
	@echo "  WebSocket:        ws://localhost:$(GIS_DASHBOARD_PORT)/ws"
	@echo ""
	@echo "$(YELLOW)Key Files:$(NC)"
	@echo "  $(DASHBOARD_GIS)     - Enhanced GIS dashboard"
	@echo "  $(IP_GEOLOCATOR)     - IP geolocation service"
	@echo "  ip_cache.db          - Geolocation cache database"

# Default target
all: setup install-all verify
	@echo "$(GREEN)✅ Upgraded Happiness setup completed successfully!$(NC)"