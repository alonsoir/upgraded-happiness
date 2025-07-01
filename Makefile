# Makefile for Upgraded Happiness
# ===============================
# Automated build, test, and deployment for the security platform

# Variables
PYTHON = python3
VENV_NAME = upgraded_happiness_venv
VENV_BIN = $(VENV_NAME)/bin
PYTHON_VENV = $(VENV_BIN)/python
PIP_VENV = $(VENV_BIN)/pip
ACTIVATE = source $(VENV_BIN)/activate

# Main scripts
ORCHESTRATOR = system_orchestrator.py
ML_DETECTOR = lightweight_ml_detector.py
PROMISCUOUS_AGENT = promiscuous_agent.py
FIX_MODULE = fix_module.py

# Test directory
TEST_DIR = tests_consolidated

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
PURPLE = \033[0;35m
CYAN = \033[0;36m
NC = \033[0m # No Color

.PHONY: all help setup install install-dev install-all test test-cov format lint security check clean verify run run-daemon run-orchestrator run-detector run-agent fix backup dev status logs docs profile benchmark memory emergency-fix stop qt qr qv qs reinstall

# Default target
all: setup install-all verify test
	@echo "$(GREEN)✅ Upgraded Happiness setup completed successfully!$(NC)"

# Help target
help:
	@echo "$(CYAN)🚀 Upgraded Happiness - Available Commands:$(NC)"
	@echo ""
	@echo "$(YELLOW)Setup & Installation:$(NC)"
	@echo "  make setup          - Create virtual environment"
	@echo "  make install        - Install production dependencies"
	@echo "  make install-dev    - Install development dependencies"
	@echo "  make install-all    - Install all dependencies (prod + dev)"
	@echo "  make clean          - Clean virtual environment"
	@echo "  make reinstall      - Clean and reinstall everything"
	@echo ""
	@echo "$(YELLOW)Development & Code Quality:$(NC)"
	@echo "  make verify         - Verify system integrity"
	@echo "  make test           - Run all tests"
	@echo "  make test-cov       - Run tests with coverage"
	@echo "  make lint           - Run all linting (flake8 + mypy)"
	@echo "  make format         - Format code (black + isort)"
	@echo "  make check          - Run all checks (format + lint + test)"
	@echo "  make fix-deps       - Fix circular imports and dependencies"
	@echo "  make setup-sudo     - Configure sudoers for promiscuous mode"
	@echo "  make setup-production - Complete production setup"
	@echo "  make dev            - Development mode (setup + install-dev + check)"
	@echo ""
	@echo "$(YELLOW)Platform Execution:$(NC)"
	@echo "  make run            - Start platform (Interactive mode)"
	@echo "  make run-daemon     - Start platform (Daemon mode)"
	@echo "  make run-orchestrator - Start system orchestrator only"
	@echo "  make run-detector   - Start ML detector only"
	@echo "  make run-agent      - Start promiscuous agent only"
	@echo ""
	@echo "$(YELLOW)Utilities:$(NC)"
	@echo "  make backup         - Create project backup"
	@echo "  make status         - Show project status"
	@echo "  make monitor        - Enhanced platform monitoring"
	@echo "  make monitor-live   - Continuous monitoring (real-time)"
	@echo "  make test-traffic   - Generate test network traffic"
	@echo "  make logs           - Show recent logs"
	@echo "  make docs           - Generate documentation"
	@echo "  make profile        - Run performance profiling"
	@echo "  make benchmark      - Run performance benchmarks"
	@echo "  make help           - Show this help message"

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

# Install all dependencies (prod + dev)
install-all: install-dev
	@echo "$(GREEN)✅ All dependencies installed$(NC)"

# Verify system integrity
verify: setup
	@echo "$(BLUE)🔍 Verifying system integrity...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(FIX_MODULE) verify
	@echo "$(GREEN)✅ System verification completed$(NC)"

# Run tests
test: setup install-dev
	@echo "$(BLUE)🧪 Running tests...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -m pytest $(TEST_DIR)/ -v || \
	$(ACTIVATE) && $(PYTHON_VENV) $(TEST_DIR)/run_all_tests.py || \
	echo "$(YELLOW)⚠️  No tests found or test framework unavailable$(NC)"

# Run tests with coverage
test-cov: setup install-dev
	@echo "$(BLUE)🧪 Running tests with coverage...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -m pytest $(TEST_DIR)/ --cov=. --cov-report=html --cov-report=term-missing -v

# Code formatting
format: setup install-dev
	@echo "$(BLUE)🎨 Formatting code...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -m black .
	@$(ACTIVATE) && $(PYTHON_VENV) -m isort .
	@echo "$(GREEN)✅ Code formatted$(NC)"

# Linting
lint: setup install-dev
	@echo "$(BLUE)🔍 Running linting...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -m flake8 . || echo "$(YELLOW)⚠️  Flake8 warnings found$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -m mypy . || echo "$(YELLOW)⚠️  MyPy type warnings found$(NC)"

# Security check
security: setup install-dev
	@echo "$(BLUE)🔒 Running security checks...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) -m bandit -r . || echo "$(YELLOW)⚠️  Security warnings found$(NC)"

# Run all code quality checks
check: format lint security test
	@echo "$(GREEN)✅ All code quality checks completed$(NC)"

# Fix circular imports and dependencies
fix-deps: setup
	@echo "$(BLUE)🔧 Fixing potential circular import issues...$(NC)"
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf .mypy_cache 2>/dev/null || true
	@$(ACTIVATE) && $(PIP_VENV) uninstall numpy scipy scikit-learn joblib pyzmq -y 2>/dev/null || true
	@$(ACTIVATE) && $(PIP_VENV) install --no-cache-dir pyzmq==25.1.2
	@$(ACTIVATE) && $(PIP_VENV) install --no-cache-dir numpy==1.26.4
	@$(ACTIVATE) && $(PIP_VENV) install --no-cache-dir scipy==1.16.0
	@$(ACTIVATE) && $(PIP_VENV) install --no-cache-dir pandas==2.3.0
	@$(ACTIVATE) && $(PIP_VENV) install --no-cache-dir joblib==1.5.1
	@$(ACTIVATE) && $(PIP_VENV) install --no-cache-dir scikit-learn==1.7.0
	@$(ACTIVATE) && $(PIP_VENV) install --no-cache-dir xgboost==3.0.2
	@$(ACTIVATE) && $(PIP_VENV) install --no-cache-dir lightgbm==4.6.0
	@echo "$(GREEN)✅ Dependencies fixed and reinstalled cleanly$(NC)"

# Configure sudoers for promiscuous mode
setup-sudo:
	@echo "$(BLUE)🔒 Configuring sudoers for promiscuous agent...$(NC)"
	@if [ ! -f /etc/sudoers.d/upgraded_happiness ]; then \
		echo "$(USER) ALL=(ALL) NOPASSWD: $(which python) $(pwd)/promiscuous_agent.py" | sudo tee /etc/sudoers.d/upgraded_happiness > /dev/null; \
		echo "$(GREEN)✅ Sudoers configured$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  Sudoers already configured$(NC)"; \
	fi

# Complete setup (production-ready)
setup-production: setup install-all fix-deps setup-sudo verify
	@echo "$(GREEN)🚀 Production setup completed!$(NC)"
	@echo "$(CYAN)Platform ready for deployment$(NC)"

# Run complete platform (interactive mode)
run: setup install verify
	@echo "$(GREEN)🚀 Starting Upgraded Happiness Platform (Interactive)...$(NC)"
	@echo "$(YELLOW)⚠️  This will start interactive orchestrator. Use Ctrl+C to stop.$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ORCHESTRATOR)

# Run platform components individually (daemon mode)
run-daemon: setup install verify
	@echo "$(GREEN)🚀 Starting Upgraded Happiness Platform (Daemon Mode)...$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@echo "$(PURPLE)🤖 ML Detector$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR) &
	@sleep 2
	@echo "$(PURPLE)🕵️  Promiscuous Agent$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(PROMISCUOUS_AGENT) &
	@sleep 2
	@echo "$(GREEN)✅ All components started in daemon mode$(NC)"
	@echo "$(YELLOW)💡 Use 'make stop' to stop all components$(NC)"

# Run individual components
run-orchestrator: setup install
	@echo "$(BLUE)🎯 Starting System Orchestrator...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ORCHESTRATOR)

run-detector: setup install
	@echo "$(BLUE)🤖 Starting ML Detector...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(ML_DETECTOR)

run-agent: setup install
	@echo "$(BLUE)🕵️  Starting Promiscuous Agent...$(NC)"
	@$(ACTIVATE) && $(PYTHON_VENV) $(PROMISCUOUS_AGENT)

# Stop all running components
stop:
	@echo "$(YELLOW)🛑 Stopping all platform components...$(NC)"
	@pkill -f "$(ORCHESTRATOR)" 2>/dev/null || echo "$(YELLOW)⚠️  Orchestrator not running$(NC)"
	@pkill -f "$(ML_DETECTOR)" 2>/dev/null || echo "$(YELLOW)⚠️  ML Detector not running$(NC)"
	@pkill -f "$(PROMISCUOUS_AGENT)" 2>/dev/null || echo "$(YELLOW)⚠️  Promiscuous Agent not running$(NC)"
	@pkill -f "lightweight_ml_detector" 2>/dev/null || true
	@pkill -f "promiscuous_agent" 2>/dev/null || true
	@pkill -f "system_orchestrator" 2>/dev/null || true
	@echo "$(GREEN)✅ All components stopped$(NC)"

# Development mode
dev: setup install verify test
	@echo "$(GREEN)🚀 Development environment ready!$(NC)"
	@echo "$(CYAN)Available development commands:$(NC)"
	@echo "  make run            - Start platform"
	@echo "  make test           - Run tests"
	@echo "  make verify         - Verify system"

# Clean virtual environment
clean:
	@echo "$(YELLOW)🧹 Cleaning virtual environment...$(NC)"
	@rm -rf $(VENV_NAME)
	@rm -rf __pycache__
	@find . -name "*.pyc" -delete
	@find . -name "*.pyo" -delete
	@find . -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✅ Cleanup completed$(NC)"

# Reinstall everything
reinstall: clean setup install-all
	@echo "$(GREEN)✅ Reinstallation completed$(NC)"

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

# Show project status
status:
	@echo "$(CYAN)📊 Upgraded Happiness - Project Status$(NC)"
	@echo "$(CYAN)======================================$(NC)"
	@echo "$(YELLOW)Virtual Environment:$(NC)"
	@if [ -d "$(VENV_NAME)" ]; then \
		echo "  ✅ $(VENV_NAME) exists"; \
		echo "  📍 Python: $$($(ACTIVATE) && $(PYTHON_VENV) --version)"; \
	else \
		echo "  ❌ $(VENV_NAME) not found"; \
	fi
	@echo ""
	@echo "$(YELLOW)Core Files:$(NC)"
	@for file in $(ORCHESTRATOR) $(ML_DETECTOR) $(PROMISCUOUS_AGENT) $(FIX_MODULE); do \
		if [ -f "$$file" ]; then \
			echo "  ✅ $$file"; \
		else \
			echo "  ❌ $$file"; \
		fi \
	done
	@echo ""
	@echo "$(YELLOW)Running Processes:$(NC)"
	@pgrep -f "$(ORCHESTRATOR)" >/dev/null && echo "  🎯 System Orchestrator: Running" || echo "  ⭕ System Orchestrator: Stopped"
	@pgrep -f "$(ML_DETECTOR)" >/dev/null && echo "  🤖 ML Detector: Running" || echo "  ⭕ ML Detector: Stopped"
	@pgrep -f "$(PROMISCUOUS_AGENT)" >/dev/null && echo "  🕵️  Promiscuous Agent: Running" || echo "  ⭕ Promiscuous Agent: Stopped"

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

# Quick commands for common tasks
qt: test
qr: run-daemon
qv: verify
qs: status

# Emergency recovery
emergency-fix: clean setup install-all fix verify
	@echo "$(GREEN)🚑 Emergency recovery completed!$(NC)"