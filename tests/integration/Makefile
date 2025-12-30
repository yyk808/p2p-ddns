# Makefile for p2p-ddns Integration Tests
# Provides convenient targets for common testing operations

.PHONY: help build start stop clean test validate logs status

# Default target
.DEFAULT_GOAL := help

# Variables
SCRIPT_DIR := scripts
NETWORK_DIR := networks

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

help: ## Show this help message
	@echo "p2p-ddns Integration Test Framework"
	@echo "===================================="
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Setup and Environment
setup: ## Set up the test environment
	@echo "$(BLUE)Setting up test environment...$(NC)"
	@chmod +x $(SCRIPT_DIR)/*.sh
	@chmod +x $(NETWORK_DIR)/*.sh
	@chmod +x quick-test.sh
	@mkdir -p logs reports volumes
	@echo "$(GREEN)Setup completed$(NC)"

# Docker Images
build: ## Build Docker images for testing
	@echo "$(BLUE)Building Docker images...$(NC)"
	@$(SCRIPT_DIR)/build-images-simple.sh build --tag test

build-no-cache: ## Build Docker images without cache
	@echo "$(BLUE)Building Docker images (no cache)...$(NC)"
	@$(SCRIPT_DIR)/build-images-simple.sh build --tag test
	@docker system prune -f

# Container Management
start: ## Start the test environment
	@echo "$(BLUE)Starting test environment...$(NC)"
	@./quick-test.sh start

stop: ## Stop the test environment
	@echo "$(BLUE)Stopping test environment...$(NC)"
	@./quick-test.sh stop

restart: stop start ## Restart the test environment

# Testing
test: ## Run quick smoke test
	@echo "$(BLUE)Running quick smoke test...$(NC)"
	@./quick-test.sh quick

test-basic: ## Run basic functionality test
	@echo "$(BLUE)Running basic functionality test...$(NC)"
	@./quick-test.sh basic

test-network: ## Run network topology test
	@echo "$(BLUE)Running network topology test...$(NC)"
	@./quick-test.sh network

test-fault: ## Run fault recovery test
	@echo "$(BLUE)Running fault recovery test...$(NC)"
	@./quick-test.sh fault

test-full: ## Run full test suite
	@echo "$(BLUE)Running full test suite...$(NC)"
	@./quick-test.sh full --timeout 1800

test-debug: ## Run tests with debug logging
	@echo "$(BLUE)Running tests with debug logging...$(NC)"
	@./quick-test.sh quick --debug

# Validation and Reporting
validate: ## Validate test results
	@echo "$(BLUE)Validating test results...$(NC)"
	@$(SCRIPT_DIR)/validate.sh

validate-json: ## Generate JSON validation report
	@echo "$(BLUE)Generating JSON validation report...$(NC)"
	@$(SCRIPT_DIR)/validate.sh --output json

validate-html: ## Generate HTML validation report
	@echo "$(BLUE)Generating HTML validation report...$(NC)"
	@$(SCRIPT_DIR)/validate.sh --output html

validate-strict: ## Run strict validation
	@echo "$(BLUE)Running strict validation...$(NC)"
	@$(SCRIPT_DIR)/validate.sh --strict

# Monitoring and Debugging
status: ## Show test environment status
	@echo "$(BLUE)Test environment status:$(NC)"
	@./quick-test.sh status

logs: ## Show container logs
	@echo "$(BLUE)Container logs:$(NC)"
	@./quick-test.sh logs

logs-primary: ## Show primary node logs
	@echo "$(BLUE)Primary node logs:$(NC)"
	@cd .. && docker-compose logs primary-node

logs-daemons: ## Show daemon node logs
	@echo "$(BLUE)Daemon node logs:$(NC)"
	@cd .. && docker-compose logs daemon-a1 daemon-a2 daemon-b1 daemon-b2

logs-clients: ## Show client node logs
	@echo "$(BLUE)Client node logs:$(NC)"
	@cd .. && docker-compose logs client-a1 client-b1

shell-primary: ## Open shell in primary node
	@echo "$(BLUE)Opening shell in primary node...$(NC)"
	@cd .. && docker-compose exec primary-node /bin/bash

shell-daemon: ## Open shell in daemon-a1
	@echo "$(BLUE)Opening shell in daemon-a1...$(NC)"
	@cd .. && docker-compose exec daemon-a1 /bin/bash

monitor: ## Monitor test environment in real-time
	@echo "$(BLUE)Starting real-time monitoring...$(NC)"
	@watch -n 5 './quick-test.sh status'

# Network Operations
isolate-subnet-a: ## Isolate subnet-a for testing
	@echo "$(YELLOW)Isolating subnet-a...$(NC)"
	@$(NETWORK_DIR)/network-control.sh isolate-network subnet-a

restore-subnet-a: ## Restore subnet-a connectivity
	@echo "$(GREEN)Restoring subnet-a connectivity...$(NC)"
	@$(NETWORK_DIR)/network-control.sh restore-network subnet-a

isolate-primary: ## Isolate primary node for testing
	@echo "$(YELLOW)Isolating primary node...$(NC)"
	@$(NETWORK_DIR)/network-control.sh isolate-container primary-node

restore-primary: ## Restore primary node connectivity
	@echo "$(GREEN)Restoring primary node connectivity...$(NC)"
	@$(NETWORK_DIR)/network-control.sh restore-container primary-node

# Cleanup
clean: ## Clean up test environment
	@echo "$(BLUE)Cleaning up test environment...$(NC)"
	@./quick-test.sh clean

clean-all: ## Clean up everything including Docker resources
	@echo "$(BLUE)Cleaning up all resources...$(NC)"
	@./quick-test.sh clean
	@docker system prune -f
	@docker volume prune -f

# Development and CI
ci-test: ## Run CI test suite
	@echo "$(BLUE)Running CI test suite...$(NC)"
	@./quick-test.sh full --timeout 1800 --no-build

ci-validate: ## Run CI validation
	@echo "$(BLUE)Running CI validation...$(NC)"
	@$(SCRIPT_DIR)/validate.sh --output json --strict

ci: build ci-test ci-validate ## Run complete CI pipeline

# Development helpers
dev-setup: setup build ## Complete development setup
	@echo "$(GREEN)Development setup completed$(NC)"

dev-test: test validate ## Run test and validation
	@echo "$(GREEN)Development test completed$(NC)"

dev-watch: ## Watch for changes and re-run tests
	@echo "$(BLUE)Watching for changes...$(NC)"
	@while true; do \
		find ../src -name "*.rs" | xargs ls -la 2>/dev/null | head -1 > /dev/null && \
		echo "$(YELLOW)Changes detected, running tests...$(NC)" && \
		make test && \
		echo "$(GREEN)Tests completed$(NC)" || \
		echo "$(RED)Tests failed$(NC)"; \
		sleep 10; \
	done

# Performance and Stress
stress-test: ## Run stress test
	@echo "$(BLUE)Running stress test...$(NC)"
	@$(SCRIPT_DIR)/test-scenarios.sh --scenario performance-stress --timeout 300

perf-monitor: ## Monitor performance metrics
	@echo "$(BLUE)Monitoring performance metrics...$(NC)"
	@watch -n 2 'docker stats --no-stream'

# Network Testing
network-test: ## Run comprehensive network tests
	@echo "$(BLUE)Running comprehensive network tests...$(NC)"
	@make test-network
	@sleep 10
	@make isolate-subnet-a
	@sleep 30
	@make restore-subnet-a
	@sleep 10
	@make validate

# Utilities
check-deps: ## Check if all dependencies are available
	@echo "$(BLUE)Checking dependencies...$(NC)"
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)Docker is required$(NC)"; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1 || { echo "$(RED)Docker Compose is required$(NC)"; exit 1; }
	@echo "$(GREEN)All dependencies available$(NC)"

version: ## Show version information
	@echo "$(BLUE)p2p-ddns Integration Test Framework$(NC)"
	@echo "Docker: $$(docker --version)"
	@echo "Docker Compose: $$(docker-compose --version 2>/dev/null || docker compose version)"
	@echo "Make: $$(make --version | head -1)"
	@echo "Shell: $$SHELL"

# Quick aliases (for convenience)
q: test ## Quick test
b: build ## Build images
s: status ## Show status
l: logs ## Show logs
c: clean ## Clean up

# Help for specific topics
help-scenarios: ## Show available test scenarios
	@echo "$(BLUE)Available test scenarios:$(NC)"
	@$(SCRIPT_DIR)/test-scenarios.sh --list

help-network: ## Show network control options
	@echo "$(BLUE)Network control options:$(NC)"
	@$(NETWORK_DIR)/network-control.sh

help-validate: ## Show validation options
	@echo "$(BLUE)Validation options:$(NC)"
	@$(SCRIPT_DIR)/validate.sh --help