DOCKER = docker
COMPOSE = docker compose

.PHONY: help up down logs clean build dev test-contract coverage-contract test-frontend lint-frontend typecheck
.PHONY: help up down build test-contract coverage-contract lint-frontend dev clean monitoring-up monitoring-down 

COMPOSE_MONITORING = $(COMPOSE) -f docker-compose.yml -f monitoring/docker-compose.monitoring.yml

help:
	@echo "StellarWork Development Commands"
	@echo "================================"
	@echo ""
	@echo "Docker Compose (Recommended):"
	@echo "  make up               Start all services (frontend + local Stellar + contract builder)"
	@echo "  make down             Stop all services (preserves volumes)"
	@echo "  make logs             View logs from all services (follow mode)"
	@echo "  make logs-stellar     View Stellar service logs"
	@echo "  make logs-frontend    View frontend service logs"
	@echo "  make clean            Remove all services and volumes (fresh start)"
	@echo ""
	@echo "Testing (with Docker):"
	@echo "  make test-contract    Run contract unit tests in Docker"
	@echo "  make coverage-contract Run contract coverage analysis"
	@echo "  make test-frontend    Run frontend tests in Docker"
	@echo ""
	@echo "Building and Development (with Docker):"
	@echo "  make build            Build frontend production bundle in Docker"
	@echo "  make lint-frontend    Run ESLint on frontend in Docker"
	@echo "  make typecheck        Run TypeScript type checking"
	@echo ""
	@echo "Development (without Docker):"
	@echo "  make dev              Start frontend dev server locally (no Docker)"
	@echo ""
	@echo "For detailed setup and troubleshooting, see: docs/DOCKER_COMPOSE_SETUP.md"
	@echo "make up               Start all services (frontend + local Stellar)"
	@echo "make down             Stop all services"
	@echo "make build            Build frontend for production"
	@echo "make dev              Start frontend dev server (without Docker)"
	@echo "make test-contract    Run contract unit tests"
	@echo "make coverage-contract Run contract test coverage analysis"
	@echo "make test-frontend    Run frontend unit tests"
	@echo "make lint-frontend    Run ESLint on frontend"
	@echo "make typecheck        Run TypeScript type checking"
	@echo "make monitoring-up    Start Prometheus + Grafana + Alertmanager"
	@echo "make monitoring-down  Stop the monitoring stack"
	@echo "make clean            Remove Docker volumes and cached data"

up:
	@echo "Starting all services..."
	$(COMPOSE) up

down:
	@echo "Stopping services..."
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

logs-stellar:
	$(COMPOSE) logs -f stellar

logs-frontend:
	$(COMPOSE) logs -f frontend

build:
	$(COMPOSE) exec frontend npm run build

dev:
	cd frontend && npm run dev

test-contract:
	$(COMPOSE) exec contract-builder bash -c "cd /workspace/contracts/escrow && cargo test"

coverage-contract:
	$(COMPOSE) exec contract-builder bash -c "cd /workspace && ./contracts/coverage.sh"

test-frontend:
	$(COMPOSE) exec frontend npm test

lint-frontend:
	$(COMPOSE) exec frontend npm run lint

typecheck:
	$(COMPOSE) exec frontend npm run typecheck

monitoring-up:
	$(COMPOSE_MONITORING) up -d
	@echo "Grafana: http://localhost:3001 (admin/admin) | Prometheus: http://localhost:9090"

monitoring-down:
	$(COMPOSE_MONITORING) down

clean:
	@echo "Cleaning up all containers and volumes..."
	$(COMPOSE) down -v
	cd frontend && rm -rf .next node_modules 2>/dev/null || true
