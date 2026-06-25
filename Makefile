# BehaveGuard - developer task runner
#
# eBPF instrumentation needs root, so `run` and integration tests use sudo.
# Unit tests, lint, typecheck, and build run unprivileged.

.PHONY: install dev test test-unit test-integration lint format typecheck clean build docker run check

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

lint:
	ruff check behaveguard/ tests/

format:
	black behaveguard/ tests/
	ruff check --fix behaveguard/ tests/

typecheck:
	mypy behaveguard/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	rm -f .coverage
	rm -rf htmlcov/ dist/ build/
	find . -type d -name '*.egg-info' -exec rm -rf {} +

build:
	python -m build

docker:
	docker-compose build

run:
	sudo behaveguard run

check: lint typecheck test
	@echo "All checks passed!"
