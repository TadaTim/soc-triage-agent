PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: venv install lint typecheck test test-unit test-integration eval schemas tree migrate-sql

venv:
	python3 -m venv .venv
	$(PIP) install -q --upgrade pip
	$(PIP) install -q -e ".[dev]"

install:
	$(PIP) install -q -e ".[dev]"

lint:
	.venv/bin/ruff check apps packages tests tools
	.venv/bin/ruff format --check apps packages tests tools

format:
	.venv/bin/ruff check --fix apps packages tests tools
	.venv/bin/ruff format apps packages tests tools

typecheck:
	.venv/bin/mypy apps packages

test: test-unit

test-unit:
	$(PY) -m pytest tests/unit tests/contract -q

test-integration:
	$(PY) -m pytest tests/integration -q

coverage-enrich:
	$(PY) -m pytest tests/unit tests/contract -q --cov=packages.enrich --cov-report=term-missing --cov-fail-under=95

eval:
	$(PY) -m packages.evals

schemas:
	$(PY) tools/dump_schemas.py --check

migrate-sql:
	.venv/bin/alembic -c packages/schemas/alembic.ini upgrade head --sql > /tmp/soc_migrations.sql && wc -l /tmp/soc_migrations.sql

tree:
	find apps packages -type f | sort
