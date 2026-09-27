.PHONY: install dev lint test test-cov clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

fmt:
	ruff format src/ tests/
	ruff check --fix src/ tests/

test:
	pytest tests/

test-cov:
	pytest tests/ --cov=simaudit --cov-report=term-missing

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete
	rm -rf .pytest_cache .ruff_cache dist build *.egg-info
