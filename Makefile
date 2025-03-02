.PHONY: lint run install clean test

PYTHON := poetry run python
FLAKE8 := poetry run flake8
BLACK := poetry run black
ISORT := poetry run isort
MYPY := poetry run mypy

lint: 
	$(ISORT) --check .
	$(BLACK) --check .
	$(FLAKE8) .
	$(MYPY) .

run:
	$(PYTHON) api.py

install:
	poetry install --no-root

clean:
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete
	rm -rf .mypy_cache .venv

test:
	$(PYTHON) test.py