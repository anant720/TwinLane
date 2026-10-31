.PHONY: setup lint format type test bench demo docs clean help

help:
	@echo "TwinLane Build and Quality Automation"
	@echo "====================================="
	@echo "make setup    - Install dependencies in editable mode with dev tools"
	@echo "make lint     - Run ruff linter"
	@echo "make format   - Run ruff formatter"
	@echo "make type     - Run strict mypy type checking"
	@echo "make test     - Run pytest with coverage"
	@echo "make bench    - Run benchmark attack evaluation"
	@echo "make demo     - Launch side-by-side interactive demo"
	@echo "make docs     - Check documentation links and integrity"
	@echo "make clean    - Clean build, coverage and cache artifacts"

setup:
	python -m pip install --upgrade pip
	pip install -e ".[dev]"

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

type:
	mypy --strict src/

test:
	pytest --cov=twinlane --cov-report=term-missing tests/

bench:
	python -m twinlane.cli bench --attacks bench/attacks --output bench/results/latest.json

demo:
	python -m twinlane.cli run-demo

docs:
	python -c "import os; print('Validating doc files...'); assert os.path.exists('docs/research/gap-analysis.md')"

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov .mypy_cache .ruff_cache
