PY ?= python3
PI ?= $(shell cat .pi 2>/dev/null || echo tvgw)  # ssh host of the gateway; put yours in .pi (gitignored)

.PHONY: dev lint test gate mutmut hardware deploy clean

dev:            ## install the package editable with dev extras
	$(PY) -m pip install -e ".[dev]"

lint:           ## ruff check + format check
	ruff check src tests
	ruff format --check src tests

test:           ## unit tests
	$(PY) -m pytest

gate:           ## exactly what CI runs: lint, format check, unit tests, profile lint
	ruff check src tests
	ruff format --check src tests
	$(PY) -m pytest -q

mutmut:         ## mutation testing of the unit tests (slow)
	mutmut run
	mutmut results

hardware:       ## run the hardware suite on the Pi against the live gateway
	ssh $(PI) 'cd /opt/tvgw/src && sudo /opt/tvgw-venv/bin/python -m pytest -m hardware tests/hardware -q -p no:cacheprovider'

deploy:         ## sync the repo to the Pi and (re)install
	rsync -a --delete --exclude .git --exclude '*.db' --exclude build --exclude '*.egg-info' \
		--exclude __pycache__ --exclude .pytest_cache --exclude .ruff_cache --exclude mutants ./ $(PI):/opt/tvgw/src/
	ssh $(PI) 'cd /opt/tvgw/src/deploy && sudo ./install.sh'

clean:
	rm -rf build dist .pytest_cache .ruff_cache .mutmut-cache mutants src/*.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
