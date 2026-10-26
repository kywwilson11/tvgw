PY ?= python3
PI ?= kylepi5

.PHONY: dev lint test mutmut hardware deploy clean

dev:            ## install the package editable with dev extras
	$(PY) -m pip install -e ".[dev]"

lint:           ## ruff check + format check
	ruff check src tests
	ruff format --check src tests

test:           ## unit tests
	$(PY) -m pytest

mutmut:         ## mutation testing of the unit tests (slow)
	mutmut run
	mutmut results

hardware:       ## run the hardware suite on the Pi against the live gateway
	ssh $(PI) 'cd /opt/tvgw/src && sudo /opt/tvgw-venv/bin/python -m pytest -m hardware tests/hardware -q -p no:cacheprovider'

deploy:         ## sync the repo to the Pi and (re)install
	rsync -a --delete --exclude .git --exclude '*.db' ./ $(PI):/opt/tvgw/src/
	ssh $(PI) 'cd /opt/tvgw/src/deploy && sudo ./install.sh'

clean:
	rm -rf build dist .pytest_cache .ruff_cache .mutmut-cache mutants src/*.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
