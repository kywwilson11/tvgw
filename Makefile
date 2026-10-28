PY ?= python3
# ssh host of the gateway; put yours in .pi (gitignored) or pass PI=<host>
PI ?= $(shell cat .pi 2>/dev/null || echo tvgw)

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

hardware:       ## run the hardware suite on the Pi against the live gateway, under the install lock
	ssh $(PI) 'cd /opt/tvgw/src && sudo flock -w 600 /run/tvgw/install.lock /opt/tvgw-venv/bin/python -m pytest -m hardware tests/hardware -q -p no:cacheprovider'

deploy:         ## sync the repo to a staging copy on the Pi, then replace /opt/tvgw/src and install under the install lock
	rsync -a --delete --exclude-from=deploy/rsync.exclude ./ $(PI):tvgw-deploy/
	ssh $(PI) 'sudo tvgw-deploy/deploy/sync-install.sh'

backup:         ## pull the checked store copies from the Pi into ./backups/ (never committed)
	rsync -a --rsync-path="sudo rsync" $(PI):/var/lib/tvgw/backup/ backups/

clean:
	rm -rf build dist .pytest_cache .ruff_cache .mutmut-cache mutants src/*.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
