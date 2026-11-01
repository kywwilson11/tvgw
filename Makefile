PY ?= python3
# ssh host of the gateway; put yours in .pi (gitignored) or pass PI=<host>
PI ?= $(shell cat .pi 2>/dev/null || echo tvgw)
UV ?= uv
# (packaging) the uv `make lock` resolves with: another version may resolve or annotate the locks
# differently, so a different one is refused rather than used
UV_VERSION := 0.13.1

.PHONY: dev lint test gate mutmut hardware deploy backup clean lock wheel deb

dev:            ## install the package editable with dev extras
	$(PY) -m pip install -e ".[dev]"

lint:           ## ruff check + format check
	ruff check src tests packaging
	ruff format --check src tests packaging

test:           ## unit tests
	$(PY) -m pytest

gate:           ## exactly what CI runs: lint, format check, unit tests, profile lint
	ruff check src tests packaging
	ruff format --check src tests packaging
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

lock:           ## regenerate the hash-pinned locks of the .deb's runtime dependencies and its build backend (needs uv)
	@$(UV) --version | grep -qE '^uv $(subst .,\.,$(UV_VERSION))( |$$)' || \
		{ echo "make lock: needs uv $(UV_VERSION) (pip install uv==$(UV_VERSION)); found: $$($(UV) --version 2>&1)" >&2; exit 1; }
	$(UV) pip compile pyproject.toml --extra lgwebos --extra analyst --universal --python-version 3.11 \
		--generate-hashes --custom-compile-command "make lock" --quiet -o packaging/requirements.lock
	$(UV) pip compile packaging/build-requirements.in --universal --python-version 3.11 \
		--generate-hashes --custom-compile-command "make lock" --quiet -o packaging/build-requirements.lock

wheel:          ## build the tvgw wheel into dist/ from a fresh build directory
	rm -rf build/lib
	$(PY) -m pip wheel -q --no-deps --wheel-dir dist .

deb:            ## build the arm64 .deb into dist/: wheel, wheelhouse from the lock, nfpm (docs/packaging.md)
	packaging/build-deb.sh dist

clean:
	rm -rf build dist .pytest_cache .ruff_cache .mutmut-cache mutants src/*.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
