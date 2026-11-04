PY ?= python3
# ssh host of the gateway; put yours in .pi (gitignored) or pass PI=<host>
PI ?= $(shell cat .pi 2>/dev/null || echo tvgw)
UV ?= uv
# (packaging) the uv `make lock` resolves with: another version may resolve or annotate the locks
# differently, so a different one is refused rather than used
UV_VERSION := 0.13.1
# what ruff checks and formats: the package, the tests, the packaging scripts, the figure renderer, the
# documentation site's scripts and the repository tools
LINT_PATHS := src tests packaging docs/diagrams/build.py docs/site tools
# (packaging) the POSIX sh scripts shellcheck reads, when it is installed: the installer and the release
# scripts, the maintainer scripts and the dispatcher. A new one is listed here, or
# test_every_posix_script_is_shellchecked_by_the_gate fails. Findings from warning up fail, so shellcheck's
# releases (CI's runners carry an older one) agree on the verdict
SH_PATHS := packaging/get.sh.in packaging/install-check.sh packaging/publish-release.sh \
	packaging/release-assets.sh packaging/scripts/preinst packaging/scripts/postinst packaging/scripts/prerm \
	packaging/scripts/postrm deploy/networkmanager/90-tvgw-dispatcher
SHELLCHECK = if command -v shellcheck >/dev/null 2>&1; then shellcheck -s sh -S warning $(SH_PATHS); \
	else echo "shellcheck is not installed: the POSIX scripts were not checked"; fi
# (deploy window) what `make gate` compares the branch's commits with: each commit that changes how the
# gateway treats the TV must carry `Deploy-window: tv-off` (tools/check_deploy_window.py)
WINDOW_BASE ?= origin/main
# (site) the venv `make site` builds the documentation site with: the generator from
# docs/site/requirements.lock, hash-checked, made again whenever the lock changes
SITE_VENV := build/site-venv

.PHONY: dev lint test links gate site mutmut hardware deploy backup clean lock wheel deb

dev:            ## install the package editable with dev extras
	$(PY) -m pip install -e ".[dev]"

lint:           ## ruff check + format check, shellcheck when installed
	ruff check $(LINT_PATHS)
	ruff format --check $(LINT_PATHS)
	@$(SHELLCHECK)

test:           ## unit tests
	$(PY) -m pytest

links:          ## every Markdown link and anchor, and every docs path other files name, resolves
	$(PY) tools/check_docs_links.py

gate:           ## exactly what CI runs: lint, format check, shellcheck when installed, the deploy-window trailers, the docs links, unit tests, profile lint
	ruff check $(LINT_PATHS)
	ruff format --check $(LINT_PATHS)
	@$(SHELLCHECK)
	$(PY) tools/check_deploy_window.py --base $(WINDOW_BASE)
	$(PY) tools/check_docs_links.py
	$(PY) -m pytest -q

# the last step is reported, not enforced: CI publishes main only while it passes against the latest release
site: $(SITE_VENV)/installed ## build the docs site into build/site, strict, check its HTML and its commands (docs/site/README.md)
	$(PY) tools/check_docs_links.py
	$(PY) docs/site/prebuild.py --out build/site-docs --repo https://github.com/kywwilson11/tvgw --ref "$$(git rev-parse HEAD)"
	$(SITE_VENV)/bin/zensical build --strict --clean
	$(PY) docs/site/check_site.py build/site --prefix /tvgw/
	-$(PY) docs/site/check_commands.py --against "$$(git describe --tags --abbrev=0)"

$(SITE_VENV)/installed: docs/site/requirements.lock
	rm -rf $(SITE_VENV)
	$(PY) -m venv $(SITE_VENV)
	$(SITE_VENV)/bin/python -m pip install -q --disable-pip-version-check --require-hashes --no-deps -r docs/site/requirements.lock
	touch $@

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

lock:           ## regenerate the hash-pinned locks of the .deb's runtime dependencies, its build backend and the docs site's generator (needs uv)
	@$(UV) --version | grep -qE '^uv $(subst .,\.,$(UV_VERSION))( |$$)' || \
		{ echo "make lock: needs uv $(UV_VERSION) (pip install uv==$(UV_VERSION)); found: $$($(UV) --version 2>&1)" >&2; exit 1; }
	$(UV) pip compile pyproject.toml --extra lgwebos --extra analyst --universal --python-version 3.11 \
		--generate-hashes --custom-compile-command "make lock" --quiet -o packaging/requirements.lock
	$(UV) pip compile packaging/build-requirements.in --universal --python-version 3.11 \
		--generate-hashes --custom-compile-command "make lock" --quiet -o packaging/build-requirements.lock
	$(UV) pip compile docs/site/requirements.in --universal --python-version 3.11 \
		--generate-hashes --custom-compile-command "make lock" --quiet -o docs/site/requirements.lock

wheel:          ## build the tvgw wheel into dist/ from a fresh build directory
	rm -rf build/lib
	$(PY) -m pip wheel -q --no-deps --wheel-dir dist .

deb:            ## build the .deb into dist/ (arm64; TVGW_ARCH=amd64 for the other): wheel, wheelhouse, nfpm (docs/project/packaging.md)
	packaging/build-deb.sh dist

clean:
	rm -rf build dist .pytest_cache .ruff_cache .mutmut-cache .cache mutants src/*.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
