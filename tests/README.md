# Tests

This page owns the six kinds of tests, the question each answers, where each runs, and how the code is tested without a gateway. It is for developers changing the code, the deploy tree or the profile. How CI runs them is in [how a change reaches the gateway](../deploy/README.md#how-a-change-reaches-the-gateway).

## Kinds of tests

| Kind | Question it answers | Command | Where it runs |
|---|---|---|---|
| Unit, in [`unit/`](unit/README.md) | Does the code do the right thing with real input? | `make test`, or `make gate` for ruff and the tests together | Anywhere, with no gateway; in CI's `test` job on Python 3.11 and 3.13 |
| Mutation, over `unit/` | Would the unit tests notice if the code were wrong? | `make mutmut` | On demand, and in CI's weekly `mutation` job; it never blocks a push |
| Virtual, in [`virtual/`](virtual/README.md) | Does the firewall, loaded into a kernel, refuse and pass what it should? | `sudo ... python -m pytest -m virtual tests/virtual` ([running it](virtual/README.md#running-it)) | As root on Linux: a VM, a privileged container, and CI's `virtual` workflow on every pull request and push to `main` |
| Platform, by [`packaging/check-platform.sh`](../packaging/check-platform.sh) | Do a distribution's own programs (apt, Python, nft, dumpcap, nginx, dnsmasq, systemd) run what tvgw installs? | `sudo sh packaging/check-platform.sh --source`, in a throwaway container ([the platform check](../docs/project/packaging.md#the-platform-check)) | As root in a container only: CI's `distro` workflow in Debian 12 and 13 and Ubuntu 24.04 and 26.04 on both architectures, and each release's install checks |
| Container, in [`container/`](container/README.md) | Does the real installer bring a gateway up on systemd and NetworkManager, and does `tvgw verify` then pass? | `python3 -m pytest -m container tests/container` ([running it](container/README.md#running-it)) | Anywhere Docker runs, and CI's `container` workflow on every pull request and push to `main` |
| Hardware, in [`hardware/`](hardware/README.md) | Does the live gateway hold right now? | `make hardware PI=<ssh-host>` | On the gateway, as root, under the install lock; in CI's `hardware` job right after each deploy, inside the same lock (`deploy/sync-install.sh`) |

- **Unit tests** are built from lines captured on the gateway, with site identifiers replaced. The extractor's golden corpus in [`corpora/`](corpora/README.md) is synthesised instead: small ClientHello pcaps, their tshark rows and the expected hellos, checked against tshark where it is installed. They include the profile lint, so a policy change that breaks the lint fails `make gate`.
- **Mutation testing** changes the code in small ways, such as `<` to `<=`, a constant or a dropped call, and runs the unit tests again. A mutant that survives is a behavior no test pins. `pyproject.toml` mutates `src/tvgw/` with `tests/unit/` and leaves out `src/tvgw/lgwebos.py`, which needs a TV.
- **Virtual tests** build the gateway from network namespaces, load the real `tvgw-apply` into it, check every ruleset variant with `nft -c`, and probe the loaded firewall from a namespace TV against a reachability matrix kept as data ([the virtual gateway](virtual/README.md)). They need no gateway, only root on a Linux kernel.
- **Platform checks** install the package's dependencies with a distribution's own apt and run the unit suite on its Python, then check tvgw's files with its own programs; the kernel is the runner's ([the platform check](../docs/project/packaging.md#the-platform-check)).
- **Container tests** boot Debian 13 with systemd as PID 1 in a privileged container, put a TV in a network namespace behind its TV port, install AdGuard Home from the pin, run `install.sh`'s two setup passes and a deploy (on a second container, a first install with no pass), and wait for `tvgw verify` to exit 0 ([the container tier](container/README.md)). They need Docker, not a gateway, and nothing of the host's network changes.
- **Hardware tests** read the real firewall, resolver, URL filter, services and store, and state one operational guarantee each.

<!-- (fin-release) --> `make gate` is `ruff check` and `ruff format --check` over `src`, `tests`, `packaging`, `docs/diagrams/build.py`, `docs/site` and `tools` (`LINT_PATHS` in the Makefile), then the repository's own checks in `tools/` (the deploy-window trailers and the links), then `python3 -m pytest -q`, which is what CI's `test` job runs. `pyproject.toml` sets `testpaths = ["tests/unit"]`, so a bare `pytest` never runs the hardware suite, and ruff checks 110-column lines, except that long lines are allowed under `tests/` for verbatim log lines. `make dev` installs the package editable with the `dev` extras (pytest, ruff, mutmut).

## How the code is tested without a gateway

Everything that touches the gateway is a parameter, and the unit tests pass fakes; [the package's rules](../src/tvgw/README.md#rules-of-the-code) state the rule. The seams and their fakes:

| Dependency on the gateway | Seam | Fake in the unit tests |
|---|---|---|
| `/proc`, for the pcap the capture holds open | `ingest.run(live=)` and `pcaps.live_files` | the autouse fixture `fake_live` |
| journalctl's kernel lines | `ingest.run(oddport_lines=, gate_lines=)` | `fake_oddport` in `unit/conftest.py`, and `no_kernel_lines` in the test files |
| `tvgw-flowlog`'s journal, for conntrack's lost events | `ingest.run(flowlog_lines=)` and `ingest.journal_flowlog_lines` | the autouse fixture `quiet_flowlog` |
| `nft`, `sysctl`, `systemctl`, files and DNS | `verify.check(run, read, mtime, resolve)` | the scripted gateway in `unit/test_verify.py` |
| `/proc`, for the flow logger's event socket | `verify.check(sockets=)` and `flowlog.event_sockets(pid, proc)` | the scripted socket in `unit/test_verify.py`, fake `/proc` trees in `unit/test_flowlog.py` |
| tcpdump and `nft`, for the DNS gate feeder | `dnsgate.feed(read, nft, log, clock)` | fakes in `unit/test_dnsgate.py` |
| The kernel's packet queue and nf_tables, for the DNS gate's in-path filler | `inpath.Filler(release, adder, clock, log)`, `inpath.Loop(qsock, filler, live, ping, publish)`, `inpath.NftSocket(sock)` and `inpath.QueueSocket(sock=)` | fakes and a socket pair in `unit/test_inpath.py`; the kernel's half in `virtual/test_virtual_inpath.py` |
| The AdGuard Home service and binary | `adguardcfg.apply(control, ready, check, guard)`, `adguardcfg.upgrade(control, ready, check, verify, guard, version)`, `adguardcfg.ensure_service(control, ready, effective, guard)` | functions that record the calls in `unit/test_adguardcfg.py` and `unit/test_adguard_discipline.py` |
| The Anthropic API | `analyst.run(make_client=, key_path=)` | `FakeClient` in `unit/test_analyst.py` and `unit/test_autoblock.py` |
| The TV, the clocks, the TV port's counter and the key store, for the live reading | `tvlive.run(env=)` and `tvlive.held(env=)` with `tvlive.Env`, one callable each | `Sim` (days in fast time) and `Bench` (one session against `FakeTv` on localhost) in `unit/test_tvlive.py` |
| The disk and the clock, for pcap retention | `pcaps.prune(now=, disk_free=)` | fakes in `unit/test_pcaps.py` |
| The local time zone | `TZ`, set for every test | the autouse fixture `fixed_time_zone` |
| The second model, AdGuard, the TV and the clock during an autonomous block | `analyst.run(hooks=)` with `call`, `apply`, `sampler`, `sleep` and `now` | fakes in `unit/test_autoblock.py` |
| The TV network, for discovery | `discover.discover(probe=, ssdp=, describe=)` | captured text and fake probes in `unit/test_discover.py` |
| Discovery, the installer, pairing, verify and the lock, for `tvgw setup` | `setup.Env`, one callable each | `Fake` in `unit/test_setup.py` |
| `time.time` | patched for every test | the autouse fixture `frozen_now` |
| tshark on a pcap | `ingest.run(extract=)` | `fake_extract` in `unit/conftest.py` |

The deploy tree is tested as text: `unit/test_deploy_lint.py`, `unit/test_deploy_units.py`, `unit/test_deploy_files.py` and `unit/test_fw_lines.py` read the scripts, units and workflow without running them. `unit/test_capture_filter.py` runs a deployed artifact, the capture filter, through tcpdump, and it skips where tcpdump is not installed. `unit/test_apply.py` and `unit/test_apply_check.py` run `tvgw-apply` against stub commands; what a kernel makes of its rules is the virtual suite's question.

## Which tests guard what

| You changed | Run at least | What guards it |
|---|---|---|
| `install.sh`, a shell job or the dispatcher | `make gate`, the container tier, then `make deploy` and `make hardware` | `unit/test_deploy_lint.py` (shell syntax), `unit/test_deploy_files.py`, `unit/test_install_passes.py`; the container tier (`container/`); the hardware suite's installed-file and generated-config tests |
| A parser, the store, ingest, a query or the CLI | `make gate` | the parser tests from captured lines, `unit/test_ingest.py`, `unit/test_queries_cli.py`, and the goldens in `unit/test_cli_golden.py` |
| A setting in src/tvgw/config.py | `make gate` | `unit/test_config.py`, and `unit/test_deploy_lint.py` for the defaults `tvgw-apply` shares |
| A systemd unit or timer | `make gate`, then `make deploy` and `make hardware` | `unit/test_deploy_units.py`, `unit/test_deploy_lint.py` (start timeouts); the hardware suite's enabled-unit and installed-file tests |
| An nginx file | `make gate`, then `make deploy` and `make hardware` | `test_nginx_conf_matches_the_profile` in `unit/test_profile.py`; the hardware suite's URL-filter tests |
| Anything, before a release | `make mutmut` | the surviving mutants it lists |
| The analyst or autonomy | `make gate`, then `make hardware` after a deploy | `unit/test_analyst.py`, `unit/test_autoblock.py`; the hardware suite's analyst and autoblock tests |
| The brief's output | `make gate`, then regenerate the golden brief | `unit/test_cli_golden.py` ([golden tests](unit/README.md#golden-tests)) |
| The capture filter in `tvgw-pcap.service` | `make gate` on a machine with tcpdump | `unit/test_capture_filter.py` |
| The profile or its `.rules` file | `make gate`, then `sudo tvgw adguard diff` after a deploy | `unit/test_profile.py` (the lint and the categorizer), `unit/test_brief_sections.py`; the hardware suite's AdGuard drift test |
| `tvgw-apply`, a rule or its comment | `make gate`, the virtual suite, then `make deploy` and `make hardware` | `unit/test_fw_lines.py`, `unit/test_deploy_lint.py` (key rules, defaults), `unit/test_apply.py`; the virtual suite (`nft -c` on every variant, the reachability matrix in `virtual/matrix.txt`); the hardware suite's firewall tests |
| A page, a heading, or a docs path that code, a deployed file, a workflow or a test names | `make links`, then `make gate` | `tools/check_docs_links.py` and `unit/test_docs_links.py` ([the link check](../tools/README.md#what-the-link-check-reads)) |
| The documentation site: `mkdocs.yml`, `docs/site/`, or the landing page's sections | `make site`, then `make gate` | `unit/test_site_prebuild.py`, `unit/test_check_commands.py`, `unit/test_supply_chain.py` for `pages.yml`; the strict build ([the documentation site](../docs/site/README.md)) |
| `tools/page-map.csv`, or a page it moves | `python3 tools/rewrite_doc_paths.py`, then `make gate` | `unit/test_rewrite_doc_paths.py` ([moving a page](../tools/README.md#moving-a-page)) |
| `packaging/`, or a file `packaging/nfpm.yaml` copies from the checkout | `make gate`, and `make deb` where nfpm is installed | `unit/test_packaging.py`; CI's `deb-build` job builds the package on a pull request that changes either |
| The workflow or `deploy/rsync.exclude` | `make gate` | `unit/test_deploy_lint.py` (the workflow's shape, pinned actions, one rsync list) |

Only the live system can show that the firewall, routing and services hold, so a change to anything under `deploy/` ends with the hardware suite.

## Before you push

On your workstation:

```sh
make gate                     # what CI's test job runs
make deploy PI=<ssh-host>     # optional: try the change on the Pi first
make hardware PI=<ssh-host>   # the hardware suite against the live gateway
```

A push to `main` that changes more than Markdown deploys to the gateway and runs the hardware suite there; a pull request runs the unit tests, the virtual suite (the `virtual` workflow), the platform check (the `distro` workflow) and the container tier (the `container` workflow), which also run on every such push to `main`, beside the deploy rather than ahead of it.
