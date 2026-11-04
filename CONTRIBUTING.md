# Contributing to tvgw

This page says how to set up a working copy, run the checks CI runs, write a change the way the project writes code and documentation, and get it merged. It is for anyone sending a pull request or a report from another TV. The project's map is [the documentation index](docs/README.md), and the tests are described in [the tests](tests/README.md).

## Set up

You need Python 3.11 or newer and git. On Linux or macOS:

```sh
git clone https://github.com/kywwilson11/tvgw.git
cd tvgw
python3 -m venv .venv
. .venv/bin/activate
make dev                      # pip install -e ".[dev]": pytest, ruff and mutmut
```

`make dev` installs the package editable with the `dev` extras from `pyproject.toml`. The `lgwebos` and `analyst` extras are for a running gateway and are not needed to develop.

## Run the gate

```sh
make gate
```

`make gate` is exactly what CI's `test` job runs, on Python 3.11 and 3.13: `ruff check` and `ruff format --check` over `src`, `tests`, `packaging`, `docs/diagrams/build.py`, `docs/site` and `tools` (`LINT_PATHS` in the Makefile); `shellcheck -s sh -S warning` over the POSIX shell scripts (`SH_PATHS`), when shellcheck is installed, as it is on CI's runners; then `tools/check_deploy_window.py` against `origin/main`, then `tools/check_docs_links.py`, which fails on a link, an anchor or a docs path the code names that leads nowhere, then `python3 -m pytest -q`. A pull request is not reviewed until it passes. `make links` runs the link check alone. To fix formatting, run `ruff format src tests packaging docs/diagrams/build.py docs/site tools`.

## The three test tiers

| Tier | Where it runs | Who runs it |
|---|---|---|
| Unit, in [tests/unit](tests/unit/README.md) | Anywhere, with no gateway | You, with `make gate`; CI on every pull request |
| Virtual, in [tests/virtual](tests/virtual/README.md) | Linux as root, with `nft`, `ip` and `unshare`: a VM or a privileged container | You, when you touch the firewall; CI's `virtual` workflow on every pull request |
| Hardware, in [tests/hardware](tests/hardware/README.md) | The owner's gateway, under the install lock | CI's `hardware` job, only after a push to `main` of this repository |

The virtual tier skips every test where root or a tool is missing, so a green run on macOS proves nothing about the firewall. [Running it](tests/virtual/README.md#running-it) gives the VM and Docker commands. The hardware tier never runs for a pull request or a fork ([supply chain](docs/project/supply-chain.md)), so a change under `deploy/` lists in its pull request the steps the owner should watch after the deploy.

## House rules

These hold for code, tests, fixtures, documentation and commit messages.

- **No site identifiers.** No real MAC address (the placeholders are `b4:b2:91:aa:bb:cc` and `00:00:00:00:00:00`), no home-LAN address such as 192.168.x.x, no host or user name of anyone's machines, no Wi-Fi network name, router or VPN account detail, ZIP code or location, and no household viewing schedule. Use the TV subnet `10.10.10.0/24`, the gateway `10.10.10.1`, the TV `10.10.10.17` and the documentation ranges `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`. A device hash, a UUID or any hexadecimal string longer than 16 characters inside a host name becomes a placeholder such as `<device-hash>`. Check every line copied from a log, a brief or a capture before it goes in ([site identifiers](docs/project/writing-docs.md), rule A12).
- **UTF-8, said out loud.** Every `open()`, `read_text()` and `write_text()` names `encoding="utf-8"`, in tests too.
- **Lines of 110 columns.** `ruff` enforces it under `src/` and `packaging/`; under `tests/` long lines are allowed only for verbatim log lines and fixtures.
- **A test for every behavior.** A new behavior comes with the test that pins it, and a bug fix with the test that failed before it. Code that touches the gateway takes its dependency as a parameter so the unit tests can pass a fake ([how the code is tested without a gateway](tests/README.md#how-the-code-is-tested-without-a-gateway)).
- **Docs in step.** A change to behavior changes the page that owns the fact in the same pull request, and adds a line under "Unreleased" in [the changelog](CHANGELOG.md). The page that owns each kind of fact, and the writing rules (plain present tense, no em dashes, no counts that ordinary commits change), are in [writing these pages](docs/project/writing-docs.md).
- **Say when a commit must wait for the TV.** A commit that changes the firewall, the TV port's network or DHCP setup, the URL filter, a TV's LAN-API module, a profile's `[firewall]` or `[url_filter]` table, or the routing and dnsmasq parts of `install.sh` ends its message with the line `Deploy-window: tv-off`, so it reaches the owner's gateway only in its quiet window. `make gate` names a commit that lacks it ([the quiet window](deploy/README.md#the-quiet-window)).
- **A design decision for every decision.** A choice that someone could undo by accident gets a numbered entry in [the design decisions](docs/design-decisions.md) with its context, decision and consequences. The log is append-only: to reverse a decision, add a new entry that says so.

## Profiles and evidence

A profile entry is either verified or unverified, and the rubric is [grading evidence](docs/reference/profile-format.md#grading-evidence). Verified means seen on a set behind a tvgw gateway, with the evidence named and dated: a `capture`, a `lan-api` reading, an `on-screen` reading or a `breakage`. Everything else is unverified and must cite a source by URL. A must-allow host is verified only by a breakage on hardware: a host the TV merely contacts is a candidate.

One TV is verified so far: the LG CX in `lg-webos`. The `samsung-tizen`, `roku` and `vizio-smartcast` profiles are DNS-only and built from published lists and papers ([the bundled profiles](src/tvgw/profiles/README.md)). The most useful contribution from an owner of another TV is a report of what that TV does behind a gateway:

1. Run the gateway with the profile closest to your TV, or a skeleton profile, for at least 48 hours ([phase 1: capture first](docs/project/adding-a-profile.md#phase-1-capture-first)).
2. Open a TV report from the repository's issue page: the model, the firmware, the profile, what you measured and a scrubbed excerpt of `tvgw brief`.
3. If you write the profile change yourself, follow [how a profile graduates](docs/reference/profile-format.md#how-a-profile-graduates): entry by entry, each with its date, model, firmware and evidence.

## How a change lands

1. Fork the repository and branch from `main`.
2. Make the change with its tests and its documentation, then run `make gate`.
3. Open a pull request and fill in its checklist. CI runs the unit tests and the virtual suite; a first-time contributor's run waits for the owner's approval.
4. The owner reviews it. `main` keeps a linear history, so the pull request is merged by rebase or squash, never by a merge commit; rebase on `main` when asked. A squash keeps any `Deploy-window: tv-off` line as the last line of the squashed message.
5. After the merge, the push to `main` deploys to the owner's gateway and runs the hardware suite, at once or, for a commit with `Deploy-window: tv-off`, in the gateway's next quiet window. A change that fails there is reverted or fixed on `main`.

Security problems do not go in a public issue or pull request: see [the security policy](SECURITY.md). Everyone taking part follows [the code of conduct](CODE_OF_CONDUCT.md).
