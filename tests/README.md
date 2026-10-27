# Tests

Three kinds of tests guard the gateway. They answer different questions and run at different times.

| Kind | Where | Question it answers | Command | When it runs |
|---|---|---|---|---|
| Unit | [`unit/`](unit/README.md) | Does the code do the right thing with real input? | `make test`, or `make gate` for lint plus tests | Locally before every deploy; in CI on every push, pull request and manual run, on Python 3.11 (the Pi's Debian 12) and 3.13 |
| Mutation | `unit/` again, through mutmut | Would the unit tests notice if the code were wrong? | `make mutmut` | Weekly in CI (Monday 06:17 UTC) and on demand; never blocks a push |
| Hardware | [`hardware/`](hardware/README.md) | Does the live gateway hold right now? | `make hardware PI=<ssh-host>` | On the Pi as root; in CI after the unit tests on every push to `main` |

About 330 unit tests and 35 hardware tests (counting parametrized cases).

## How they fit

- **Unit tests** need no gateway. Fixtures are lines captured on the Pi, and everything that would touch the system (files, tshark, journalctl, nft, systemctl, DNS) is injected. They include the profile lint, so a policy change that breaks the lint fails `make gate`.
- **Mutation testing** changes the code in small ways (`<` to `<=`, a constant, a dropped call) and reruns the unit tests. A mutant that survives is a behavior no test pins. `src/tvgw/lgwebos.py` is excluded, since it needs a TV.
- **Hardware tests** read the real firewall, resolver, URL filter, services and store. They change nothing except running `tvgw ingest` twice.

`pyproject.toml` sets `testpaths = ["tests/unit"]`, so a bare `pytest` never runs the hardware suite.

## CI

`.github/workflows/ci.yml` has three jobs:

- `test`: `pip install -e ".[dev]"` and `make gate`, on 3.11 and 3.13. Skipped for the weekly schedule.
- `hardware`: needs `test`; runs only for pushes to `main` in the upstream repository (not forks), on a self-hosted runner on the Pi labelled `self-hosted, tvgw`. It rsyncs the checkout to `/opt/tvgw/src` as root, runs `install.sh`, then the hardware suite. A push to `main` therefore deploys to the Pi.
- `mutation`: `mutmut run` and `mutmut results` on 3.13, for the schedule and manual runs.

Permissions are read-only, and a newer run on the same ref cancels an older one.

## Which tests guard what

| You changed | Run at least | Why |
|---|---|---|
| A parser, the store, ingest, queries or the CLI | `make gate` | Fixtures and goldens pin the behavior. |
| The brief's output | `make gate`, then regenerate the golden brief | See [unit/README.md](unit/README.md#golden-tests). |
| The profile or `.rules` | `make gate` | The lint and the categorizer cases run in the unit tests. After deploying, the hardware suite checks for AdGuard drift. |
| `tvgw-apply`, a unit, `install.sh` or an nginx file | `make deploy` then `make hardware` | Only the live system can show that the firewall, routing and services hold. |
| Anything, before a release | `make mutmut` | Finds tests that pass whatever the code does. |

## Before you push

```sh
make gate                     # what CI runs
make deploy PI=<ssh-host>     # optional: try it on the Pi first
make hardware PI=<ssh-host>
```
