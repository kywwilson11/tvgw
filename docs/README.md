# Documentation

Start with the [README](../README.md) for what tvgw is and how to install it. Then:

| Page | One line |
|---|---|
| [architecture.md](architecture.md) | How it works: the data path, control and data planes, every table in the store, flow naming, cadences, trust boundaries. |
| [design-decisions.md](design-decisions.md) | Why it works that way, one short record per decision, starting with the direct-uplink choice. |
| [operations.md](operations.md) | The runbook: daily routine, red lines, deploy and rollback, `verify` checks, timers, paths, common breakages. |
| [adding-a-profile.md](adding-a-profile.md) | Writing and testing a profile for another TV vendor. |
| [privacy-and-retention.md](privacy-and-retention.md) | What is recorded, how long it is kept, who can read it, and how to back it up. |
| [incidents.md](incidents.md) | What broke on the running gateway, why, and what changed. |
| [lg-cx-deployment.md](lg-cx-deployment.md) | The original LG CX bring-up log. Historical; superseded by the pages above. |

Each directory with moving parts has its own README:

- [../src/tvgw/README.md](../src/tvgw/README.md): the Python package, module by module.
- [../src/tvgw/profiles/README.md](../src/tvgw/profiles/README.md): the `lg-webos` profile and its evidence.
- [../deploy/README.md](../deploy/README.md): `install.sh` and the settings file, with links to [nftables](../deploy/nftables/README.md), [systemd](../deploy/systemd/README.md), [nginx](../deploy/nginx/README.md), [dnsmasq](../deploy/dnsmasq/README.md), [networkmanager](../deploy/networkmanager/README.md), [logrotate](../deploy/logrotate/README.md) and [bin](../deploy/bin/README.md).
- [../tests/README.md](../tests/README.md): unit, mutation and hardware tests, with [unit](../tests/unit/README.md) and [hardware](../tests/hardware/README.md) details.

## Which page when

| You want to | Read |
|---|---|
| Understand the system before changing it | [architecture.md](architecture.md), then [design-decisions.md](design-decisions.md) |
| Act on a red line or a failed `verify` | [operations.md](operations.md#red-lines) and [operations.md](operations.md#what-tvgw-verify-checks) |
| Deploy, roll back, or change a firewall setting | [operations.md](operations.md#deploying-and-rolling-back) |
| Block or unblock a name | [../src/tvgw/profiles/README.md](../src/tvgw/profiles/README.md#how-to-change-it) |
| Put a different TV behind the Pi | [adding-a-profile.md](adding-a-profile.md) |
| Know what is kept about the household, and who can see it | [privacy-and-retention.md](privacy-and-retention.md) |
| Write up something that broke | [incidents.md](incidents.md), using the template at its top |
| Record a choice so nobody undoes it | [design-decisions.md](design-decisions.md), as a new numbered entry |

## Conventions for these pages

- Everything here describes the code as it is. If you change behavior, change the page in the same commit.
- No site identifiers: no MAC addresses, no home-LAN addresses, no ZIP codes, no host or account names. Say "the Pi". The gateway's own `10.10.10.0/24` is fine.
- American spelling, short sentences, the reason as well as the rule.
- Relative links between pages, so they work on any clone.

Changes are recorded in [../CHANGELOG.md](../CHANGELOG.md).
