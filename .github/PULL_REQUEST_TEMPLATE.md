## What this changes

<!-- What the change does and why. Link the issue it closes. -->

## Checklist

- [ ] `make gate` passes: ruff, the format check and the unit tests.
- [ ] No site identifiers anywhere in the diff: no real MAC address, home-LAN address, host or user name, Wi-Fi name, location, viewing schedule, or device hash or UUID inside a host name.
- [ ] Every file the code opens names `encoding="utf-8"`.
- [ ] A test pins each new behavior, and a bug fix comes with the test that failed before it.
- [ ] The page that owns each changed fact is updated, and `CHANGELOG.md` has a line under "Unreleased".
- [ ] If this makes a choice someone could undo by accident, `docs/design-decisions.md` has a new numbered entry.
- [ ] If this touches the firewall (`deploy/nftables/`), the virtual suite passes as root on Linux, or I say below that I could not run it.
- [ ] If this touches anything installed on the gateway (`deploy/`, `packaging/`, a unit, a setting), the steps the owner should watch after the deploy are listed below.

## After the deploy

<!-- For a change to the gateway: what to run on the Pi after the deploy and what it should print
(for example `sudo tvgw verify`, a line of the brief, a counter). Write "none" for code that never
reaches the gateway. -->
