# Incident log

Things that broke on a running gateway, newest first. Each entry says what the symptom was, how it was found, the root cause, the fix, and the lesson. Add an entry for any outage, and for any near miss that would have been one.

Template: date and title; impact; detection; root cause; fix; lesson.

## 2026-10-26: streaming stopped after a deploy (TV had no route)

**Impact.** Right after a deploy, the TV could not stream. Its packets had no route out. The firewall and DNS were up; forwarding on the TV's interface was off.

**Detection.** Two ways, at about the same time. `tvgw verify`, which `install.sh` runs at the end, reported `FAIL tv_route: via nothing, expected <uplink>`. The user also saw streaming stop.

**Root cause.** The same day's change made the firewall fail closed. `tvgw.service` has an `ExecStop` that turns forwarding off on the TV interface (`net.ipv4.conf.eth0.forwarding=0`), so a stopped service leaves the TV dark and not unfiltered. `install.sh` restarts `tvgw.service`, which runs that `ExecStop` and then `tvgw-apply`.

`tvgw-apply` only wrote the global switch, `net.ipv4.ip_forward=1`. The kernel copies the global value onto the per-interface switches only when the global value changes. It was already 1, so the write changed nothing and `eth0` stayed at 0. With forwarding off on the interface, the kernel would not forward the TV's packets and `ip route get` for them returned nothing.

`tvgw verify` did report the fault, but through `tv_route`. Its `forwarding` check reads only the global `ip_forward`, which was 1 and passed. No hardware test looked at the per-interface switches or at the TV's route.

**Fix** (`tvgw-apply`, commit d4073de). After the ruleset loads, the script now writes the global switch and both per-interface switches explicitly: `net.ipv4.ip_forward`, `net.ipv4.conf.<TV interface>.forwarding` and `net.ipv4.conf.<uplink>.forwarding`. Forwarding is still enabled last, after the filter is in place.

Two hardware tests were added or extended in `tests/hardware/test_gateway.py`:

- `test_ipv6_guard_and_fail_closed_state` asserts that `ip_forward` and the per-interface `forwarding` of both the TV interface and the uplink are 1.
- `test_tv_has_a_route_out` asks the kernel for the route of a packet from the TV's address entering on its interface, and asserts it leaves by the uplink.

**Lesson.** Treat every `tvgw verify` FAIL after a deploy as an outage, even when the service reports success and the global checks pass. A restart exercises the stop path as well as the start path, and the stop path now changes state that the start path has to restore. When you add a "turn it off" step, add a test that turns it back on from the off state.

**Still true.** The `forwarding` check in `tvgw verify` looks at the global switch only. The per-interface case is caught by `tv_route` and by the hardware suite.
