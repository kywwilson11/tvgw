# Incident log

Things that broke on a running gateway, newest first. Each entry says what the symptom was, how it was found, the root cause, the fix, and the lesson. Add an entry for any outage, and for any near miss that would have been one.

Template: date and title; impact; detection; root cause; fix; lesson.

## 2026-10-27: pcaps yielded nothing after the state directory was closed

**Impact.** For about twelve hours no TLS names or plain-HTTP requests reached the store. Twelve hourly pcaps were marked done with zero rows, and every streaming flow from that evening showed as Unresolved in the brief. DNS, flows and the firewall were unaffected; the TV kept working.

**Detection.** Every Peacock flow from 21:00 on showed as Unresolved. No check caught it: a pcap with zero rows looked like a quiet hour.

**Root cause.** The previous day's permission tightening made `/var/lib/tvgw` `2750 root:adm`. tshark runs as `nobody` (`tshark.py`, through `setpriv`) and could no longer reach the pcaps. tshark exits 2 when it cannot open a file, and it also exits 2 when a file is cut short mid-packet, which is normal for a capture. `tshark.extract` treated every exit 2 as "cut short", so the failure became an empty result and the pcap was recorded in `pcaps_done`.

**Fix** (commit 83e0610).

- Exit 2 counts as "cut short" only when tshark's error text says so. Otherwise `extract` raises, ingest warns, and the pcap is retried next run. A unit test covers both cases (`test_extract_distinguishes_cut_short_from_a_file_it_could_not_open`).
- The state directory is `2751`: others may pass through but not list it. The pcap directory is `2750 root:nogroup` and `tvgw-pcap.service` has `UMask=0027`, so each pcap is `640 root:nogroup`. tshark, with group `nogroup`, can read them; other users cannot.
- New hardware test `test_finished_pcaps_yield_rows_while_the_tv_is_on`, and `test_state_is_not_world_readable` now covers the pcap directory and files.

The fix does not revisit pcaps already marked done.

**Lesson.** An exit code that means two things must be split by its message, never assumed. When you tighten permissions, test the unprivileged reader, not only that others are kept out. A source that can return "nothing" needs a check that nothing is plausible.

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

**Since then.** The `forwarding` check in `tvgw verify` reads the per-interface switches of the TV interface and the uplink as well as the global one (`test_interface_forwarding_off_is_the_outage_we_had` in `tests/unit/test_verify.py`). `install.sh` re-applies the firewall in place when `tvgw.service` is already running, so a deploy no longer runs the stop path at all.
