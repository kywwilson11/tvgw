"""Judge v2, in shadow, and the placebo calibration (design decision 48).

The shipped judge (`autoblock.judge`) reverts a machine rule when any TV hour of its trial reads
under 20% of the days before, and passes it when the TV was on too little to tell. Both fail in the
same direction on this gateway: an HDMI evening, a VPN reconnect or an AdGuard restart reads as a
collapse, a revert is a verdict never asked again, and a blind trial passes. Judge v2 is strict on
passing and soft on reverting:

- it judges only clean demand hours (`ledger.Classifier`);
- two consecutive low demand hours revert the rule when both are clean, and *suspend* it when one of
  them is confounded (the safe direction: the rule comes out, and the trial is to be asked again);
- it passes only after K clean demand hours (`JUDGE2_CLEAN_HOURS`); short of K at the end of the
  trial it returns NODATA and the trial extends, up to a 14-day ceiling;
- the hard red lines (a must-allow name or a clock lookup blocked, the blocked name retried at ten
  times its rate) revert in any hour, whatever the class.

It decides nothing. `shadow()` computes both judges' verdicts every hour and writes them to
`judge_shadow`, so two weeks of side-by-side verdicts can be compared before the owner adopts it.
`calibrate()` replays the store's history as placebo trials (a rule pretended at every hour of the
last 60 days, nothing blocked) under three arms, so the false-revert rate of each design is measured
rather than argued.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sqlite3
import time
from collections.abc import Callable
from datetime import datetime

from tvgw import autoblock, ledger, queries
from tvgw.profile import Profile

CEILING = ledger.CEILING  # seconds: the longest a trial may extend for want of clean hours
BASELINE = 3 * autoblock.TRIAL  # the days before a rule its rates are compared with, as the shipped judge
LOW_RUN = 2  # consecutive low demand hours before the hourly test acts
RETRY_STORM = 10.0  # the blocked name looked up this many times its pre-block rate per TV hour
RETRY_HOURS = 2  # ... over at least this many TV hours
MIN_BASELINE_HOURS = autoblock.MIN_TRIAL_TV_HOURS  # clean demand hours before a baseline means anything
FINAL = ("reverted", "suspended", "passed")
# the TV hours the shipped judge counts: queries.AWAKE since decision 41 moved
# autoblock's demand counting to every reading of a TV that is on. Arm A of the calibration mirrors it
SHIPPED_ON = queries.AWAKE


@dataclasses.dataclass(frozen=True)
class Verdict:
    verdict: str  # watching | reverted | suspended | passed | nodata
    reason: str
    clean_hours: int
    demand_hours: int
    final: bool  # no later hour can change it: a verdict, or NODATA at the ceiling


def _hour_rate(bytes_by_hour: dict[int, float], hs: list[int]) -> float:
    return sum(bytes_by_hour.get(h, 0.0) for h in hs) / len(hs) if hs else 0.0


def verdict(
    conn: sqlite3.Connection,
    prof: Profile,
    row: dict,
    now: float,
    k: int = 6,
    prorate: bool = False,
) -> Verdict:
    """Judge v2's verdict on one machine rule at `now`, from the store alone (no state is kept between
    calls, so a verdict can be recomputed and compared at any time)."""
    added = float(row["added_t"])
    until = float(row.get("trial_until") or added + autoblock.TRIAL)
    ceiling = added + CEILING
    upto = min(now, ceiling)
    if queries.must_allow_blocked(conn, added, upto, prof):
        return Verdict("reverted", "a must-allow name was blocked after this rule", 0, 0, True)
    if queries.clock_sync(conn, added, upto, prof).get("blocked"):
        return Verdict("reverted", "clock lookups were blocked after this rule", 0, 0, True)
    clf = ledger.Classifier(conn, prof, added - BASELINE, upto)
    trial = {"rule": row["rule"], "added_t": added}
    base_hours = [
        h for h in ledger.hours(added - BASELINE, added - 3600 + 1) if clf.classify(h)[0] == "clean"
    ]
    after = ledger.hours(added, upto - 3600 + 1)
    classes = {h: clf.classify(h, trial) for h in after}
    clean = [h for h in after if classes[h][0] == "clean"]
    demand = [h for h in after if classes[h][0] in ("clean", "confounded")]
    on_hours = [h for h in after if classes[h][0] != "off"]
    storm = _retry_storm(conn, row.get("name") or "", added, base_hours, on_hours)
    if storm:
        return Verdict("reverted", storm, len(clean), len(demand), True)
    by_hour = clf.bytes_pro if prorate else clf.bytes_end
    base = _hour_rate(by_hour, base_hours)
    comparable = len(base_hours) >= MIN_BASELINE_HOURS and base > 0
    if comparable:
        run: list[int] = []
        for h in after:
            cls = classes[h][0]
            if cls not in ("clean", "confounded"):
                continue  # NODATA for the hour; it neither starts nor breaks a run
            if run and h != run[-1] + 3600:
                run = []
            low = by_hour.get(h, 0.0) < autoblock.HOURLY_COLLAPSE * base
            run = [*run, h] if low else []
            if len(run) >= LOW_RUN:
                share = _hour_rate(by_hour, run) / base
                hit = run[-LOW_RUN:]
                bad = [r for x in hit if classes[x][0] == "confounded" for r in classes[x][1]]
                at = datetime.fromtimestamp(hit[0]).strftime("%m-%d %H:00")
                if bad:
                    why = ", ".join(dict.fromkeys(bad))
                    return Verdict(
                        "suspended",
                        f"streaming fell to {share:.0%} in {LOW_RUN} TV hours from {at}, confounded ({why}):"
                        " out for now, to be tried again",
                        len(clean),
                        len(demand),
                        True,
                    )
                return Verdict(
                    "reverted",
                    f"streaming fell to {share:.0%} of the clean hours before in {LOW_RUN} clean TV hours"
                    f" from {at}",
                    len(clean),
                    len(demand),
                    True,
                )
    if now < until:
        return Verdict("watching", f"{len(clean)} of {k} clean TV hours", len(clean), len(demand), False)
    if len(clean) >= k and comparable:
        share = _hour_rate(by_hour, clean) / base
        if share < autoblock.STREAMING_COLLAPSE:
            return Verdict(
                "reverted",
                f"streaming per clean TV hour at {share:.0%} of the clean hours before",
                len(clean),
                len(demand),
                True,
            )
        return Verdict(
            "passed",
            f"streaming per clean TV hour at {share:.0%} of the clean hours before, over {len(clean)} clean"
            " hours; no red line",
            len(clean),
            len(demand),
            True,
        )
    short = (
        f"{len(clean)} of {k} clean TV hours"
        if len(clean) < k
        else f"only {len(base_hours)} clean TV hours in the {BASELINE // 86400} days before"
    )
    if now >= ceiling:
        return Verdict(
            "nodata", f"ceiling reached with {short}: stays on probation", len(clean), len(demand), True
        )
    return Verdict("nodata", f"extend: {short}", len(clean), len(demand), False)


def _retry_storm(
    conn: sqlite3.Connection, name: str, added: float, base_hours: list[int], on_hours: list[int]
) -> str | None:
    """The blocked name asked for at RETRY_STORM times its rate before the block, per TV hour, over at
    least RETRY_HOURS TV hours: the TV wants it. Specific to the rule, so it acts in any hour."""
    if not name or len(on_hours) < RETRY_HOURS or not base_hours:
        return None

    def per_hour(hs: list[int]) -> float:
        n = sum(
            conn.execute(
                "SELECT COUNT(*) FROM dns WHERE qname = ? AND t >= ? AND t < ?", (name, h, h + 3600)
            ).fetchone()[0]
            for h in hs
        )
        return n / len(hs)

    before, after = per_hour(base_hours), per_hour(on_hours)
    if after >= RETRY_HOURS and after > RETRY_STORM * max(before, 1 / len(base_hours)):
        return f"the blocked name was asked for {after:.1f} times per TV hour, {before:.1f} before the block"
    return None


# ---- the shadow run ---------------------------------------------------------------------------------------
def rows_to_shadow(conn: sqlite3.Connection, now: float) -> list[dict]:
    """The machine rules both judges should see this hour: those on probation, those decided in the last
    two hours (so the hour the shipped judge decided is recorded beside v2's), and those the shipped
    judge passed whose v2 verdict is not final yet and whose ceiling has not passed."""
    out = []
    for r in autoblock.rows(conn):
        recent = r["decided_t"] is not None and r["decided_t"] >= now - 7200
        open_pass = r["verdict"] == "passed" and r["added_t"] >= now - CEILING
        if r["verdict"] is None or recent or (open_pass and not _v2_final(conn, r)):
            out.append(r)
    return out


def _v2_final(conn: sqlite3.Connection, r: dict) -> bool:
    return bool(
        conn.execute(
            "SELECT 1 FROM judge_shadow WHERE rule = ? AND added_t = ? AND final = 1 LIMIT 1",
            (r["rule"], r["added_t"]),
        ).fetchone()
    )


def shadow(
    conn: sqlite3.Connection,
    prof: Profile,
    now: float | None = None,
    k: int = 6,
    after_check: bool = False,
    budget: float | None = None,
    clock: Callable[[], float] | None = None,
) -> list[dict]:
    """Both judges' verdicts on every rule `rows_to_shadow` names, written to `judge_shadow` keyed by
    rule, trial and the last full hour, so a second call in the same hour replaces its row and decides
    nothing. The shipped judge's verdict is its recorded one when it has decided. A rule still on
    probation is "watching" when `after_check` (the hourly check has just run and kept it), else what
    `autoblock.judge` would say now (a read). With a `budget` in seconds, rules not reached by then are
    left for the next hour: the shadow pass never holds up the unit it shares with the shipped judge.
    Each row commits on its own, so a pass cut short keeps what it wrote."""
    now = now if now is not None else time.time()
    hour = int(now // 3600) * 3600 - 3600
    out = []
    clock = clock or time.monotonic
    start = clock()
    for r in rows_to_shadow(conn, now):
        if budget is not None and clock() - start > budget:
            break
        if r["verdict"]:
            v1, v1_reason = r["verdict"], r["reason"] or ""
        elif after_check:
            v1, v1_reason = "watching", ""
        else:
            got = autoblock.judge(conn, prof, r, now)
            v1, v1_reason = got if got else ("watching", "")
        v2 = verdict(conn, prof, r, now, k)
        cls = ledger.classify_hour(conn, hour, prof, {"rule": r["rule"], "added_t": r["added_t"]})
        rec = {
            "t": now, "rule": r["rule"], "added_t": r["added_t"], "hour": hour, "hour_class": cls[0],
            "v1": v1, "v1_reason": v1_reason[:300], "v2": v2.verdict, "v2_reason": v2.reason[:300],
            "clean_hours": v2.clean_hours, "k": k, "final": int(v2.final),
        }  # fmt: skip
        conn.execute(
            f"INSERT OR REPLACE INTO judge_shadow({', '.join(rec)}) VALUES ({','.join('?' * len(rec))})",
            tuple(rec.values()),
        )
        conn.commit()
        out.append(rec)
    return out


# ---- the placebo calibration ------------------------------------------------------------------------------
ARMS = ("A", "B", "C", "D")
# each arm's byte accounting: a flow's bytes at its end (as the shipped judge and the shadow count
# them) or spread over its lifetime
ARM_BYTES = {"A": "end-time", "B": "end-time", "C": "prorated", "D": "end-time"}


@dataclasses.dataclass
class Outcome:
    verdict: str  # reverted | suspended | passed | blind_pass | nodata
    stage: str = ""  # hourly | final
    hour: int | None = None  # the hour whose test reverted or suspended


def _prefix(values: dict[int, float], hs: list[int]) -> dict[int, float]:
    """Running sums over the hour list, so a window's sum is two lookups."""
    acc, out = 0.0, {}
    for h in hs:
        out[h] = acc
        acc += values.get(h, 0.0)
    out[hs[-1] + 3600] = acc
    return out


def calibrate(
    conn: sqlite3.Connection,
    prof: Profile,
    days: int = 60,
    arms: tuple[str, ...] = ARMS,
    now: float | None = None,
    k: int = 6,
    breakage: float = 0.3,
    by_class: bool = False,
) -> dict:
    """Placebo trials at every hour of the last `days` days, nothing blocked, under each arm:

    - A, as shipped: `autoblock.judge`'s arithmetic (end-time bytes, SHIPPED_ON readings, any TV hour
      under HOURLY_COLLAPSE reverts, a trial with under MIN_TRIAL_TV_HOURS passes blind);
    - B, confounders excluded: A on clean hours only, on both sides of each comparison;
    - C, judge v2: prorated bytes, clean demand hours, two-hour runs, suspension in confounded hours,
      K clean hours to pass, NODATA and extension to the ceiling (within the store's history);
    - D, judge v2 as it runs in shadow: C with end-time bytes, so the calibration and the shadow
      verdicts measure the same judge.

    For each arm: the false-revert rate alpha (hourly and final), the blind-pass or NODATA rate, the
    share of trials holding a confounded hour, the share whose reverting hour was confounded or had no
    demand, and the power at `breakage` (every expected-category byte after the pretended rule scaled
    by that factor: the share of trials that then take the rule out). Read-only."""
    now = now if now is not None else time.time()
    end = int(now // 3600) * 3600
    start = end - days * 86400
    first = start - BASELINE
    clf = ledger.Classifier(conn, prof, first, end)
    all_hours = list(range(first, end, 3600))
    cls = {h: clf.classify(h) for h in all_hours}
    active = {h: float(clf.facts(h).readings_active) for h in all_hours}
    if SHIPPED_ON != ("Active",):
        on_set = set(SHIPPED_ON)
        active = {h: float(sum(1 for r in clf.readings.get(h, []) if r[1] in on_set)) for h in all_hours}
    placebo = [h for h in all_hours if start <= h <= end - autoblock.TRIAL]
    classes = {c: sum(1 for h in all_hours if h >= start and cls[h][0] == c) for c in ledger.CLASSES}
    result: dict = {
        "generated": now, "days": days, "trials": len(placebo), "k": k, "breakage": breakage,
        "hour_classes": classes, "arms": {},
    }  # fmt: skip
    if not placebo:
        return result
    for arm in arms:
        out = [_run_arm(arm, h, clf, cls, active, k, 1.0, end) for h in placebo]
        broken = [_run_arm(arm, h, clf, cls, active, k, breakage, end) for h in placebo]
        result["arms"][arm] = _summary(out, broken, placebo, cls)
    if by_class:
        result["hours"] = [
            {"h": h, "class": cls[h][0], "reasons": cls[h][1]} for h in all_hours if h >= start
        ]
        result["reverting_hour_classes"] = {
            arm: _reverting_classes(arm, placebo, clf, cls, active, k, end) for arm in arms
        }
    return result


def _summary(
    out: list[Outcome], broken: list[Outcome], placebo: list[int], cls: dict[int, tuple[str, list[str]]]
) -> dict[str, float]:
    """One arm's numbers: shares of the placebo trials."""
    n = len(placebo)

    def share(outcomes: list[Outcome], pred) -> float:
        return round(sum(1 for o in outcomes if pred(o)) / n, 4)

    def at(o: Outcome, c: str) -> bool:
        return o.verdict == "reverted" and o.hour is not None and cls[o.hour][0] == c

    held = sum(
        1
        for h in placebo
        if any(cls.get(x, ("off",))[0] == "confounded" for x in range(h, h + autoblock.TRIAL, 3600))
    )
    return {
        "alpha": share(out, lambda o: o.verdict == "reverted"),
        "alpha_hourly": share(out, lambda o: o.verdict == "reverted" and o.stage == "hourly"),
        "alpha_final": share(out, lambda o: o.verdict == "reverted" and o.stage == "final"),
        "suspended": share(out, lambda o: o.verdict == "suspended"),
        "blind_pass": share(out, lambda o: o.verdict == "blind_pass"),
        "nodata": share(out, lambda o: o.verdict == "nodata"),
        "trials_with_confounded_hour": round(held / n, 4),
        "revert_hour_confounded": share(out, lambda o: at(o, "confounded")),
        "revert_hour_no_demand": share(out, lambda o: at(o, "no_demand")),
        "power": share(broken, lambda o: o.verdict == "reverted"),
        "power_out": share(broken, lambda o: o.verdict in ("reverted", "suspended")),
    }


def _reverting_classes(arm, placebo, clf, cls, active, k, end) -> dict[str, int]:
    out: dict[str, int] = {}
    for h in placebo:
        o = _run_arm(arm, h, clf, cls, active, k, 1.0, end)
        if o.verdict == "reverted":
            key = cls[o.hour][0] if o.hour is not None else "final"
            out[key] = out.get(key, 0) + 1
    return out


def _run_arm(
    arm: str,
    h: int,
    clf: ledger.Classifier,
    cls: dict[int, tuple[str, list[str]]],
    active: dict[int, float],
    k: int,
    scale: float,
    end: int,
) -> Outcome:
    """One placebo trial starting at `h`, bytes after it scaled by `scale`."""
    trial = list(range(h, h + autoblock.TRIAL, 3600))
    base = list(range(h - BASELINE, h, 3600))

    def b(x: int, prorated: bool = False) -> float:
        v = (clf.bytes_pro if prorated else clf.bytes_end).get(x, 0.0)
        return v * scale if x >= h else v

    if arm in ("A", "B"):
        use = (lambda x: True) if arm == "A" else (lambda x: cls[x][0] == "clean")
        before_b = sum(b(x) for x in base if use(x))
        before_n = sum(active[x] for x in base if use(x))
        before = before_b / before_n if before_n else 0.0
        for x in trial[:-1]:  # the shipped judge's hourly checks, the last hour going to the final test
            if not use(x):
                continue
            if (
                active[x] >= 1
                and before_n >= autoblock.MIN_TRIAL_TV_HOURS
                and before > 0
                and b(x) / active[x] < autoblock.HOURLY_COLLAPSE * before
            ):
                return Outcome("reverted", "hourly", x)
        after_n = sum(active[x] for x in trial if use(x))
        after = sum(b(x) for x in trial if use(x)) / after_n if after_n else 0.0
        if after_n < autoblock.MIN_TRIAL_TV_HOURS or before_n < autoblock.MIN_TRIAL_TV_HOURS:
            return Outcome("blind_pass", "final")
        if before > 0 and after < autoblock.STREAMING_COLLAPSE * before:
            return Outcome("reverted", "final")
        return Outcome("passed", "final")
    # arms C and D: judge v2's arithmetic over the precomputed classes, prorated or end-time bytes
    pro = ARM_BYTES[arm] == "prorated"
    base_clean = [x for x in base if cls[x][0] == "clean"]
    base_rate = sum(b(x, pro) for x in base_clean) / len(base_clean) if base_clean else 0.0
    comparable = len(base_clean) >= MIN_BASELINE_HOURS and base_rate > 0
    run: list[int] = []
    clean: list[int] = []
    x = h
    while x < min(h + CEILING, end):
        c = cls.get(x, ("off", []))[0]
        if c == "clean":
            clean.append(x)
        if c in ("clean", "confounded") and comparable:
            if run and x != run[-1] + 3600:
                run = []
            run = [*run, x] if b(x, pro) < autoblock.HOURLY_COLLAPSE * base_rate else []
            if len(run) >= LOW_RUN:
                hit = run[-LOW_RUN:]
                confounded = next((y for y in hit if cls[y][0] == "confounded"), None)
                if confounded is not None:
                    return Outcome("suspended", "hourly", confounded)
                return Outcome("reverted", "hourly", hit[-1])
        x += 3600
        if x >= h + autoblock.TRIAL and len(clean) >= k and comparable:
            rate = sum(b(y, pro) for y in clean) / len(clean)
            if rate < autoblock.STREAMING_COLLAPSE * base_rate:
                return Outcome("reverted", "final")
            return Outcome("passed", "final")
    return Outcome("nodata", "final")


def write_report(result: dict, reports_dir: str) -> str:
    """`<reports_dir>/calibrate/<date>.json`, written whole (a temporary file renamed into place)."""
    d = os.path.join(reports_dir, "calibrate")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, datetime.fromtimestamp(result["generated"]).strftime("%Y-%m-%d") + ".json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)
    return path


def summary_lines(result: dict) -> list[str]:
    """The calibration as a table for the terminal."""
    out = [
        f"placebo trials: {result['trials']} over {result['days']} days; K = {result['k']} clean hours;"
        f" power at breakage x{result['breakage']:g}",
        "hours: " + ", ".join(f"{c} {n}" for c, n in result["hour_classes"].items()),
        "arm  alpha  hourly  final  suspended  blind/nodata  trials-with-confounded  revert-hour-conf"
        "  revert-hour-no-demand  power  power-out",
    ]
    for arm, r in result["arms"].items():
        blind = r["blind_pass"] if arm in ("A", "B") else r["nodata"]
        out.append(
            f"{arm:<4} {r['alpha']:<6.1%} {r['alpha_hourly']:<7.1%} {r['alpha_final']:<6.1%}"
            f" {r['suspended']:<10.1%} {blind:<13.1%} {r['trials_with_confounded_hour']:<23.1%}"
            f" {r['revert_hour_confounded']:<17.1%} {r['revert_hour_no_demand']:<22.1%}"
            f" {r['power']:<6.1%} {r['power_out']:.1%}"
        )
    if not result["arms"]:
        out.append("(no complete trial window in the store yet)")
    else:
        out.append(
            "bytes: "
            + "; ".join(f"{arm} {ARM_BYTES.get(arm, '?')}" for arm in result["arms"])
            + " (the shadow judge counts end-time bytes: D is the judge it records)"
        )
    return out


def parse_arms(text: str) -> tuple[str, ...]:
    """`A,B,C,D` -> ('A', 'B', 'C', 'D'); ValueError on an arm that does not exist."""
    arms = tuple(dict.fromkeys(a.strip().upper() for a in text.split(",") if a.strip()))
    bad = [a for a in arms if a not in ARMS]
    if bad or not arms:
        raise ValueError(f"--arms: expected some of {','.join(ARMS)}, got {text!r}")
    return arms
