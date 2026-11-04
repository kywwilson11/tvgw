"""(plain) The analyst's novelty without the rotating video nodes (design decision 22, its dated note of
2026-11-03): a first-seen name under a known registrable domain, in an expected category, allowed and
carrying content, buys no daily request; the weekly review still counts it."""

import dataclasses

from ledger_store import H0, HOUR

from tvgw import analyst, autoblock, db
from tvgw.config import Settings

DAY = 86400


def settings(tmp_path):
    return Settings(state_dir=str(tmp_path), db_path=str(tmp_path / "s.db"), reports_dir=str(tmp_path / "r"))


def youtube_day(conn, lg, extra=()):
    """2026-10-26 as a viewing day: 17 new rotating video nodes under googlevideo.com, which the store
    knew before, each carrying video, and Google's panel research name, a tracker filed as 3rd-party ads
    and blocked. `extra` adds (name, bytes down) rows."""
    conn.execute(
        "INSERT INTO hosts(name, first_seen, last_seen, category, last_blocked) VALUES (?, ?, ?, 'Streaming', 0)",
        ("rr1---sn-old.googlevideo.com", H0 - 5 * DAY, H0 - 5 * DAY),
    )
    names = [(f"rr{i}---sn-n{i}.googlevideo.com", 60_000_000) for i in range(2, 19)]
    names += [(name, down) for name, down in extra]
    sport = 50000
    for i, (name, down) in enumerate(names):
        t = H0 + 19 * HOUR + i * 60
        conn.execute(
            "INSERT INTO hosts(name, first_seen, last_seen, category, last_blocked) VALUES (?, ?, ?, ?, 0)",
            (name, t, t, lg.categorize(name)),
        )
        conn.execute(
            "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, ?, 'A', 'A:203.0.113.9', 0)",
            (t, name),
        )
        for k in range(3):
            sport += 1
            conn.execute(
                "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (?, '203.0.113.9', 443, ?, ?)",
                (t + k, sport, name),
            )
            conn.execute(
                "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_down) VALUES (?, ?, 'tcp',"
                " '203.0.113.9', 443, ?, ?)",
                (t + k, t + k + 300, sport, down // 3),
            )
    panel = "eligibility-panelresearch.googlevideo.com"
    conn.execute(
        "INSERT INTO hosts(name, first_seen, last_seen, category, last_blocked) VALUES (?, ?, ?, ?, 1)",
        (panel, H0 + 20 * HOUR, H0 + 20 * HOUR, lg.categorize(panel)),
    )
    conn.execute("INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, ?, 'A', 1)", (H0 + 20 * HOUR, panel))
    conn.execute(
        "INSERT INTO tvstate(t, power, app) VALUES (?, 'Active', 'youtube.leanback.v4')", (H0 + 19 * HOUR,)
    )
    # the clock lookup of an ordinary evening, so the day raises no red line of its own
    conn.execute(
        "INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, 'us.lgtvsdp.com', 'A', 0)", (H0 + 19 * HOUR,)
    )
    conn.commit()
    assert lg.categorize(panel) == "3rd-party ads" and lg.categorize(names[0][0]) == "Streaming"


def the_pack(tmp_path, lg, extra=()):
    s = settings(tmp_path)
    conn = db.connect(s.db_path)
    youtube_day(conn, lg, extra)
    p = analyst.pack(conn, H0, H0 + DAY, "2026-10-26", lg, s)
    conn.close()
    return p


def test_seventeen_video_nodes_and_one_tracker_buy_one_reason(tmp_path, lg):
    """Design section 9, W14: the pack's shapes are autoblock.shapes()'s own (total_down, median_down),
    so the exemption reads the fields the code writes."""
    p = the_pack(tmp_path, lg)
    assert {"total_down", "median_down"} <= set(next(iter(p["shapes"].values())))
    assert set(dataclasses.asdict(autoblock.Shape(0, 0, 0, 0, 0, 0.0, 0, [], 0, None, None))) >= {
        "total_down",
        "median_down",
    }
    assert len(p["new_hosts"]) == 18
    assert analyst.novelty(p) == ["1 name(s) first seen"]
    assert analyst.novelty(p, review=True) == ["18 name(s) first seen"]  # the weekly review is unchanged


def test_a_name_under_the_video_domain_without_content_still_counts(tmp_path, lg):
    p = the_pack(tmp_path, lg, extra=[("telemetry-x.googlevideo.com", 30_000)])
    assert analyst.novelty(p) == ["2 name(s) first seen"]


def test_routine_needs_every_condition():
    p = {"profile": {"expected_categories": ["Streaming"]}, "shapes": {"a.x": {"total_down": 3 << 20}}}
    good = {"name": "a.x", "category": "Streaming", "new_domain": 0, "blocked": 0}
    assert analyst._routine(good, p)
    assert not analyst._routine({**good, "new_domain": 1}, p)
    assert not analyst._routine({k: v for k, v in good.items() if k != "new_domain"}, p)
    assert not analyst._routine({**good, "category": "3rd-party ads"}, p)
    assert not analyst._routine({**good, "blocked": 1}, p)
    assert not analyst._routine({**good, "name": "b.x"}, p)  # no shape: no evidence of content
    assert analyst._routine(good, {**p, "shapes": {"a.x": {"total_down": 0, "median_down": 32 << 10}}})
    assert not analyst._routine("a capped list's note", p)
