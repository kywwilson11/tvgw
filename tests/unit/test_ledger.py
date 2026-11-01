"""(ledger) The change ledger: the spool, the sampler, events from samples, the hour classifier, the
brief's "Changes in effect" and the analyst's counts (design decision 48)."""

import dataclasses
import io
import json
import os
import types

import pytest
from ledger_store import APP, CDN, H0, HDMI, HOUR, Synth

from tvgw import cli, db, ingest, ledger, queries
from tvgw.config import Settings


@pytest.fixture()
def s(tmp_path):
    return Settings(state_dir=str(tmp_path), db_path=str(tmp_path / "s.db"), reports_dir=str(tmp_path / "r"))


@pytest.fixture()
def synth(s):
    x = Synth(s.db_path)
    yield x
    x.close()


def kinds(conn, *cols):
    cols = cols or ("kind", "subject", "effect_class")
    return conn.execute(f"SELECT {', '.join(cols)} FROM changes ORDER BY t, kind").fetchall()


# ---- the spool -----------------------------------------------------------------------------------------
def spool(s, *lines):
    with open(ledger.spool_path(s), "a", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")


def load(conn, s):
    warnings = []
    n = ledger.load_spool(conn, s, ingest._tail, warnings.append)
    conn.commit()
    return n, warnings


def test_each_writer_line_becomes_one_change_with_its_class(s, synth):
    spool(
        s,
        f"{H0}\tdispatcher\teth0\tup",
        f"{H0 + 1}\tdispatcher\twlan0\tdhcp4-change",
        f"{H0 + 2}\tdispatcher\ttun0\tup",
        f"{H0 + 3}\tdispatcher\twlan0\tdown",
        f"{H0 + 4}\tapply\tnm-dispatcher\tunchanged",
        f"{H0 + 5}\tapply\ttvgw-doh-update\tchanged",
    )
    n, warnings = load(synth.conn, s)
    assert n == 6 and warnings == []
    assert kinds(synth.conn) == [
        ("tv_link_up", "eth0", "A"),
        ("dhcp_change", "wlan0", "B"),
        ("vpn_up", "tun0", "A"),
        ("wan_link_down", "wlan0", "A"),
        ("apply", "nm-dispatcher", "B"),  # an apply that left routing alone breaks nothing
        ("apply", "tvgw-doh-update", "A"),
    ]
    assert synth.conn.execute("SELECT MAX(t_precision), MIN(controllable) FROM changes").fetchone() == (
        1.0,
        0,
    )


def test_a_deploy_is_class_a_only_when_the_code_changed_and_says_when_the_metric_did(s, synth):
    spool(s, f"{H0}\tdeploy\ttvgw_0.1.0\taaaa\tmmmm", f"{H0 + 60}\tdeploy\ttvgw_0.1.0\taaaa\tmmmm")
    load(synth.conn, s)
    spool(s, f"{H0 + 120}\tdeploy\ttvgw_0.1.0\tbbbb\tmmmm", f"{H0 + 180}\tdeploy\ttvgw_0.1.0\tcccc\tnnnn")
    load(synth.conn, s)
    rows = kinds(synth.conn, "effect_class", "metric_affecting", "detail")
    assert [(c, m) for c, m, _ in rows] == [("A", None), ("B", None), ("A", None), ("A", "naming")]
    assert json.loads(rows[0][2]) == {"code": "aaaa", "metric": "mmmm", "code_changed": True}


def test_the_spool_is_read_once_junk_is_counted_and_a_large_spool_is_rotated(s, synth, monkeypatch):
    spool(
        s,
        "not a line",
        f"{H0}\tmystery\tx",
        f"{H0}\tdispatcher\teth0\tup",
        f"{H0 + 1}\tapply\t$(rm -rf)\tchanged",
    )
    n, warnings = load(synth.conn, s)
    assert n == 2 and warnings == ["changes: 2 spool line(s) this version cannot read were skipped"]
    assert kinds(synth.conn)[-1] == ("apply", "?", "A")  # a field that is not a plain word is not kept
    assert load(synth.conn, s)[0] == 0  # the cursor holds: nothing twice
    monkeypatch.setattr(ledger, "SPOOL_ROTATE", 10)
    spool(s, f"{H0 + 2}\tdispatcher\teth0\tdown")
    load(synth.conn, s)  # read whole, then renamed away
    assert not os.path.exists(ledger.spool_path(s)) and os.path.exists(ledger.spool_path(s) + ".1")
    with open(ledger.spool_path(s) + ".1", "a", encoding="utf-8") as fh:  # a writer that held it open
        fh.write(f"{H0 + 3}\tdispatcher\teth0\tup\n")
    spool(s, f"{H0 + 4}\tdispatcher\ttun0\tdown")  # the next writer starts a new file
    load(synth.conn, s)
    assert [k for k, *_ in kinds(synth.conn)][-3:] == ["tv_link_down", "tv_link_up", "vpn_down"]


def test_no_spool_yet_is_not_a_missing_source(s, synth):
    assert load(synth.conn, s) == (0, [])
    with open(ledger.spool_path(s) + ".1", "w", encoding="utf-8") as fh:  # someone else's old file
        fh.write(f"{H0}\tdispatcher\teth0\tup\n")
    assert load(synth.conn, s) == (0, [])


def test_append_spool_and_note_deploy_write_one_plain_line(s, tmp_path):
    ledger.append_spool(ledger.spool_path(s), ["dispatcher", "eth0", "up;reboot"], now=H0)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "ingest.py").write_text("a = 1\n", encoding="utf-8")
    (pkg / "cli.py").write_text("b = 1\n", encoding="utf-8")
    line = ledger.note_deploy(s, "tvgw 0.1.0", now=H0 + 1, package_dir=str(pkg))
    code, metric = ledger.code_fingerprint(str(pkg))
    assert line == f"deploy tvgw_0.1.0 {code} {metric}"
    (pkg / "cli.py").write_text("b = 2\n", encoding="utf-8")
    assert ledger.code_fingerprint(str(pkg)) == (ledger.code_fingerprint(str(pkg))[0], metric)  # metric same
    assert ledger.code_fingerprint(str(pkg))[0] != code
    (pkg / "ingest.py").write_text("a = 2\n", encoding="utf-8")
    assert ledger.code_fingerprint(str(pkg))[1] != metric
    with open(ledger.spool_path(s), encoding="utf-8") as fh:
        assert fh.read().splitlines() == [
            f"{H0}\tdispatcher\teth0\t?",
            f"{H0 + 1}\tdeploy\ttvgw_0.1.0\t{code}\t{metric}",
        ]
    assert oct(os.stat(ledger.spool_path(s)).st_mode & 0o777) in ("0o640", "0o600")


# ---- the sampler -----------------------------------------------------------------------------------------
# the station's address is from RFC 7042's documentation range, and the sampler must never keep it
STATION = """Station 00:00:5e:00:53:01 (on wlan0)
\tinactive time:\t120 ms
\trx bytes:\t123456
\ttx failed:\t7
\tsignal:  \t-52 [-52, -54] dBm
\ttx bitrate:\t433.3 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 1
\trx bitrate:\t390.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 1
"""
CT_STATS = (
    "cpu=0   \tfound=0 invalid=12 insert=0 insert_failed=1 drop=2 early_drop=3 error=0 search_restart=0\n"
    "cpu=1   \tfound=0 invalid=1 insert=0 insert_failed=0 drop=1 early_drop=0 error=0 search_restart=0\n"
)
FILES = {
    "/proc/sys/kernel/random/boot_id": "6f9c1a52-0000-4000-8000-000000000001\n",
    "/sys/class/net/eth0/carrier_changes": "4\n",
    "/sys/class/net/wlan0/carrier_changes": "2\n",
    "/sys/class/net/eth0/statistics/rx_bytes": "1000\n",
    "/sys/class/net/eth0/statistics/tx_bytes": "2000\n",
    "/sys/class/net/wlan0/statistics/rx_bytes": "3000\n",
    "/sys/class/net/wlan0/statistics/tx_bytes": "4000\n",
    "/sys/class/net/tun0/carrier_changes": "1\n",
    "/proc/sys/net/netfilter/nf_conntrack_count": "812\n",
    "/proc/sys/net/netfilter/nf_conntrack_max": "262144\n",
}


def fake_system(
    present=("/sys/class/net/tun0", "/sys/class/net/wlan0/wireless"),
    tools=("piactl", "iw", "conntrack", "systemctl"),
):
    calls = []

    def run(cmd):
        calls.append(cmd)
        name = os.path.basename(cmd[0])
        return {
            "piactl": "Connected\n",
            "iw": STATION,
            "conntrack": CT_STATS,
            "systemctl": "InvocationID=0123456789abcdef0123456789abcdef\nNRestarts=2\n",
        }.get(name, "")

    st = types.SimpleNamespace(st_mtime=H0 - 100.4, st_size=5000)
    return dict(
        run=run,
        read=lambda p: FILES.get(p),
        exists=lambda p: p in present,
        which=lambda t: f"/usr/bin/{t}" if t in tools else None,
        listdir=lambda d: ["1730000001.txt", "notes.txt", "1730000002.txt.old", "1730000002.txt"],
        stat=lambda p: st,
        now=H0,
    ), calls


def test_the_sampler_reads_every_source_and_keeps_no_address(s):
    kw, calls = fake_system()
    smp = ledger.sample(s, **kw)
    assert dataclasses.asdict(smp) == {
        "t": H0, "boot_id": "6f9c1a52-0000-4000-8000-000000000001", "tv_cc": 4, "wan_cc": 2, "vpn_if": "tun0",
        "vpn_present": 1, "vpn_cc": 1, "pia_state": "Connected", "wlan_signal": -52.0, "wlan_rx_mbps": 390.0,
        "wlan_tx_mbps": 433.3, "wlan_tx_failed": 7, "wan_rx_bytes": 3000, "wan_tx_bytes": 4000,
        "tv_rx_bytes": 1000, "tv_tx_bytes": 2000, "ct_count": 812, "ct_max": 262144, "ct_drop": 3,
        "ct_early_drop": 3, "ct_insert_failed": 1, "agh_invocation": "0123456789abcdef0123456789abcdef",
        "agh_nrestarts": 2, "filter_mtimes": json.dumps({"1730000001": [H0 - 101, 5000], "1730000002": [H0 - 101, 5000]}, sort_keys=True),
    }  # fmt: skip
    assert "00:00:5e" not in json.dumps(dataclasses.asdict(smp))
    assert ["/usr/bin/piactl", "get", "connectionstate"] in calls  # read-only commands only
    assert all(c[1:] in (["get", "connectionstate"], ["dev", "wlan0", "station", "dump"], ["-S"],
                         ["show", "AdGuardHome", "-p", "InvocationID", "-p", "NRestarts"]) for c in calls)  # fmt: skip


def test_a_missing_source_is_null_never_a_failure(s):
    kw, calls = fake_system(present=(), tools=())
    kw["read"] = lambda p: None
    kw["listdir"] = lambda d: (_ for _ in ()).throw(FileNotFoundError(d))
    smp = ledger.sample(s, **kw)
    assert calls == [] and smp.vpn_present == 0 and smp.vpn_if == "tun0"
    assert all(
        v is None for k, v in dataclasses.asdict(smp).items() if k not in ("t", "vpn_if", "vpn_present")
    )


def test_the_sampler_follows_a_vpn_interface_setting_and_ignores_odd_tool_output(s):
    kw, _ = fake_system(present=("/sys/class/net/wgpia0",))
    kw["run"] = lambda cmd: "Connected; rm -rf /\n" if "piactl" in cmd[0] else ""
    smp = ledger.sample(types.SimpleNamespace(**dataclasses.asdict(s), vpn_if="wgpia0"), **kw)
    assert (smp.vpn_if, smp.vpn_present, smp.pia_state, smp.agh_invocation) == ("wgpia0", 1, None, None)
    assert smp.wlan_signal is None  # no wireless directory: not a Wi-Fi uplink, iw is not asked


def test_parsers_of_the_tool_outputs():
    assert ledger.parse_conntrack_stats(CT_STATS) == (3, 3, 1)
    assert ledger.parse_conntrack_stats("") is None
    assert ledger.parse_systemctl_show("InvocationID=\nNRestarts=0\n") == (None, 0)
    two = STATION + "Station 00:00:5e:00:53:02 (on wlan0)\n\tsignal:  \t-90 dBm\n"
    assert ledger.parse_station_dump(two)["signal"] == -52.0


def test_verify_record_stores_a_sample_and_a_failed_sampler_fails_nothing(s, monkeypatch, capsys, lg):
    from tvgw import verify

    monkeypatch.setattr(verify, "check", lambda *a, **k: verify.Result(t=H0))
    monkeypatch.setattr(ledger, "sample", lambda st: ledger.Sample(H0, boot_id="b"))
    assert verify.main(s, lg, record_to_store=True) == 0
    conn = db.connect(s.db_path)
    assert conn.execute("SELECT t, boot_id FROM gw_samples").fetchall() == [(H0, "b")]

    def broken(st):
        raise RuntimeError("boom")

    monkeypatch.setattr(ledger, "sample", broken)
    assert verify.main(s, lg, record_to_store=True) == 0
    assert "the gateway sample failed: RuntimeError: boom" in capsys.readouterr().err
    monkeypatch.setattr(ledger, "sample", lambda st: pytest.fail("LEDGER=off samples nothing"))
    assert verify.main(dataclasses.replace(s, ledger="off"), lg, record_to_store=True) == 0
    conn.close()


# ---- events from consecutive samples ------------------------------------------------------------------------
def smp(t, **kw):
    base = dict(boot_id="boot-a", tv_cc=4, wan_cc=2, vpn_if="tun0", vpn_present=1, vpn_cc=1, ct_count=10,
                ct_max=1000, ct_drop=0, ct_early_drop=0, ct_insert_failed=0, agh_invocation="inv-a",
                agh_nrestarts=0, filter_mtimes=json.dumps({"1": [100, 5]}), pia_state="Connected")  # fmt: skip
    return ledger.Sample(t, **{**base, **kw})


def test_two_samples_show_flaps_restarts_drops_pressure_and_list_refreshes(s):
    a = smp(H0)
    b = smp(H0 + 600, tv_cc=6, wan_cc=3, vpn_cc=2, ct_drop=1, ct_count=900, agh_invocation="inv-b", agh_nrestarts=1,
            filter_mtimes=json.dumps({"1": [200, 6], "2": [300, 7]}))  # fmt: skip
    got = {(c.kind, c.subject): c.detail for c in ledger.derive(a, b, s)}
    assert got == {
        ("tv_flap", "eth0"): {"changes": 2},
        ("wan_flap", "wlan0"): {"changes": 1},
        ("vpn_flap", "tun0"): {"changes": 1},
        ("ct_drop", "conntrack"): {"drop": 1, "early_drop": 0, "insert_failed": 0},
        ("ct_pressure", "conntrack"): {"pct": 90},
        ("adguard_restart", "AdGuardHome"): {"automatic": 1},
        ("list_refresh", "1"): {"size": 6},
        ("list_refresh", "2"): {"size": 7},
    }
    assert {c.t_precision for c in ledger.derive(a, b, s)} == {600.0}
    c = dataclasses.replace(b, t=H0 + 1200, filter_mtimes="{}")
    assert [x.kind for x in ledger.derive(b, c, s)] == ["list_removed", "list_removed"]


def test_a_reboot_is_the_one_event_and_counter_resets_are_not_flaps(s):
    a = smp(H0, tv_cc=40)
    assert [c.kind for c in ledger.derive(a, smp(H0 + 600, boot_id="boot-b", tv_cc=1), s)] == ["reboot"]
    assert ledger.derive(a, smp(H0 + 600, tv_cc=1), s) == []  # went down without a reboot: not a flap
    gap = ledger.derive(a, smp(H0 + 3000, tv_cc=41), s)
    assert gap[0].t_precision == 3000  # samples missed: the time is known only to the gap


def test_the_vpn_interface_going_and_coming_back(s):
    assert [c.kind for c in ledger.derive(smp(H0), smp(H0 + 600, vpn_present=0, vpn_cc=None), s)] == [
        "vpn_gone"
    ]
    assert [c.kind for c in ledger.derive(smp(H0, vpn_present=0), smp(H0 + 600), s)] == ["vpn_back"]


def test_derive_all_is_incremental_and_a_pia_outage_is_one_row_when_it_ends(s, synth):
    for i, state in enumerate(["Connected", "Reconnecting", "Interrupted"]):
        ledger.record_sample(synth.conn, smp(H0 + i * 600, pia_state=state))
    assert ledger.derive_all(synth.conn, s) == 0  # the outage is open: nothing written yet
    assert ledger.derive_all(synth.conn, s) == 0
    ledger.record_sample(synth.conn, smp(H0 + 1800, pia_state="Connected", tv_cc=5))
    assert ledger.derive_all(synth.conn, s) == 2
    rows = synth.conn.execute("SELECT kind, t, t_end, subject, detail FROM changes ORDER BY t").fetchall()
    assert rows[0] == (
        "pia_down",
        H0 + 600,
        H0 + 1800,
        "Reconnecting",
        '{"states": ["Reconnecting", "Interrupted"]}',
    )
    assert rows[1][:2] == ("tv_flap", H0 + 1800)
    assert ledger.derive_all(synth.conn, s) == 0


def test_machine_rules_are_copied_and_a_second_trial_keeps_the_first(s, synth):
    c = synth.conn
    c.execute("INSERT INTO auto_rules(rule, name, added_t, verdict, decided_t) VALUES ('||t.example^', 't.example', ?, 'reverted', ?)", (H0, H0 + 3600))  # fmt: skip
    c.commit()
    assert ledger.from_auto_rules(c) == 2
    c.execute("UPDATE auto_rules SET added_t = ?, verdict = NULL, decided_t = NULL", (H0 + 86400,))
    assert ledger.from_auto_rules(c) == 1
    assert [k for k, *_ in kinds(c)] == ["machine_rule_add", "machine_rule_reverted", "machine_rule_add"]


def test_the_ingest_runs_the_ledger_step_and_prunes_it_with_the_store(gateway, lg, monkeypatch):
    from conftest import NOW, fake_extract, fake_oddport

    spool(gateway, f"{int(NOW) - 60}\tdispatcher\teth0\tup")
    conn = db.connect(gateway.db_path)
    ledger.record_sample(conn, smp(NOW - 1200))
    ledger.record_sample(conn, smp(NOW - 600, tv_cc=9))
    ledger.record_sample(conn, smp(NOW - 400 * 86400))  # older than DB_DAYS
    conn.close()
    stats = ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda since: [], lock=False
    )
    assert not [w for w in stats.warnings if w.startswith("changes")]
    conn = db.connect(gateway.db_path)
    assert [k for k, *_ in kinds(conn)] == ["tv_flap", "tv_link_up"]
    assert conn.execute("SELECT COUNT(*) FROM gw_samples").fetchone()[0] == 2  # the old one pruned
    conn.close()
    off = dataclasses.replace(gateway, ledger="off")
    assert ledger.ingest(db.connect(off.db_path), off, ingest._tail) == 0


# ---- the hour classifier -------------------------------------------------------------------------------------
def test_off_no_demand_demand_and_clean(synth, lg):
    synth.reading(H0, "unreachable", None)
    synth.reading(H0 + HOUR, "Active", HDMI)
    synth.stream(H0 + 2 * HOUR, app=HDMI)  # an input in front at the reading, but the CDN was in use
    synth.stream(H0 + 3 * HOUR)
    synth.reading(H0 + 4 * HOUR, "Screen Saver", "")
    got = [ledger.classify_hour(synth.conn, H0 + i * HOUR, lg) for i in range(6)]
    assert [c for c, _ in got] == ["off", "no_demand", "clean", "clean", "no_demand", "off"]
    assert got[2][1] == ["4 expected starts", "3 expected lookups"]
    assert got[3][1] == ["app in front", "4 expected starts", "3 expected lookups"]


def test_class_a_changes_confound_from_ten_minutes_before_class_b_never(synth, lg):
    for i in range(4):
        synth.stream(H0 + i * HOUR)
    synth.change(H0 + 2 * HOUR - 300, "adguard_restart", "AdGuardHome", t_precision=0)  # :55
    synth.change(H0 + 60, "dhcp_change", "wlan0", source="dispatcher")
    synth.change(H0 + 3 * HOUR + 1200, "pia_down", "Reconnecting", t_end=H0 + 3 * HOUR + 1500)
    clf = ledger.Classifier(synth.conn, lg, H0, H0 + 4 * HOUR)
    clean = ("clean", ["app in front", "4 expected starts", "3 expected lookups"])
    assert [clf.classify(H0 + i * HOUR) for i in range(4)] == [
        clean,  # class B: logged, never a confounder
        ("confounded", ["AdGuard restart"]),  # its own hour
        ("confounded", ["AdGuard restart"]),  # and the next: 5 minutes before it, inside LEAD
        ("confounded", ["PIA not connected"]),
    ]


def test_a_sampler_event_counts_where_it_may_have_happened(synth, lg):
    synth.stream(H0)
    synth.stream(H0 + HOUR)
    synth.stream(H0 + 3 * HOUR)
    synth.change(H0 + HOUR + 300, "tv_flap", "eth0", t_precision=600)  # seen at :05: from :55 on
    assert ledger.classify_hour(synth.conn, H0, lg) == ("confounded", ["TV link flap"])  # it may be :55
    assert ledger.classify_hour(synth.conn, H0 + HOUR, lg) == ("confounded", ["TV link flap"])
    assert ledger.classify_hour(synth.conn, H0 + 3 * HOUR, lg)[0] == "clean"


def test_the_rule_under_trial_and_its_own_restart_are_excused(synth, lg):
    synth.stream(H0)
    synth.stream(H0 + HOUR)
    synth.change(H0 + 60, "machine_rule_add", "||t.example^", source="autoblock")
    synth.change(H0 + 600, "adguard_restart", "AdGuardHome", t_precision=600)  # seen at :10, within 5 min
    synth.change(H0 + HOUR + 60, "machine_rule_add", "||other.example^", source="autoblock")
    trial = {"rule": "||t.example^", "added_t": H0 + 60}
    assert ledger.classify_hour(synth.conn, H0, lg, trial)[0] == "clean"
    assert ledger.classify_hour(synth.conn, H0, lg)[1] == ["machine rule added", "AdGuard restart"]
    assert ledger.classify_hour(synth.conn, H0 + HOUR, lg, trial) == ("confounded", ["machine rule added"])
    synth.change(
        H0 + 1500, "adguard_restart", "AdGuardHome", t_precision=600
    )  # 24 minutes later: not its own
    assert ledger.classify_hour(synth.conn, H0, lg, trial) == ("confounded", ["AdGuard restart"])


def test_samples_in_the_hour_confound_pia_pressure_wifi_and_contention(synth, lg):
    for d in range(1, 3):  # two days of steady Wi-Fi history
        for i in range(0, 86400, 3600):
            synth.sample(H0 - d * 86400 + i, wlan_signal=-50.0, wlan_rx_mbps=400.0)
    for i in range(4):
        synth.stream(H0 + i * HOUR)
    synth.sample(H0 + 600, pia_state="Reconnecting")
    synth.sample(H0 + HOUR + 600, ct_count=200_000, ct_max=262144)
    synth.sample(H0 + 2 * HOUR + 600, wlan_signal=-60.0)
    synth.sample(H0 + 2 * HOUR + 1200, wlan_signal=-61.0)
    synth.sample(H0 + 3 * HOUR, tv_tx_bytes=0, tv_rx_bytes=0, wan_tx_bytes=0)
    synth.sample(H0 + 3 * HOUR + 600, tv_tx_bytes=6_000_000, tv_rx_bytes=100_000, wan_tx_bytes=600_000_000)
    clf = ledger.Classifier(synth.conn, lg, H0, H0 + 4 * HOUR)
    assert [clf.classify(H0 + i * HOUR)[1] for i in range(4)] == [
        ["PIA Reconnecting"],
        ["conntrack pressure"],
        ["Wi-Fi degraded"],
        ["uplink contention"],
    ]


def test_measurement_faults_confound(synth, lg):
    for i in range(3):
        synth.stream(H0 + i * HOUR)
    utc = (
        __import__("datetime").datetime.fromtimestamp(H0, __import__("datetime").UTC).strftime("%Y%m%d%H%M%S")
    )
    synth.conn.execute(
        "INSERT INTO pcaps_done(name, done_at, tls_rows, syn443_rows) VALUES (?, 0, 0, 40)",
        (f"tv_{utc}_00001.pcap",),
    )
    synth.conn.execute(
        "UPDATE flows SET state='ESTABLISHED', timeout_left=300 WHERE t_start = ?", (H0 + HOUR + 300,)
    )
    synth.conn.execute("INSERT INTO ingest_runs(t, warnings) VALUES (?, ?)", (H0 + 2 * HOUR + 1200, json.dumps(["flows: conntrack lost events 2 time(s) since the last run"])))  # fmt: skip
    synth.conn.commit()
    clf = ledger.Classifier(synth.conn, lg, H0, H0 + 3 * HOUR)
    assert clf.classify(H0)[1] == ["capture named nothing"]
    assert "connections broken by the gateway" in clf.classify(H0 + HOUR)[1]
    assert clf.classify(H0 + 2 * HOUR)[1] == ["conntrack lost events"]


def test_pcap_names_give_the_hour_they_start():
    assert ledger.pcap_hour("tv_20261026050000_00001.pcap") == H0  # dumpcap, UTC: 00:00 CDT
    assert ledger.pcap_hour("tvhdr_20261026050000_00002.pcap") == H0
    assert ledger.pcap_hour("tv-20261026-0100.pcap") == H0 + HOUR  # tcpdump, local
    assert ledger.pcap_hour("notes.txt") is None


def test_bytes_end_where_the_flow_ended_and_prorate_over_its_life(synth, lg):
    synth.flow(H0 + 1800, H0 + 2 * HOUR + 1800, 120.0)  # two hours across three clock hours
    clf = ledger.Classifier(synth.conn, lg, H0, H0 + 3 * HOUR)
    assert [clf.facts(H0 + i * HOUR).bytes_end for i in range(3)] == [0, 0, 120e6]
    assert [round(clf.facts(H0 + i * HOUR).bytes_prorated / 1e6) for i in range(3)] == [30, 60, 30]


# ---- the brief section and the pack ------------------------------------------------------------------------
def test_a_store_from_before_the_ledger_has_no_section(synth, lg):
    synth.stream(H0)
    assert ledger.section(synth.conn, lg, H0, H0 + 86400, H0 + 86400) is None
    assert queries.brief(synth.conn, "2026-10-26", lg, now=H0 + 86400)["changes_in_effect"] is None


def build_day(synth):
    for i in range(18, 22):
        synth.stream(H0 + i * HOUR)
    synth.reading(H0 + 22 * HOUR, "Active", HDMI)
    for i in range(0, 86400, 600):
        synth.sample(H0 + i)
    synth.change(H0 + 3 * HOUR + 50 * 60, "adguard_restart", "AdGuardHome", t_precision=600)
    for i in range(12):
        synth.change(H0 + i * 7200 + 5, "dhcp_change", "wlan0", source="dispatcher", t_precision=1)
        synth.change(
            H0 + i * 7200 + 6, "apply", "nm-dispatcher", source="apply", t_precision=1, effect_class="B"
        )
    synth.change(
        H0 + 20 * HOUR + 600, "pia_down", "Reconnecting", t_end=H0 + 20 * HOUR + 2400, t_precision=600
    )
    synth.change(
        H0 + 14 * HOUR + 300, "code_deploy", "tvgw_0.1.0", source="deploy", metric_affecting="naming"
    )


def test_the_section_counts_class_b_and_times_class_a(synth, lg):
    build_day(synth)
    sec = ledger.section(synth.conn, lg, H0, H0 + 86400, H0 + 86400)
    lines = ledger.render(sec)
    assert lines[0].startswith("Changes in effect (10-26 00:00 .. 10-27 00:00")
    gateway = next(ln for ln in lines if ln.startswith("  Gateway"))
    assert "~03:50 AdGuard restart" in gateway and "14:05 deploy (metric-affecting)" in gateway
    assert "DHCP change (wlan0) x12" in gateway and "apply (nm-dispatcher) x12" in gateway
    assert next(ln for ln in lines if ln.startswith("  Uplink")).endswith(
        "~20:10-20:40 PIA not connected (Reconnecting)"
    )
    assert next(ln for ln in lines if ln.startswith("  TV path")).startswith(
        "  TV path    TV link flaps: 0   conntrack: max 262144, peak 0% full"
    )
    assert lines[-1] == (
        "  Hours      TV on 5: clean 3, confounded 1 (PIA not connected 20h), no demand 1 (input or launcher in front 22h)"
    )
    assert sec["hour_counts"] == {"off": 19, "no_demand": 1, "confounded": 1, "clean": 3}


def test_the_pack_gets_counts_and_never_a_subject_or_a_time(synth, lg):
    build_day(synth)
    entry = ledger.pack_entry(ledger.section(synth.conn, lg, H0, H0 + 86400, H0 + 86400))
    assert entry == {
        "changes": {"adguard_restart": 1, "apply": 12, "code_deploy": 1, "dhcp_change": 12, "pia_down": 1},
        "hours": {"off": 19, "no_demand": 1, "confounded": 1, "clean": 3},
        "confounded_by": {"PIA not connected": 1},
        "firmware_changes": 0,
        "machine_rules_on_trial": 0,
    }
    text = json.dumps(entry)
    assert "wlan0" not in text and "Reconnecting" not in text and "nm-dispatcher" not in text
    assert ledger.pack_entry(None) == {}
    synth.sample(H0 + 19 * HOUR + 600, pia_state="Interrupted")  # a state word from the sampler
    entry = ledger.pack_entry(ledger.section(synth.conn, lg, H0, H0 + 86400, H0 + 86400))
    assert entry["confounded_by"] == {"PIA not connected": 2} and "Interrupted" not in json.dumps(entry)


def test_a_trial_short_of_clean_hours_past_half_its_ceiling_is_a_red_line(synth, lg):
    build_day(synth)
    added = H0 - 8 * 86400
    synth.conn.execute("INSERT INTO auto_rules(rule, name, added_t, trial_until) VALUES ('||t.example^', 't.example', ?, ?)", (added, added + 86400))  # fmt: skip
    synth.conn.execute(
        "INSERT INTO judge_shadow(t, rule, added_t, hour, v2, v2_reason, clean_hours, k, final) VALUES (?, '||t.example^', ?, ?, 'nodata', 'extend', 2, 6, 0)",
        (H0, added, H0 - 3600),
    )
    synth.conn.commit()
    o = queries.brief(synth.conn, "2026-10-26", lg, now=H0 + 86400)
    assert o["changes_in_effect"]["on_trial"][0]["v2"] == "nodata"
    assert any(
        "has spent more than half of judge v2's 14-day ceiling with 2 of 6 clean TV hours" in r
        for r in o["red_lines"]
    )
    buf = io.StringIO()
    cli.render_brief(o, buf)
    text = buf.getvalue()
    assert (
        "  On trial   ||t.example^   added 10-18 00:00; clean TV hours 2 of 6 needed; judge: watching; judge v2 (shadow): nodata"
        in text
    )
    # after the red lines and the summary lines, before the tables and the machine rules
    assert text.index("RED LINE") < text.index("Changes in effect") < text.index("New hosts")


def test_the_section_says_when_no_sample_was_taken(synth, lg):
    synth.change(H0 + 60, "apply", "tvgw", source="apply", effect_class="B")
    lines = ledger.render(ledger.section(synth.conn, lg, H0, H0 + 86400, H0 + 86400))
    assert lines[-1].startswith("  (no gateway samples in this window")


def test_a_reader_of_an_unmigrated_store_gets_no_section(tmp_path, lg):
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "old.db"))
    conn.execute("CREATE TABLE tvstate(t REAL PRIMARY KEY, power TEXT, app TEXT)")
    assert ledger.section(conn, lg, H0, H0 + 86400, H0 + 86400) is None


def test_app_ids_with_no_streaming_by_construction():
    assert (
        ledger.no_demand_app(None) and ledger.no_demand_app("") and ledger.no_demand_app("com.webos.app.home")
    )
    assert ledger.no_demand_app("com.webos.app.hdmi3") and ledger.no_demand_app("com.webos.app.livetv")
    assert not ledger.no_demand_app(APP) and not ledger.no_demand_app("youtube.leanback.v4")
    assert CDN == "cdn.example"
