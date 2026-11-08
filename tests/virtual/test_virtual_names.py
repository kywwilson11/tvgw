"""(namebound) The live name count on a kernel (design decision 70): tvgw-apply's names table, the real
`tvgw.nametap` process bound to its NFLOG group in the gateway namespace, and a namespace TV that looks
names up and opens TLS connections under names of its choosing.

What only a kernel can say, and this module asks it:

- with the table loaded and nobody reading the group, every lookup answers and every connection opens:
  the rules copy, and a copy nobody reads is thrown away;
- with the reader bound, the copies arrive in order, so an answer is read before the hello that follows
  it: a hello naming the name its address was answered for is name-bound, one naming a name answered for
  another address is `shared`, and one to an address no answer gave is `never`;
- a reader killed with SIGKILL costs no later lookup or connection;
- `tvgw verify`'s check reads the table, the bound group and the status file;
- NAME_BINDING=off takes the table away.

The stand-in resolver of the gateway namespace answers a name `ip-A-B-C-D.<anything>` with A.B.C.D
(agent.py), so each test chooses the addresses its answers hand out. Port 443 is served at the web server,
the public resolver and the uplink router of the internet side (vnet.WAN_SERVE); the TV's hello there is
answered with no TLS at all, which ends the handshake after the hello has gone, all the count needs. The
module leaves the gateway as the `direct` scenario of matrix.txt has it."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time

import pytest
import vnet

from tvgw import config, nametap, verify

pytestmark = pytest.mark.virtual

DIRECT = next(s for s in vnet.parse_matrix(vnet.MATRIX.read_text(encoding="utf-8")) if s.name == "direct")
COUNT = {**DIRECT.settings, "NAME_BINDING": "count"}
REQUIRED = os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1"
# runs inside the gateway namespace with `python -I`: this checkout's count, as its unit would run it, with
# an empty query log, so its memory holds the whole last day (nothing) and every class can be told
RUNNER = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tvgw import config, nametap\n"
    "nametap.STATUS_EVERY = 0.2\n"
    "s = config.Settings(name_binding='count', adguard_querylog=sys.argv[3], tv_ip=sys.argv[4], gw_ip=sys.argv[5])\n"
    "sys.exit(nametap.main(s, status_path=sys.argv[2]))\n"
)
# runs inside the TV namespace: one TLS hello to ADDRESS:443 naming NAME, whatever the far end answers
HELLO = (
    "import socket, ssl, sys\n"
    "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
    "ctx.check_hostname = False\n"
    "ctx.verify_mode = ssl.CERT_NONE\n"
    "s = socket.create_connection((sys.argv[1], 443), timeout=3)\n"
    "try:\n"
    "    ctx.wrap_socket(s, server_hostname=sys.argv[2])\n"
    "except (OSError, ssl.SSLError):\n"
    "    pass\n"
    "print('sent')\n"
)


def unable(why: str) -> None:
    if REQUIRED:
        pytest.fail(f"TVGW_VIRTUAL_REQUIRED=1 but {why}")
    pytest.skip(why)


def name_for(address: str, zone: str = "names.tvgw.example") -> str:
    return f"ip-{address.replace('.', '-')}.{zone}"


def lookup(net, name: str) -> str:
    return net.probe("tv", "dns-udp", vnet.GW_TV, 53, name=name)


def hello(net, address: str, name: str) -> None:
    out = net.ns(net.tv, sys.executable, "-I", "-c", HELLO, address, name, check=False, timeout=15)
    assert out.stdout.strip() == "sent", out.stderr


def count(net, comment: str) -> int:
    return net.counters().get(comment, (0, ""))[0]


def apply(net, settings: dict[str, str], tag: str) -> subprocess.CompletedProcess:
    out = net.apply(net.gw, vnet.render_conf(settings))
    net.save(f"names/apply-{tag}.log", out.stdout + out.stderr)
    assert out.returncode == 0, out.stderr
    return out


class Reader:
    """One count process in the gateway namespace, and its status file."""

    def __init__(self, net, tag: str):
        self.net = net
        self.status = net.sandbox / f"names-{tag}.json"
        self.querylog = net.sandbox / f"names-{tag}-querylog.json"
        self.querylog.write_text("", encoding="utf-8")
        self.log_path = net.artifacts / "names" / f"{tag}.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.proc: subprocess.Popen | None = None

    def start(self, wait: float = 15.0) -> Reader:
        self.log = self.log_path.open("w", encoding="utf-8")
        argv = [sys.executable, "-I", "-c", RUNNER, str(vnet.ROOT / "src"), str(self.status)]
        argv += [str(self.querylog), vnet.TV_IP, vnet.GW_TV]
        self.proc = subprocess.Popen(
            ["ip", "netns", "exec", self.net.gw, *argv], stdout=self.log, stderr=subprocess.STDOUT
        )
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if self.doc() is not None:
                return self
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        with contextlib.suppress(OSError):
            self.log.flush()
        unable(
            f"the name count did not come up in {wait:.0f} s: {self.log_path.read_text(encoding='utf-8')[-600:]!r}"
        )
        raise AssertionError  # not reached

    def doc(self) -> dict | None:
        try:
            return json.loads(self.status.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def stats(self, until, wait: float = 10.0) -> dict:
        """The counts once `until(stats)` holds, or as they stand after `wait` seconds."""
        deadline = time.monotonic() + wait
        stats = (self.doc() or {}).get("stats", {})
        while not until(stats) and time.monotonic() < deadline:
            time.sleep(0.1)
            stats = (self.doc() or {}).get("stats", {})
        return stats

    def end(self, sig: int = signal.SIGTERM) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                self.proc.send_signal(sig)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        with contextlib.suppress(OSError):
            self.log.close()
        self.proc = None


@pytest.fixture(scope="module")
def gw(net):
    """The gateway with NAME_BINDING=count applied and no reader yet; the `direct` scenario put back when
    the module is done."""
    if shutil.which("modprobe"):  # both modules load on demand too; a container has no modprobe
        subprocess.run(["modprobe", "-a", "nfnetlink_log", "nft_log"], capture_output=True, check=False)
    out = apply(net, COUNT, "count")
    if "names table not loaded" in out.stderr:
        unable(f"this kernel does not load the names table: {out.stderr.strip()[-300:]}")
    readers: list[Reader] = []
    net.names_readers = readers
    try:
        yield net
    finally:
        for r in readers:
            r.end(signal.SIGKILL)
        apply(net, DIRECT.settings, "restore")
        net.save("names/ruleset-after.nft", net.ns(net.gw, "nft", "list", "ruleset").stdout)


def start(net, tag: str) -> Reader:
    r = Reader(net, tag)
    net.names_readers.append(r)
    return r.start()


def test_the_table_copies_and_with_no_reader_every_lookup_and_connection_goes_on(gw):
    net = gw
    table = net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_names").stdout
    net.save("names/table.nft", table)
    for needle, what in verify.NAMES_NEEDLES:
        assert needle in table, what
    assert table.count("log group 8 snaplen 4096 queue-threshold 1") == 3
    assert nametap.GROUP not in verify.log_groups(net.ns(net.gw, "cat", verify.PROC_LOG, check=False).stdout)
    before = count(net, nametap.COPY_RULES[0])
    assert lookup(net, name_for("203.0.113.10")) == "answer:203.0.113.10"
    assert net.probe("tv", "tcp", vnet.WEB, 443) == "pass:wlan0"
    hello(net, vnet.WEB, name_for("203.0.113.10"))
    assert count(net, nametap.COPY_RULES[0]) > before  # copied, and thrown away: nobody holds the group
    assert count(net, nametap.COPY_RULES[2]) >= 1


def test_the_copies_arrive_in_order_and_each_connection_gets_its_class(gw):
    net = gw
    reader = start(net, "classes")
    try:
        assert nametap.GROUP in verify.log_groups(net.ns(net.gw, "cat", verify.PROC_LOG, check=False).stdout)
        web, other = name_for(vnet.WEB), name_for(vnet.RESOLVER, "other.tvgw.example")
        assert lookup(net, web) == f"answer:{vnet.WEB}"
        assert lookup(net, other) == f"answer:{vnet.RESOLVER}"
        hello(net, vnet.WEB, web)  # the name its address was answered for
        hello(net, vnet.WEB, other)  # a name the filter answered, but for another address
        hello(net, vnet.WAN_GW, web)  # an address no answer gave
        stats = reader.stats(lambda st: st.get("bound", 0) and st.get("shared", 0) and st.get("never", 0))
        assert (stats.get("bound"), stats.get("shared"), stats.get("never")) == (1, 1, 1), stats
        assert (
            stats["answers"] >= 2 and stats["lost"] == 0 and stats["errors"] == 0 and stats["unparsed"] == 0
        )
        samples = {(s["name"], s["dst"], s["cls"]) for s in (reader.doc() or {}).get("samples", [])}
        assert {(other, vnet.WEB, "shared"), (web, vnet.WAN_GW, "never")} <= samples

        def run(cmd):
            return net.ns(net.gw, *cmd, check=False).stdout

        def read(path):
            if path == nametap.STATUS:
                return reader.status.read_text(encoding="utf-8")
            return net.ns(net.gw, "cat", path, check=False).stdout

        check, series = verify.names_check(config.Settings(name_binding="count"), run, read, time.time())
        assert check.ok and not check.warn and check.detail.startswith("bound and counting"), check.detail
        assert {rule for rule, _, _ in series} == {rule for _, rule in nametap.SERIES}
    finally:
        reader.end(signal.SIGKILL)
    # killed: the group is let go, and nothing the TV does waits for it
    assert nametap.GROUP not in verify.log_groups(net.ns(net.gw, "cat", verify.PROC_LOG, check=False).stdout)
    assert lookup(net, name_for("203.0.113.10", "after.tvgw.example")) == "answer:203.0.113.10"
    assert net.probe("tv", "tcp", vnet.WEB, 443) == "pass:wlan0"
    check, series = verify.names_check(
        config.Settings(name_binding="count"),
        lambda cmd: net.ns(net.gw, *cmd, check=False).stdout,
        lambda path: net.ns(net.gw, "cat", path, check=False).stdout,
        time.time(),
    )
    assert check.ok and check.warn and "no process holds NFLOG group 8" in check.detail and series == []


def test_off_takes_the_table_away(gw):
    net = gw
    apply(net, DIRECT.settings, "off")
    assert net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_names", check=False).returncode != 0
    assert lookup(net, name_for("203.0.113.10")) == "answer:203.0.113.10"
    apply(net, COUNT, "count-again")
