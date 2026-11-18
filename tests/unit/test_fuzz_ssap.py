"""The two readers of what an LG TV sends in a session, the probe's (lgwebos._on_message) and the live
reading's (tvlive._message), never raise, whatever the TV sends: text that is not JSON, JSON of any
shape, and messages built from the words the readers look for. `{"id": []}` raised TypeError in both (an
unhashable id), and `tvgw tvprobe` ended in a traceback (design decision 106)."""

import json

import pytest

pytest.importorskip("hypothesis")  # the dev extras carry it
from hypothesis import example, given, settings
from hypothesis import strategies as st

from tvgw import lgwebos, tvlive

WORDS = ["power", "app", "error", "Active", "Screen Off", "com.webos.app.home"]
FIELDS = ["id", "type", "payload", "error", "state", "appId", "returnValue", "processing", "subscribed"]
values = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=12), st.sampled_from(WORDS)),
    lambda inner: st.one_of(
        st.lists(inner, max_size=3), st.dictionaries(st.sampled_from(FIELDS), inner, max_size=5)
    ),
    max_leaves=10,
)
messages = st.one_of(st.text(max_size=100), values.map(json.dumps))
SUBS = {"power": lgwebos.POWER_URI, "app": lgwebos.APP_URI}


class Log:
    """An event log that writes each line as the real ones do, and keeps nothing."""

    def write(self, kind, **fields) -> None:
        json.dumps({"kind": kind, **fields}, default=str)


@settings(max_examples=300, deadline=None)
@given(messages)
@example('{"id": []}')
def test_the_probes_reader_never_raises(raw):
    lgwebos._on_message(raw, SUBS, set(), Log())


@settings(max_examples=300, deadline=None)
@given(messages)
@example('{"id": []}')
def test_the_live_readings_reader_never_raises(raw):
    tvlive._message(raw, SUBS, tvlive._State(), Log())
