"""(web) The page's sign-in: the password kept as a hash, the sessions kept in memory, the limit on failed
sign-ins, and the tokens its two forms carry (design decision 76).

Nothing here opens a socket or a file but `read_hash`: every clock and every random source is the
caller's or a parameter, so the rules are tested without a server. The clocks are monotonic seconds (the
server passes `time.monotonic()`): a session lives in memory only, so a restart signs everyone out, and a
step of the wall clock can neither lengthen nor end one.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import re
import secrets
import threading
import unicodedata
from collections import OrderedDict, deque
from dataclasses import dataclass

MIN_PASSWORD = 12  # characters
MAX_PASSWORD = 1024  # characters: longer is refused before any hashing (the form's body is 4 KB anyway)
# scrypt's cost: N = 2**15, r = 8, p = 1 takes 32 MiB and one core for a moment per check. The hash keeps
# its own parameters, so a later version can raise them and still read an older file
SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P = 15, 8, 1
SCRYPT_MAXMEM = 64 * 2**20  # OpenSSL's default ceiling is 32 MiB, which N = 2**15, r = 8 just passes
# what a hash file may ask for: a file edited to ask for more would make each check a denial of service
LOG_N_RANGE, R_RANGE, P_RANGE = range(14, 21), range(1, 17), range(1, 5)
SALT_BYTES = 16
KEY_BYTES = 32
SCHEME = "scrypt"
TOKEN_BYTES = 32  # a session, its form token and the sign-in form's token: 32 random bytes each
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")  # secrets.token_urlsafe(32), and nothing else
SESSION_CAP = 20
SESSION_ABSOLUTE = 30 * 86400  # seconds a session lasts at most, however often it is used
SESSION_IDLE = 7 * 86400  # seconds a session lasts unused
# the limit on failed sign-ins (design decision 76): per address, a wait that doubles; for a device the page
# does not know, one password check every few seconds and a cap per day; a known device skips the last two
FREE_TRIES = 5  # failed sign-ins from one address before it waits
BACKOFF_FIRST = 60  # seconds it waits after the fifth, doubled after each further failure
BACKOFF_CAP = 3600  # seconds: the longest wait
FORGET = 86400  # seconds without a failure after which an address starts again with its free tries
UNKNOWN_SPACING = 3.0  # seconds between two password checks for devices the page does not know
UNKNOWN_DAILY = 100  # failed sign-ins from such devices in UNKNOWN_DAY before they are refused
UNKNOWN_DAY = 86400  # seconds
MAX_ADDRESSES = 4096  # addresses whose failures are remembered; the oldest is forgotten first
DEVICE_ID = re.compile(r"[A-Za-z0-9_-]{22}")  # secrets.token_urlsafe(16)
DEVICE = re.compile(r"[A-Za-z0-9_-]{22}\.[0-9a-f]{64}")  # a known device's cookie: its id and an HMAC of it


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _normal(password: str) -> bytes:
    """The password as hashed: NFC, so a phone's keyboard and the gateway's terminal agree on an accent
    typed either way, then UTF-8."""
    return unicodedata.normalize("NFC", password).encode("utf-8")


def password_problem(password: str) -> str | None:
    """Why a new password is refused, in plain words, or None when it is accepted."""
    if len(password) < MIN_PASSWORD:
        return f"The password must be at least {MIN_PASSWORD} characters long."
    if len(password) > MAX_PASSWORD:
        return f"The password must be at most {MAX_PASSWORD} characters long."
    if not password.strip():
        return "The password must not be only spaces."
    return None


def _derive(password: str, salt: bytes, log_n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        _normal(password), salt=salt, n=2**log_n, r=r, p=p, maxmem=SCRYPT_MAXMEM, dklen=KEY_BYTES
    )


def hash_password(password: str, salt: bytes | None = None) -> str:
    """`scrypt$<log2 N>$<r>$<p>$<salt>$<key>`, salt and key in unpadded URL-safe base64. ValueError for a
    password `password_problem` refuses: the writer never stores one."""
    problem = password_problem(password)
    if problem:
        raise ValueError(problem)
    salt = secrets.token_bytes(SALT_BYTES) if salt is None else salt
    key = _derive(password, salt, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)
    return f"{SCHEME}${SCRYPT_LOG_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(key)}"


@dataclass(frozen=True)
class Stored:
    log_n: int
    r: int
    p: int
    salt: bytes
    key: bytes


def parse_hash(text: str | None) -> Stored | None:
    """A stored hash, or None when the text is not one this version writes, or asks for more memory or
    work than it may."""
    parts = (text or "").strip().split("$")
    if len(parts) != 6 or parts[0] != SCHEME or not all(re.fullmatch(r"[0-9]{1,3}", x) for x in parts[1:4]):
        return None
    log_n, r, p = (int(x) for x in parts[1:4])
    if log_n not in LOG_N_RANGE or r not in R_RANGE or p not in P_RANGE:
        return None
    try:
        salt, key = _unb64(parts[4]), _unb64(parts[5])
    except (ValueError, TypeError):
        return None
    if len(salt) < SALT_BYTES or len(key) != KEY_BYTES:
        return None
    return Stored(log_n, r, p, salt, key)


def check_password(password: str, stored_text: str | None) -> bool:
    """Whether `password` is the one `stored_text` holds, compared in constant time. A malformed hash or
    an oversized password is False, never an error."""
    stored = parse_hash(stored_text)
    if stored is None or not isinstance(password, str) or len(password) > MAX_PASSWORD:
        return False
    try:
        got = _derive(password, stored.salt, stored.log_n, stored.r, stored.p)
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(got, stored.key)


def mark(stored_text: str | None) -> str:
    """What a session remembers of the password it was opened under: a hash of the stored hash. A new
    password changes it, and every session opened under the old one ends."""
    return hashlib.sha256((stored_text or "").strip().encode("utf-8")).hexdigest()


def read_hash(path: str) -> str | None:
    """The stored hash's text, None when the file is missing, cannot be read, or holds no hash."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read(4096).strip()
    except OSError:
        return None
    return text if parse_hash(text) else None


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


# ---- sessions ------------------------------------------------------------------------------------------
@dataclass
class Session:
    csrf: str  # the token the sign-out form carries
    created: float
    seen: float
    password: str  # mark() of the hash it was opened under


class Sessions:
    """At most SESSION_CAP sessions in memory, by a hash of their cookie's token (the token itself is
    never kept). A session ends SESSION_ABSOLUTE after it opened, SESSION_IDLE after its last use, when
    the password changes, or when the cap needs its place (the one unused longest goes)."""

    def __init__(
        self,
        cap: int = SESSION_CAP,
        absolute: float = SESSION_ABSOLUTE,
        idle: float = SESSION_IDLE,
        token=new_token,
    ):
        self.cap, self.absolute, self.idle, self._token = cap, absolute, idle, token
        self._by_key: dict[str, Session] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def _alive(self, s: Session, now: float, password: str) -> bool:
        return (
            0 <= now - s.created < self.absolute
            and now - s.seen < self.idle
            and hmac.compare_digest(s.password, password)
        )

    def open(self, now: float, password: str) -> tuple[str, Session]:
        """A new session's cookie token and the session."""
        token = self._token()
        s = Session(csrf=self._token(), created=now, seen=now, password=password)
        with self._lock:
            for key in [k for k, v in self._by_key.items() if not self._alive(v, now, password)]:
                del self._by_key[key]
            while len(self._by_key) >= self.cap:
                oldest = min(self._by_key, key=lambda k: self._by_key[k].seen)
                del self._by_key[oldest]
            self._by_key[self._key(token)] = s
        return token, s

    def get(self, token: str | None, now: float, password: str) -> Session | None:
        """The live session a cookie names, its last use moved to `now`; None for anything else, and a
        session found dead is ended."""
        if not token or not TOKEN.fullmatch(token):
            return None
        key = self._key(token)
        with self._lock:
            s = self._by_key.get(key)
            if s is None:
                return None
            if not self._alive(s, now, password):
                del self._by_key[key]
                return None
            s.seen = now
            return s

    def close(self, token: str | None) -> None:
        if token and TOKEN.fullmatch(token):
            with self._lock:
                self._by_key.pop(self._key(token), None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_key)


# ---- the limit on failed sign-ins ----------------------------------------------------------------------
@dataclass
class Ticket:
    """One password check the limiter let through, counted as a failure until `succeeded` says otherwise."""

    address: str
    known: bool
    at: float


@dataclass
class _Address:
    fails: int = 0
    last: float = float("-inf")
    until: float = float("-inf")


def backoff(fails: int) -> float:
    """Seconds an address waits after its `fails`-th failure in a row: none for the first FREE_TRIES - 1,
    then BACKOFF_FIRST, doubled after each further failure, never over BACKOFF_CAP."""
    if fails < FREE_TRIES:
        return 0.0
    return float(min(BACKOFF_FIRST * 2 ** (fails - FREE_TRIES), BACKOFF_CAP))


class Limiter:
    """Failed sign-ins, so that a guesser on the home network gets few tries and the owner is never locked
    out for long (design decision 76).

    Per client address: FREE_TRIES failures, then a wait of BACKOFF_FIRST that doubles after each further
    failure up to BACKOFF_CAP; a success, or FORGET without a failure, starts the address again. For a device
    the page does not know (no valid known-device cookie): one password check every UNKNOWN_SPACING seconds
    among all of them, and at most UNKNOWN_DAILY failures in UNKNOWN_DAY, after which such devices are refused
    until the oldest ages out. A known device is held to its address's waits only, so a guesser can never
    keep the owner's phone out.

    `admit` reserves a check under the lock before the slow hash, counting it as a failure at once, so
    sixteen guesses sent together are judged one after another: `succeeded` takes the count back. A refused
    attempt is never hashed and never counted."""

    def __init__(
        self,
        free: int = FREE_TRIES,
        spacing: float = UNKNOWN_SPACING,
        daily: int = UNKNOWN_DAILY,
        day: float = UNKNOWN_DAY,
        forget: float = FORGET,
        max_addresses: int = MAX_ADDRESSES,
    ):
        self.free, self.spacing, self.daily, self.day, self.forget = free, spacing, daily, day, forget
        self.max_addresses = max_addresses
        self._addresses: OrderedDict[str, _Address] = OrderedDict()
        self._unknown: deque[float] = deque()  # failures (reserved ones included) of unknown devices
        self._next_unknown = float("-inf")
        self._lock = threading.Lock()

    def _address(self, address: str, now: float) -> _Address:
        st = self._addresses.pop(address, None) or _Address()
        if now - st.last >= self.forget and now >= st.until:
            st = _Address()
        self._addresses[address] = st  # the newest at the end: the oldest is forgotten first
        while len(self._addresses) > self.max_addresses:
            self._addresses.popitem(last=False)
        return st

    def admit(self, address: str, known: bool, now: float) -> tuple[Ticket | None, float]:
        """(a ticket, 0) when a password may be checked now; (None, seconds to wait) when it may not."""
        with self._lock:
            st = self._address(address, now)
            while self._unknown and now - self._unknown[0] >= self.day:
                self._unknown.popleft()
            waits = [st.until - now]
            if not known:
                waits.append(self._next_unknown - now)
                if len(self._unknown) >= self.daily:
                    waits.append(self._unknown[0] + self.day - now)
            wait = max(waits)
            if wait > 0:
                return None, wait
            st.fails += 1
            st.last = now
            st.until = now + backoff(st.fails) if st.fails >= self.free else float("-inf")
            if not known:
                self._next_unknown = now + self.spacing
                self._unknown.append(now)
            return Ticket(address, known, now), 0.0

    def succeeded(self, ticket: Ticket) -> None:
        """The password was right: its address starts again, and the reserved failure is taken back."""
        with self._lock:
            self._addresses.pop(ticket.address, None)
            if not ticket.known:
                with contextlib.suppress(ValueError):
                    self._unknown.remove(ticket.at)

    def waiting(self, ticket: Ticket, now: float) -> float:
        """Seconds the address of a failed check now waits before its next one (0 while it has free tries)."""
        with self._lock:
            st = self._addresses.get(ticket.address)
            return max((st.until - now) if st else 0.0, 0.0)

    def unknown_full(self) -> bool:
        """Whether devices the page does not know are refused for the day."""
        with self._lock:
            return len(self._unknown) >= self.daily


class Devices:
    """The known-device cookie: a random id and an HMAC of it under a key derived from the stored password
    hash. It survives a restart of the page (the key is the hash's), ends with a new password (a new salt,
    a new key), and only spares its device the limit for unknown devices: it signs nobody in."""

    @staticmethod
    def _key(stored: str) -> bytes:
        return hmac.new(stored.strip().encode("utf-8"), b"tvgw-web known device", hashlib.sha256).digest()

    def issue(self, stored: str) -> str:
        device = secrets.token_urlsafe(16)
        return f"{device}.{hmac.new(self._key(stored), device.encode('ascii'), hashlib.sha256).hexdigest()}"

    def known(self, cookie: str | None, stored: str | None) -> bool:
        if not cookie or not stored or not DEVICE.fullmatch(cookie):
            return False
        device, _, mac = cookie.partition(".")
        want = hmac.new(self._key(stored), device.encode("ascii"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(want, mac)


# ---- the forms' tokens ---------------------------------------------------------------------------------
class FormTokens:
    """The sign-in form's token, tied to the browser that asked for the form: the page sets a random
    cookie with the form, and the form carries an HMAC of that cookie under a key this process alone
    holds. A post whose two do not match is refused, so another site cannot post the form."""

    def __init__(self, key: bytes | None = None):
        self._key = key or secrets.token_bytes(32)

    def issue(self, cookie: str) -> str:
        return hmac.new(self._key, b"sign-in:" + cookie.encode("ascii"), hashlib.sha256).hexdigest()

    def check(self, cookie: str | None, token: str | None) -> bool:
        if not cookie or not token or not TOKEN.fullmatch(cookie) or not re.fullmatch(r"[0-9a-f]{64}", token):
            return False
        return hmac.compare_digest(self.issue(cookie), token)
