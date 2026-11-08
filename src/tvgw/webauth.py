"""(web) The page's sign-in: the password kept as a hash, the sessions kept in memory, the limit on failed
sign-ins, and the tokens its two forms carry (design decision 76).

Nothing here opens a socket or a file but `read_hash`: every clock and every random source is the
caller's or a parameter, so the rules are tested without a server. The clocks are monotonic seconds (the
server passes `time.monotonic()`): a session lives in memory only, so a restart signs everyone out, and a
step of the wall clock can neither lengthen nor end one.
"""

from __future__ import annotations

import base64
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
FAILS_PER_ADDRESS = 5  # failed sign-ins from one address in the window before that address is refused
FAILS_TOTAL = 20  # failed sign-ins from all addresses in the window before every sign-in is refused
FAIL_WINDOW = 15 * 60  # seconds
REFUSAL = 15 * 60  # seconds a refusal lasts
MAX_ADDRESSES = 4096  # addresses whose failures are remembered; the oldest is forgotten first


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
    if len(parts) != 6 or parts[0] != SCHEME or not all(x.isdigit() for x in parts[1:4]):
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
class Limiter:
    """Failed sign-ins, per client address and in total, in a sliding window. FAILS_PER_ADDRESS failures
    from one address in FAIL_WINDOW refuse that address for REFUSAL; FAILS_TOTAL from all addresses refuse
    every sign-in for REFUSAL, which slows a guesser who has many addresses on the home network, at the
    cost of keeping the owner out for as long (SSH still works). A refused attempt is never checked, so it
    costs no hashing. A success clears that address's failures, never the total."""

    def __init__(
        self,
        per_address: int = FAILS_PER_ADDRESS,
        total: int = FAILS_TOTAL,
        window: float = FAIL_WINDOW,
        refusal: float = REFUSAL,
        max_addresses: int = MAX_ADDRESSES,
    ):
        self.per_address, self.total, self.window, self.refusal = per_address, total, window, refusal
        self.max_addresses = max_addresses
        self._fails: OrderedDict[str, deque[float]] = OrderedDict()
        self._all: deque[float] = deque()
        self._locked: dict[str, float] = {}
        self._locked_all = float("-inf")
        self._lock = threading.Lock()

    def _prune(self, q: deque[float], now: float) -> None:
        while q and now - q[0] >= self.window:
            q.popleft()

    def refused(self, address: str, now: float) -> float:
        """Seconds until `address` may try again, 0 when it may now."""
        with self._lock:
            left = max(self._locked.get(address, float("-inf")), self._locked_all) - now
            if self._locked.get(address, now) <= now:
                self._locked.pop(address, None)
            return max(left, 0.0)

    def failed(self, address: str, now: float) -> bool:
        """Count one failure; True when it starts a refusal."""
        with self._lock:
            q = self._fails.pop(address, None) or deque()
            self._fails[address] = q  # the newest at the end: the oldest is forgotten first
            while len(self._fails) > self.max_addresses:
                gone, _ = self._fails.popitem(last=False)
                self._locked.pop(gone, None)
            self._prune(q, now)
            self._prune(self._all, now)
            q.append(now)
            self._all.append(now)
            started = False
            if len(q) >= self.per_address:
                self._locked[address] = now + self.refusal
                q.clear()
                started = True
            if len(self._all) >= self.total:
                self._locked_all = now + self.refusal
                self._all.clear()
                started = True
            return started

    def succeeded(self, address: str) -> None:
        with self._lock:
            self._fails.pop(address, None)


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
