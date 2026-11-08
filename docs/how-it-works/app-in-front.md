# The app in front

This page owns how tvgw joins the TV's own account of itself with its traffic: sessions, which session a connection belongs to, each app's picture, the TLS stack as a second witness, and the live reading with its connection rules. It is for the owner who wants to know what a receipt can claim, and for developers changing `appfront.py`, `receipt.py`, `appeval.py` or `tvlive.py`. The reasons are in [design decision 67](../design-decisions.md#67-the-tvs-own-account-of-itself-is-the-ground-sessions-a-receipt-and-a-replay-keyed-to-the-app-in-front-a-live-reading-that-never-knocks-blind-no-rule-yet); reading a receipt is in [what the TV reached while each app was in front](../use/receipt.md).

## Sessions, gaps and none

`appfront.timeline()` cuts a window into pieces that touch and never overlap:

| Piece | What it means | Where it comes from |
|---|---|---|
| Session, timed `live` | One app in front from start to end, to the second | The live record: `app` and `power` events while the session to the TV was up |
| Session, timed `hourly` | Two hourly readings at most `STANDBY_GAP` (5400 s, in src/tvgw/queries.py) apart, both awake, naming the same app | `tvstate` |
| Gap | The TV may have been on, and nothing says which app was in front | A lost live session, readings that disagree or are missing, a clock step |
| None | The TV said it was off at both ends | Two readings that are not awake; a power event that says off |

- Inside the time the live session was up only its events count, and outside it only the readings.
- A lost session ends the app's session there, marked as not exact. The time until the next session is a gap even when the same app is in front afterwards.
- The first app a live session reports was already in front, so that session's start is not exact.
- A power event with a `processing` of `Request Power Off`, `Request Active Standby`, `Prepare Active Standby`, `Request Suspend` or `Prepare Suspend`, or a state of `Active Standby`, `Suspend` or `Power Off`, ends the session. `Screen Saver` keeps the app in front and its time is counted apart; `Screen Off` is on.
- The home screen, inputs (HDMI, live TV, external inputs) and cast receivers are sessions of the kinds `home`, `input` and `cast`. They learn no picture. An input needs no internet, so what talks under one is the TV's own software or an app behind it; what a phone casts is not visible to the gateway.
- A `clock` event (the gateway's clock jumped) makes the stretch that happened twice, or never happened, a gap, and nothing reported inside it is used.
- Events that share a timestamp are taken in one fixed order, so the result does not depend on the order they arrive in.

## Which session a connection belongs to

A connection belongs to the session that holds the time it started: the time of its own TLS hello where the capture has one, else conntrack's start, which can run a minute late. A continuation inherits its hello ([design decision 21](../design-decisions.md#21-a-continuation-inherits-its-name)) and so its session. A connection in the `LEAD_SECONDS = 3` (src/tvgw/appfront.py) before an app change the TV reported belongs to the new app. Connections to the gateway itself and to addresses no internet host answers from are left out. A connection's bytes are counted where it started, also when it ran on after a switch.

This is a match in time. It does not show which software opened a connection, and the TV's own software talks under every app, so each name is first sorted by what the profile says it is (`appfront.classify`):

| Class | Names | In a receipt |
|---|---|---|
| `platform` | The must-allow hosts, the clock hosts, the vendor's expected category | "The TV's own services (clock, sign-in, updates)" |
| `vendor` | The TV maker's other categories | Its advertising, usage reporting and fingerprinting (`plain.is_tracking`): "Advertising and measurement while X was in front", by full host name. The rest, such as `LG IoT`: with the TV's own services, whose heading then adds "and its maker's other services" |
| `tracking` | `ACR` and `3rd-party ads` | "Advertising and measurement while X was in front", by full host name; `3rd-party ads` reads "advertising or app measurement", since it holds the apps' own analytics too |
| `content` | The profile's other expected categories | By the picture |
| `shared` | `Infra` | By the picture |
| `other` | A category the profile names that is none of these | By the picture |
| `unclassified` | No pattern of the profile matches | By the picture, as "no category yet" |

## Pictures

A picture is what was seen under an app on earlier viewing days. It is learned from the TLS hellos of the last `PICTURE_DAYS = 28` days that fell in the app's sessions, platform and vendor names left out.

- **The unit** is the registrable domain with its category, such as `nflxvideo.net` with `Streaming`.
- **A viewing day** runs from 05:00 to 05:00 local time (`DAY_START_HOUR`), so an evening that runs past midnight is one day.
- **In the picture**: seen under the app on at least `PICTURE_MIN_DAYS = 1` earlier viewing day. Every report gives the number of days; one day is thin, `PICTURE_FIRM_DAYS = 2` or more is firm.
- **New**: no earlier day has the unit under this app. Nothing is called new until the app has `PICTURE_READY_DAYS = 3` earlier days.
- **Shared units** are in every picture they were seen under, and the reports say which apps share one.

## The TLS stack

`appfront.Stacks` counts the JA4 of each hello by the app in front. A fingerprint with at least `STACK_PURE = 0.9` of at least `STACK_MIN = 100` hellos under one app names that app. One under `SYSTEM_APPS = 3` apps or more with none above `SYSTEM_PURITY = 0.5` is the system's. A stack is a statistic, not a fact: it suggests which software opened a connection, whichever app was in front, and says nothing about which app was in front. The receipt remarks on a new name whose stack is another app's ("opened like YouTube's software"); `tvgw receipt --evaluate` reports how often a stack learned on the other days names the app in front on a day left out, and how much of the traffic that started in a gap it would attribute.

## The four views

`tvgw receipt` ([the commands](../reference/commands.md)) reads the store and writes nothing.

- **The evening** is the default screen: the newest viewing day's sessions, one block per app in the order the apps came to the front, verdict first ("New for X: ...", "No name was new for X", or "Not judged yet" with the days the gateway has seen the app), then the advertising and measurement names reached meanwhile, the blocked names asked for, the names without a category. Two sessions of one app with a loss between them are one block that names the minutes the gateway lost touch; a home-screen visit with nothing but the TV's own services is one line; an hourly session is "seen in front at 20:20 and 21:20; it may have started earlier and run longer", never a duration. It closes with the footer, a line on what the times mean, an action line in the plain brief's voice (`sudo tvgw check NAME` for an advertising or measurement name that got through, "nothing to do", or when to run it again while a session settles) and the two commands for more.
- **The receipt** (`--since`) lists, for each session that started since then, the connections that started under it in groups: new for the app, advertising and measurement (by full host name), seen with the app before (by site), the TV's own services, no name captured; then what the filter refused meanwhile, and at the end what started in gaps and how many of those carry a TLS fingerprint that is one app's. A session that ended less than `SETTLE` (11640 s, 3 h 14 min, in src/tvgw/receipt.py) ago is marked as settling, because conntrack logs a connection only when it lets it go. Lines wrap at `WIDTH = 100` columns.
- **The picture** (`--picture`) lists each app's units with their days and the apps that share them.
- **The replay** (`--replay`) holds an imagined rule against the store: while an app with enough earlier days is in front, allow its picture and the platform's essentials, refuse what is new. It prints what would have been refused, small shares with their bytes and names, and one verdict that names every condition not met (`receipt.failing`); the count of must-allow names refused is a self-check that can only be other than 0 through a bug. The numbers are [design decision 67](../design-decisions.md#67-the-tvs-own-account-of-itself-is-the-ground-sessions-a-receipt-and-a-replay-keyed-to-the-app-in-front-a-live-reading-that-never-knocks-blind-no-rule-yet) asks for. Nothing enforces it.
- **Why** (`--why NAME`) says what class a name has and what each app's days say of it.

`receipt.FORBIDDEN` lists the words no line may use ("sent", "tracked", "talked to" and their like), and tests/unit/test_receipt.py holds every line the four views write to it.

## Did it work

`src/tvgw/didit.py` reads the sessions above for app starts that may have failed, and joins each with what the gateway refused in its minutes ([design decision 72](../design-decisions.md#72-did-it-work-a-failed-app-start-is-read-from-the-tvs-own-account-and-joined-with-what-was-refused-in-its-minutes-a-wall-on-probation-asks-one-question-what-is-counting-since-when-and-when-its-two-weeks-end)). It reads the store and writes nothing.

### Which apps are judged

Only an app the gateway has seen working, by a start the TV reported:

- The app has a picture as of that viewing day: a site of its own reached on an earlier day, learned as the receipt learns it (`didit.evidence()`), so the receipt and the brief judge alike. A newly installed app is not judged.
- It is of the kind `app`, and not one of the TV maker's own in `SYSTEM_APPS` (settings, the input picker, the media player and the like), which bring nothing down when they work.
- The TV reported it coming to the front by a change of app, to the second, and reported its end the same way, with the home screen next. The first app a session to the TV reports was already in front, an app the TV woke with was not started, and a session the gateway lost touch during ends `lost`: none of them is counted. A start that ended at another app, an input, a cast receiver or standby is a choice.

### A failed start

The constants are in src/tvgw/didit.py.

| Kind | What was seen | Shown |
|---|---|---|
| Quick | In front under `SHORT = 60` s, with under `LITTLE_DOWN` (1 MiB) down on the connections that started in it | On its timing when `REPEAT = 2` or more of one app follow each other within `CLUSTER = 600` s and the app had not been in front earlier that viewing day; otherwise only with a likely cause |
| Stalled | In front up to `STALL_MAX = 600` s with under `LITTLE_DOWN` down | Only with a likely cause |
| Hourly | One pair of hourly readings at most `STANDBY_GAP` apart, awake and not behind the screen saver, with under `HOURLY_LITTLE_DOWN` (10 MiB) down | Only with a strong cause between the two readings, and the line says its times are to the hour |

- Every candidate waits for its bytes to settle (`receipt.SETTLE`, 3 h 14 min): before that a start that worked reads as one that failed, so it is pending (`episodes()` returns it apart), never a failed start.
- An app that was in front earlier the same viewing day can come back from memory and bring little down; its quick exits need a likely cause, and the line says it may have come back from memory.
- `LITTLE_DOWN` is a guess, as `LEAD_SECONDS` is, until the live record has measured starts that worked and starts that did not.

### What was refused in its minutes

The refused lookups the store holds in `SLACK = 5` s either side of the episode's stays, or between the two readings of an hourly one, are its causes, record types the TV goes without left out. A caller may add other readers' refusals (`extra`, `didit.Refusal` rows with their own `source`). Each cause is judged and ranked:

1. a name the profile says the TV needs (`refused.needed`);
2. a name whose site the app reached on earlier viewing days, from its picture;
3. a refusal its record has not seen before: for the filter's, by [`tvgw refused`](../reference/commands.md)'s own history queries (`refused.store_history`, `refused.domain_history`: not refused before by its rule under its site, or refused again after the filter had let it through); for another reader's, its own `seen_before`, and never when that is not given;
4. the rest, known trackers last.

The first two are strong causes, the first three likely ones, and a known tracker (`plain.is_tracking`) is neither: the gateway refuses it on purpose. A live start counts a likely cause, an hourly one only a strong cause. Each line says what refused it, "the filter" or, for another reader's refusal, "the gateway", and ends with the command that says why (`sudo tvgw check NAME`, or `sudo tvgw refused`); a refusal in the same minutes is a match in time, never proof, and `receipt.FORBIDDEN` holds these lines too. A lookup the TV answers from its own cache of a refusal (60 seconds) leaves nothing in the minutes, so a cause can be missed.

### Where it is shown

- `tvgw receipt` opens with the failed starts of its window, the evening's on the default screen; its JSON has `failed_starts`.
- The interactive `tvgw brief` has a section "Did it work" and, in its plain form, an `Apps:` line ([the brief's sections](../reference/brief-sections.md#did-it-work)).
- A persisted report carries `failed_starts` as counts only (`didit.summary()`): how many, how many with a cause that counts for it, how many from the hourly readings. Its line names no app, no time and no name, and points at `sudo tvgw receipt --since <day>`, so the minute-level record stays out of `reports/`, as design decision 67 asks.

### The probation hook

A wall that has begun to refuse, on probation, asks one question:

```python
from tvgw import didit

verdict = didit.since(conn, profile, t, now, gw_ip=gw_ip, events=lines, extra=refusals)
```

| `verdict.state` | When |
|---|---|
| `broke` | At least one failed start since `t`, as above. `verdict.failed` lists them and `verdict.causes` their likely causes, each name once per source, ranked |
| `clean` | None failed and none is pending (`verdict.pending`); at least one app start's settled bytes show it working: in front `SHORT` or longer with `LITTLE_DOWN` down, or an hourly session with `HOURLY_LITTLE_DOWN` down (`verdict.worked`); and the record of lookups (`verdict.covered_until`) reaches past the end of the last app stay since `t` |
| `unknown` | Anything less: nobody started an app, a start is still settling, time in front without the bytes to show it, or a record of lookups that stops short. It is never read as `clean` |

- It reads the store and the apps' pictures; the hourly ingest fills the store up to an hour late. A caller that must answer sooner passes the live reading's own lines (`events`, `appfront.read_events()` of `tvlive-events.log`, with `known_until`) and the refusals the store does not hold yet (`extra`: AdGuard's query log through `adguard.records_since()`, or a wall's own refusals, each with `seen_before`).
- A wall's undo acts on `broke` only for causes it can tie to its own refusals. No wall calls it yet; tests/unit/test_didit.py holds its three answers.

## The live reading

`tvgw-tvlive.service` runs `tvgw tvlive` ([the units](../../deploy/systemd/README.md#units)). With `LIVE_READING=off`, or a profile other than `lg-webos`, it exits at once. With `on` it holds at most one session to the TV: it registers with the stored key and the manifest recorded for it, subscribes to `com.webos.service.tvpower/power/getPowerState` and `com.webos.applicationManager/getForegroundAppInfo`, pings every 30 seconds, and appends each change to `tvlive-events.log` as one JSON line. It only reads: it asks the TV to report changes and sends no command, no setting, no Wake-on-LAN. What the session itself tells the TV is that an authenticated client is subscribed to its power state and foreground app and pinging every 30 seconds all evening; whether webOS reports its connected clients to LG is not measured, and the only way to avoid even that is to leave `LIVE_READING=off`, the default. The hourly ingest loads the file into `tv_events` ([the data model](../reference/data-model.md#tv_events)).

### Before every connection

All of these hold before the service opens a connection, and when one does not, it sends nothing (`tvlive.Discipline.why_not`, constants in src/tvgw/tvlive.py):

| Condition | Value |
|---|---|
| The key file holds a key for `TV_IP`, and the key store records no refusal | Read again just before each attempt |
| The TV port's link is not down | A link that is up says nothing: the reference TV keeps it up while off |
| Evidence that the TV is on, newer than the last attempt | `EVIDENCE_BYTES = 8_000` received from the TV inside `EVIDENCE_SECONDS = 30`, or an hourly reading that found the TV awake |
| After `TRAFFIC_TRUSTED = 3` failures in a row | Only an hourly reading counts as evidence, until the port has been silent for `QUIET_RESET = 600` s: the TV went off, and its next evening is tried on the first traffic again |
| The back-off has run | `BACKOFF`: 15, 30, 60, 120, 300, 600, then 900 s; never under `MIN_GAP = 15` s; `STANDBY_HOLD = 120` s after the TV said it was switching off |
| The hour has room | Fewer than `SERVICE_LIMIT = 6` attempts by anyone in the last 3600 s (the real ceiling: at most 6 an hour, 144 a day), counted in `tvlive-attempts` and by the process's own steady clock |
| The TV is not still waking | `BOOT_GUARD = 75` s has passed since the first traffic after the port was quiet `QUIET_RESET` s: webOS answers slowly while it boots, and a registration then is the one most likely to leave a prompt. The guard arms only once the service itself has seen that quiet |
| The hourly reading is not at work | `YIELD = 120` s after one of its attempts |
| The service has not stood down | No `tvlive-stood-down` file |

The counts that stand the daemon down are kept in `tvlive-progress` and read again at start, so a crash loop or a forward clock step buys no fresh knocks. `tvlive-attempts` is cut to the last hour on every write, so it never becomes a record of when the TV was on. A line stamped more than an hour ahead of the clock, after the clock was set back, counts as made now and is written back as made now, so it ages out an hour later.

Every `lgwebos.read()` (the hourly reading, the analyst's canary, `tvgw tvcheck` by hand) writes its two connections to `tvlive-attempts` once that file exists, and only the service creates it. The reading is counted and never refused. `tvgw forget` empties the file in place rather than removing it, so both go on counting. If the file goes missing anyway, the service makes it again, empty, and says so once in its journal and its events file; a file it cannot read or write means no attempt, said once the same way.

A service started while the TV is already on has seen no quiet, so the boot guard does not hold it: it attempts on the first evidence, within a few seconds of starting. That is accepted, because a TV that was on before the service started has usually finished booting.

### How a session ends

| What happens | What the service does |
|---|---|
| The TV sends an error denying the key (a 403) | Records the refusal where the hourly reading obeys it; attempts nothing until `sudo tvgw tv pair`. A prompt that the TV does not follow with a denial (a slow answer, a reset, a close) is never recorded as a refusal: the daemon counts it a failed attempt and stands itself down after `PROMPT_LIMIT = 3` of them, so a transient at a wake moment never stops the hourly reading |
| The TV says it is switching off | Writes the event, closes the session with a close frame, waits `STANDBY_HOLD` |
| A ping is not answered within 10 s, the socket breaks, the TV closes | Writes the loss; a failure for the back-off unless the session had been up `STABLE = 600` s |
| An hourly reading finds the TV unreachable `CONFLICT_AFTER = 60` s or more into the session | Ends the session and backs off; a second such reading (`CONFLICT_LIMIT = 2`) stands the daemon down |
| The TV pushes more than `FLOOD_PER_MINUTE = 120` messages a minute | Ends the session, so a TV cannot fill the Pi's disk through the events file. A flood is a failure for the back-off and counts toward `GIVE_UP` |
| The TV refuses a subscription, or `GIVE_UP = 12` attempts fail with no session between them that stayed up `STABLE` | Stands down |
| It is stopped | Closes the session with a close frame |

A service that stood down attempts nothing until `sudo tvgw tvlive --resume`. `tvgw tvlive --status` says what it would do and why, from its files alone.

### The first days

For the first days after turning the live reading on, look each day at what it did.

On the gateway:

```sh
sudo tvgw tvlive --status
sudo grep -c '"error": "prompted"' /var/lib/tvgw/tvlive-events.log    # registrations that may have left a prompt
```

- A stand-down says why: a prompt that may have shown, a conflict with the hourly reading, a refused subscription or `GIVE_UP` failures. Find the cause before `sudo tvgw tvlive --resume`.
- A `prompted` failure soon after the TV was switched on means the 75 s of `BOOT_GUARD` is too short for that TV.
- The flood count takes every message the TV pushes, power messages that repeat the state it already reported among them. A firmware that repeats them often can end session after session as a flood, and `GIVE_UP` (12) of those stand the daemon down.

### When it is not there

Nothing the TV needs depends on the service. systemd restarts a crash after 60 seconds and kills a loop that stops reporting to its watchdog; the attempts of the last hour are in a file, so a restart buys no attempt. The receipt uses the hourly readings for the time the service did not cover and says so on each session.

## Measuring it

`tvgw receipt --evaluate` prints numbers only, over the store and a live record, which `--events` can take from one or more `tvgw tvprobe` logs (`--live-until now` for a log still being written, so that a session up at its end counts up to now: a held session with no events is the signal):

- **record**: events, attempts, the busiest hour, the readings taken while the session was up and whether they agreed, the power words seen;
- **evidence**: the bytes from the TV per 600 s in sessions, off and in gaps, with every pair of samples accounted for;
- **coverage** and **composition**: where connections started, and what talked under each app by class;
- **generalization**: leave one viewing day out, for three units and three thresholds, and the units that fall outside;
- **unclassified**: the domains the profile has no category for, by bytes;
- **lag** and **lead**: what a late or hourly signal costs, and when connections start around an app change;
- **outsiders** and **stacks**.

It prints app identifiers, registrable domains, categories, JA4 and counts: no address, no date, no time of day and no full host name. It is a developers' view of a household's own viewing all the same (which apps, how many hours, how many sessions, the domains without a category and the apps they appear under), so it is not something to post in public; keep it to the gateway or a private report.

## What only a gateway can show

- Whether the power and app subscriptions push on a given TV, and with which words.
- Whether the hourly reading still works while a session is held; the service stands down when it does not.
- How long a waking TV takes to answer after its first packet, and what its port carries while it is off.
- Whether a held session changes the time the TV takes to reach standby; until that is measured the service lets go at the first off message.
