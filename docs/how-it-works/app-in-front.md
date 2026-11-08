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
| `vendor` | The TV maker's other categories (its advertising, usage reporting, fingerprinting) | "Advertising and measurement while X was in front", by full host name |
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

## The live reading

`tvgw-tvlive.service` runs `tvgw tvlive` ([the units](../../deploy/systemd/README.md#units)). With `LIVE_READING=off`, or a profile other than `lg-webos`, it exits at once. With `on` it holds at most one session to the TV: it registers with the stored key and the manifest recorded for it, subscribes to `com.webos.service.tvpower/power/getPowerState` and `com.webos.applicationManager/getForegroundAppInfo`, pings every 30 seconds, and appends each change to `tvlive-events.log` as one JSON line. It sends nothing else. The hourly ingest loads the file into `tv_events` ([the data model](../reference/data-model.md#tv_events)).

### Before every connection

All of these hold before the service opens a connection, and when one does not, it sends nothing (`tvlive.Discipline.why_not`, constants in src/tvgw/tvlive.py):

| Condition | Value |
|---|---|
| The key file holds a key for `TV_IP`, and the key store records no refusal | Read again just before each attempt |
| The TV port's link is not down | A link that is up says nothing: the reference TV keeps it up while off |
| Evidence that the TV is on, newer than the last attempt | `EVIDENCE_BYTES = 8_000` received from the TV inside `EVIDENCE_SECONDS = 30`, or an hourly reading that found the TV awake |
| After `TRAFFIC_TRUSTED = 3` failures in a row | Only an hourly reading counts as evidence, until the port has been silent for `QUIET_RESET = 600` s: the TV went off, and its next evening is tried on the first traffic again |
| The back-off has run | `BACKOFF`: 15, 30, 60, 120, 300, 600, then 900 s; never under `MIN_GAP = 15` s; `STANDBY_HOLD = 120` s after the TV said it was switching off |
| The hour has room | Fewer than `SERVICE_LIMIT = 6` attempts by anyone in the last 3600 s, counted in `tvlive-attempts` and by the process's own steady clock |
| The hourly reading is not at work | `YIELD = 120` s after one of its attempts |
| The service has not stood down | No `tvlive-stood-down` file |

Every `lgwebos.read()` (the hourly reading, the analyst's canary, `tvgw tvcheck` by hand) writes its two connections to `tvlive-attempts` once that file exists, and only the service creates it. The reading is counted and never refused.

### How a session ends

| What happens | What the service does |
|---|---|
| The TV answers the registration with a prompt or a 403 | Records the refusal where the hourly reading obeys it; attempts nothing until `sudo tvgw tv pair` |
| The TV says it is switching off | Writes the event, closes the session with a close frame, waits `STANDBY_HOLD` |
| A ping is not answered within 10 s, the socket breaks, the TV closes | Writes the loss; a failure for the back-off unless the session had been up `STABLE = 600` s |
| An hourly reading finds the TV unreachable `CONFLICT_AFTER = 60` s or more into the session | Closes the session and stands down |
| The TV refuses a subscription, or `GIVE_UP = 12` attempts fail with no session between them that stayed up `STABLE` | Stands down |
| It is stopped | Closes the session with a close frame |

A service that stood down attempts nothing until `sudo tvgw tvlive --resume`. `tvgw tvlive --status` says what it would do and why, from its files alone.

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

It prints app identifiers, registrable domains, categories, JA4 and counts: no address, no date, no time of day and no full host name.

## What only a gateway can show

- Whether the power and app subscriptions push on a given TV, and with which words.
- Whether the hourly reading still works while a session is held; the service stands down when it does not.
- How long a waking TV takes to answer after its first packet, and what its port carries while it is off.
- Whether a held session changes the time the TV takes to reach standby; until that is measured the service lets go at the first off message.
