# The experiments

This page owns tvgw's report-only experiments: what `tvgw experiment`, `tvgw evidence` and `tvgw requests` read, how each decides, what it cannot show and how to read its output. It is for the owner deciding whether a rule that is not built would be worth trying, and for developers extending one. Why they exist is [design decision 75](../design-decisions.md#75-the-inventions-not-built-are-measured-first-five-report-only-experiments-an-evidence-file-chained-by-hash-and-kept-local-request-drafts-tvgw-never-sends-and-fail-closed-drills-in-ci); the fail-closed drills and the table of what the TV keeps when a part fails are in [when a part fails](architecture.md#when-a-part-fails).

## What they have in common

Each experiment is the cheapest measurement a later rule would rest on, run over the gateway's own record. None refuses, holds or sends anything, and none adds a setting, a unit or a line to the brief. `tvgw experiment` opens the store `mode=ro`, as every read command does; its only other work is the ACR meter's positive control, built in a store held in memory and thrown away. `tvgw evidence` and `tvgw requests --draft` read the store the same way and write one file or one directory under the state directory, which `tvgw forget` deletes ([where it lives](privacy-and-retention.md#where-it-lives-and-who-can-read-it)). Their arguments and exit codes are in [the commands](../reference/commands.md).

The TV's state at a moment, which the platform report and the ACR meter use, comes from `appfront.timeline()` over the live record and the hourly readings ([the app in front](app-in-front.md)): an app in front, the home screen, an input (HDMI, live TV), a cast receiver, the screen saver, off (two readings no more than 90 minutes apart that both found the TV off or out of reach) and unknown (a gap). With hourly readings alone most of a day is unknown; with the live reading, the states are timed to the second.

## New-name probation

`tvgw experiment probation` answers what a rule that holds every never-seen registrable domain until it is judged would have held. A domain is new in the week of the first sighting of any name under it (`hosts.first_seen`, which every source fills and nothing prunes), and is counted only after the record's first `WARMUP_DAYS = 14` calendar days (src/tvgw/experiments.py): a new store sees everything for the first time. Weeks are ISO weeks in local time; a week the window cuts is marked as a part week.

Each new domain gets its class from the profile (`appfront.classify`: platform, vendor, tracking, content, shared, other, unclassified), the company behind its first name where the shipped snapshot knows one, its lookups since it was first seen, answered and refused, and the connections a hello named. The filter's verdict is `refused` (every lookup), `partly refused`, `answered` or `no lookup`. A domain the filter answered at least once is one the rule would have held, and its weekly count is the rule's cost. Two counts stand apart:

- a must-allow host among the held domains, since the rule would have to let it through whatever it holds;
- a domain first reached with no lookup in the store, which a rule at the resolver cannot hold at all.

On a gateway whose record has two whole weeks past the warm-up it prints, for example (documentation names):

```text
week       days  new  refused  would hold  held, by class
2026-W46      7    3        1           2  unclassified 2
2026-W47      7    2        0           1  platform 1
2026-W48     2*    0        0           0  -
* a part week
Over 2 whole weeks a rule would have held 1.5 new domains a week, at most 2.
Of them, 1 domain the TV must reach: a rule would have to let it through whatever it holds.
1 new domain reached with no lookup in the store: a rule at the resolver cannot hold such a domain.
```

Then each week's domains follow, one line each. A handful a month, mostly `other` and `unclassified`, is a rule a household could live with; a stream of new delivery domains every week is not.

## Platform hosts by the TV's state

`tvgw experiment platform [--days N]` counts, over the last N days (14 by default), the lookups of each must-allow host and each clock host of the profile, and the connections a hello named for each, by the TV's state at that moment, with the hours spent in each state. A name both lists cover is counted once, under its must-allow host, so a country's clock host appears under the clock pattern only when it is not the TV's own must-allow one. A refused lookup of a must-allow host is named, since the TV must reach it. Each cell is lookups/connections:

```text
hours in each state: app 0.5, home 0, input 0.5, cast 0, idle 0.5, off 0.85, unknown 1.65

host                                app       home      input       cast       idle        off    unknown
us.lgtvsdp.com                      1/1        0/0        1/0        0/0        0/0        0/0        0/0
snu.lge.com                         0/0        0/0        0/0        0/0        1/1        0/0        0/0
```

A state with no contacts is a state in which the host was not contacted in those days, which few hours in that state, an answer the TV kept, or a connection opened in another state can explain. Nothing is scheduled: a rule that opens a platform host only in some states would rest on this table, read over weeks with the live reading on.

## Fan-out association

`tvgw experiment fanout [--days N]` looks at the registrable domains the profile has no category for and the filter answered. Lookups of one such domain within `FANOUT_EPISODE_GAP = 10` seconds of each other are one episode, and a domain is ranked only once it has `FANOUT_MIN_EPISODES = 3` episodes on `FANOUT_MIN_DAYS = 2` local days. For each episode it takes the classified names and the refused lookups within `FANOUT_WINDOW = 2.0` seconds before or after.

A neighbour's base rate is the share of the TV's other lookups that have one of the neighbour's lookups within the same 2 seconds (`base_rate()`), and `lift` is the share of the unclassified domain's episodes the neighbour comes next to, over that rate. The base rate is anchored on lookups rather than on time because the TV looks names up in bursts: a burst puts every name near every other, and a base taken over time would read two names that only share the TV's busy moments as associated. Only a neighbour with a lift of `FANOUT_MIN_LIFT = 2.0` or more is shown or counted. The ten domains with the most episodes beside such a neighbour that was refused, or that the profile files under tracking, are printed, each with its three most frequent neighbours. The TV maker's own names (the vendor class) are shown but do not count, since the line says "refused or tracking":

```text
1. example-cdn.net: 5 episodes on 5 days; a refused or tracking lookup with a lift of 2 or more next to it in 5, a refused one after it in 5
     youtube.com: content (Streaming); 5 episodes on 5 days, 5 before and 0 after, lift 7.2
     doubleclick.net: refused (3rd-party ads); 5 episodes on 5 days, 0 before and 5 after, lift 2.6
```

Every report ends with the same sentence: this is association, not proof. A player's own server comes shortly before its ad calls every time, so a domain beside refused ad lookups may be the app that asks for the ads. Check each of the ten by hand before anything uses it.

## ACR uploads per viewing hour

`tvgw experiment acr [--days N]` is a meter: what the TV sent names the profile files under ACR, beyond what came back on the same connections ([the upload budget's measure](../reference/brief-sections.md#upload-budget), `budget.net_up()`), split by the state the TV was in when each connection opened. The rate is the net of the connections opened while the TV was on (the screen saver included), divided by the hours it was on: the same states above and below the line. What opened while the TV was off, or in a gap, is printed apart, outside the rate. The uploads the ACR test flags ([the ACR red line](../use/daily-brief.md#red-lines), `queries.acr_uploader()`) are counted beside it with their payload, and carry no rate, since the test buckets them by hour and day, not by state. Lookups of ACR names, answered and refused, are counted apart: a lookup is an attempt, not an upload. The TV's Live Plus reading and its consent flags are printed beside it.

Above the reading stands the record it was taken over: the lookups, the connections, those a hello named, and the capture files the ingest read in the window. A zero over a window with no connections says nothing about the TV, and the report says so.

With the agreements declined, the expected reading is zero. So every reading has a positive control beside it: one clock hour of 4,125,000 bytes of frames both ways at 7 up to 1 down, every frame full-size, on 60 connections a minute apart, with an input in front (`CONTROL_FRAMES`, `CONTROL_RATIO`, `CONTROL_CONNS`). That is the corner the budget's estimate of the quietest published hour of LG's screen recognition rests on. On `lg-webos` the control reads 2,982,780 bytes, 2.8 MB, per hour on, and the ACR test flags it once. On a profile with no ACR category the control reads nothing named and is still flagged, since only the shape test can see it there. The control is built from published figures and runs through the same arithmetic, not through the capture and the ingest: it shows the arithmetic sees such an hour, and the record line shows how much the capture gave it to see.

The meter cannot see an upload inside a connection that returns as much, or one moved to a name the profile does not file under screen recognition and shaped unlike the test. With the gateway refusing the ACR names, a zero cannot show what the TV would have sent without the gateway.

## Firmware before and after

`tvgw experiment firmware` compares, for each software change the hourly reading recorded (the TV's firmware, or its webOS release where the software call is refused), the `FIRMWARE_DAYS = 14` days before with the days after, from `UPDATE_LEAD = 3600` seconds before the reading that found it: the reading sees an update that happened since the reading before it. The features are the registrable domains the TV looked up or named in a hello, the (protocol, port) pairs it connected to on public servers, its TLS stacks (the JA4 of every hello, named or not), its record types, and its lookups a day.

The noise floor is an A/A comparison: the latest two adjacent 14-day windows with no change inside them that the record covers, compared the same way. A count is marked above the floor when it is more than `FLOOR_TIMES = 2` times the floor's and at least its feature's `FLOOR_MARGIN` over it: 3 for domains, since a quiet fortnight brings new delivery networks of its own, and 1 for ports, stacks and record types, which a quiet fortnight rarely brings. A window with lookups on fewer than `FIRMWARE_MIN_DAYS = 10` of its days is marked thin, since a gap makes things vanish that never left.

```text
2026-12-05 20:00: 04.64.00 (firmware). 14 days before against 14 days after.
  registrable domains: 3 new, 2 gone
    new: churn6.example, churn7.example, newvendor.example
  ports: 1 new, 0 gone  above the A/A floor
    new: tcp/8883
  TLS stacks (JA4): 1 new, 1 gone  above the A/A floor
```

Apps and servers change on their own, so a domain above the floor is a lead to check, not what the update did. The reference TV's firmware predates the gateway, so there only the A/A half has data until the next update.

## Ad breaks from an ad's lookups

`tvgw experiment adbreaks [--days N]` counts ad breaks over the last N days (14 by default), per app the TV said was in front when each began. It exists because most services send an ad down the connection the show comes down, so no connection says "this is an ad". But an ad is measured: when one starts, the player calls the firms that count it, several within a second or two, and each call begins with a lookup of the firm's name. The filter refuses those names, so the lookups are in the record already ([design decision 89](../design-decisions.md#89-ad-breaks-are-read-from-the-lookups-an-ad-makes-a-report-first-nothing-stored-nothing-refused)).

What it reads: the refused lookups of the window, the list of advertising firms (`src/tvgw/data/adfirms.txt`, the advertising rows of the companies snapshot, read through `companies.snapshot(companies.ADFIRMS)`) and the app in front from the same timeline the other experiments use. Only refused names count. A name the filter answers is kept by the TV for as long as the answer says, so its lookups are no clock, and the general names the database also files under advertising, such as a search engine's, are answered and never count.

How it decides (the constants are in src/tvgw/adbreaks.py, and `tests/unit/test_adbreaks.py` pins them):

- a label is a refused lookup of an advertising firm's name. The firm is the company behind the name, not the domain. A firm asked again and again is one label until it has been quiet for 5 seconds (`MERGE`), whichever of its names and domains were asked;
- 3 labels of different firms, that is different companies, within 10 seconds (`NEED`, `WINDOW`) open a break. One company's software often asks several of its own domains at once, and that is no ad;
- a label within 65 seconds (`CHAIN`) of the break's last one extends it. That is longer than the minute the TV holds a refusal, since the ads of one break call many of the same firms and the TV does not ask a name again sooner;
- the break ends 20 seconds (`TAIL`) after its last label, since a lookup marks an ad's start and not its end.

A timer is a name asked whatever is on the screen, by an app's own measurement or by the TV, and it is left out (`timers()`). It is told by two things together. It keeps a steady beat: within each of its runs, 70% (`STEADY_SHARE`) or more of the time lies in gaps no longer than 3 times (`STEADY`) the run's usual gap, where an ad's name has a minute's gaps inside a break and many minutes between breaks. And it comes alone: under half (`ALONE`) of its lookups have two other firms refused within the same 10 seconds (`WINDOW`), where an ad's name is refused with the other firms of the ad. A run ends when the name is absent for 45 minutes (`TIMER_PAUSE`), and a name is judged once it has 20 gaps that come to half an hour (`TIMER_GAPS`, `TIMER_SPAN`). Counting the five-minute bins a name is in, or its lookups an hour, takes the firms of a service that breaks every few minutes for timers.

No break lasts ten minutes (`LONG_BREAK`). A stretch of labels that runs longer is not counted as a break: it is names on timers that the test above could not tell apart, about a dozen at once or one fast name with under half an hour of it in the window. The report sets such stretches aside, counts them nowhere else and says how many there were.

Each break is counted under the app in front at its first label. Hours in front leave out the time behind the screen saver, and the home screen, the inputs and a cast receiver are no app. An app is listed with 1 hour in front or with a break. The report prints counts, hours and minutes only: no name and no time of day. It prints, for example (made-up apps):

```text
Ad breaks, read from the lookups an ad makes: the last 14 days.
A break is 3 or more advertising firms refused within 10 seconds; it lasts while more follow.

  Some App (some.app.id): 12.5 hours in front, 50 breaks, 4.0 an hour, about 45 minutes of ads
  Other App (other.app.id): 3.0 hours in front, 1 break, 0.3 an hour, under a minute of ads
  Third App (third.app.id): 11.0 hours in front, no break seen: if it shows ads, they cannot be seen this way
  Fourth App (fourth.app.id): 2.0 hours in front, no break seen (under 10 hours is too few to say)

There may be more: an ad that calls fewer than 3 refused firms is not counted, nor one the service reports from its own servers.
The minutes are an estimate: a break's start is known to the second, its end to within one ad.
It has not been checked against breaks marked by hand.
This TV asks a refused name again after about 60 seconds (31 names).
```

A line of breaks with no app known in front, a line that counts the stretches past ten minutes that were set aside, a note that the list of firms could not be read, and a note that the filter refused nothing in the window are the other lines it can print. The last line is the hold: how long the TV waits before it asks a refused name again, from the shortest usual gap of each name with 20 gaps or more. When that is under 45 seconds it adds that the rule is set for about a minute and that on this TV the minutes may run about a quarter long.

What it cannot show:

- There may be more breaks than it counts. An ad whose player calls fewer than 3 refused firms opens nothing, and an ad that the service's own servers report leaves no lookup at all.
- An app with 10 hours or more in front and no break is one whose ads cannot be seen this way. That is not a finding that it shows none.
- The minutes are an estimate: a break's start is known to the second and its end to within one ad.
- The rule was set before any break was marked by hand and has not been checked against one.
- Three firms asked together on one beat would read as a break at each turn.
- A timer is known as one only after 20 gaps that come to half an hour: a name asked every five minutes takes over an hour and a half. Until then, and where about a dozen names on timers crowd one another, what they open is set aside when it runs past ten minutes and counted when it does not.

Nothing is stored and nothing is refused on the strength of it.

## The evidence file

`sudo tvgw evidence [--days N]` appends to `/var/lib/tvgw/evidence/evidence.jsonl` one JSON line per settled local day of the last N (30 by default) that the file does not have yet. A day is settled 3 hours after it ends (`SETTLE` in src/tvgw/budget.py), and no day before the store's record starts is written. A line is never rewritten, so a day is written only when the record covers it (`uncovered()` in src/tvgw/evidence.py):

- the hourly ingest ran during the day, so a day the gateway was off, or that a clock stepped forward skipped, is left out rather than written empty;
- it ran again after the day settled, so the day's last connections are in the store;
- no run from the day's start to that one warned that connections or lookups were lost (a log rotated past, malformed lines, conntrack's lost events, the resolver's log missing).

A day that fails is named in the run's output with the reason and is not written. A day whose settled run has not come yet is written by a later run; a day that failed for good stays a gap in the file, which the header says is a gap in the record and not a quiet day. The first line is that header: it tells a reader who has never seen the gateway what the lines are, what was observed and what was estimated, and what the file cannot show.

Each day line holds:

- the TV's model and firmware as its readings name them;
- its Live Plus reading and consent flags at the day's end, and any flag accepted that day;
- per tracking domain: the lookups refused and answered, the connections a hello named, and what those sent beyond what came back;
- the uploads the ACR test flagged, and the day's own destination-hours over the upload budget, with no hour, at the ceiling in force that day (the floor for a day before the ceiling was set);
- how much record the day has (lookups, connections, the share of TLS connections that carried a name, TV readings, ingest runs);
- one plain sentence that says the rest.

Names are registrable domains, never full host names. There is no address of the home, no time of day and no record of which app was in front. A destination over the budget or flagged by the ACR test can still be an app's own server, and the day's counts show how much the TV was used that day.

Each line holds, in `prev`, the SHA-256 of the exact text of the line above (the header's `prev` is 64 zeros), and every line has one canonical form. `tvgw evidence --verify` names the first line changed, put in or reordered without the chain being computed again, a cut-off last line, a byte that is not ASCII, or a version it does not know. The chain has no key: whoever can write the file can compute it again, and a file with its last lines cut off still checks. Against both it holds only up to a head hash written down off the gateway. Every run prints the last line's SHA-256, and `tvgw evidence --verify --head HASH` checks that one of the file's lines still has it, which shows every line up to that one is as it was when the hash was written down. A run refuses a file whose chain is broken and adds nothing; keep that file, since it is the old record, and move it aside to start a new one.

The chain is not anchored anywhere. A public timestamp would show the file existed at a time, and would also tell that service, and anyone watching, that this home runs the gateway. To show later that the file was not changed, write the printed hash down somewhere off the gateway.

## Request drafts

`tvgw requests [--days N]` lists, over the last N days (30 by default), the companies the TV reached, those it only attempted, and those it looked up with no connection seen:

- reached: a connection whose TLS hello named one of the company's names and that carried data both ways, or a plain-HTTP request that got a success or redirect answer: a connection the firewall refused, a QUIC opening it rejected, or a request the URL filter refused never counts;
- only attempted: the filter refused every lookup and nothing reached the company, so the TV sent it nothing through the gateway;
- looked up, no connection seen: the filter answered, and the record cannot say whether the TV reached it.

The company is the shipped snapshot's ([the data folder](../../src/tvgw/data/README.md)); a reached name it does not know is counted under its registrable domain and never guessed.

`sudo tvgw requests --draft` writes one plain-text draft per company reached, and a `README.txt`, into `/var/lib/tvgw/requests/<day>/`, or into a new or empty directory `--out` names. It never writes over a file. Each draft opens with what sending it would tell the company: who the owner is, that this household owns this TV, and, in one paragraph the owner may delete, that a gateway watched the TV. It says that tvgw never sends a draft, that tvgw does not know the company's privacy address, and that it is a template, not legal advice. Every identifier is a placeholder (name, email, the account on the TV, the TV's model and serial number), and tvgw fills in none of them. The letter lists the company's own registrable domains with the number of days each was reached, and those of its names the gateway refused. No draft is written for a company the TV only attempted.

## Running them after a deploy

On the gateway, each of these reads the store and changes nothing but its own file:

```sh
tvgw experiment probation
tvgw experiment platform --days 14
tvgw experiment fanout --days 14
tvgw experiment acr --days 14
tvgw experiment firmware
tvgw experiment adbreaks --days 14
sudo tvgw evidence --days 30           # appends the settled days, prints the last line's hash
sudo tvgw evidence --verify --head <hash>   # with the hash a run printed, written down off the gateway
tvgw requests --days 30                # the lists only; --draft writes the drafts
```

`--json` prints any of them as data. A report shows no address of the home; the evidence file and the drafts stay on the gateway until the owner copies them.
