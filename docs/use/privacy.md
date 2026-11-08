# Your household's privacy

You can see here what the gateway keeps about your household's viewing, and keep less of it. You can also delete it, and tell your household about it with a notice you print.

## What the gateway keeps

The gateway records what the TV does on the network, so that it can report it and find new tracking. The record stays on the gateway. With the default settings it keeps:

| Record | Kept |
|---|---|
| The detailed record of names, connections and times | 365 days |
| The list of every name the TV ever used, with when each was first and last seen | until you delete the record |
| Raw captures of the TV's traffic | 7 days once read, at most 14 |
| The gateway's own logs | up to 3 weeks |
| The hourly record of whether the TV was on, and which app was in front | until you delete the record |
| The TV's settings history | with no limit, even after you delete the record |
| The computer's system log | 14 days |
| The daily and weekly summaries | until deleted |
| Copies of the record kept for recovery | 7 days |

Every file, where it lives and who can read it is in [privacy and retention](../how-it-works/privacy-and-retention.md).

## Keep less

Each setting below keeps less of the record. The ones that cost nothing are always on. The others trade something you may want, so each keeps today's behaviour until you change it.

| What | Setting and default | What it does | What it costs |
|---|---|---|---|
| No host name or hardware addresses in stored firewall lines | always on | Firewall log lines are stored without the gateway's name and with hardware addresses emptied. | Nothing. |
| Shorter logs | always on | The connection and filter logs keep up to 3 weeks instead of 12, and the TV readings 35 days instead of forever. | Less margin after a long outage. |
| The system log's span | `JOURNAL_DAYS=14` | How many days the computer's system log keeps, for every service on it. It replaces a longer span you set yourself. | Older lines of every service go after 14 days. Set your old span, or `off`, to keep it. |
| The detailed record | `DB_DAYS=365` | Rows older than this go at the next hourly run. | Nothing the brief needs: it looks back 14 days. 90 keeps every weekly report reproducible for a quarter. |
| The app in front, to the second | `TV_EVENTS_DAYS=14` | Kept only when you turned the live reading on ([what the TV reached while each app was in front](receipt.md)). Older rows go at the next hourly run. | A receipt older than this is timed by the hourly readings again. |
| What a plain web request asked for | `URI_VALUES=keep` | `lengths` stores each value of a plain web request as its length only. | You can no longer read what such a request asked for. Nothing in tvgw needs it. |
| Names that carry what you watch | `NAME_HMAC=off` | `on` stores the names of the free-channel services, which carry the show in the name, as a tag that cannot be read back, with a new key every 90 days. | The brief shows a tag instead of a show, and such a name can only be blocked as a whole service, by hand. |
| The filter's own log | `QUERYLOG_DAYS=90` | How long the filter (AdGuard Home) keeps every lookup. tvgw reads it every hour and needs only a few days of it. | The log can hold up to twice this span. |
| The weekly analyst's model | `ANALYST_WEEKLY_MODEL=claude-fable-5-1` | `claude-opus-5-5` sends each week's summary to a model with the standard retention. | The weekly proposals may change. |
| Deleting everything | `sudo tvgw forget` | Deletes the whole viewing record at once, as the next section says. | The brief and the analyst start again from nothing. |

To change a setting, edit the settings file on the gateway. Each setting's details, and what to run after a change, are in [the settings](../reference/settings.md).

```sh
sudoedit /etc/tvgw/tvgw.conf      # for example DB_DAYS=90
```

## Forget the viewing record

`sudo tvgw forget` deletes the gateway's record of what your household watched, and keeps the gateway itself working. Use it when someone in the household asks, after guests, or before the gateway or its card changes hands. It is all or nothing: there is no way to delete one day or one name.

**What goes:** the detailed record, every capture, every report and proposal, the copies kept for recovery, and the gateway's logs of the TV. With `--querylog`, the filter's own log of lookups goes too.

**What stays:** the settings, the rules with your own allows and blocks, the results of the gateway's own checks, the TV's settings history, the pairing key, and the capture being written right now. The exact lists are in [forgetting](../how-it-works/privacy-and-retention.md#forgetting).

On the gateway:

1. See what would go. It prints counts and sizes, never a name:
   ```sh
   sudo tvgw forget --dry-run
   ```
2. Pick a time away from the analyst's runs, which by default start at 03:50 every day and at 04:10 on Mondays. A run that read the record before the delete writes its proposals after it.
3. Delete. It asks you to type `forget`:
   ```sh
   sudo tvgw forget
   ```
4. Check the result. The counts are near zero, and the record checks out as `ok`:
   ```sh
   tvgw size
   sudo tvgw sql "PRAGMA integrity_check"      # ok
   ```
5. If you ever copied backups of the gateway to your own computer, delete those copies too.

What it cannot reach, which it says every time it runs:

- the computer's system log, which cannot delete chosen lines and keeps its own span;
- the filter's statistics, and its log of lookups unless you add `--querylog`;
- copies on your own computer;
- the analyst's requests at Anthropic: the daily ones are deleted there within 30 days, and the weekly model's are kept for 30 days ([at Anthropic](../how-it-works/privacy-and-retention.md#at-anthropic));
- the logs of the project's automated tests on GitHub, if a failing test there quoted a value from your gateway;
- the blocks of the memory card that once held the deleted files.

After a delete, the brief and the analyst start again from nothing.

## A notice for your household

This section is a template you can fill in, print and post where your household will see it, or give to each adult who lives in the house. It says in plain words what the gateway records about the TV, for how long, who can read it, what leaves the house, and how to have it deleted. Replace each `<...>` before posting it, and update it when you change a setting it names. It is not legal advice.

---

### The TV's network is recorded

The TV in `<room>` reaches the internet only through a small computer, the gateway, which blocks the TV's advertising and tracking. To do that it keeps a record of what the TV does on the network.

**What is recorded.**

- The names of the internet services the TV contacts, such as a streaming service or the TV maker's servers, and when.
- How much data each connection moved, and when it started and ended.
- Once an hour, whether the TV was on and which app was in front.
- The TV's own settings, such as whether its viewing-data sharing (Live Plus) is off.

**What is not recorded.** What was said in the room, what was typed into an app's search, passwords, or the picture on screen. The gateway cannot read encrypted traffic. Phones, laptops and other devices on the home network are not in the record, `<unless they use the gateway's filter as their DNS resolver: then the filter's own log keeps the names they look up for up to 180 days>`.

**How long it is kept.**

| Record | Kept |
|---|---|
| The detailed record of names, connections and times | `<days of detail>` days |
| The list of every service name the TV ever used, with when each was first and last seen, and the AI's verdicts on some of them | until `tvgw forget` |
| Raw captures of the TV's traffic | 7 days once read, at most 14 |
| The gateway's logs | up to 3 weeks |
| The hourly on/off and app record | until `tvgw forget`: the log file 35 days, the record of it in the gateway's database with no limit |
| The TV's settings history, its ZIP code and device name among them | with no limit, even after `tvgw forget`: the gateway checks it |
| The computer's system log | `<days of system log>` days |
| The daily summaries | until deleted |
| Copies of the record kept for recovery | 7 days on the gateway; `<where else, if any>` |

**Who can read it.** `<the owner's name or role>`, and anyone with an administrator account on the gateway: `<list them, or "no one else">`.

**What leaves the house.** Once a day, and once a week, a short summary goes to an AI service (Anthropic's Claude) to suggest what to block. It says which internet names the TV used, how often, and which apps were in front. It never carries the house's addresses, the TV's name, the ZIP code or a timeline of the day. Anthropic keeps it for about 30 days, or at least 30 days for the weekly summary's model. `<If the analyst is off: "Nothing leaves the house; the AI summary is turned off.">`

**Guests.** If you are visiting and would rather your viewing not be recorded, say so. A short version for a card by the TV: "This TV's network traffic is logged for privacy filtering: the detail for `<days of detail>` days, the list of services it used and when it was on until deleted. Ask `<the owner>` if you would like it deleted."

**Having it deleted.** Ask `<the owner>`. The gateway can delete its whole record of viewing at once (`tvgw forget`); it cannot delete one day or one show alone. It keeps the TV's settings history, which holds no viewing. What it cannot reach: the summaries already sent to the AI service, which expire there on their own, and the computer's system log, which expires after `<days of system log>` days.

**Questions.** `<how to reach the owner>`.

---

### Filling it in

| Blank | Where to find it |
|---|---|
| `<days of detail>` | The `DB_DAYS` line of `/etc/tvgw/tvgw.conf`: 365 unless you changed it |
| `<days of system log>` | The `JOURNAL_DAYS` line of the same file: 14 unless you changed it |
| Who can read it | `getent group adm` on the gateway lists the accounts that can read the record |
| What leaves the house | Whether `/etc/tvgw/claude.key` exists; without it nothing is sent |
| Other devices | Whether any device besides the TV uses the gateway's filter: `sudo jq -r '.IP' /opt/AdGuardHome/data/querylog.json \| sort \| uniq -c` counts lookups per device address. Do not paste its output anywhere. If only the TV's address appears, delete the blank's sentence |

A setting from [keep less](#keep-less) that shortens the record makes the notice shorter too.
