# Household notice

This page is a template the owner may fill in, print and post where the household will see it, or give to each adult who lives in the house. It says in plain words what the gateway records about the TV, for how long, who can read it, what leaves the house, and how to have it deleted. The facts behind it are in [privacy and retention](privacy-and-retention.md). Replace each `<...>` before posting it, and update it when you change a setting it names. It is not legal advice.

---

## The TV's network is recorded

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
| The detailed record of names, connections and times | `<DB_DAYS>` days |
| Raw captures of the TV's traffic | 7 days |
| The gateway's logs | up to 3 weeks |
| The hourly on/off and app log | 35 days |
| The computer's system log | `<JOURNAL_DAYS>` days |
| The daily summaries | until deleted |
| Copies of the record kept for recovery | 7 days on the gateway; `<where else, if any>` |

**Who can read it.** `<the owner's name or role>`, and anyone with an administrator account on the gateway: `<list them, or "no one else">`.

**What leaves the house.** Once a day, and once a week, a short summary goes to an AI service (Anthropic's Claude) to suggest what to block: which internet names the TV used, how often, and which apps were in front. It never carries the house's addresses, the TV's name, the ZIP code or a timeline of the day. Anthropic keeps it for about 30 days, or at least 30 days for the weekly summary's model. `<If the analyst is off: "Nothing leaves the house; the AI summary is turned off.">`

**Guests.** If you are visiting and would rather your viewing not be recorded, say so. A short version for a card by the TV: "This TV's network traffic is logged for `<DB_DAYS>` days for privacy filtering. Ask `<the owner>` if you would like it deleted."

**Having it deleted.** Ask `<the owner>`. The gateway can delete its whole record of viewing at once (`tvgw forget`); it cannot delete one day or one show alone. What it cannot reach: the summaries already sent to the AI service, which expire there on their own, and the computer's system log, which expires after `<JOURNAL_DAYS>` days.

**Questions.** `<how to reach the owner>`.

---

## Filling it in

| Blank | Where to find it |
|---|---|
| `<DB_DAYS>` | `DB_DAYS` in `/etc/tvgw/tvgw.conf`, 365 unless you changed it |
| `<JOURNAL_DAYS>` | `JOURNAL_DAYS` in the same file, 14 unless you changed it |
| Who can read it | `getent group adm` on the gateway lists the accounts that can read the record |
| What leaves the house | Whether `/etc/tvgw/claude.key` exists; without it nothing is sent |
| Other devices | Whether any device besides the TV uses the gateway's resolver: `sudo jq -r '.IP' /opt/AdGuardHome/data/querylog.json \| sort \| uniq -c` counts lookups per client address; do not paste its output anywhere. Delete the blank's sentence if only the TV appears |

A setting that shortens the record, such as `DB_DAYS=90`, or `URI_VALUES=lengths` and `NAME_HMAC=on`, which keep less of what is stored, makes the notice shorter too: [the levers](privacy-and-retention.md#the-levers).
