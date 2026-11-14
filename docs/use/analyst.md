# Turn on the analyst

You can add the optional analyst here: a Claude model that reads a scrubbed summary of each day and proposes what to block. This page shows how to give it a key, what it sends and to whom, and what it costs. It also shows how to let it block on its own, and how to take its blocks out.

## What it does

The analyst is optional, and it needs an Anthropic API key. Once a day, and once a week, it sends a scrubbed summary of what the TV did to a Claude model, which proposes names to block.

By default it only proposes. The proposals are files you read, and you decide. You can also let the gateway add a block on its own. Then it adds one at a time and at most three in any 24 hours, a second model must agree with each, and the TV is watched for harm afterwards. `sudo tvgw undo` takes a block out at any time.

Every step and every check it passes is in [the analyst and autonomous blocking](../how-it-works/analyst-and-autonomy.md).

## Add the key

Make the key on the API keys page of Anthropic's [Claude Console](https://platform.claude.com/settings/keys) (address read on 2026-11-04). Each request is billed to that account; the cost section below gives the prices.

The key lives in one file on the gateway, `/etc/tvgw/claude.key`, and nowhere else: not in the settings, and not in the project's code. Only the administrator can read it, and the analyst refuses to run if anyone else can.

On the gateway:

```sh
sudo install -m 600 -o root -g root /dev/null /etc/tvgw/claude.key
sudoedit /etc/tvgw/claude.key      # paste the API key on one line, save, close
```

The next nightly run uses it. To stop the analyst, delete the file:

```sh
sudo rm /etc/tvgw/claude.key
```

## What it sends, and to whom

It sends requests to Anthropic's API, and only on a day with something the gateway has not seen before. A quiet day sends nothing and costs nothing.

Each request carries a summary of the day:

- the names the TV looked up, how often, how they are classed, and whether they were blocked;
- the current rules, and the names the TV must keep reaching;
- the public servers the TV connected to, and the traffic of each name it asks about;
- how often the TV was on, and which apps were seen;
- which TV settings changed, with the value only for the privacy switches, the software version, the model and the country;
- the day's red lines and the firewall's counts.

It never carries your home's addresses, any device's hardware address, the TV's or the gateway's names, the postal code the TV holds, or an hour-by-hour timeline of your day. A scrubber removes those before anything is written or sent.

Some internet names carry an identifier of a device or an account, as a long run of letters and digits. In what is sent, a run of 16 or more letters and digits is replaced by a placeholder like `<id32-1>`. The run must be all hexadecimal or hold three digits or more.

A shorter run, a UUID written with hyphens and an identifier split over labels go as they are. The gateway puts the real name back in the answer, so the proposals you read name the real hosts.

When the gateway may block on its own, a second model, also `claude-fable-5-1` by default, sees each proposed block with its name's traffic, never the first model's reasoning. [What leaves the gateway](../how-it-works/privacy-and-retention.md#the-analyst) has the whole list, and the known gaps.

At Anthropic, the standard API deletes the daily requests within 30 days. The weekly model, `claude-fable-5-1`, requires 30-day retention, and its requests are checked by Anthropic's automated safety systems ([at Anthropic](../how-it-works/privacy-and-retention.md#at-anthropic)).

## See what would be sent

A dry run writes the summary and the request to files and sends nothing. On the gateway:

```sh
sudo tvgw analyst --dry-run --day <day>
sudo less /var/lib/tvgw/reports/proposals/<day>.pack.json
sudo less /var/lib/tvgw/reports/proposals/<day>.prompt.txt
```

## Run a pass

The analyst runs on its own every night and every week. To run it by hand, on the gateway:

```sh
sudo tvgw analyst --day <day>            # one calendar day
sudo tvgw analyst --day <day> --force    # ask even when nothing is new
sudo tvgw analyst --since 6h             # the last 6 hours
sudo tvgw analyst --week 2026-W43        # one week
sudo tvgw analyst --weekly               # the weekly pass, with its own model
sudo tvgw analyst --show                 # print the newest proposals
```

Use one of `--day`, `--since`, `--week` and `--weekly` at a time. `--since` takes up to `168h`. When the gateway may block on its own, a run by hand can add blocks too.

## Compare two models

To ask another model about the same day, on the gateway:

```sh
sudo tvgw analyst --day <day> --model claude-fable-5-1 --effort max --force
```

It writes its proposals beside the day's own, under the model's name. `--force` is needed once the day's own run has judged its names. When the gateway may block on its own, this run can add blocks too.

## Let it block on its own, or not

The choice is one line of the settings file. Each run reads it, so no deploy is needed. On the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # ANALYST_APPLY=auto to let it block, ANALYST_APPLY=off to only propose
```

Switching back to proposals only stops new blocks. The blocks already in place stay, and stay watched. To take them all out as well:

```sh
sudo tvgw undo --all
```

## Taking a rule out

You have three ways, and each is recorded:

- `sudo tvgw undo` takes out the newest block the gateway added on its own, and applies the filter again;
- `sudo tvgw undo --all` takes out every one of them;
- deleting a line from the gateway's own rules file, `/var/lib/tvgw/auto.rules`, takes that block out at the next hourly check.

On the gateway:

```sh
sudo tvgw undo          # the newest block the gateway added
sudo tvgw undo --all    # every block the gateway added
```

After a block comes out, the TV may keep the blocked answer for up to 60 seconds. Wait a minute before you retry the app.

If `tvgw undo` says the filter was not applied again, the file has changed and the filter has not. The gateway applies it again at its next hourly check; to do it now, run `sudo tvgw adguard apply`. A block whose trial ended without enough TV use stays in place, listed in the brief every day, until you decide: keep it, or take it out.

On its own, the gateway can never:

- add anything but a block, or unblock a name;
- edit the profile, or change the firewall;
- add more than three blocks in 24 hours;
- keep a block that covers a name the TV needs.

## Check what it did

On the gateway:

```sh
sudo tvgw autoblock list                     # the blocks the gateway added, and their state
journalctl -u tvgw-autoblock --since today   # the hourly check's log
journalctl -u tvgw-analyst --since today     # the nightly run's log
```

The brief's "Rules the gateway added on its own" lists them every day too.

## Cost

The analyst records the cost of every request, at Anthropic's list prices of 2026-10, in dollars per million tokens:

| Model | Input | Output |
|---|---|---|
| `claude-opus-5-5` | $4.00 | $20.00 |
| `claude-sonnet-5-5` | $2.00 | $10.00 |
| `claude-haiku-5-5` | $0.10 | $0.50 |
| `claude-fable-5-1` | $10.00 | $50.00 |
| `claude-opus-5` | $5.00 | $25.00 |

As of 2026-10, a day costs about $0.07 with the default daily model, `claude-opus-5-5`. A weekly pass with the default weekly model, `claude-fable-5-1`, costs about $0.40 to $0.60. A quiet day sends nothing and costs nothing.

Each day's proposals end with the tokens used and the cost, to the cent. To see what the passes have cost so far, on the gateway:

```sh
sudo jq '.usage, .verifier_usage' /var/lib/tvgw/reports/proposals/2026-1*.json
```

A model that is not in the table has no price on file, and its proposals say so.
