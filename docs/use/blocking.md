# Block or unblock something

You can see here where the gateway's rules live, and how to find out why a name is blocked, block a name, unblock one, or get an app working again. A few commands on the gateway do it, with no copy of tvgw's code needed. The names your TV needs come first, because they must never be blocked.

## Names never to block

Every profile keeps a list of the names the TV needs to keep working. A block on one of them breaks the TV: its clock, its store or its updates. The profile check refuses any rule that covers one, including the rules the gateway adds on its own.

On an LG TV, they include:

- LG's clock servers, `us.lgtvsdp.com`, and `us.nextlgsdp.com` on newer sets. Blocked, the TV's clock resets and every secure connection fails;
- the Content Store's feed `us.lgrecommends.lgappstv.com`, and its services `aic.service.lgtvcommon.com`;
- LG's file service, which a filter splits request by request instead of a block, so app downloads keep working.

Your TV's page lists every one, with the reason, under "What stays reachable on purpose" ([which TVs work](../tv/README.md)).

## Block a name

Use this when you want a name blocked that the blocklists let through.

On the gateway:

1. Find the name. `tvgw brief --full` lists what the TV asked for and what was blocked, and `tvgw host <name>` shows one name's history.
2. Run `sudo tvgw block <name>`. It blocks the name and every name under it. Add `--reason` with a few words to keep a note beside the rule.
3. Read the last lines it prints. They say that the filter took the rule, and how to undo it.

```sh
tvgw host ads.example                                   # what the TV did with this name
sudo tvgw block ads.example --reason "home-screen ads"  # block it and every name under it
```

The command refuses a block of anything the TV needs, and says which rule stopped it. That covers a name kept reachable on purpose and a name above one. It also covers the names the TV sets its clock from and the vendor file service the gateway filters. The whole of a site that mixes what the TV needs with what it reports is refused too: block single names under it instead.

The next brief's Rule changes section shows the new rule.

## Find out why a name is blocked

Use this when an app stops working and you want to know whether a name it needs is blocked, and by what. The gateway asks the filter itself, so the answer is the one the TV gets. That holds even for a name the TV has not asked for yet.

When you do not know the name, run `sudo tvgw refused` first, right after the app fails. It lists what the filter refused the TV just now, the likely cause first ([if an app stopped working](troubleshooting.md#if-an-app-stopped-working)).

On the gateway:

1. Run `sudo tvgw check <name>`.
2. Read the first line. It says whether the name is blocked or allowed for the TV.
3. If the name is blocked, run the command on the `Fix:` line.

```sh
sudo tvgw check ads.example      # blocked or allowed, by which rule, and the fix
```

A blocked name looks like this:

```text
ads.example is blocked for the TV.
  Rule: ||ads.example^, from the shared list HaGeZi Pro
  Kind: other services
  Kept reachable on purpose: no
  Through the URL filter: no
  Fix: sudo tvgw allow ads.example
```

The `Rule:` line says where the block comes from. It can be a shared blocklist by its name, your TV's profile, your own rules, or a rule the gateway added on its own. A `Company:` line follows `Kind:` when the gateway knows the company behind the name, as in `Company: LG Group`. `Kept reachable on purpose` says whether the TV needs the name to keep working. Such a name is never blocked. If one is, the `Fix:` line sends you to `sudo tvgw doctor` instead.

The gateway may not keep the filter's password. Then the command asks for it: the one you chose on the filter's first-run page. It uses the password for this one question and keeps it nowhere.

## Unblock a name

Use this when an app stops working and a name it needs is blocked.

On the gateway:

1. Find the name, as above. A blocked name shows `state=BLOCKED` in `tvgw host <name>`, and `sudo tvgw check <name>` says what blocks it.
2. Run `sudo tvgw allow <name>`. It lets the name and every name under it through, whatever a blocklist says.
3. Wait a minute, then try the app again, as [after unblocking something](#after-unblocking-something) explains.

Success looks like this:

```text
tvgw allow: ads.example is allowed for the TV (in /etc/tvgw/local.rules); AdGuard Home re-applied
tvgw allow: to undo it: sudo tvgw unallow ads.example
```

Some names belong to a site the TV's profile files under tracking: viewing trackers, advertising, usage reporting or fingerprinting. An allow of one such name says what it unblocks and goes ahead. An allow of the whole site says what it would unblock and stops. Add `--force` only if you mean it.

If the block was one the gateway added on its own, `sudo tvgw allow` takes that block out too. `sudo tvgw undo` is the other way ([taking a rule out](analyst.md#taking-a-rule-out)).

## Your own rules

Your allows and blocks are kept on the gateway in one file, `/etc/tvgw/local.rules`. The file does not exist until your first allow or block. Upgrades leave it alone, and so does `tvgw forget`.

```sh
tvgw rules --local                 # your rules, with the day and the reason of each
sudo tvgw unallow ads.example      # take your own allow out again
sudo tvgw unblock ads.example      # take your own block out again
```

Your rules come after the profile's rules and before the gateway's own. An allow beats every blocklist's block, and the gateway never adds a block of a name you allowed. An allow replaces your own block of the same name. A block replaces your own allow of it.

When the filter's servers on the internet cannot be reached, the command prints `deferred: upstream down` and changes nothing. Run it again once lookups work.

## Change the profile itself

A rule every gateway with your kind of TV should have belongs in the TV's profile instead. That needs an engineer, working in a copy of tvgw's code (a checkout) on their own computer:

1. Add the block to your TV's rules file in the profile, with a dated comment saying why. If blocking it breaks a feature, write the cost down too. To keep a name reachable, add it to the profile's list of names to keep reachable, with the reason.
2. Run the project's checks, which include the profile check.
3. Deploy the change to the gateway, which applies it to the filter.

On your workstation:

```sh
$EDITOR src/tvgw/profiles/lg-webos.rules      # one block per line, such as ||tracker.example^
$EDITOR src/tvgw/profiles/lg-webos.toml       # the [must_allow] table: "<name>" = "<why the TV needs it>"
make gate                                     # the checks, the profile check among them
make deploy PI=<ssh-host>                     # copy it to the gateway and apply it
```

Then, on the gateway, confirm the filter holds what the profile says:

```sh
sudo tvgw adguard diff      # prints: AdGuard Home matches the profile and settings
```

The format of a profile and its rules is in [the profile format](../reference/profile-format.md).

Never make a change on the filter's own web page: tvgw writes its settings back at the next apply.

## After unblocking something

The TV may keep a blocked answer for up to 60 seconds after its rule is gone. After `sudo tvgw allow`, after an unblock reaches the gateway, or after `sudo tvgw undo`, wait at least a minute and then retry the app. A test before then can meet the old answer.

## Block an address

Some services are reached by an address written into the TV's software, with no name to block. Those addresses go in a file on the gateway, which tvgw creates once and never overwrites.

On the gateway:

1. Add one address, or one address range, per line to `/etc/tvgw/block4.txt`.
2. Apply the firewall again. It must end with `tvgw: applied (...)`. An error means it rejected a line, and the old list stays in force.
3. Check the gateway.

```sh
sudoedit /etc/tvgw/block4.txt      # one address or range per line
sudo tvgw-apply                     # ends with: tvgw: applied (...)
sudo tvgw verify                    # every line should start with OK
```

Connections that are already open keep going after a new block, as [cut an open connection](#cut-an-open-connection) explains.

## The rules the gateway adds on its own

When the analyst is allowed to block on its own, the gateway keeps its blocks in a file of its own, beside the profile's. It never edits the profile or your own rules, and it never blocks a name you allowed. To see its blocks, or take one out, see [taking a rule out](analyst.md#taking-a-rule-out).

<a id="strict_ports"></a>

## Refuse unusual ports

By default, the TV's traffic to ports other than 80, 123 and 443 is logged, counted and allowed, and the brief lists it under Unexpected ports. LG's advertising ports are refused by default, whatever this setting says. With the stricter setting, the rest is refused too, so an app that needs such a port fails at once instead of hanging.

The project's rule is two clean weeks before the switch. Make it only when:

- two weeks of briefs in a row show `Unexpected ports: none`, or only entries you looked up and accepted;
- those weeks include a software update check, a start from cold, a Content Store install, and every app your household uses;
- the `odd ports` counter in Firewall held is zero, or explained.

The gateway can check the first and the last of these for you. This command reads the last 14 days and says in one line whether the setting is ready, or what stands in its way:

```sh
tvgw ports
```

It lists every unusual port the TV used in those days, with the name behind each address where the TV looked one up. It also says the same for the clock port (below).

To switch it on, on the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # set STRICT_PORTS=yes
sudo tvgw-apply
sudo tvgw verify
```

Then use the TV for a few hours across its apps. The `odd ports` counter now counts refused packets. If an app stops working, `sudo tvgw refused` names an unusual port the gateway refused, first if it is new. What the setting does is in [the settings](../reference/settings.md). To switch it off again, on the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # set STRICT_PORTS=no
sudo tvgw-apply
```

<a id="clock-port"></a>

## Close the clock port

The TV may ask a clock server for the time over NTP (UDP port 123). An LG TV takes its clock from LG's own servers over an ordinary secure connection instead, so on such a TV this port may carry nothing at all, and closing it closes one of the last paths left open to any address. The gateway counts the TV's NTP by server, and `tvgw ports` says when that count has had two clean weeks.

Close it only when `tvgw ports` says it is ready. Then, on the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # set CLOCK_PORT=none
sudo tvgw-apply
```

If the TV sent NTP to any server in the last 10 days, the apply keeps the port open and says so: closing it would leave the TV's clock wrong, and a wrong clock breaks every secure connection. If the TV's clock or an app goes wrong after the change, `sudo tvgw refused` names the refused clock server first. To open the port again, set `CLOCK_PORT=profile` (or `any`) and run `sudo tvgw-apply`.

<a id="established-connections"></a>

## Cut an open connection

A new block stops only new connections. A connection the TV already has open keeps going until it ends, which for an idle one can take up to 2 hours 4 minutes. That holds for a new name block, a new address in the list above, and the stricter port setting.

To cut the open connections to one address now, on the gateway:

```sh
sudo conntrack -D -d <address>
```

The TV opens a new connection, and that one meets the new rule.
