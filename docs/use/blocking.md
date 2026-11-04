# Block or unblock something

You can see here where the gateway's rules live, and how to block a name, unblock one, or get an app working again. Changing a rule today needs an engineer with a copy of tvgw's code on their own computer; a command that does it on the gateway is being built. The names your TV needs come first, because they must never be blocked.

## Names never to block

Every profile keeps a list of the names the TV needs to keep working. A block on one of them breaks the TV: its clock, its store or its updates. The profile check refuses any rule that covers one, including the rules the gateway adds on its own.

On an LG TV, they include:

- LG's clock servers, `us.lgtvsdp.com`, and `us.nextlgsdp.com` on newer sets. Blocked, the TV's clock resets and every secure connection fails;
- the Content Store's feed `us.lgrecommends.lgappstv.com`, and its services `aic.service.lgtvcommon.com`;
- LG's file service, which a filter splits request by request instead of a block, so app downloads keep working.

Your TV's page lists every one, with the reason, under "What stays reachable on purpose" ([which TVs work](../tv/README.md)).

## Block a name

This needs an engineer, working in a copy of tvgw's code (a checkout) on their own computer:

1. Add the block to your TV's rules file in the profile, with a dated comment saying why. If blocking it breaks a feature, write the cost down too.
2. Run the project's checks, which include the profile check.
3. Deploy the change to the gateway, which applies it to the filter.

On your workstation:

```sh
$EDITOR src/tvgw/profiles/lg-webos.rules      # one block per line, such as ||tracker.example^
make gate                                     # the checks, the profile check among them
make deploy PI=<ssh-host>                     # copy it to the gateway and apply it
```

Then, on the gateway, confirm the filter holds what the profile says:

```sh
sudo tvgw adguard diff      # prints: AdGuard Home matches the profile and settings
```

The next brief's Rule changes section shows the new rule. The format of a profile and its rules is in [the profile format](../reference/profile-format.md).

Never make the change on the filter's own web page: tvgw writes its settings back at the next apply.

## Unblock a name

The same way, as an engineer. If the profile's rules file blocks the name, delete that line. If a shared blocklist blocks it, add the name to the profile's list of names to keep reachable, with the reason:

```sh
$EDITOR src/tvgw/profiles/lg-webos.toml       # the [must_allow] table: "<name>" = "<why the TV needs it>"
make gate
make deploy PI=<ssh-host>
```

If the block was one the gateway added on its own, take it out on the gateway with `sudo tvgw undo` instead ([taking a rule out](analyst.md#taking-a-rule-out)).

## After unblocking something

The TV may keep a blocked answer for up to 60 seconds after its rule is gone. After an unblock reaches the gateway, or after `sudo tvgw undo`, wait at least a minute and then retry the app. A test before then can meet the old answer.

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

When the analyst is allowed to block on its own, the gateway keeps its blocks in a file of its own, beside the profile's. It never edits the profile. To see them, or take one out, see [taking a rule out](analyst.md#taking-a-rule-out).

<a id="strict_ports"></a>

## Refuse unusual ports

By default, the TV's traffic to ports other than 80, 123 and 443 is logged, counted and allowed, and the brief lists it under Unexpected ports. LG's advertising ports are refused by default, whatever this setting says. With the stricter setting, the rest is refused too, so an app that needs such a port fails at once instead of hanging.

The project's rule is two clean weeks before the switch. Make it only when:

- two weeks of briefs in a row show `Unexpected ports: none`, or only entries you looked up and accepted;
- those weeks include a software update check, a start from cold, a Content Store install, and every app your household uses;
- the `odd ports` counter in Firewall held is zero, or explained.

To switch it on, on the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # set STRICT_PORTS=yes
sudo tvgw-apply
sudo tvgw verify
```

Then use the TV for a few hours across its apps. The `odd ports` counter now counts refused packets. What the setting does is in [the settings](../reference/settings.md). To switch it off again, on the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # set STRICT_PORTS=no
sudo tvgw-apply
```

<a id="established-connections"></a>

## Cut an open connection

A new block stops only new connections. A connection the TV already has open keeps going until it ends, which for an idle one can take up to 2 hours 4 minutes. That holds for a new name block, a new address in the list above, and the stricter port setting.

To cut the open connections to one address now, on the gateway:

```sh
sudo conntrack -D -d <address>
```

The TV opens a new connection, and that one meets the new rule.
