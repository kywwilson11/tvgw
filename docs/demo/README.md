# The demo recording

This folder holds a short terminal recording of tvgw on the owner's gateway, made on 2026-11-01. It is for a reader who wants to see what the gateway prints before installing one. What each line means is in [what tvgw verify checks](../troubleshooting.md#what-tvgw-verify-checks) and [the brief's sections](../reading-the-brief.md#sections).

## Files

| File | What it is |
|---|---|
| `tvgw-demo.cast` | The recording in asciinema's format: text, so it can be searched and copied from |
| `tvgw-demo.gif` | The same recording as an animated image, for pages that cannot play a cast |

## What it shows

1. `sudo tvgw verify`: one line per check, `OK`, `WARN` or `FAIL`, for the firewall, the guard, the resolver, the capture, the flow log and the TV's network paths.
2. `tvgw brief`: the daily summary of the TV's lookups, blocks, connections and red lines.

The output is scrubbed before it is shown. MAC addresses, home-LAN addresses, the gateway's host name, device hashes and UUIDs inside host names, and the hours the TV was in use are replaced by placeholders such as `192.0.2.x` and `<device-hash>`. What the same week's briefs measured is in [what an LG CX does on the network](../findings.md).

## Playing it

With [asciinema](https://docs.asciinema.org/getting-started/) installed, from the repository root:

```sh
asciinema play docs/demo/tvgw-demo.cast
```

`asciinema play -s 2 docs/demo/tvgw-demo.cast` plays it at twice the speed; Space pauses it and Ctrl-C ends it.
