# See what the TV reached while each app was in front

You can ask the gateway which app was in front of the TV last evening, and what the TV reached on the internet while it was. This page shows you how to read that screen, and what it can and cannot tell you. Reading one takes a few minutes.

## Print last evening

On the gateway:

```sh
sudo tvgw receipt
```

```text
Last evening, Fri 6 Nov, 19:52 to 23:05 (exact times, reported by the TV)
Home screen, 11 min in all: only the TV's own services.
Netflix, 20:00 to 21:52 (1 h 52 min), 2.7 GB down
  New for Netflix: nflxso.net (streaming), demdex.net (no category yet)
  Advertising and measurement while it was in front: ichnaea.netflix.com, 4 connections, 105.5 KB
  Asked for 4 blocked names 14 times, every one refused: customerevents.netflix.com 6 (advertising
      or app measurement), us.info.lgsmartad.com 4 (LG advertising), ...
YouTube, 21:55 to 23:05 (1 h 10 min; the gateway lost touch 22:40 to 22:49), 810.1 MB down
  Not judged yet: the gateway has seen YouTube in front on 2 earlier days, and 3 are needed before a
      name is called new.
  ...

A connection is listed under the app that was in front when it started. That is a match in time, not
    proof of which software opened it: the TV's own software talks under every app.
Action: ichnaea.netflix.com (advertising or app measurement) got through the filter; `sudo tvgw
    check ichnaea.netflix.com` says why, and how to block it.
Every name: sudo tvgw receipt --since 1d   One name: sudo tvgw receipt --why NAME
```

A session is one stretch with one app in front. An evening runs from 5 in the morning to 5 the next morning, so a late film belongs to the evening it started in.

## What each part means

- **The first line** says which evening, when the TV was in use, and whether the times are exact. "Exact times" means the TV reported each change itself. "Times to the hour" means the gateway asked the TV once an hour and saw the app at those readings only.
- **Each block** is one app. Its first line gives the times and how much came down.
- **New for Netflix** lists sites never seen with this app on an earlier evening. A site is the part of a name its owner registered, such as `nflxso.net`. It appears once the gateway has seen the app on 3 earlier evenings.
- **Not judged yet** means the app has fewer evenings behind it than that. Nothing is called new before.
- **Advertising and measurement** lists advertisers, measurement services and the TV maker's advertising reached while the app was in front, by full name.
- **Asked for N blocked names** counts what the TV looked up that the filter refused.
- **No category yet** marks a name the gateway has no category for. The receipt does not guess whose it is.
- **Still settling** means the numbers of a session that just ended keep filling in for about three hours.
- **Action** says what to do. `sudo tvgw check NAME` explains why a name got through and how to block it.

Every name a session reached, with sizes and the TV's own services, is one command away: `sudo tvgw receipt --since 1d`.

## What this screen cannot tell you

A connection is listed under the app that was in front when it started. That is a match in time. It does not prove which software opened the connection. The TV's own software talks whatever you watch, and another app can keep running behind the one you see.

The gateway cannot read what was said. It sees names, times and sizes.

"New for Netflix" means new for this app in the last 28 days, and nothing more. An app's own rare name shows up as new once, and new does not mean harmful. "No name was new" does not mean no advertising: the advertising line stands beside it.

Without exact times, a session under about two hours can be missing, and the hour an app started in is left out. Numbers stay incomplete for about three hours after a session.

## Get exact times

The gateway asks the TV which app is in front once an hour. An LG TV can also report the moment the app changes. It works only with a TV you have paired, and it only reads: it asks the TV to report changes and sends no commands. To turn it on, add one line to [the settings file](../reference/settings.md) and start the service again.

On the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # add the line LIVE_READING=on
sudo systemctl restart tvgw-tvlive
sudo tvgw tvlive --status         # the setting, the key, the attempts of the last hour
```

```text
LIVE_READING=on, PROFILE=lg-webos
connection attempts in the last hour: live 1 (at most 6 an hour)
last heard the TV at 2026-11-06 22:49
```

The service connects to the TV only while the TV is on, at most 6 times an hour, and never without the key you paired with. If it stands down, `--status` says why and `sudo tvgw tvlive --resume` lets it try again.

That finer record says to the second what was in front. The gateway keeps it for 14 days, and [your household's privacy](privacy.md) says how to delete it sooner.

## Ask about one name

On the gateway:

```sh
sudo tvgw receipt --why i.ytimg.com
```

```text
i.ytimg.com: streaming (ytimg.com), because the profile files it under Streaming. It belongs to an app's picture once it has been seen with that app.
With YouTube it was seen on 6 of 6 viewing days: it is in YouTube's picture.
```

An app's picture is what has been seen with it on earlier evenings. `sudo tvgw receipt --picture` prints every app's picture.

Next: [your household's privacy](privacy.md).
