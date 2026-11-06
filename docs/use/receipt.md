# See what each app talked to

You can ask the gateway which app was in front of the TV, and what the TV talked to while it was. This page shows you how to read that receipt, and what it can and cannot tell you. Reading one takes a few minutes.

## Print the receipt of the last session

On the gateway:

```sh
sudo tvgw receipt
```

```text
YouTube (youtube.leanback.v4)
  Sat 31 Oct 19:58 to 21:30: 1 h 32 min, timed by the live reading
  6 connections started while it was in front: 1.0 MB down, 5.9 KB up
  Seen with YouTube before
    googlevideo.com        streaming            2 connections   987.3 KB  (on 5 of 5 earlier days)
  Advertising and measurement, while YouTube was in front
    doubleclick.net        other advertisers    1 connection      9.8 KB  (on 5 of 5 earlier days)
  The TV's own services, while YouTube was in front
    lgtvsdp.com            LG's own services    1 connection      9.8 KB
  Nothing new talked while YouTube was in front.
  The filter refused no lookup while YouTube was in front.
```

To see every session of the last week, add `--since 7d`.

## What each part means

- **The first lines** name the app, say when it was in front and for how long, and how much the TV sent and received.
- **Seen with the app before** lists names that also appeared on earlier days with this app. The note says on how many days.
- **Advertising and measurement** lists known advertisers and measurement services that connected meanwhile.
- **The TV's own services** lists what the TV maker's software did meanwhile. It runs under every app.
- **Also talked: new** lists names never seen with this app before. It appears once the app has three earlier days.
- **The filter refused** counts the lookups the gateway blocked meanwhile.

A name marked "not classified yet" is one the gateway has no category for. It is nobody's until it has one.

## What a receipt cannot tell you

A connection is listed under the app that was in front when it started. That is a match in time. It does not prove which software opened the connection. The TV's own software talks whatever you watch, and another app can keep running behind the one you see.

The gateway cannot read what was said. It sees names, times and sizes.

A new name is new for this app in the last 28 days, and nothing more. An app's own rare name shows up as new once.

## Get exact times

The gateway asks the TV which app is in front once an hour. A receipt made from those readings says "timed by the hourly readings". The hour an app starts in and the hour it ends in are then left out.

An LG TV can also tell the gateway the moment the app changes. It works only with a TV you have paired, and it only listens. To turn it on, add one line to [the settings file](../reference/settings.md) and start the service again.

On the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # add the line LIVE_READING=on
sudo systemctl restart tvgw-tvlive
sudo tvgw tvlive --status         # what it does now, and why
```

```text
LIVE_READING=on, PROFILE=lg-webos
connection attempts in the last hour: none (the service stops at 6)
```

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

`sudo tvgw receipt --picture` lists every name each app has been seen with.

Next: [your household's privacy](privacy.md).
