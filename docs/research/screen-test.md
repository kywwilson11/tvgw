# The screen test: research behind the numbers

This page holds the evidence and the statistics behind the constants in `src/tvgw/screentest.py`, the module for the screen test. It is for a reader of that code, or of [design decision 88](../design-decisions.md#88-the-screen-test-a-random-half-of-fixed-slots-an-exact-rank-test-of-each-destinations-uploads-and-a-first-stage-that-plays-nothing), who wants to know where each number comes from. The lab figures are aggregates from two public studies, read on 2026-11-12; no row of any trace is reproduced here.

## Where the constants come from

| Constant, in `src/tvgw/screentest.py` | Value | Where it comes from |
|---|---|---|
| `SHAPES["LG"]` | 13.9 s, 22,600 bytes | The median gap between uploads and the median upload of LG's client on an HDMI input with recognition on, in the released traces of the 2026 study ([the measurements](#what-the-released-traces-show)). |
| `SHAPES["Samsung"]` | 60 s, 2,600 bytes | The published period of about a minute (56 and 64 s in the study, every minute in Anselmi et al.) and a size between the 0.89 KB median upload and the second mode near 3.2 KB, which gives the 2.5 KB a minute the traces show. 2,600 is a rounded planting size, not a measured median. |
| `SLOTS_FAST` | 20 slots of 45 s (15 minutes) | The shortest run that catches LG's shape 99% of the time on its own destination or in a quiet connection, at level 1% ([power](#power-and-run-length)). |
| `SLOTS_GENERAL` | 20 slots of 120 s (40 minutes) | The shortest run that catches Samsung's shape 96% of the time on its own destination ([power](#power-and-run-length)). |
| `EVENT_BYTES` | 200 | The payload at which a second counts as holding an upload, in the second reading of each series ([the statistic](#the-statistic)). |
| `ALPHA` | 0.01 | The level the false-alarm and power measurements use: a run with nothing to find reports something in at most 1% of runs ([false alarms](#false-alarms)). |
| `MAX_SLOTS` | 64 | The counting keeps each count in 64 bits, and the largest count, 64 choose 32, fits ([exact counting](#counting-the-rank-sum-exactly)). |

`TCP_HEADERS = 52` and `UDP_HEADERS = 28` in `src/tvgw/connpoll.py` are the header bytes taken off each packet to leave payload ([the instrument](#the-instrument)).

## What is built, and what is not

Built: the kernel in `src/tvgw/screentest.py` (the slot draw, the exact rank test, the correction over destinations, the planting that says what a "no" is worth, and the words of the result); the one-second poll in `src/tvgw/connpoll.py`; the command `tvgw screen-test --dry-run`; and a stand-in TV in `tests/unit/tvdouble.py` that CI scores. The command in this stage plays nothing. It watches what the TV sends for one run's length, scores it against slots nobody played, and calls any finding "the test's own false alarm". Without `--dry-run` it refuses and says that playing is not built yet.

Not built, and so not described as working anywhere: the builder of the on and off pattern for ffmpeg, playing it on the gateway's HDMI output, a stored result, a comparison with an earlier run, and a test with the TV behind the namespace tier. Each of these is a later stage. Nothing here has been run against a real TV that does screen recognition.

## How screen recognition behaves on the wire

### What is published

The studies are *Watching the Watchers* (Mammadov, Joshi, Dubois and Choffnes, PoPETs 2027, data from April and May 2026) and Anselmi et al. (IMC 2024, arXiv 2409.06203).

| | LG webOS | Samsung Tizen | Vizio SmartCast | Roku OS |
|---|---|---|---|---|
| Endpoint found | `tkacrNNN.alphonso.tv`, 41 rotating names, TCP 4431 | `acr-us-prd.samsungcloud.tv`, TCP 443 | `kinesis.us-west-2.amazonaws.com` (shared AWS) | `scribe.logs.roku.com` (a general log host) |
| Upload period (paper, fig. 5) | 14 s | 56 and 64 s | 36, 44 and 53 s | 7 and 10 s (Roku TV); 9, 14, 18 s (TCL) |
| Up to down ratio | about 7 | about 1.7 | not given | not given |
| Runs on an HDMI input (table 5) | yes | yes | no | no |
| Black screen, sound on | no decrease | no traffic in 30 of 30 runs | no change | no change |
| Moving picture, no sound | down 97.3% (sigma 11.1%) | no change in shape | no change | no change |
| So it fingerprints | sound | picture | cannot be told | cannot be told |
| After opt-out | none in any run | still present in 18 of 30 HDMI runs, 41 of 60 antenna runs | no change in any run | gone on antenna; unchanged on its own streaming |

The same study found three more. Sony Google TV (Samba) runs on HDMI, falls 52.9% on a black screen, and has periods of 12, 96 and 135 s. Fire TV runs on HDMI and does not change with content (16 s). VIDAA runs on HDMI, fingerprints sound, every 7 s. No TV tracked Netflix or YouTube.

Anselmi et al. agree for LG and Samsung in the UK and the US. Recognition runs when the TV is a plain display for a laptop or console on HDMI. LG contacts its endpoint every 15 seconds and Samsung every minute with peaks every 5 minutes, and opt-out stops it on both. In their one-hour HDMI experiments LG exchanged 4,125 KB of frames and Samsung 148.5 KB. Their HDMI content was a laptop browsing and a console playing, so the client uploads fingerprints for content that no reference database holds: it uploads without a local match.

RTINGS published "Testing Smart TV Tracking" in 2026. The article body could not be read, so this is from search summaries only. It compared consent on against off with Wireshark on a mirrored switch port, saw clear recognition traffic on a Samsung S95F, a Sony Bravia 8 II and an LG G5, and on a TCL QM8K saw no clear change in destination names or traffic volume. That last case is the one the screen test is for: recognition that cannot be told apart by name or volume.

### What the released traces show

An upload is a run of upstream data frames with gaps under 3 s (LG) or 1 s (others); sizes are frame bytes less 66 per frame. Each scenario run in the study lasts 16 to 19 minutes, with 20 to 49 runs per cell. Only these aggregates are used.

| | LG | Samsung |
|---|---|---|
| HDMI, recognition on: one upload | 22.4 to 23.6 KB (10th to 90th percentile; median 22.6) | 0.83 to 3.6 KB; median 0.89; a second mode near 3.2 KB |
| Gap between uploads | 13.8 to 14.0 s (median 13.9) | 5 to 60 s; median 51 |
| Rate | 89 KB a minute in steady state, 1.5 KB/s | 2.5 KB a minute |
| 60-second windows that hold an upload | 93% (99% on the antenna feed) | 96% |
| The silencing condition, same measure | no sound: 1.5% of windows hold an upload of 2 KB or more | black: 7% of windows; 0.07 KB a minute |
| First upload after the TV comes up on a tracked source | median 13 s; within 15 s in 85% of runs | median 37 s; 19 to 61 s (10th to 90th) |
| After the TV lands on a silent channel | 14.5, 3.7, 1.2, then under 0.6 KB per 15 s: gone in 15 to 30 s | not resolvable at one upload a minute |
| Opted out, HDMI | 0 uploads in 26 of 26 runs | 20 of 30 runs still upload (any upload counted; the paper's threshold gives 18), 1.7 KB a minute over all 30 |
| Opted out, black screen | 0 | 0.3 KB a minute |

The last two Samsung rows are the paper's headline as this test would see it: with the setting off, what the TV sends still follows the picture.

Vizio's endpoint on HDMI carries 11.7 KB a minute with recognition on and 10.2 with it off. On antenna it carries 21.8, 21.9 and 20.5 KB a minute for channel, black and no sound. Roku's on HDMI carries 3.7 on and 3.6 off; on antenna 18.3, 17.7 and 18.2, falling to 12.5 after opt-out. Both are flat against content, as the paper says.

### What an on and off stimulus would produce

- **LG.** A square wave. About 1.5 KB/s while sound plays (one 22.6 KB upload every 13.9 s) and almost nothing when it is silent, with edges one upload period wide plus up to 15 s. The picture alone does nothing: a moving picture with no sound is "off" to LG, and a black screen with sound is "on". The stimulus must carry sound.
- **Samsung.** Sparse ticks. One or two small uploads a minute while the picture moves, none on black. Sound does nothing. Edges are one 60-second period wide.
- **Vizio and Roku.** Nothing over HDMI, because they do not recognize HDMI inputs. Where they do run (antenna, their own streaming), the uploads do not change with picture or sound. Vizio also uploads when idle. This test cannot see them at any length.
- **Sony (Samba).** A wave of half depth with a period up to 135 s: slow and shallow. Fire TV: flat. VIDAA: like LG, faster.

So the stimulus is a moving picture with sound against black and silence. That pair is on for a sound client and a picture client alike, and off for both. A still frame as the off state is not published for any vendor, so it is not used.

## The measurement

### The instrument

The test needs what the TV sent in each second, by destination, in connections that are still open. `src/tvgw/connpoll.py` lists the TV's connections once a second with `conntrack -L` and differences the counters per connection.

- **Payload, not bytes.** The counters include bare acknowledgements. A second's payload is its bytes less 52 per packet for TCP (IP and TCP headers with timestamps) and 28 for UDP, floored at 0. At one-second grain the difference from 40 matters: 17 acknowledgements would otherwise pass for an upload.
- **Destinations.** The /24 and the port, as `queries.acr_cell` groups unnamed traffic, plus one more series for everything the TV sent. LG's client changes address about once a minute among 41 names, so a test per address would cut the wave into pieces. The test never uses a name.

### The statistic

For one destination, one reading and one lag, the value of a slot is what the TV sent in the slot's seconds, moved `lag` seconds later. The statistic is the rank sum of the on slots' values (Mann and Whitney), one-sided: more is sent while the pattern is on.

- **Two readings.** The bytes, and the number of seconds in which at least `EVENT_BYTES` (200) of payload went. A large upload in heavy traffic shows in the first; a small regular one among a few irregular ones shows in the second. On LG's shape in a busy connection over 12 minutes the second reading alone finds 40% where bytes alone find 18%.
- **Two lags,** a quarter and a half of the slot (`default_lags`). An upload reports what was on the screen before it. A quarter fits a prompt client (LG: 11 s of 45); a half catches a sluggish one.
- **The reference set is the labelings themselves.** If the TV's uploads would have been the same whatever was played, the slot values are fixed numbers and the on label falls on a uniformly random half of them. The rank sum's distribution under that is counted exactly, ties included. No baseline period is needed, and nothing assumes that traffic is steady, independent or well behaved.
- **Many destinations.** Holm's correction over every destination, reading and lag. A run in which nothing follows the picture reports something at level `ALPHA` in at most `ALPHA` of runs, whatever the number of destinations.

Circular shifts of the schedule are valid only for steady traffic and add nothing once the labels are random, so they are not used.

### Counting the rank sum exactly

The count uses the standard library only. One big integer per subset size holds the count of every rank sum in 64-bit fields, so adding a slot is a shift and an add. In exploration it agreed with brute-force enumeration on 300 random cases with ties to the last digit, and took 0.4 ms for a run of 16 slots with 15 tests and 15 ms for one test of 64 slots. Nothing is simulated when a run is scored. CI asserts the same agreement (`tests/unit/test_screentest.py`).

### The first design, kept as a lesson

The first design used blocks of random length, the difference of mean log-bytes between on and off seconds, standardized over 999 re-drawn schedules, with the largest over destinations and lags compared with its own re-drawn distribution (Westfall and Young). It is valid and weak. A destination that follows the pattern perfectly scores only about 0.65 times the square root of the number of blocks, so 20 blocks give about 2.9, and the largest of 22 destinations and 7 lags reaches 3.0 by chance one run in twenty. A standardized score reads "as far as it can possibly go" as "three standard deviations". The exact count reads the same 20 slots as 1 chance in 184,756.

| 15 minutes, LG shape on its own destination | Flagged |
|---|---|
| First design (blocks, standardized difference, re-drawn maximum) | 55% at 5% |
| Second design (slots, exact rank sum, Holm) | 99.5% at 1% |

### False alarms

Each row is 2,000 simulated runs with no recognition anywhere: 20 ordinary destinations (heartbeats, telemetry, two with bursty sessions), a busy one, and the total.

| Traffic | Slots | Screen test at 1% | at 5% | Welch t per second at 1% | Welch t per slot at 1% |
|---|---|---|---|---|---|
| Ordinary | 16 of 45 s | 0.20% | 0.60% | 52.7% | 2.6% |
| Ordinary | 16 of 120 s | 0.20% | 1.00% | 84.4% | 4.6% |
| Everything decaying over the run | 16 of 45 s | 0.00% | 0.35% | 49.6% | 2.8% |
| Everything decaying over the run | 16 of 120 s | 0.15% | 1.20% | 85.0% | 6.3% |
| A 120 s square wave on four destinations | 16 of 120 s | 0.20% | 1.65% | 94.8% | 4.4% |
| A 45 s square wave on four destinations | 16 of 45 s | 0.15% | 0.70% | 82.3% | 2.6% |

The two textbook columns are Welch's t with Bonferroni over the destinations: once treating every second as a sample, once with one total per slot. The first is what a quick script would do, and it is wrong most of the time because a TV's seconds are not independent. The second is 2.6 to 6.3 times its stated level. The screen test stays under its level in every row, as the design requires. One more check: one fixed awkward series (a trend, a 90 s timer, a 30 s burst, a sparse and a dense destination) under 20,000 fresh labelings flags at 0.15% for level 1%. CI repeats this kind of check with one awkward series under fresh orders.

### Power and run length

The carrier holds the recognition uploads; 20 other destinations and the total are tested with it; level 1%; 200 runs a cell. The recognition traffic is spliced from the lab traces: real on stretches (HDMI, recognition on) and real off stretches (LG: moving picture, no sound; Samsung: black with sound), cut in at each change with an onset and a hangover of up to one upload period. The carrier's own background is nothing ("own destination"), a heartbeat and one upload a minute ("quiet"), or six uploads a minute with a heavy tail, sessions of 1 to 5 KB/s and one upload of 0.1 to 2 MB an hour ("busy").

LG shape, 22.6 KB every 13.9 s. Bold rows are the lengths the constants use.

| Slots | Minutes | Own destination | Inside a quiet connection | Inside a busy connection |
|---|---|---|---|---|
| 14 of 45 s | 10.5 | 0% (98% at 5%) | 0% | 0% |
| 16 of 45 s | 12 | 93.5% | 93.0% | 51.5% |
| **20 of 45 s** | **15** | **99.5%** | **99.0%** | 55.0% |
| 24 of 45 s | 18 | 100% | 100% | 68.5% |
| 40 of 45 s | 30 | | | 94.5% |
| 48 of 45 s | 36 | | | 97.0% |
| 20 of 30 s | 10 | 98.0% | 98.5% | 64.0% |
| 48 of 30 s | 24 | | | 95.5% |

Samsung shape, 0.9 to 3.3 KB about once a minute.

| Slots | Minutes | Own destination | Inside a quiet connection | Inside a busy connection |
|---|---|---|---|---|
| 16 of 120 s | 32 | 60.5% | 4.0% | 0% |
| **20 of 120 s** | **40** | **96.0%** | 20.0% | 1.0% |
| 24 of 120 s | 48 | 98.0% | 32.5% | 0.5% |
| 30 of 90 s | 45 | 99.0% | 32.5% | 0% |
| 48 of 120 s | 96 | | 95.0% | 4.0% |
| Opted out and still uploading, 20 of 120 s | 40 | 84.0% | 15.5% | 0% |
| Opted out and still uploading, 24 of 120 s | 48 | 96.0% | 26.5% | 0.5% |

The step from 14 to 16 slots is the arithmetic of the smallest exact p, not noise: 14 slots cannot reach level 1% after correction over many tests.

To catch it 95% of the time:

- LG's cadence: 15 minutes on its own destination or in a quiet connection; 36 minutes inside a busy one (24 with 30-second slots, which a sluggish client defeats). `SLOTS_FAST` is the 15-minute run.
- Samsung's cadence: 40 minutes on its own destination; 48 when it is the leftover traffic of an opted-out set; 96 inside a quiet connection; never inside a busy one. Three kilobytes a minute cannot be found under fifty. `SLOTS_GENERAL` is the 40-minute run.
- Vizio and Roku: no length, over HDMI or anywhere, for the reasons above.
- A slow, half-depth client like Sony's (period 120 s, half of it staying on black; upload size assumed at 10 KB, not measured): 89% at 128 minutes. Not practical.

What a real client's reaction time does to this (LG shape, parametric): a client that needs the whole window on, or scales the upload with the share of the window that was on, is caught 100% of the time at 16 slots of 45 s. A sluggish client (20 s to start, 30 s of hangover) is caught 93.5% at 16 slots and 100% at 20, and 1.5% with 30-second slots. The stand-in TV's `sluggish` mode has these timings.

### What a "no" is worth

A "no" needs a number beside it. After a run that finds nothing, `sensitivity` plants an upload of each shape in `SHAPES` into each destination's series in turn, following the labels that were actually played, and scores the run again. A plant goes where the pattern was mostly on in the period before it. The count of destinations where the plant is caught is the run's own sensitivity, and the result line carries one count for each shape. It is a count for that run's traffic, never a promise about the TV.

## The test double and what CI asserts

`tests/unit/tvdouble.py` plays a TV on a clock of its own and is told only what is on its screen, never the order the test drew. It sends ordinary traffic to seven servers and, by mode, a recognition client:

| Mode | What it does |
|---|---|
| `lg` | 22.6 KB about every 14 s to a server of its own, when the last period was mostly on. |
| `lg-hidden` | The same uploads inside the busiest ordinary connection. |
| `samsung` | 0.86 KB, and 3.3 KB more half the time, about once a minute, to a server of its own. |
| `sluggish` | LG's client, but it takes 20 s of pattern to start and goes on for 30 s after it stops. |
| `timer` | An upload every 14 s whatever is on the screen, as three vendors were measured to do. |
| `none` | Ordinary traffic only. |

CI asserts that `lg` is flagged in at least 97 of 100 runs of `SLOTS_FAST`, `samsung` in at least 95 of 100 of `SLOTS_GENERAL`, `lg-hidden` in at least 36 of 40 runs of 48 slots of 45 s, and `sluggish` in at least 97 of 100 runs of `SLOTS_FAST` but in at most 75 of 100 with 20 slots of 30 s. `none` and `timer` are flagged in at most 4 of 400 runs. The `timer` mode is there so that the test stays silent where recognition is not tied to the screen, which is why a "no" never reads as "no recognition".

## What is not proven

- **How fast a real client reacts when sound or picture stops on the same input.** The lab changed whole scenarios, never 45 seconds of silence. LG's uploads stopped within 15 to 30 seconds of a scenario change and started within 15 seconds. A client that held on for minutes would defeat short slots. Only a run on a TV with recognition on can settle it.
- **That the test double is a real TV.** It is built from the summary numbers above. Its results show that the arithmetic works on traffic of that shape, not that a given TV behaves that way.
- **Vizio, Roku and Fire TV.** In the 2026 study Roku and Vizio did not run recognition on HDMI inputs, and the uploads of Roku, Vizio and Fire TV were the same with and without picture or sound. A "no" on those sets says nothing, and the result line says so.
- **The RTINGS result,** which is read from search summaries only.
- **A client that is slow or shallow,** such as Sony's, at any practical length.

## Prior art, and what is new

What exists:

- **The lab audits changed the content and compared runs.** *Watching the Watchers* fed an antenna channel, a black screen with sound and a moving picture without sound, 30 runs each, in shuffled order, and compared traffic to endpoints it had already named by keyword, ratio and periodicity. Anselmi et al. compared one-hour scenarios. RTINGS switched consent on and off. All are lab work on named endpoints.
- **LeakyPick (Mitev, Pazii and Miettinen, ACSAC 2020, arXiv 2007.00500) is the nearest.** A Raspberry Pi plays audio probes into a room and tests each device's traffic after a probe against an idle baseline with a two-sample t-test, to find devices that send audio. It has the same shape of idea: a stimulus you control, and the device's own traffic as the witness.
- **Smart-speaker misactivation studies** (Dubois et al., PoPETs 2020) played hours of television at speakers and read activations from traffic.
- **Differential black-box analysis** of apps (Agrigento, NDSS 2017) changes one input and looks for a change in what is sent.
- **The statistics are old.** Random assignment with a counted reference set is Fisher's; the rank sum is Mann and Whitney's; a random on and off drive to find what responds is how control engineers identify a system.

What is new, as far as searches found (no patent search was done):

1. **The stimulus goes in through an HDMI input of the owner's own TV, from the gateway that already filters it.** One box plays and measures, with no lab feed, no second device and nothing installed on the TV. In the stage built so far the gateway does not yet play.
2. **No name, port, ratio or period is used to choose what to test.** Every destination and the total are tested and corrected together. The lab methods start from a candidate list; this one can find recognition that has moved to a new name or sits inside a connection the TV needs (LG's shape inside a busy connection: 97% in 36 minutes).
3. **The false-alarm rate is exact and holds for any traffic,** because the tool randomizes the labels within one run and counts the reference set. LeakyPick's t-test against an idle baseline assumes independent samples; a test of that kind flagged 50% to 95% of simulated runs with nothing to find ([false alarms](#false-alarms)).
4. **A "no" comes with its own sensitivity,** from uploads planted into the run's real series.

What is not new: switching sound and picture off to see whether recognition traffic falls, and the knowledge of which vendor listens and which watches. Those are the lab's. The big-integer counting is an implementation convenience, not a result.
