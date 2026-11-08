# tvgw documentation

These pages show how to install tvgw, use it day to day and set up your TV, then how it works inside. Pick the part that matches what you want to do: the first four need no networking knowledge, and the last three are there when you want them. On the documentation site, every command these pages show exists in the latest release; on GitHub, the same pages describe the newest code, which can be ahead of the release.

## Start here

| Page | Read it to |
|---|---|
| [What it stops, and what it cannot](what-it-stops.md) | know what tvgw assumes about your TV, what it blocks, and what stays outside its reach |

## Install

| Page | Read it to |
|---|---|
| [Install tvgw](install/README.md) | go from a new computer to a working gateway |
| [Choose a gateway computer](install/choosing-a-gateway.md) | pick a computer, check its ports, and see which systems are tested |
| [Other ways to install](install/advanced.md) | install by hand, from the package, with no one at the keyboard, or as a dry run |

## Everyday use

| Page | Read it to |
|---|---|
| [Read your daily brief](use/daily-brief.md) | understand the one-screen summary, and what to do when it says RED LINE |
| [Block or unblock something](use/blocking.md) | block a name the TV uses, or get an app working again |
| [Fix a problem](use/troubleshooting.md) | go from a symptom, such as "the TV has no internet", to its fix |
| [Turn on the analyst](use/analyst.md) | add the optional Claude analyst, and decide whether it may block on its own |
| [Your household's privacy](use/privacy.md) | keep less of the record, delete it, and tell your household what it holds |
| [See what the TV reached while each app was in front](use/receipt.md) | read an evening's receipt: which app was in front, and what the TV reached meanwhile |
| [Keep it running](use/maintenance.md) | upgrade, back up, restore, or remove tvgw |

## Your TV

| Page | Read it to |
|---|---|
| [Which TVs work](tv/README.md) | find your TV's support level, and what tvgw does for a TV it has no profile for |
| [LG TVs](tv/lg-webos.md) | set up an LG TV: pairing, and what tvgw found on one |
| [What an LG CX does on the network, measured](tv/lg-cx-measured.md) | see a week of one LG CX behind the gateway, in numbers |
| [Samsung TVs](tv/samsung-tizen.md) | set up a Samsung TV, and help test the Samsung profile |
| [Roku TVs](tv/roku.md) | set up a Roku TV or player |
| [Vizio TVs](tv/vizio-smartcast.md) | set up a Vizio TV |

## How it works

For the curious, and for anyone checking that tvgw does what it says. You do not need these pages to use it.

| Page | Read it to |
|---|---|
| [How tvgw works, in pictures](how-it-works/README.md) | see how the parts fit together |
| [Architecture](how-it-works/architecture.md) | follow a packet, a rule and a piece of evidence through the gateway |
| [The firewall](../deploy/nftables/README.md) | read the firewall rule by rule |
| [AdGuard Home](how-it-works/adguard.md) | see how the resolver is installed, configured, watched and upgraded |
| [The capture](how-it-works/capture.md) and [the extractor](how-it-works/extractor.md) | see what is recorded from the TV's traffic and how each connection gets its name |
| [The analyst and autonomous blocking](how-it-works/analyst-and-autonomy.md) | see every gate and watch a machine-made block passes |
| [The app in front](how-it-works/app-in-front.md) | see how a connection is matched to the app that was in front, and the rules the live reading keeps |
| [Privacy and retention](how-it-works/privacy-and-retention.md) | audit every file the gateway keeps, where, for how long, and what leaves it |

## Reference

Look things up here; the pages above link to the exact entry.

| Page | Holds |
|---|---|
| [Settings](reference/settings.md) | every key in `/etc/tvgw/tvgw.conf`, its default, and what to run after changing it |
| [Commands](reference/commands.md) | every `tvgw` command, its options, who may run it and its exit codes |
| [What tvgw verify checks](reference/verify-checks.md) | every check in the order `tvgw verify` runs it, what it proves, and what a `FAIL` or `WARN` means |
| [The brief, section by section](reference/brief-sections.md) | every line of the brief and of its JSON |
| [The store](reference/data-model.md) | every table and column of the database |
| [The profile format](reference/profile-format.md) | every table and key of a TV profile, and the evidence grades |
| [Glossary](reference/glossary.md) | a short definition of every term these pages use |

## Project

For contributors and the maintainer.

| Page | Read it to |
|---|---|
| [Working on tvgw](project/README.md) | find your way around the repository and its records |
| [Add a profile for another TV](project/adding-a-profile.md) | capture what a new TV does and turn it into a profile |
| [Deploy a change](project/deploying.md) | deploy from a workstation or through CI, and roll back |
| [Packaging and releases](project/packaging.md) | build the package and cut a release |
| [Supply chain](project/supply-chain.md) | see what the repository's automation may do |
| [Writing these pages](project/writing-docs.md) | follow the conventions every page keeps |
| [Rehearse a cold install](project/reinstall-rehearsal.md) | test the install from scratch on a working gateway |
| [Post-deploy validation, 2026-11-01](project/validation-2026-11-01.md) | follow the checks of the 2026-11-01 deploy and where each stands |
| [Design decisions](design-decisions.md), [incidents](incidents.md), [research](research/README.md) | read why tvgw is the way it is, what broke, and what was proposed |

## Reading paths

| If you are | Read, in this order |
|---|---|
| Setting up a gateway | [What it stops, and what it cannot](what-it-stops.md), [Install tvgw](install/README.md), [your TV's page](tv/README.md), then [Read your daily brief](use/daily-brief.md) the next day |
| Running one | [Read your daily brief](use/daily-brief.md) each day, [the red lines](use/daily-brief.md#red-lines) when one appears, and [Fix a problem](use/troubleshooting.md) when something breaks |
| Checking that it is safe | [What it stops, and what it cannot](what-it-stops.md), [How tvgw works](how-it-works/README.md), [Your household's privacy](use/privacy.md), [Privacy and retention](how-it-works/privacy-and-retention.md), [The analyst and autonomous blocking](how-it-works/analyst-and-autonomy.md), then the [design decisions](design-decisions.md) |
| Looking for a TV that is not listed | [Which TVs work](tv/README.md), then [Add a profile for another TV](project/adding-a-profile.md) |
| Changing the code | [CONTRIBUTING.md](../CONTRIBUTING.md), [Architecture](how-it-works/architecture.md), [Working on tvgw](project/README.md), then [the tests](../tests/README.md) |
