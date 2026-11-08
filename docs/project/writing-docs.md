# Writing these pages

This page holds the conventions every page of the repository follows: where a fact comes from and which page owns it, the shape and tone of a page, numbers, commands, links, figures, tables, folder READMEs, site identifiers, and the two audiences the pages are written for. It is for anyone who writes or reviews a page. A1, A2 and A12 hold on every page; A3, A4, A6, A7, A8 and A9 are narrowed or widened for the user pages that A13 names, because those are written for a reader who does not know networking.

**A1. Sources of truth**

Every statement of fact comes from one of four sources, as they stand at the commit you start from:

- the code: src/, deploy/, .github/workflows/ci.yml, Makefile and pyproject.toml;
- the tests: tests/;
- docs/design-decisions.md;
- CHANGELOG.md.

Existing pages, docs/research/ and the incident log are leads to check, never sources. If you cannot find a fact in those four sources, leave it out. The first time a page uses a constant or threshold, give its name and file so a reader can check it, for example `MAX_PER_DAY = 3` in src/tvgw/autoblock.py.

Facts about other products (hardware, distributions, other software on the computer) come from their primary source, linked where the fact is used, with the date it was read. Such a fact never describes what tvgw itself does.

On user pages (A13), give a constant's value in plain words and link its reference entry; do not name the constant or its file in prose.

**A2. One fact, one place**

Each fact has exactly one owning page. Other pages may name it in passing ("the hourly ingest"), but they link to the owner. They never restate its value, its table, its steps or its reasoning. A page's own figure may show facts that are in its own text; a figure never carries a fact the page's text and links lack. The fixed owners:

- setting defaults: docs/reference/settings.md
- unit schedules, users and timeouts: deploy/systemd/README.md#units
- paths, owners and modes: docs/how-it-works/privacy-and-retention.md#where-it-lives-and-who-can-read-it
- command syntax, privileges and exit codes: docs/reference/commands.md
- verify checks, what each proves and its fix: docs/reference/verify-checks.md
- red lines, what each means and what to do: docs/use/daily-brief.md#red-lines
- brief sections: docs/reference/brief-sections.md#sections
- table columns: docs/reference/data-model.md#tables
- firewall rules: deploy/nftables/README.md
- the capture filter: docs/how-it-works/privacy-and-retention.md#what-the-capture-keeps
- analyst and autonomy constants: docs/how-it-works/analyst-and-autonomy.md
- the CI wiring: deploy/README.md#how-a-change-reaches-the-gateway
- the profile format: docs/reference/profile-format.md
- term definitions: docs/reference/glossary.md
- the bring-up steps: docs/install/README.md, and by hand from a checkout docs/install/advanced.md#install-from-a-source-checkout
- what to set on each TV, what stays reachable, what tvgw can check and the support of each generation: the profile in src/tvgw/profiles/, shown on that vendor's page in docs/tv/
- which computers and systems are supported: docs/install/choosing-a-gateway.md
- what tvgw assumes, and what it cannot stop: docs/what-it-stops.md

A user page may repeat a stable fact its task needs (a default, a menu path, a command) in a sentence that links the owner; it never repeats a threshold or a count. A table generated from the code is not a repeat.

A generated table sits between a `<!-- generated:NAME -->` line and a `<!-- /generated:NAME -->` line, and `tools/docgen.py` writes it from the code: the support tables, the vendor pages' support levels and what the gateway reads, verify's plain words and new checks, and the red lines' plain words ([generated tables](../../tools/README.md#generated-tables)). Change the code it comes from and run `make docgen`, never the text between the markers: `make gate` fails on a region that differs from the code. Its words follow the page's conventions all the same; on a user page, the lint skips the region, so write `docgen.py`'s phrasing to A4's targets and A14's words. A marker shown as an example goes in a code span or a fenced block, where docgen does not read it.

**A3. Page shape**

- One H1, the page title, in sentence case.
- Directly under the H1, one paragraph of at most three sentences: what the page owns and who it is for. No table of contents, no "Overview" heading, no "See also" list at the end.
- Sections are H2 and subsections H3; nothing deeper. Headings use sentence case, with no trailing punctuation and no numbers. The glossary is the only exception: an H2 for each letter and an H3 for each term.
- Keep every fixed H2 heading word for word, because other pages link to it. You may add H2 and H3 headings. Use code spans in headings only for literal names, and never in a fixed heading.
- Folder READMEs follow A11.
- A user page opens with what the reader will be able to do, and how long it takes once that is measured. Its H2s name a task or answer a question, and it may end with one "Next:" line naming the next page of its reading path.

**A4. Tone**

- Write plain, direct sentences in the present tense, in the active voice, with American spelling.
- Describe what the code does now. No plans, no "will". Add history only where a design decision or the changelog gives it as a reason ("since 2026-10-27").
- Procedures are numbered steps in the imperative ("Run", "Edit").
- Call the project tvgw and the computer that runs it the gateway. Say the reference gateway for the owner's Raspberry Pi 5 where a fact is true of it alone; name the Raspberry Pi only for a Pi-specific fact, such as its operating system's journal default. Records keep the words they were written in.
- On engineering pages, the person who runs the gateway is "the owner", and procedures address the reader as "you". User pages address the reader as "you" throughout. Never use "we".
- No exclamation marks, em dashes, emoji, rhetorical questions or filler (simply, just, easily, obviously, note that, please). No marketing words (powerful, seamless, robust, best-in-class, enterprise-grade, cutting-edge).
- Give the reason next to the rule, in one clause. Use short sentences, one idea per sentence.
- On user pages the mean sentence is at most 18 words, no sentence is over 35, and no paragraph is over 80 words.

**A5. Numbers, units, dates**

- Use digits for every number that has a unit and for every setting value, constant, threshold, percentage, port and address. Use digits for every number in tables and figures. In running prose, write counts from one to nine without a unit as words ("three watches", "seven copies").
- Put a space between a number and its unit. In prose, write duration units as words: "30 seconds", "10 minutes", "2 hours", "7 days". In tables and figures, use s, min, h and d. You may give a code value in the code's own unit with the conversion: "7440 s (2 h 04 min)".
- Write sizes as B, KB, MB or GB with a space ("16 KB", "1.5 GB"). They mean powers of 1024, as the brief (`cli.hb()`) and `tvgw prune-pcaps` compute them, except where a page quotes `tvgw size`, `tvgw ingest` or `tvgw backup`, which print MB of 1,000,000 bytes; say so there.
- Write percentages without a space ("20%"). Quote ratios from code as the code writes them (`0.2`) and give the percentage in prose.
- Separate thousands with commas in prose ("10,000 lines"). Write code literals as the code does (`10_000`).
- Dates are ISO 8601 (2026-10-28). ISO weeks look like 2026-W43. Times of day use the 24-hour clock (03:50) and are the gateway's local time, which the timers use. Say "UTC" where a value is UTC, as in pcap and backup file names.
- Give money in US dollars with two decimals ("$0.07"), with the date of the price.
- Do not state counts that ordinary commits change: numbers of tests, rules in a list, lines of code. Counts fixed by the design are fine once you check them against the tree: seventeen services and eight timers in deploy/systemd, 28 tables and one view in src/tvgw/db.py.

**A6. Commands and code**

- Put commands in fenced blocks tagged `sh`, one command per line, with no prompt characters. Show root as `sudo`. A `#` comment at the end of a line may say what the command shows. Before the block, say where it runs: "On the gateway:", or "On your computer:" for a command run elsewhere ("On your workstation:" on engineering pages, for a checkout of the repository). After a command that changes something, show what success prints.
- Put output in a separate block tagged `text`, trimmed, with nothing site-specific.
- Write placeholders in angle brackets: `<ssh-host>`, `<TV_IP>`, `<day>`, `<stamp>`. CLI arguments use the names cli.py gives them (DAY, SINCE, NAME, QUERY).
- Use inline code for command names, file paths, settings keys, table and column names, unit names, rule text, nftables comments and literal values. Write settings as `KEY=value`.
- Paths on the gateway are absolute (`/var/lib/tvgw/tvgw.db`). Repository paths are relative to the repository root (`deploy/nftables/tvgw-apply`), and are links where the reader should open the file.
- Never show `ssh`, `scp` or `rsync` with a real host. Write `make deploy PI=<ssh-host>`.

**A7. Links**

- Use relative links only, written from the linking file's folder (`../reference/settings.md#the-tv-side`), so they work on any clone. No bare URLs. External links go only to the primary source of something a procedure needs, such as AdGuard Home's install instructions.
- When one section owns a fact, link to that section, not to the page. Anchors follow GitHub's rules: lowercase, spaces become hyphens, and punctuation other than hyphens and underscores is removed (`#what-installsh-does`, `#the-machines-rules-file`). Keep a heading free of a run of hyphens in its anchor, such as a `--flag` after a space, so that GitHub's anchor and the site's agree.
- Link text names the target ("the settings file", "design decision 20"), never "here" or "this page".
- Link the first mention of an owned fact in each section, not every mention.
- `make gate` fails on a relative link, an anchor or a docs path the code names that leads nowhere, by file and line ([the link check](../../tools/README.md#what-the-link-check-reads)); `make links` runs that check alone.
- On user pages, put at most one link in a step or paragraph, and at most four in 100 words. The front page may also carry the badge row, one link to the documentation site, the install command's URL and links to the latest release.
- Records (docs/design-decisions.md, docs/incidents.md, CHANGELOG.md, docs/research/) receive script-made, link-only edits when a page moves; their text never changes ([moving a page](../../tools/README.md#moving-a-page)).
- Records link to pages and their sections, and the link check holds every one of those links. Keep a heading that a record links word for word, as docs/how-it-works/architecture.md#naming-a-connection, docs/use/daily-brief.md#red-lines, docs/use/blocking.md#strict_ports, docs/how-it-works/capture.md#measuring-it-on-the-pi and docs/how-it-works/extractor.md#validating-on-the-pi are, or move it with `tools/rewrite_doc_paths.py` so that the records' links follow.

**A8. Citing a design decision**

User pages do not cite design decisions: where a reason is needed, give it in one plain clause, and end the page, if it helps, with one "Why it works this way" link. Engineering pages cite them as follows.

- Write "design decision N", in lowercase, and link it to its heading in docs/design-decisions.md on first mention in a section: `[design decision 20](design-decisions.md#20-the-gateway-blocks-on-its-own-under-three-watches)`. For several, write `design decisions [19](...) and [20](...)`. Never write "DD20", "ADR 20" or "decision #20".
- Give the consequence the reader needs in one clause and link for the reasoning. Do not restate the context or quote the record.
- Where the code and a decision differ, describe the code and cite the decision that matches it. For example, decision 19 says nothing is applied, while decision 20 and the code apply blocks when `ANALYST_APPLY=auto`.
- The anchors:
  - `#1-the-tv-uses-the-direct-uplink-not-the-vpn`
  - `#2-isolate-first-then-filter`
  - `#3-no-tls-interception`
  - `#4-no-rooting-of-the-tv`
  - `#5-fail-closed`
  - `#6-adguard-home-is-configured-as-code`
  - `#7-must-allow-exceptions-are-generated-from-the-toml`
  - `#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block`
  - `#9-doh-upstreams-by-ip-address`
  - `#10-a-rollback-journal-not-wal`
  - `#11-row-id-watermarks-for-the-hosts-counters`
  - `#12-each-flow-is-named-by-its-own-tls-hello`
  - `#13-counters-not-logs-prove-the-firewall-held`
  - `#14-red-lines-are-the-alarm-model`
  - `#15-blocklist-entries-come-from-evidence-with-grades`
  - `#16-quickset-and-hue-stay-blocked-with-the-cost-written-down`
  - `#17-strict_ports-stays-off-until-two-clean-weeks`
  - `#18-dns-gated-egress-starts-as-a-count-in-its-own-table`
  - `#19-a-daily-analyst-that-only-proposes`
  - `#20-the-gateway-blocks-on-its-own-under-three-watches`
  - `#21-a-continuation-inherits-its-name`
  - `#22-a-pass-that-proposes-nothing-is-remembered`
  - `#23-the-deb-runs-installsh`
  - `#24-the-tv-side-comes-from-the-settings-file`
  - `#25-adguard-home-is-a-checked-dependency-never-bundled`
  - `#26-the-workflows-are-the-most-privileged-code-in-the-repository`
  - `#27-a-namespace-copy-of-the-gateway-in-ci`
  - `#28-tvgw-setup-drives-the-existing-steps-it-does-not-replace-them`
  - `#29-the-settings-file-is-edited-in-place-and-refused-whole`
  - `#30-an-unattended-setup-takes-the-answers-file-in-the-settings-format-and-never-guesses`
  - `#31-reference-records-name-their-evidence-or-their-source`
  - `#32-a-vendor-profile-without-hardware-is-dns-only-cited-and-subscribed`
  - `#33-parse-the-held-back-first-segment-of-a-split-hello`
  - `#34-a-hello-without-a-name-gets-its-own-table`
  - `#35-ja4-is-computed-from-the-fields-not-taken-from-tshark`
  - `#36-a-known-ech-public-name-is-real-ech`
  - `#37-the-tshark-sandbox-has-no-weaker-fallback`
  - `#38-dumpcap-writes-the-hourly-ring`
  - `#39-the-first-packets-of-each-connection-behind-a-switch`
  - `#40-the-tvs-radios-are-checked-not-assumed`
  - `#41-the-autonomy-refuses-what-it-cannot-see-and-keeps-what-it-decided`
  - `#42-the-pi-is-closed-to-the-tv-whatever-nftables-holds`
  - `#43-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer`
  - `#44-the-tunnel-is-a-setting-and-the-pis-own-leaks-are-counted`
  - `#45-the-acr-red-line-is-an-upload-test-and-a-port-wall`
  - `#46-the-blocklists-are-watched-and-adguard-changes-only-on-purpose`
  - `#47-the-gateway-keeps-the-least-of-its-own-record-that-the-detectors-need`
  - `#48-one-ledger-of-changes-one-hour-classifier-and-a-second-judge-that-only-watches`
  - `#49-the-gateway-answers-the-tv-through-the-tv-port-table-100-carries-the-tv-subnet`
  - `#52-setup-fetches-adguard-homes-own-release-pinned-and-hash-checked-and-seeds-it-without-the-wizard`
  - `#53-releases-carry-a-hash-checked-bootstrap-for-two-architectures-with-provenance-under-immutable-releases-updates-are-checked-weekly-installed-only-by-the-user-judged-by-verify-and-rolled-back-a-new-settings-key-never-changes-the-meaning-of-an-old-keys-value`
  - `#54-a-tvs-lan-api-is-a-module-the-profile-names-a-reading-never-pairs-a-profile-declares-what-it-can-check`
  - `#57-consent-the-tv-will-not-report-is-the-owners-dated-word-including-unknown-asked-again-after-a-software-download-samsung-is-read-without-pairing`
  - `#58-the-brief-has-a-plain-form-with-three-tiers-the-login-message-shows-its-status-and-action-and-tvgw-doctor-explains-every-check`
  - `#59-site-rules-etctvgwlocalrules-written-by-tvgw-allow-and-tvgw-block-applied-after-the-profile-and-before-machine-rules-under-the-same-lint`
  - `#60-the-documentation-is-organized-by-what-the-reader-wants-to-do-user-pages-are-written-for-a-non-engineer-the-site-is-a-view-of-docs-built-by-a-pinned-generator-never-showing-a-command-the-latest-release-lacks-and-github-stays-complete`
  - `#62-a-tv-gets-a-vendor-profile-only-on-evidence-or-its-owners-answer-otherwise-the-general-profile-which-isolates-records-briefs-and-blocks-only-shared-lists`
  - `#63-behavior-changing-deploys-to-the-reference-wait-for-a-quiet-window-decided-on-the-gateway-nothing-the-gateway-prints-where-others-can-read-it-carries-a-home-identifier-acceptance-that-needs-systemd-runs-in-a-container-tier`
  - `#66-an-upload-budget-with-a-ceiling-set-once-count-only-and-the-names-of-a-tv-that-goes-online-while-off`
  - `#67-the-tvs-own-account-of-itself-is-the-ground-sessions-a-receipt-and-a-replay-keyed-to-the-app-in-front-a-live-reading-that-never-knocks-blind-no-rule-yet`
  - `#73-the-store-refuses-a-newer-version-and-commits-durably-the-gateway-samples-its-own-health-the-quic-refusal-is-watched-an-encrypted-copy-leaves-the-box`
  - `#owner-decisions-pending-2026-11-01`, the owner decisions still open

**A9. Figures**

- A figure is an HTML file in `docs/diagrams/`, drawn with the figure system ([diagrams/STYLE.md](../diagrams/STYLE.md)) and rendered by `python3 docs/diagrams/build.py` to a light and a dark PNG at 2x. Mermaid is not used.
- Embed it with the `<picture>` snippet in STYLE.md, with the path relative to the page. The `alt` text says in full sentences what the figure shows, so the page reads without the image.
- One idea per figure, about eight to twelve elements. A sequence of ideas is a series of figures; a sequence of steps is a numbered list, and a mapping is a table, not a figure.
- Every wire carries a label saying what moves. The canvas is 960 px wide and every label 15 to 16 px, so it reads at the width GitHub shows it.
- Labels use the names in the code (unit, chain, table, file and constant names), kept short.
- Caption: directly under the picture and after one blank line, write exactly one line in italics (`*...*`). It is one sentence ending with a period, saying what the figure shows and the one thing to notice. Nothing goes above the figure, and there are no "Figure N" labels.
- Every fact a figure shows is also in the page's text or in a linked owner, so the page reads without the figure rendering.
- A figure shows only things that exist in the code. No planned components.
- On user pages a figure may also show a physical arrangement (where the cables go); annotated output whose text the build takes from the code or a golden file; or a numbered journey of at most four steps that also appears as the list directly below it and shows no command a reader must copy. Its labels are plain words, not the code's names ([user-path figures](../diagrams/STYLE.md#user-path-figures)). A cable is drawn as a cable: an object, curved and unlabelled. A wire still carries a label.
- A number in a figure is measured, with its date and source in the caption, or generated at build time.

**A10. Tables**

- Each table has a header row in sentence case and one fact per cell, with literal values in code font.
- Use at most five columns. Reference tables for settings, commands, units and checks may use seven.
- Order rows the way the code does (chain order, render order, run order); otherwise, alphabetically.

**A11. Folder READMEs**

Every folder with tracked files has a README, except `.github/`, `.github/ISSUE_TEMPLATE/`, `.github/workflows/` and `src/`: [the repository map](README.md#repository-map) describes those, and the CI wiring is in [how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway). A README is the reference for the files in that folder and for nothing else. The shape:

1. An H1 naming the folder's role, for example "The firewall".
2. One paragraph: what the folder holds, when its files run, and which docs page explains the concept.
3. An H2 "Files" with a table of each file, what it is, and where it is installed or who uses it. In deploy/systemd/README.md this table is "Units".
4. The sections specific to the folder: how it works, rule by rule or line by line, each with its reason.
5. Where they apply: "Checking it" (read-only commands), "Changing it" (where to edit, what to run, which test guards it) and "Gotchas".

Facts about the files in the folder live in its README. Concepts and procedures that span folders live in docs/ and are linked from there. The settings reference lives in docs/reference/settings.md, and deploy/README.md's Files table links it.

**A12. Site identifiers**

Never write a site identifier. That means:

- no real MAC address; the only allowed MAC values are the placeholders b4:b2:91:aa:bb:cc and 00:00:00:00:00:00;
- no 192.168.x.x address or other home-LAN address;
- no host name or user name of the owner's machines or of the gateway;
- no router or VPN account detail, no Wi-Fi network name, no ZIP code, no location;
- an interface name that embeds a MAC address (`enx` and 12 hex digits) is a MAC address.

The rule covers what tvgw prints where others can read it, too: the CI logs of the public repository, setup's error tail, and any report or bundle a user is asked to attach.

Allowed addresses: the TV subnet 10.10.10.0/24, the gateway 10.10.10.1, the TV 10.10.10.17, the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24, and public addresses that appear in the code (1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 156.147.69.32). Write "the home router", "the router's address" and "your ssh host". Public vendor host names that appear in the profile are code facts and are allowed. Check any text copied from a log, a brief or a template line by line before it goes in.

**A13. Two audiences**

User pages are README.md, docs/README.md, docs/what-it-stops.md and the pages in docs/install/, docs/use/ and docs/tv/. They are written for a reader who can copy a command but does not know networking. Every other page is an engineering page. A user page names a mechanism at most once, in parentheses after the plain words ("the filter (AdGuard Home)"), and links the engineering page that explains it at the end of a step, never in the middle of one.

**A14. Plain words**

Outside code blocks and generated tables, user pages avoid these engineering terms: design decision N, guard, nftables and its table names, conntrack, dumpcap, DoH, DoT, DoQ, QUIC, SDP, GFTS, MQTT, store and SQLite, evidence pack, canary, probation, judge, shadow, any settings key, sudoedit, debconf, PYTHONPATH, venv, make deploy, nginx, dnsmasq, NetworkManager, VPN product names, LAN API and must-allow. Define "red line" and "ACR" once, where each is first used. The support words are fixed: Tested, Reported and Not yet tested; for gateways also In daily use, Checked automatically and Not supported.

`tests/unit/test_user_pages.py` holds README.md and the user pages to the targets of A4, the link limits of A7, A8's rule and this list, outside code, tables, HTML comments, alt text and generated blocks, and refuses a `src/` path in their prose.
