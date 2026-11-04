# R3: incremental improvements to the tvgw documentation

*Research record, written 2026-11-04; the code that followed is in the [CHANGELOG](../../../CHANGELOG.md) under 2026-11-04.*

Audit of 2026-11-04, read as the intended reader: a careful person with a smart TV, a spare Raspberry Pi and no networking knowledge, who wants to know what tvgw is, whether to trust it, and how to install it. Sources: the live site at `https://kywwilson11.github.io/tvgw/` (built from `31ef8e1`, "Release 0.3.0"; pages fetched as HTML and read for structure, headings, alt text, footer links and outbound links), the Markdown at the same commit, `docs/project/writing-docs.md` (A1 to A14), `tests/unit/test_user_pages.py`, `docs/site/README.md`, `mkdocs.yml`, `tests/unit/test_site_prebuild.py`, the v0.3.0 release page (`gh release view v0.3.0`) and the code where a page makes a claim. Nothing in the repository was edited.

Every replacement text below is written to pass `test_user_pages.py`: present tense, no "will", no em dash, no sentence over 35 words, at most one relative link per paragraph, no A14 term outside code. Checked, not assumed: the texts of Q1 to Q10 and items 11 to 19 were applied to scratch copies of the eight pages they touch (front page, landing page, what it stops, install guide, other ways to install, daily brief, troubleshooting, Samsung) and the test's own `problems()` returns nothing on any of them, the page-wide mean sentence included. Every command proposed exists in v0.3.0's `build_parser()` (`tvgw status`, `tvgw doctor`, `tvgw block`, `tvgw setup --installer`, `tvgw setup --dry-run`), so the `pages.yml` command check passes. No site identifier appears.

## Contents of this report

1. The verdict in five lines
2. How the pages should mention release 0.3.0 and the installer
3. The ranked improvements (ten quick wins first, then the rest, then the ones that need code)
4. Cross-page inconsistencies
5. What must not change
6. Site-level proposals, with feasibility
7. The exemplar comparison
8. Accessibility
9. The page walk, page by page
10. Found along the way (not documentation)

## 1. The verdict in five lines

- The first screen of every user page answers the reader's arrival question. The front page is the strongest: a one-sentence lede, an honest status line, a figure with a measured card, and "it stops / it cannot stop / it costs".
- The honesty holds everywhere except where 0.3.0 moved under the pages this morning: the front page says the one-command install "is being built" and "will" appear, while the release badge on the same page leads to a release page whose first command is that installer, with "Step by step: the front page".
- The install guide's real stumbles are small and concrete: the TV's Wi-Fi is turned off before its networks are forgotten (on an LG the list then hides), the ssh step has a placeholder that breaks when pasted and no fallback when `tvgw.local` is not found, and "how to tell it worked" describes the three lines instead of showing them.
- A handful of facts went stale with 0.3.0 (Intel and AMD packages "from the next release on", "ARM computers only"), and three status words disagree between the front page, the gateway page and the conventions.
- The site is sound. Its two reader-facing gaps are that the home page's footer "Next" leads to the table of all pages rather than to "What it stops", and that the site shows no version anywhere, because the prebuild drops the badge row.

## 2. How the pages should mention release 0.3.0 and the installer

The owner's design holds: the installer goes on the front page only after a non-engineer has run it on a fresh gateway. Until then the pages should say, in this order of prominence:

| Where | What it says | Item |
|---|---|---|
| Front page, Get started | That releases now carry a one-line installer, that it has not yet been run on a real gateway, that it stops when the filter is not installed first, and that this page shows it once someone who is not an engineer has used it. No command, no link to the release. | Q1 |
| Install guide, lead | One clause: the guide installs from source; releases also carry an installer the guide does not use yet. | Q1 |
| Install guide, "Install the package" | Moved to the end of the page, heading kept. States both packages, the installer, that neither has run on a real gateway, the two known stops, and links "Other ways to install". | 13 |
| Other ways to install, "Install from the package" | The only place the `get.sh` command appears for a new install, for an engineer, with the two known stops and the workaround (`TVGW_NO_SETUP=1`, then `sudo tvgw setup --installer ...`). | 13, F1 |
| Choose a gateway computer, mini PC row | Intel and AMD packages exist since 0.3.0; none has been installed on one. | Q5 |
| Keep it running, "Upgrade tvgw" | Already right: `get.sh` with `TVGW_NO_SETUP=1` for package installs. No change. | |
| The site's home page | One plain line naming the release the site describes, written by the prebuild in place of the dropped badge row. | S2 |
| The release notes template | Its "Step by step: the front page" link goes to the install guide, and one sentence says the installer has not yet been run on a real gateway, for as long as that is true. | 27 |

Word the version as "since 0.3.0" or "the latest release", not "0.3.0 is the latest", so a sentence stays true after 0.3.1.

## 3. The ranked improvements

Each item gives the page and section, what the reader meets today, the change (replacement text where it is a sentence or two), why it helps, the effort, and whether it needs code.

### The ten quick wins (words only, under 30 minutes each)

#### Q1. Say that the installer exists, and why the guide does not use it yet

- **Where:** `README.md`, "Get started", fourth paragraph; `docs/install/README.md`, lead paragraph.
- **Today:** "A one-command install that sets everything up for you is being built. This page will show it once it has been tested on a clean computer and by someone who is not an engineer." The install guide: "A one-command install that does these steps for you is being built."
- **Change (front page):** "Since 0.3.0, each release also carries a one-line installer. It has not yet been run on a real gateway, and it stops when the filter is not installed first. This page shows it once someone who is not an engineer has installed tvgw with it."
- **Change (install guide lead, third sentence):** "Since 0.3.0, each release also carries a one-line installer, which this guide does not use until it has been run on a real gateway."
- **Why:** The front page's own release badge leads to a page that says "run this" and "Step by step: the front page"; the front page then says the installer does not exist. A careful reader notices the contradiction and trusts both less. The current sentence also breaks A4 ("will", and a plan). The new text keeps the design's honesty and gives the reason, which the release page's own Status paragraph already states.
- **Effort:** 15 minutes. **Kind:** words only.

#### Q2. Forget the TV's Wi-Fi networks before turning Wi-Fi off

- **Where:** `docs/install/README.md`, "Connect the TV", step 3.
- **Today:** "On the TV, turn **Wi-Fi off** and make it **forget every saved Wi-Fi network**, so its only connection is the cable."
- **Change:** "On the TV, first make it **forget every saved Wi-Fi network**, then turn **Wi-Fi off**, so its only connection is the cable. On some TVs the saved networks are hidden once Wi-Fi is off. Turn Wi-Fi Direct and screen sharing off as well. [Your TV's page](../../tv/README.md) says where each switch is."
- **Why:** The LG page's own menu path says "the list is hidden while the switch is off". A reader who follows the install guide's order switches Wi-Fi off, then cannot find the networks to forget, which is the one assumption the whole product rests on. The "Other TVs" steps and the Samsung, Roku and Vizio radios already put forgetting first.
- **Effort:** 5 minutes. **Kind:** words only.

#### Q3. Make the ssh step survive a paste and a missing name

- **Where:** `docs/install/README.md`, "Prepare the gateway", step 6, and the last paragraph of "What you need".
- **Today:** "In that terminal, connect to the Pi. Use the username and hostname you chose:" followed by `ssh <username>@tvgw.local`. "What you need" ends: "Copy every command below as it is written."
- **Change (end of "What you need"):** "Copy every command below as it is written. A word in angle brackets, such as `<username>`, is yours to fill in: replace it, brackets included."
- **Change (after the ssh block, before "Answer yes"):** "If the terminal says the name is not known, wait a minute and try again. If it still fails, your router's app or web page lists the Pi under its hostname, with an address: use `ssh <username>@<address>` instead."
- **Why:** The copy button copies `<username>` literally. In PowerShell `<` is a reserved operator and in a Unix shell it is a redirect, so the reader gets an error that does not mention the placeholder. A `.local` name is the step most likely to fail on a first try, and the page has no "if not, then" (Home Assistant's Pi page gives one for exactly this case).
- **Effort:** 15 minutes. **Kind:** words only.

#### Q4. Show what "it worked" looks like

- **Where:** `docs/install/README.md`, "How to tell it worked".
- **Today:** "It answers in three lines: whether the protection held at the last check, how long ago that was, and what to do."
- **Change:** after the `tvgw status` block, add "On a working gateway it prints:" and

  ```text
  tvgw: the protection held at 21:40 (<N> checks passed).
  The checks run every 10 minutes; this one is 4 minutes old.
  Nothing needs your attention.
  ```

  then: "Then check the TV itself: open a streaming app and play something. It plays as it did before."
- **Why:** A6 asks for what success prints after a command, and the reader's real question after setup is "did it work, and is my TV still fine?". The lines are the format strings and `FINE` of `src/tvgw/status.py`; `<N>` avoids a count that commits change (A5). The status file is written by every `tvgw verify` run from the command line: the installer setup runs ends with one (`deploy/install.sh`, last line), and the timer repeats it every 10 minutes. Setup's own closing check calls `verify.check()` and does not write it, so add: "If it says no check has run yet, wait 10 minutes and run it again."
- **Effort:** 15 minutes. **Kind:** words only.

#### Q5. Correct the facts 0.3.0 made stale

- **Where:** `docs/install/advanced.md`, "Install from the package", first paragraph; `docs/install/choosing-a-gateway.md`, "Hardware", mini PC row.
- **Today:** "Each release carries a package and its `SHA256SUMS`: for ARM computers so far, and from the next release on for Intel and AMD computers too." And: "**Not yet tested**. Releases carry a package for ARM computers only, so such a computer installs from source".
- **Change (advanced):** "Each release carries a package and its `SHA256SUMS`: since 0.3.0, one for 64-bit ARM computers, such as a Raspberry Pi, and one for Intel and AMD computers. It also carries a one-line installer that picks the package and checks its fingerprint. Neither has been installed on a real gateway yet."
- **Change (mini PC cell):** "**Not yet tested**. Since 0.3.0, releases carry a package for Intel and AMD computers too; none has been installed on one yet".
- **Why:** The release page lists `tvgw_0.3.0-1_amd64.deb`. A mini PC owner reads "ARM only" and either gives up or installs from source for no reason. "From the next release on" is also a plan (A4).
- **Effort:** 10 minutes. **Kind:** words only.

#### Q6. Tell a returning reader how to get back onto the gateway

- **Where:** `docs/use/daily-brief.md`, "Your daily check", before step 1.
- **Today:** "1. On the gateway, run `tvgw brief`."
- **Change:** a new step 1: "Open a terminal on your own computer and connect to the gateway with `ssh <username>@tvgw.local`, as when you installed it." The current steps become 2 to 4.
- **Why:** The daily brief is the product, and it lives in a terminal on another computer. Days after the install, the reader no longer remembers the ssh line, and nothing on the page says how to get "on the gateway". This is the page they bookmark.
- **Effort:** 5 minutes. **Kind:** words only.

#### Q7. Complete "what you need": the TV's port, your computer, and a gateway that stays on

- **Where:** `README.md`, "Get started", the list; `docs/install/README.md`, "What you need".
- **Today (front page):** two bullets, a small computer and an Ethernet cable. The install guide adds the card, the power supply and your own computer. Neither says the TV needs a network port, or what happens when the gateway is off.
- **Change (front page, two bullets added):** "a TV with its own network port, since the cable becomes its only way out;" and "your own computer, to type the gateway's commands from." Then, after the list: "The gateway stays on, like your router. When it is off, the TV has no internet, never an unfiltered one."
- **Change (install guide, after the TV bullet):** "**The TV's network port.** The TV needs a socket for a network cable. A TV that can only use Wi-Fi cannot sit behind the gateway."
- **Why:** The TV's port is the one hard prerequisite that is not on any list; the Roku page alone says "a Roku player with a network port". "The gateway stays on" answers the household question nobody asks until the power fails, and it states the fail-closed design in plain words.
- **Effort:** 15 minutes. **Kind:** words only.

#### Q8. Date the studies so a reader does not doubt them

- **Where:** `docs/what-it-stops.md` (the table row on a setting that does not do what the menu says), `docs/tv/samsung-tizen.md`, `docs/tv/roku.md`, `docs/tv/vizio-smartcast.md` (the paragraph after each privacy-settings table).
- **Today:** "a 2027 study" on all four pages, and the link text "Watching the Watchers, PoPETs 2027".
- **Change:** "a study in the proceedings of the 2027 Privacy Enhancing Technologies Symposium". On the Samsung page, for example: "One 2024 study saw screen recognition stop after opting out. A study in the proceedings of the 2027 Privacy Enhancing Technologies Symposium found the opt-out failing in most of its scenarios."
- **Why:** On 2026-11-04 "a 2027 study" reads as a typo or a fabrication, on the one claim the reader is most likely to check. The paper's own page names its venue as "Proceedings of Privacy Enhancing Technologies Symposium, 2027" (read 2026-11-04).
- **Effort:** 10 minutes. **Kind:** words only.

#### Q9. Say where the analyst's key comes from

- **Where:** `docs/use/analyst.md`, "Add the key"; `docs/install/README.md`, "Add the analyst, if you want it".
- **Today:** "The analyst is optional, and it needs an Anthropic API key." Nothing says where a key is made or that it is billed.
- **Change (analyst page, first paragraph of "Add the key"):** "Make the key in `[Anthropic's Console](<Anthropic's own page for creating an API key, read and dated when written>)`. Each request is billed to that account; the cost section below gives the prices." One link in the paragraph, as A7 allows. The install guide's "Add the analyst" gets the same first sentence.
- **Why:** The reader meets "Anthropic API key" with no idea where one comes from or that it costs money. A7 allows an external link to the primary source a procedure needs, which this is.
- **Effort:** 10 minutes. **Kind:** words only.

#### Q10. Explain the three statuses of the limits table

- **Where:** `docs/what-it-stops.md`, "What it cannot stop", the sentence above the table.
- **Today:** "Each limit has one of three statuses: *known, mitigated by the assumption*; *known, partly checked*; or *known, not addressed*."
- **Change:** "Each limit has one of three statuses. *Known, mitigated by the assumption* means tvgw handles it only while the cable is the TV's only connection. *Known, partly checked* means the gateway notices some of it and lists it in the brief. *Known, not addressed* means tvgw does nothing about it, and the table says what you can do, if anything."
- **Why:** "Mitigated by the assumption" is the most important phrase on the trust page, and it is engineering shorthand. Spelled out, the table becomes the honest answer to "what am I really protected from".
- **Effort:** 10 minutes. **Kind:** words only.

### The rest, ranked

#### 11. A "can you trust it" paragraph on the front page

- **Where:** `README.md`, "What it stops, and what it cannot", after "tvgw installs nothing on the TV...".
- **Today:** Trust is spread over four pages. The front page never says where the record stays or that the code is open.
- **Change:** "The record of what the TV did stays on the gateway. Only the optional analyst sends anything from it, a scrubbed daily summary, and only when you add its key. tvgw is open source under the MIT license, so anyone can read its code ([your household's privacy](../../use/privacy.md))."
- **Why:** "Whether to trust it" is one of the reader's three questions, and the facts are already owned elsewhere (what-it-stops: "The record stays at home... Only the optional analyst sends anything out"). One paragraph puts them where the decision is made.
- **Effort:** 15 minutes. **Kind:** words only.

#### 12. Make the front page's gateway table agree with the gateway page

- **Where:** `README.md`, "Works with", the second table and the sentence after it.
- **Today:** "Another 64-bit computer with Debian 13 | **Not yet tested** on hardware". Ubuntu is absent. The status words are not explained on the page.
- **Change:** "Debian 13 with a desktop, or Ubuntu 24.04 or 26.04 Desktop | **Checked automatically**: every change is checked against its programs; no gateway runs it yet". Then, under the table: "[Choose a gateway computer](../../install/choosing-a-gateway.md) says what each status word means, for every system."
- **Why:** The same system has two statuses on two pages, and the release page names Ubuntu while the front page does not. One table and one link make the front page a true summary of the owner page (A2).
- **Effort:** 15 minutes. **Kind:** words only.

#### 13. Move "Install the package" to the end of the install guide, and rewrite it

- **Where:** `docs/install/README.md`, "Install the package" (keep the heading word for word: `docs/packaging.md`, `docs/project/packaging.md` and `docs/project/reinstall-rehearsal.md` link `#install-the-package`).
- **Today:** The section sits between "Install from source" and "Connect the TV", in the middle of the reader's path, and says "Until the one-command install is built, the package suits an engineer".
- **Change:** Move it after "Add the analyst". Text: "Each release also carries a package for 64-bit ARM computers and for Intel and AMD computers, and since 0.3.0 a one-line installer that picks the right one. Neither has been run on a real gateway yet. Both still need the filter installed first, and setup does not yet find the package's installer by itself. For now they suit an engineer: [install from the package](../../install/advanced.md#install-from-the-package) has the steps." Keep the `sha256sum` paragraph. In `advanced.md`, add the installer as the download step for an engineer: `curl -fsSL https://github.com/kywwilson11/tvgw/releases/download/v<version>/get.sh | sudo env TVGW_NO_SETUP=1 sh`, then `sudo tvgw setup --installer /usr/lib/tvgw/deploy/install.sh` (see F1).
- **Why:** A newcomer reads every section in order. A section that ends "suits an engineer" in the middle of the procedure costs attention and confidence at the worst moment. At the end it is information, not a fork in the road.
- **Effort:** 25 minutes. **Kind:** words only.

#### 14. One sentence that maps the install, for orientation and for printing

- **Where:** `docs/install/README.md`, end of "What you need".
- **Today:** Eleven H2 sections and no overview; the reader cannot tell how far along they are.
- **Change:** "The install has five parts, each a section below: prepare the gateway, install from source, connect the TV, run setup, and check that it worked."
- **Why:** It doubles as the printable checklist (see S4) without restating any step, so A2 holds. A3 forbids numbers in headings, so the count belongs in prose.
- **Effort:** 5 minutes. **Kind:** words only.

#### 15. Explain `sudo` and the editor once

- **Where:** `docs/install/README.md`, "Prepare the gateway", after step 6; "Add the analyst, if you want it".
- **Today:** `sudo` appears in nearly every command and is never explained. "Paste the key, save, and close the editor" assumes the reader knows how to save in a terminal editor.
- **Change (after step 6):** "`sudo` at the start of a command runs it as the administrator. It may ask for your password." **(analyst step):** "`sudoedit` opens a text editor in the terminal. Its bottom lines list its keys, where ^ means the Ctrl key: save, then exit."
- **Why:** These are the two moments a non-engineer is most likely to stop. Check on the fresh-card trial which editor Raspberry Pi OS Lite opens before naming it; the sentence above holds for nano without naming it.
- **Effort:** 10 minutes. **Kind:** words only.

#### 16. Give the troubleshooting page a healthy result and a visible edge

- **Where:** `docs/use/troubleshooting.md`, "Start here", and the line before "Failed units".
- **Today:** The doctor is described but its "all clear" is not shown. After "The TV" table, about 80% of the page is engineering tables with no marker.
- **Change (after the first list):** "On a healthy gateway the doctor prints:" and

  ```text
  tvgw doctor: all <N> checks pass. The gateway holds.
  If the TV still has no internet: move its cable from the gateway to your router; tvgw keeps its settings.
  ```

  **(before "Failed units"):** "The sections from here on list every message the gateway's background jobs print. They are for an engineer, and you need them only when the doctor or the brief sends you here."
- **Why:** The reader in trouble needs to know what "nothing wrong" looks like (strings from `src/tvgw/doctor.py`), and where the page stops being for them.
- **Effort:** 15 minutes. **Kind:** words only.

#### 17. Attribute the sample brief, and use one word for the 3,983

- **Where:** `docs/use/daily-brief.md`, "Your daily check"; `docs/what-it-stops.md`, "What it stops".
- **Today:** "A brief looks like this:" shows "Wednesday 4 November" with the measured day's 3,983, which a careful reader takes for a real brief of today. what-it-stops says "known advertising, tracking and screen-recognition services 3,983 times"; the front page and the measured page say "advertising, tracking and fingerprinting".
- **Change:** "A brief looks like this one, from the project's tests:" (the text is `tests/unit/test_plain.py`'s). In what-it-stops: "known advertising, tracking and fingerprinting services 3,983 times".
- **Why:** The project's credibility rests on its measured numbers; a sample that looks measured, and one count described two ways, invite doubt.
- **Effort:** 5 minutes. **Kind:** words only.

#### 18. Rewrite the landing page's sentence about the site and GitHub

- **Where:** `docs/README.md`, lead paragraph, last sentence (it renders as the site's "All the pages").
- **Today:** "The documentation site shows only commands that exist in the latest release; these pages on GitHub describe the newest code."
- **Change:** "On the documentation site, every command these pages show exists in the latest release. On GitHub, the same pages describe the newest code, which can be ahead of the release."
- **Why:** On the site, "these pages on GitHub" points at pages the reader is not on. The rewrite says the same thing from either side.
- **Effort:** 5 minutes. **Kind:** words only.

#### 19. Say that the TV report form needs a GitHub account

- **Where:** `docs/tv/README.md`, "Help test a TV".
- **Today:** "...then fill in the `[TV report form](...)`." The form is a GitHub issue form.
- **Change:** add "The form is on GitHub, and needs a free GitHub account."
- **Why:** The most useful contribution the project asks for has a hidden prerequisite that a non-engineer meets only after a week of data collection.
- **Effort:** 2 minutes. **Kind:** words only.

#### 20. One fact, one place: the key command and Anthropic's retention

- **Where:** `docs/install/README.md` "Add the analyst" and `docs/use/analyst.md` "Add the key"; `docs/use/analyst.md` "What it sends" and `docs/use/privacy.md` "Forget the viewing record".
- **Today:** Two different commands create the same key file (`sudo install -m 600 /dev/null ...` and `sudo install -m 600 -o root -g root /dev/null ...`). Retention reads "deletes the daily requests within 30 days" on one page and "expire there after about 30 days" on the other.
- **Change:** The install guide uses the analyst page's command verbatim (or links "Add the key" instead of repeating it). Both retention sentences use "within 30 days" and link the owner, `how-it-works/privacy-and-retention.md#at-anthropic`.
- **Why:** A careful reader comparing pages sees two answers to one question (A2).
- **Effort:** 10 minutes. **Kind:** words only.

#### 21. Fix the dry run's hidden prerequisite

- **Where:** `docs/install/advanced.md`, "See what setup would change".
- **Today:** "On the gateway: `tvgw setup --dry-run`". Before the first install, `tvgw` is not on the path; the install guide runs setup as `PYTHONPATH=src python3 -m tvgw setup` from `/opt/tvgw/src`.
- **Change:** add "Before the first install, run it from the checkout:" and a block `cd /opt/tvgw/src` / `PYTHONPATH=src python3 -m tvgw setup --dry-run`.
- **Why:** The dry run is what a cautious reader wants before the real thing, which is exactly when the command as written fails.
- **Effort:** 5 minutes. **Kind:** words only.

#### 22. Clean up the gateway status words

- **Where:** `docs/install/choosing-a-gateway.md`, "What the status words mean" and "Systems"; `docs/project/writing-docs.md` A14; `docs/diagrams/STYLE.md` line 124.
- **Today:** "Tested" means "installed the way the front page says"; the front page says "installed from source", which is how the reference gateway is installed. Debian 12 is "**Not yet tested**; checked automatically too", although `distro.yml` checks it, which is this page's own definition of Checked automatically. A14 and STYLE.md name the word "CI-tested", which no page uses.
- **Change:** "Tested: the project's hardware tests pass on a gateway installed fresh, the way the install guide says." Debian 12: "**Checked automatically**". In A14 and STYLE.md, replace "CI-tested" with "Checked automatically".
- **Why:** Status words are the project's promise; each should mean one thing everywhere. The conventions should name the word the pages use.
- **Effort:** 15 minutes. **Kind:** words only.

#### 23. Small consistency fixes

- `docs/tv/samsung-tizen.md`, "Before you connect the TV": put "Decline the TV's data agreements" second, as the LG page does, so every brand page has one order.
- `docs/use/maintenance.md`, "Remove tvgw": the table's first header cell is empty; write "What it touches". A screen reader announces the blank.
- `docs/use/maintenance.md`, "Upgrade tvgw": the link text "what is idempotent" is jargon and leaves the site for GitHub; write "[what an update restarts](../../../deploy/README.md#what-is-idempotent)".
- `docs/README.md` "Reference": the row label "The store" is an A14 term on a user page; write "The database".
- `mkdocs.yml` nav titles against H1s: "LG (webOS)" opens "LG TVs"; "What an LG CX does, measured" opens "What an LG CX does on the network, measured"; "How tvgw works" opens "How tvgw works, in pictures". Align the nav and landing labels with the H1s, so the browser tab, the sidebar and the page agree.
- **Effort:** 20 minutes together. **Kind:** words only (the nav labels are config text).

#### 24. Correct the engineering landing page's alt text for the first figure

- **Where:** `docs/how-it-works/README.md`, the `<picture>` of `fig-1-gateway`.
- **Today:** The alt text says "The LG TV's one cable runs to the Raspberry Pi... keeps a record of every connection in the store". The current drawing shows "Your smart TV", a generic small computer, phones and laptops, and the measured LG CX card. The README's alt text for the same image is correct.
- **Change:** Use the README's alt text, or one written for this page that describes the same drawing. Check the caption against the drawing too.
- **Why:** A screen-reader user hears a different picture from the one shown (WCAG 1.1.1), and the two alt texts of one image disagree.
- **Effort:** 10 minutes. **Kind:** words only.

### The ones that need code, ranked

#### 25. Setup does not find the package's installer, and `get.sh` depends on it (see F1)

- **Where:** `src/tvgw/setup.py`, `INSTALLERS` (line 37) and `find_installer()` (line 494); `packaging/get.sh.in` line 194 (`exec tvgw setup`).
- **Today:** The docs say it plainly ("Setup does not find the package's installer by itself yet"), but `get.sh` hands over to `tvgw setup` with no `--installer`.
- **Change:** Add `/usr/lib/tvgw/deploy/install.sh` to `INSTALLERS`, with a unit test; then delete the "does not yet find" sentences from the install guide and `advanced.md`.
- **Why:** Without it, the installer trial the front page waits for probably stops at setup's apply step even on a computer with the filter installed.
- **Effort:** 30 minutes. **Kind:** code.

#### 26. Plain words in setup's own questions

- **Where:** `src/tvgw/setup.py` prompts, shown in `docs/install/README.md` "What setup does" and `docs/tv/lg-webos.md` "Pair the TV".
- **Today:** `Name for the TV (DHCP and logs)`, `Interface toward the home router (WAN_IF)`, `Home router's address (WAN_GW)`, `Pair the TV's LAN API now?`. They pass the plain-words test only because they sit in a code block.
- **Change:** For example "Name for the TV, shown in the gateway's logs", "Connection to your home router", "Your router's address", "Pair with the TV now, so the gateway can read its settings?". Update the two pages' text blocks and the setup tests in the same change.
- **Why:** The reader meets these words at the moment of most doubt, typing answers into the gateway. The page then has to explain `WAN_IF` without naming it.
- **Effort:** 1 to 2 hours. **Kind:** code.

#### 27. The release notes template: send readers to the install guide while the installer is untested

- **Where:** `.github/release-notes.md.in`, "Install"; `tests/unit/test_release_notes.py`.
- **Today:** "Step by step: `[the front page](.../README.md)`." The front page does not show the installer.
- **Change:** Link "[the install guide](https://github.com/kywwilson11/tvgw/blob/v@VERSION@/docs/install/README.md)", and add one sentence while the trial is pending: "The installer has not yet been run on a real gateway; the install guide's steps are the way the project's own gateway runs." The 0.3.0 page itself is immutable for its files; whether its notes can still be edited is a GitHub question to check before trying.
- **Why:** It closes the loop from the release badge back to an honest page.
- **Effort:** 45 minutes. **Kind:** code (template and its test).

#### 28. Show the site's version (see S2)

- **Effort:** 1 to 2 hours. **Kind:** code (`docs/site/prebuild.py`, `pages.yml`, a test).

#### 29. Make the "generated" blocks generated

- **Where:** Every `<!-- generated:... -->` block: the support table on `README.md` and `docs/tv/README.md`, and the radios, can-check, privacy-settings, must-allow and generations blocks on the brand pages.
- **Today:** No script in the tree writes them (`git grep` finds the markers only in the pages and in `test_user_pages.py`, which exempts them from the plain-words rules as generated). The two support tables are hand copies of each other.
- **Change:** A `tools/` script that renders each block from `src/tvgw/profiles/*.toml`, and a gate test that fails when a page's block differs from the render, in the style of `docs/diagrams/build.py --inline`.
- **Why:** A2 treats a generated table as no repeat because the code is its owner. Today nothing holds the two support tables together, or a menu path to its profile record, and the plain-words test skips text that no machine wrote.
- **Effort:** 3 to 4 hours. **Kind:** code.

#### 30. A figure of where the cables go, including your own computer

- **Where:** `docs/install/README.md`, "Connect the TV".
- **Today:** The install guide has no figure. `fig-20` shows three hardware options; no figure shows the reader's own computer, which reaches the gateway over the home network to type commands.
- **Change:** One physical-arrangement figure (A9 allows it on user pages): router, the Pi on Wi-Fi, the TV on the Pi's cable, and your computer on the home network with a labelled wire "you type commands from here". Cables drawn as cables, unlabelled.
- **Why:** "The gateway", "your own computer" and "the router" are three boxes the reader must hold in mind through the whole guide.
- **Effort:** 2 to 3 hours. **Kind:** code (a new figure through `docs/diagrams/build.py`).

#### 31. Raise the contrast of the "let through" bars

- **Where:** `docs/diagrams/fig-21-tv-day.html` (on `docs/tv/lg-cx-measured.md`).
- **Today:** Measured on the PNGs: the grey "let through" bar fill is 1.29:1 against the dark background (outline 1.95:1), and 1.14:1 in light (outline 1.49:1). The legend swatch matches the fill. WCAG 1.4.11 asks 3:1 for a graphical object. The labels carry every number, so nothing is lost, but the Streaming and LG core bars almost vanish in dark mode.
- **Change:** A stronger grey outline token for the "let through" series in `diagram.css`, at 3:1 or more in both themes, then rebuild.
- **Effort:** 30 minutes. **Kind:** code (figure style and render).

#### 32. Replace the filter's first-run page with `tvgw adguard install`, after a fresh-card run

- **Where:** `docs/install/README.md`, "Install what tvgw needs".
- **Today:** The hardest part of the guide: an ssh tunnel in a second terminal, a browser wizard, and three answers about interfaces and ports. v0.3.0 already has `sudo tvgw adguard install`, which installs AdGuard Home's pinned release, checks its hash and answers the wizard itself on loopback (troubleshooting has its messages; `how-it-works/adguard.md` explains it).
- **Change:** Once the command has run on a fresh card, reorder the guide: packages, clone, `sudo PYTHONPATH=src python3 -m tvgw adguard install`, then setup. The tunnel and wizard leave the main path.
- **Why:** It removes the step a typical user cannot do, and the open wizard on the home network.
- **Effort:** 2 hours of writing plus one fresh-card run. **Kind:** a procedure change, not only words; do it with the installer trial.

#### 33. Measure the install, then say how long it takes and when it was last run

- **Where:** `docs/install/README.md`, lead; A3 asks for the duration "once that is measured".
- **Change:** Time the non-engineer trial. Then add "It takes about N minutes" to the lead, and a line such as "These steps were last run end to end on <date>." (Tailscale's quickstart shows "Last validated" at the top.)
- **Effort:** a stopwatch during the trial, then 5 minutes. **Kind:** words, after a measurement.

## 4. Cross-page inconsistencies

| What | One place | The other place |
|---|---|---|
| Whether the one-line installer exists | `README.md` "Get started": "is being built. This page will show it once..." | The v0.3.0 release page: "On the computer that will be the gateway: `curl ... | sudo sh`" and "Step by step: the front page". The front page's release badge links there. |
| Intel and AMD packages | `docs/install/advanced.md`: "for ARM computers so far, and from the next release on for Intel and AMD"; `choosing-a-gateway.md` mini PC row: "ARM computers only" | v0.3.0 carries `tvgw_0.3.0-1_amd64.deb`; `CHANGELOG.md` 0.3.0 Highlights |
| Debian 13's status | `README.md` gateway table: "**Not yet tested** on hardware" | `choosing-a-gateway.md`: Debian 13 with a desktop is "**Checked automatically**" |
| Ubuntu | `README.md`: not mentioned | `choosing-a-gateway.md`: Ubuntu 24.04 or 26.04 Desktop "Checked automatically", Ubuntu Server "Not supported"; the release page: "installs on ... Ubuntu 24.04 or 26.04", no Desktop qualifier |
| Debian 12's status | `choosing-a-gateway.md`: "Not yet tested; checked automatically too" | The same page's definition of Checked automatically, which `distro.yml` meets for Debian 12 |
| The status word for automatic checks | `choosing-a-gateway.md`: "Checked automatically" | `writing-docs.md` A14 and `diagrams/STYLE.md`: "CI-tested" |
| Which containers the release installs in | `CHANGELOG.md` 0.3.0 Status, and so the immutable release page: "installs each package in clean Debian 12 and 13 and Ubuntu 24.04 and 26.04 containers" | `.github/workflows/release.yml` install-check jobs: `debian:13` and `ubuntu:24.04` only; `docs/project/packaging.md` line 251 agrees with the workflow. Debian 12 and 26.04 are in `distro.yml`, which installs the Depends and runs the unit suite, not the package. |
| The order of the Wi-Fi steps | `docs/install/README.md` "Connect the TV": "turn Wi-Fi off and make it forget" | `docs/tv/lg-webos.md` radios: forget first, "the list is hidden while the switch is off"; `docs/tv/README.md` "Other TVs": delete, then switch off |
| What the 3,983 lookups were | `docs/what-it-stops.md`: "advertising, tracking and screen-recognition services" | `README.md` and `docs/tv/lg-cx-measured.md`: "advertising, tracking and fingerprinting" (the four categories are LG ads, LG telemetry, LG fingerprint, third-party ads) |
| Order of "Before you connect the TV" | `docs/tv/lg-webos.md`: radios, agreements, privacy settings | `docs/tv/samsung-tizen.md`: radios, privacy settings, agreements; Roku and Vizio: radios, privacy settings |
| The command that creates the analyst's key file | `docs/install/README.md`: `sudo install -m 600 /dev/null /etc/tvgw/claude.key` | `docs/use/analyst.md`: `sudo install -m 600 -o root -g root /dev/null /etc/tvgw/claude.key` |
| How long Anthropic keeps requests | `docs/use/analyst.md`: "deletes the daily requests within 30 days" | `docs/use/privacy.md`: "expire there after about 30 days" |
| The alt text of `fig-1-gateway` | `README.md`: describes the current drawing | `docs/how-it-works/README.md`: describes an older drawing (the LG TV, the Raspberry Pi, "the store") |
| The reading order | `choosing-a-gateway.md` ends "Next: install tvgw"; `install/README.md` ends "Next: read your daily brief" | The site's footer: Install tvgw → Choose a gateway computer → Other ways to install → Read your daily brief; the home page's footer "Next" is "All the pages" |
| Nav titles and page titles | `mkdocs.yml` and `docs/README.md`: "LG (webOS)", "Samsung (Tizen)", "What an LG CX does, measured", "How tvgw works" | H1s: "LG TVs", "Samsung TVs", "What an LG CX does on the network, measured", "How tvgw works, in pictures" |
| "What you need" | `README.md`: a computer and a cable | `install/README.md`: Pi, power supply, card, your own computer, the TV in cable reach; `choosing-a-gateway.md`: 64-bit, 32 GB, 2 GB of memory. None says the TV needs a network port. |
| "Generated" tables | `README.md` and `docs/tv/README.md` support tables, marked `generated:support-table` | No generator exists; the two are hand copies |

## 5. What must not change

- **The front page's first screen.** The bold one-sentence lede, the "Status:" line that names exactly one TV and one computer, `fig-1` with its measured card, and its one-line caption. It answers "what is this" in five seconds and "how sure are they" in ten.
- **"It stops / It cannot stop / It costs".** Three bullets, the cost included (casting and phone remotes). Few projects say what their product costs the user.
- **The honesty of the support tables.** One "Tested", everything else "Not yet tested", and a column for what you still check yourself. The "Nothing yet" sections on the Samsung, Roku and Vizio pages ("Nothing has been measured on a Samsung yet, so this is what to expect rather than what was seen") are the project's best trust signal.
- **The limits table on "What it stops, and what it cannot"**, with a source for every row.
- **The escape hatch.** "Move the TV's cable from the gateway to your router", on the install guide, troubleshooting and at the end of every doctor run. It turns a stuck reader into a reader with a working TV.
- **`tvgw status` and `sudo tvgw doctor` as the start of everything.** Three lines for "is it working", one command for "fix it".
- **The install guide's mechanics:** per-system terminal instructions, "Answer `yes` to the first-time question", setup's questions with their defaults shown, the two `Result:` lines, and the "If setup stops" table of message, meaning and fix.
- **The daily check in three steps**, the seven-line plain brief, and each red line's "What it means / What to do".
- **The brand pages' shared structure** and their dated menu paths ("read on 2026-11-03").
- **The household notice** on the privacy page, and the list of what `tvgw forget` cannot reach.
- **The blocking page's safety:** names never to block come first, and `tvgw allow` shows its success output and its undo.
- **The site's restraint:** no Google Fonts, no analytics, copy buttons on every block, footer previous and next, search, figures in both themes, and the publish gate that never shows a command the latest release lacks.
- **The voice:** no "we", no marketing words, no exclamation marks, short sentences. Readers notice the absence of hype.

## 6. Site-level proposals, with feasibility

Constraints from `docs/site/README.md` and `mkdocs.yml`: only keys that both Zensical 0.0.74 and Material 9.8.0 read; no plugins beyond search, no hooks, no overrides directory, no custom CSS or JavaScript; `test_site_prebuild.py` pins the seven tab names and their order, requires every landing-page link and every user page in the nav, and pins `content.code.copy`, `font: false`, `plugins: [search]` and `use_directory_urls: false`. The `pages.yml` gate publishes `main` only while every command a user page names exists in the latest release.

| Proposal | Recommendation | Feasibility |
|---|---|---|
| **S1. Nav: the home page's "Next" leads to "What it stops"** | Order the "Start here" tab as What tvgw is, What it stops, All the pages. The footer then reads home → what it stops → all the pages → install. | Feasible now: one swap in `mkdocs.yml`. The tests pin tab names, not the order within a tab. `docs/README.md` lists neither index nor map, so it needs no change. 10 minutes. |
| **S2. Version line** | The prebuild replaces the dropped badge row of `index.md` with one plain line: "These pages describe tvgw <version>, released <date>." linked to that release, and adds the same line under the install guide's H1 on the site only. | Feasible: `pages.yml` already resolves the latest release for the gate; pass it to `prebuild.py --release`. Standard library only, tested in `test_site_prebuild.py`. A header badge would need a theme override, which the policy forbids. Material's `extra.version` needs mike, also out. A7 allows the front page to link the latest release. 1 to 2 hours. |
| **S3. Search** | Keep it. Consider leaving the records and research out of the index: `search.json` is 2.3 MB, mostly records, and a reader's "install" search lands in research. | Material reads a page's `search: exclude: true` front matter; the prebuild could add it to the copies of `docs/research/`, `design-decisions.md` and `incidents.md` only, so GitHub never shows it. Zensical's support is unverified: the strict build on a pull request answers it. 1 hour. |
| **S4. A printable install checklist** | No separate page: it would restate the bring-up steps that `docs/install/README.md` owns (A2). Item 14's one-sentence map plus the browser's print (the theme hides the nav when printing) is the checklist. If checkboxes are wanted, a `- [ ]` list of the five parts linking each section. | Checkboxes on the site need `pymdownx.tasklist`, which ships with pymdownx (already installed); Zensical support unverified. GitHub renders `- [ ]` natively. 30 minutes. |
| **S5. "Copy all commands"** | Not recommended. | Needs custom JavaScript, which the policy forbids, and it would paste placeholders and on-your-computer commands together. Instead, item 14 and Q3 make each block safe to paste whole. |
| **S6. Glossary popovers** | Not recommended. | Possible with the `abbr` extension and `pymdownx.snippets` `auto_append` from a file outside `docs/`, so GitHub never sees it. But the tooltips are hover-only (no touch, weak keyboard and screen-reader support), and the glossary is written for engineers (`biz_code`, `watermark`, `judge v2`). Better: one plain "words you meet" section on the install guide (gateway, filter, lookup, brief, red line, profile, pairing, terminal, sudo). Words only, 30 minutes. |
| **S7. The edit pencil** | Drop `content.action.edit`. | One line in `mkdocs.yml`. The pencil leads to a 404 on the home page and on "All the pages" (a documented gotcha), and a typical reader never edits. 5 minutes. |
| **S8. The repository widget's request to api.github.com** | Consider dropping `repo_url`, keeping the GitHub link in `extra.social`. | One line. It removes the one third-party request every page view makes, which matters on a privacy project's site and is already written down as a gotcha. It also removes the edit pencil (S7) and the star count. 10 minutes. |
| **S9. A light and dark toggle** | Leave it off. | Documented: it needs `prebuild.py --picture-toggle`, untested on a published page. |
| **S10. An announcement banner for 0.3.0** | Not feasible under the policy. | Needs an overrides directory. S2 does the useful part. |

## 7. The exemplar comparison

| | First screen | How it shows "it worked" | How it handles "something went wrong" | Borrow for tvgw |
|---|---|---|---|---|
| **Tailscale quickstart** (`tailscale.com/kb/1017/install`, read 2026-11-04) | Title, "Last validated" date, one sentence of purpose, then step 1 | The device appears in the browser window, then in the admin console | A "Troubleshooting and support" list of links at the end; no inline fallbacks | The "last validated" date, once the trial runs (item 33). tvgw already does better on "it worked" (the `Result:` lines). |
| **Pi-hole** (prerequisites and "One-Step Automated Install", read 2026-11-04) | Hardware minimums, supported systems as a list, ports, firewalls | Not on the install page; a separate post-install page | Info boxes on untested systems and port conflicts | When the installer reaches the front page: Pi-hole shows `curl | bash` with a note that piping is controversial and two alternatives (clone and run; download, read, run). tvgw has the "read it first" block in `packaging.md`; put it beside the command. |
| **Home Assistant** (getting started and the Raspberry Pi install, read 2026-11-04) | Welcome, a nine-part path, "You do not need to write code", "most people about an afternoon" | "Within a few minutes ... you will be able to reach" a named address, and a closing "Congratulations" | Timed fallbacks: no answer after 5 minutes, reflash; name not found, try the address | A time estimate once measured (item 33); explicit "if not, then" at the ssh step (Q3); a hardware list with the hidden prerequisite named (Q7, the TV's port). |

What tvgw already does better than all three: it says what the product cannot do, on the front page, with sources; its "it worked" is a line the tool prints, not a screenshot; and its fallback for every failure is physical and two minutes long (move the cable).

## 8. Accessibility

| Check | Result |
|---|---|
| Heading order | Pass on every page fetched: one H1, no skipped level (checked on the built HTML of 17 pages). |
| Alt text | Pass on every user-page figure: each is a full description in sentences, as A9 asks. One mismatch on an engineering page: `how-it-works/README.md` describes an older `fig-1` (item 24). |
| Figure contrast in dark mode | Text in every figure looked at (`fig-1`, `fig-19`, `fig-20`, `fig-21`) reads well in both themes. `fig-21`'s grey "let through" bars and legend swatch are below 3:1 in both themes (item 31); the labels carry the numbers, so no information is lost. |
| A figure and its page in different themes | Documented gotcha: the theme keeps the scheme of the first visit, the figures follow the system. Nothing to do until the toggle is tested. |
| Link text out of context | Mostly descriptive. Generic ones: "the measurements" (twice), "the settings" (five times, to different anchors), "the TV" (troubleshooting, to `#the-tv`), "what is idempotent" (item 23). "LG TVs" leads to three different sections from three places. |
| Table headers | Every table has a header row. One empty header cell, on the "Remove tvgw" table (item 23). |
| Placeholders in copied commands | `<username>`, `<address>` and the like copy literally and fail as shell syntax (Q3). |
| Hover-only help | Avoid it (S6). |

## 9. The page walk, page by page

| Page | The reader's question on arrival | First screen answers it? | Where the reader stumbles | Keep |
|---|---|---|---|---|
| Home (`README.md`) | What is this, and is it for me? | Yes: lede, status, figure | The installer sentence (Q1); "what you need" (Q7); no trust paragraph (11); gateway table (12); on the site, no version and no release link (S2); footer "Next" goes to all the pages (S1) | Lede, status line, fig-1, stops/cannot/costs |
| What it stops | Honestly, what am I protected from? | Yes: lead, fig-19, the assumption | Status phrases unexplained (Q10); "a 2027 study" (Q8); "screen-recognition" for the 3,983 (17); the Source column leads into research pages, which is right but heavy | The limits table with sources; "Check your TV" |
| Install tvgw | Can I do this, and what do I need? | Partly: what you need, yes; how long, no (not measured, item 33) | Installer sentence (Q1); Wi-Fi order (Q2); ssh (Q3); "it worked" (Q4); package section mid-path (13); `sudo` and the editor (15); the filter's wizard and tunnel are the hardest step (32); setup's prompts say `WAN_IF` (26) | Terminal per system; `Result:` lines; "If setup stops"; the cable escape |
| Choose a gateway computer | Will my computer work? | Yes: needs list, status words | Mini PC row stale (Q5); Debian 12 and "Tested" (22); "NetworkManager" six times in the Systems table (an A14 term; tables are exempt from the test, not from the reader); the nav puts this page after the install guide while its own "Next" says install | Status words table; fig-20; "Other programs on the same computer" |
| Read your daily brief | What do I do every day? | Yes: three steps and the sample | How to get onto the gateway (Q6); sample looks measured (17); the red lines section is long but anchored and well shaped | The Action-line habit; each red line's meaning and fix |
| Which TVs work, and LG | Does my TV work, and what do I switch off? | Yes: support words and the table | "What tvgw can check" sits between "Turn the radios off" and "Before you connect", which refers back "as above" (move it after "Pair the TV"); the pairing prompt says "LAN API" (26); report form needs GitHub (19) | Dated menu paths; "What you may notice"; "Nothing yet" |
| Fix a problem | My TV has no internet: what now? | Yes: doctor first, the cable fix right below | No healthy-doctor sample, no edge before the engineer tables (16); the symptom table is alphabetical, so "The TV says it has no internet" comes last (A10 allows a run order; or add the two most common symptoms as a sentence above the table); two fixes link GitHub READMEs | Doctor first; the cable |
| Block or unblock something | An app broke, or I want X gone | Yes, after the safety list | No success output for `tvgw block` (A6), although `src/tvgw/localrules.py` prints one: `tvgw block: <name> is blocked for the TV (in /etc/tvgw/local.rules); AdGuard Home re-applied` and the undo line; "Change the profile itself" is engineer work between two user tasks | Never-block list; allow's success and undo; the 60-second wait |
| Keep it running | How do I update, back up, remove? | Yes: Upgrade tvgw | Link text "what is idempotent" (23); empty table header (23) | "Update when nobody is watching"; purge keeps the record, and says why |
| Your household's privacy | What does it keep about us? | Yes: the retention table | Nothing serious | The household notice; what forget cannot reach |
| Turn on the analyst | What is it, what does it send, what does it cost? | Yes | Where the key comes from (Q9); the key command differs from the install guide's (20) | The dry run that shows what would be sent; dated prices |
| All the pages (`docs/README.md`) | Where is the page for X? | Mostly | The site and GitHub sentence (18); "The store" (23) | The "Read it to" tables; reading paths |
| How tvgw works (engineering) | How does it fit together? | Yes, for an engineer | fig-1's alt and caption describe an older drawing (24) | Dense but exact |

The site's own affordances, as the reader meets them: seven tabs across the top on a wide screen and a drawer on a phone; sidebar sections; a back-to-top button; previous and next at the foot of every page; search with suggestions; a copy button on every command block (added by the theme's script); figures that follow the system's light or dark setting. Links that leave for GitHub from user pages: CONTRIBUTING, LICENSE and SECURITY from the home page (at the built commit), and five engineering READMEs from advanced, maintenance and troubleshooting; each is a reasonable exit, and none is in a step the reader must follow.

## 10. Found along the way (not documentation)

**F1. `get.sh` hands over to a setup that probably cannot find the package's installer.** `packaging/get.sh.in` ends with `exec tvgw setup`. In a package install, tvgw runs from `/opt/tvgw-venv` (`deploy/install.sh` line 35), so `find_installer()` in `src/tvgw/setup.py` looks for `deploy/install.sh` two levels above the module, inside the venv's `lib/`, then at `INSTALLERS = ("/opt/tvgw/src/deploy/install.sh",)`, and never at `/usr/lib/tvgw/deploy/install.sh`, where the package puts it (`packaging/nfpm.yaml`). On a first install setup asks to run the installer, calls `_installer()` before writing anything, and stops with `install.sh not found: give its path with --installer`. The docs already say "Setup does not find the package's installer by itself yet", so this is known as a fact; what may not be known is that the installer's own hand-over depends on it. This is read from the code, not run: confirm it on the trial, and fix it before (item 25). Until then the engineer's path is `TVGW_NO_SETUP=1`, then `sudo tvgw setup --installer /usr/lib/tvgw/deploy/install.sh`.

**F2. The 0.3.0 release page over-states the container installs** (section 4). The release page is immutable and the changelog is a record, so the correction belongs in the next version's Status paragraph.
