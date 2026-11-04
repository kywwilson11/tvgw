# Security policy

tvgw sits between a smart TV and a home network, runs as root on the gateway and changes its own firewall and resolver, so a flaw in it can expose the home rather than protect it. This page says what to report privately, how to report it, what happens next and what is out of scope. It is for anyone who finds a weakness in the code, the deploy files, the workflows or the repository.

## What to report

Report privately anything that does one of these:

- lets the TV reach the home LAN, or the gateway's other services (anything on the gateway but DHCP, DNS, nginx's ports 80 and 443 and ping on the gateway's address);
- gets the TV around the DNS filter or the firewall: a resolver, port, protocol or address family the rules miss, or a way to make the URL filter or the TLS passthrough forward what it should refuse;
- blocks something on the profile's must-allow list, or otherwise breaks the TV's clock, firmware updates or store, in a way the brief does not show;
- puts a site identifier or a secret in the repository: a real MAC address, a home-LAN address, a host name, an API key, a pairing key, or any line copied from a real gateway that was not scrubbed;
- weakens the autonomy so that it could apply an unsafe block, or lift one: a way past the code's gates or the second model, text from the TV's traffic that steers the analyst, or a canary or judge that passes what it should refuse;
- lets a pull request, a fork, a dependency or a workflow change run code on the gateway ([the supply chain](docs/project/supply-chain.md)).

What the gateway is meant to stop, and how, is in [what it stops, and what it cannot](README.md#what-it-stops-and-what-it-cannot) and [the trust boundaries](docs/how-it-works/architecture.md#trust-boundaries).

## How to report

Use GitHub's private vulnerability reporting: on the repository, open the Security tab and choose "Report a vulnerability". Only the owner sees the report.

If that button is not there, private reporting is not enabled yet. The owner enables it under Settings > Security > Private vulnerability reporting. Until then, open an ordinary issue whose title and body say only `security`, with no details, and the owner opens a private channel with you.

Include what you can: the commit or version (`tvgw --version`), the part affected, the steps or the rule text that shows the problem, and what you expected. Remove MAC addresses, home-LAN addresses and host names from any output you paste.

## What to expect

- The owner acknowledges the report and says whether it is in scope.
- A fix lands on `main` with a test that fails without it and a [design decision](docs/design-decisions.md) when the fix changes what the gateway does.
- The changelog records the fix once it is on `main`.

tvgw is maintained by one person, so there is no fixed response time.

## Out of scope

- The TV's own firmware, its radios and its apps. tvgw neither roots nor changes the TV ([design decision 4](docs/design-decisions.md#4-no-rooting-of-the-tv)); a flaw in webOS goes to LG.
- Traffic the owner chooses to allow: the must-allow hosts, the expected categories, and anything the owner unblocks.
- What tvgw states it does not do: it does not decrypt TLS, hide the home's public address, or remove ads stitched into a video stream ([what it cannot stop](docs/what-it-stops.md#what-it-cannot-stop)).
- Flaws in AdGuard Home, nginx, dnsmasq, the kernel or the gateway's other services, which go to their own projects. How tvgw configures or confines them is in scope.
