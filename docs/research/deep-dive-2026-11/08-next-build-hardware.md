# The next build: reference hardware and the appliance image

*Deep dive 08, written 2026-11-01. Research only: nothing here is implemented, and no host was touched. It reads with [state-of-the-art-2026-10.md](../state-of-the-art-2026-10.md) (called "the October pass" below, mainly its §7 Hardware and §9 Installer UX), [architecture.md](../../how-it-works/architecture.md) and [design-decisions.md](../../design-decisions.md). Packaging (nfpm .deb, templated interfaces), `tvgw setup`, the network-namespace CI gateway, supply-chain pinning, capture v2 and the hardened extractor are in flight on other branches and are treated as given. Off-box backups are tabled and not discussed.*

**Method.** Primary sources first: Raspberry Pi's documentation sources (the `raspberrypi/documentation` repository), datasheets (CM5, HAT+ specification, Raspberry Pi SSD brief), the `rpi-eeprom` 2712 release notes, the Raspberry Pi kernel tree (`rpi-6.18.y`: overlay README, `bcm2712_defconfig`, the watchdog driver and core), the `raspberrypi/linux` and `raspberrypi/firmware` issue trackers, the `rpi-image-gen`, `rpi-imager` and `rpi-preseed` repositories, the Raspberry Pi and Debian trixie apt indexes (read 2026-11-01), vendor product pages and maintainers' docs for Pi-hole, OpenWrt and Home Assistant OS. **(unverified)** means only a secondary source, or none, supports the claim. **(observed)** marks facts about the running gateway that come from the owner's audit notes of 2026-10-31 and 2026-11-01, not from this pass. Site identifiers are left out on purpose: no MACs, private addresses, host names or drive serials.

---

## Bottom line

Do not buy a 2.5 GbE or PoE anything: the CX's own Ethernet port is very likely 100 Mb/s (test T1), the TV averages under 10 Mb/s, and the Pi already has two interfaces (Ethernet for the TV, Wi-Fi up). The next build is worth doing for three reasons only: a boot disk that is not an SD card, a wired uplink if a cable or a mesh node's Ethernet port can reach the Pi, and an image that rebuilds the gateway in minutes instead of an evening. The settled bill of materials for the owner keeps the Pi 5 8 GB, the Active Cooler and the HiFiBerry DAC+ HD, adds a **USB 3 NVMe enclosure** with a known-good SSD and a **USB 3 RTL8153 gigabit adapter** for the uplink, moves the failing USB disk into a **self-powered** enclosure, and runs the Pi at **stock clocks**. That respects the owner's 2026-10-28 "no HAT" decision. If the owner lifts that veto, the official M.2 HAT+ (a *stackable* HAT+ by specification) sits over the Active Cooler and under the DAC with no GPIO or EEPROM conflict, and is the better NVMe path. For a reference appliance that other people can copy, the board is a **CM5 on a carrier whose second port hangs off USB, not PCIe** (so the one PCIe lane stays free for NVMe), for example Waveshare's CM5-DUAL-ETH-BASE. The October pass's pick, the CM5-DUAL-ETH-MINI, spends its PCIe lane on an RTL8111H and has no M.2 slot. The image pipeline is settled too: **rpi-image-gen v2.9.0** (2026-10-23) on GitHub's `ubuntu-24.04-arm` runners (rpi-image-gen's own CI does exactly that), a non-A/B ext4 image first, **rpi-preseed** (Raspberry Pi's cloud-init-free first-boot tool, 0.2.1 in the Pi archive since 2026-10-29) for the OS account, SSH and Wi-Fi, a tvgw-owned `tvgw-firstboot.service` that runs `tvgw setup --non-interactive` from `/boot/firmware/tvgw-answers.toml`, and a Raspberry Pi Imager repository JSON with `"init_format": "rpi-preseed"`. One finding matters before any purchase. Kernel 6.18, which the gateway runs, turned Energy-Efficient Ethernet on by default on the Pi 5's RP1 MAC, and that has an open link-flapping issue. Every flap re-runs `tvgw-apply` through the NetworkManager dispatcher. Test T2 says in one command whether the TV port is affected.

---

## 1. Findings

### F1. "Two-port" is the wrong goal; the TV's port is 100 Mb/s and the Pi already has two

- **The CX's Ethernet port is Fast Ethernet.** Several owners report that the 2020 CX and other LG OLEDs have a 10/100 port, and that a USB adapter on the TV's USB 2.0 port gets about 300 Mb/s ([io-tech CX owner](https://bbs.io-tech.fi/threads/oled-tv.1254/post-8999787), [Serviio forum on the LG OLED "100Mb NIC bottleneck"](https://forum.serviio.org/viewtopic.php?p=128533), [Best Buy answer for the C3](https://www.bestbuy.com/site/questions/lg-65-class-c3-series-oled-evo-4k-uhd-smart-webos-tv-2023/6535929/question/b5321f4e-1f50-3cfa-a9fc-94302c0fadbc)). I found no LG spec sheet that says so: **(unverified)** until T1 runs.
- **The load is small.** 60 to 70 GB a day (design decision 1) is about 6 Mb/s averaged over 24 hours, and a 4K stream peaks at a few tens of Mb/s. A 100 Mb/s TV link and a gigabit uplink are both far more than enough. 2.5 GbE on either side buys nothing.
- **The Pi already has two interfaces.** `eth0` serves the TV and `wlan0` is the uplink (`WAN_IF=wlan0` in `deploy/tvgw.conf.example`). A second NIC helps only if a cable to the router, or to a mesh satellite's Ethernet port near the TV, can be run. The October pass called that "the biggest reliability gain"; I agree, and the hardware question reduces to "which second port, if there is a wire".

**Test T1 (read-only, on the gateway):** `ethtool eth0 | grep -E 'Speed|Duplex|Auto-negotiation'` and `cat /sys/class/net/eth0/speed`. Expect `100Mb/s` and `Full`. If the link is ever `10Mb/s Half`, the RP1 MAC drops received frames in that mode. That is a hardware bug Raspberry Pi closed as "not planned" on 2026-06-09, and the only cure is a 100 Mb/s-capable switch between the Pi and the device ([raspberrypi/linux#7115](https://github.com/raspberrypi/linux/issues/7115)).

### F2. The onboard port on kernel 6.18: EEE is on by default and flaps with some partners

- **What changed.** `rpi-6.18.y` enabled Energy-Efficient Ethernet by default on the RP1 GEM (PR #7270). Since then, Pi 5 users report the link going down and up every few seconds, or 5 to 20% ICMP loss without flapping, against Fritz!Box, TP-Link, Netgear and UniFi partners. 6.12.75 does not reproduce it. The issue is open with no root cause or fix, and the workaround is `dtparam=eee=off` in `config.txt` or EEE off on the partner ([raspberrypi/linux#7511](https://github.com/raspberrypi/linux/issues/7511), opened 2026-07-21, reports from 6.18.33 to 6.18.39).
- **The parameter exists.** The 6.18 overlay README documents `eee  Enable Energy Efficient Ethernet support for compatible devices (default "on"). Pi3B+, Pi4, CM4, Pi5 and CM5` ([overlays README, rpi-6.18.y](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm/boot/dts/overlays/README)).
- **Why tvgw cares more than most.** The NetworkManager dispatcher re-runs `tvgw-apply` whenever `eth0` comes up ([architecture.md, the control plane](../../how-it-works/architecture.md#the-control-plane)). The 2026-10-30 incident showed that a routing change during an apply destroys the TV's conntrack entries with data in flight (observed). A flapping TV port would cause a stream of applies, `counters.before-apply` resets and broken flows, all of which look like TV behaviour in the brief.
- **Whether it bites here is unknown.** EEE exists for 100BASE-TX too, but whether the CX's PHY advertises it is **(unverified)**. The gateway runs 6.18.50 (observed), later than any version in the issue, and the issue has no fix linked, so 6.18.50 should still be treated as affected.

**Test T2 (read-only):** `ethtool --show-eee eth0` (does the link partner advertise EEE, and is it active?), then `journalctl -k --since -14d | grep -cE 'eth0: Link is (Down|Up)'` and `journalctl --since -14d | grep -c 'tvgw-apply'`. Read the result this way:

- Link-down counts that line up with TV power-offs are normal.
- Bursts of link-downs while the TV was `Active` in `tvcheck-history.log` mean flapping.
- If T2 shows flapping, the fix is `dtparam=eee=off` and a reboot (owner decision; it costs the TV a minute of darkness, fail closed). The hardware suite should then assert `ethtool --show-eee eth0` reports EEE disabled.

### F3. The second port: USB RTL8153 on a Pi 5; on a CM5 carrier, a USB-attached second port

- **Drivers are all in the Pi kernel.** `bcm2712_defconfig` on `rpi-6.18.y` builds `CONFIG_USB_RTL8152=m` (RTL8152/8153/8156), `CONFIG_USB_NET_AX88179_178A=m`, `CONFIG_USB_NET_CDC_NCM=m`, `CONFIG_R8169=m` (PCIe RTL8111/8125), `CONFIG_IGB=m` and `CONFIG_IGC=m` (Intel i210/i225/i226) ([bcm2712_defconfig](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm64/configs/bcm2712_defconfig)). No out-of-tree driver is needed for any of them.
- **The ASIX AX88179A is the riskier choice in 2026.** OpenWrt's 6.12 build lacks the AX88179A's USB ID `0b95:1790`, so the adapter binds to the wrong driver at half duplex ([openwrt#23085](https://github.com/openwrt/openwrt/issues/23085)). On Raspberry Pi OS, predictable naming broke for ASIX adapters on 6.6.20 and the interface was unregistered 26 seconds after it came up ([bookworm-feedback#239](https://github.com/raspberrypi/bookworm-feedback/issues/239)). Some AX88179 units bind to `cdc_ncm` instead of `ax88179_178a` ([Gentoo forum](https://forums.gentoo.org/viewtopic-t-1175217.html)).
- **The RTL8153 has the larger installed base, and its known failures are of the "device locks up" kind.** A January 2026 linux-usb thread shows RTL8153 Tx timeouts on 6.18.6 behind a USB-C hub. Greg Kroah-Hartman read it as a device or firmware hang the kernel cannot fix ([linux-usb, 2026-01-27](https://ratatoskr.run/linux-usb/2026/01/8892827/t)). Disabling USB autosuspend is the standard first fix for link loss ([Arch forum](https://bbs.archlinux.org/viewtopic.php?id=280781), [LibreELEC](https://forum.libreelec.tv/thread/28119-usb3-to-gigabit-ethernet-adapter-on-rpi4-5-troubles/?postID=188299)). For a gateway that fails closed, a lock-up means a dark TV, not a leak.
- **Pi 5 USB ports are independent.** RP1 has two xHCI controllers, each with one USB 3 and one USB 2 port and its own 5 Gb/s ([Raspberry Pi I/O controllers](https://www.raspberrypi.com/documentation/computers/io-controllers.html), [CNX on the RP1 datasheet](https://www.cnx-software.com/2023/10/07/raspberry-pi-rp1-datasheet-block-diagram/)). So a USB NVMe enclosure on one blue port and the NIC on the other do not share a controller.
- **On a Pi 5, PCIe NICs compete with NVMe for the one lane.** The FFC connector is a single PCIe 2.0 ×1 lane; Gen 3 "isn't certified" and "might be unstable" ([Raspberry Pi PCIe docs](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#pcie-gen-3-0)). NIC plus NVMe needs a switch. Booting NVMe behind a switch was fixed in the 2024-10-21 bootloader ([raspberrypi/firmware#1833](https://github.com/raspberrypi/firmware/issues/1833)), but users still reported failures with some stacks in 2025.
- **CM5 carriers differ in exactly this way, and it matters for the October pick.**
  - Waveshare **CM5-DUAL-ETH-MINI**: the second port is an RTL8111H "PCIe extended network port" and the board has **no M.2 slot**. Storage is the CM5's eMMC, or microSD for CM5 Lite ([Waveshare](https://www.waveshare.com/cm5-dual-eth-mini.htm)). The October pass listed it as "eMMC, metal case, two NICs" and did not note that NVMe is impossible on it.
  - Waveshare **CM5-DUAL-ETH-BASE**: one GbE port from the CM5 PHY, one 2.5 GbE port through a "USB to 2500M Ethernet chip", plus an M.2 M-key slot (PCIe Gen 2/3 ×1, 2230 to 2280), a 40-pin header, an RTC battery header, a 4-pin PWM fan header and a 7-36 V DC input. A metal-case kit is sold as CM5-DUAL-ETH-BOX-A, at $54.99 to $69.99 ([Waveshare](https://www.waveshare.com/cm5-dual-eth-base.htm)). The USB chip is probably an RTL8156B **(unverified)**; the r8152 driver covers it.
  - Geekworm **X1501**: 1 GbE plus 2.5 GbE and two M.2 2280 slots at PCIe 2.0, a CR1220 socket, USB-C 5.1 V 5 A only, $59. It needs a PCIe switch for that many devices (the chip is not named), so the switch caveat above applies ([Geekworm](https://geekworm.com/products/x1501)).

**Test T3 (on the bench, not the gateway):** plug the adapter in and run `lsusb -t` (it must show `Driver=r8152` at 5000M), then `ethtool -i <if>`. Run `iperf3 -t 3600` through it with `cat /sys/bus/usb/devices/*/power/control` showing `on` for the adapter. Pass: no `NETDEV WATCHDOG` or `Link is Down` lines in `journalctl -k` for that hour.

### F4. HAT coexistence: what the HAT+ spec allows with the DAC+ HD, and what the owner declined

- **What the DAC+ HD occupies.** Its overlay drives the I2S clock-consumer interface (GPIO 18 to 21), I2C1 on GPIO 2 and 3 with a PCM1792A at `0x4c` and a clock PLL at `0x62`, and `reset-gpio = <&gpio 16 GPIO_ACTIVE_LOW>` ([hifiberry-dacplushd overlay, rpi-6.18.y](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm/boot/dts/overlays/hifiberry-dacplushd-overlay.dts)). It has a HAT ID EEPROM ("HAT compliant, EEPROM for automatic configuration") and draws under 1 W from the Pi's 5 V ([HiFiBerry datasheet](https://www.hifiberry.com/docs/data-sheets/datasheet-dac-hd/)). Any second board that touches GPIO 16, 18 to 21 or those I2C addresses conflicts.
- **The HAT+ specification defines classes by EEPROM address.** Addresses take the form `101_00XY`. `00` is Standard (this includes every legacy HAT, so the DAC+ HD). `01` is Stackable: "Any HAT+ that only uses the ID_* pins and does not electrically connect to GPIOs 2-27". `10` and `11` are Power HAT+s. "You can connect one HAT+ from each class to a host Raspberry Pi at a time", and boards without an EEPROM, "including the Raspberry Pi PoE and Raspberry Pi PoE+ HATs, do not follow the HAT+ standard" ([HAT+ specification, build 2024-12-05](https://datasheets.raspberrypi.com/hat/hat-plus-specification.pdf)). A forum answer says the official M.2 HAT+ is Stackable at `0x51` ([Raspberry Pi forum](https://forums.raspberrypi.com/viewtopic.php?t=372508)) **(unverified against the board itself; T4 checks it)**. On that reading, the DAC+ HD and an M.2 HAT+ coexist by specification.
- **Mechanics.** The standard M.2 HAT+ takes its data and power over the PCIe ribbon, ships a 16 mm GPIO stacking header, and its spacers leave room for the Active Cooler beneath it. It takes 2230 and 2242 drives and supplies up to 3 A to the M.2 device. The M.2 HAT+ **Compact** has no stacking header and the Active Cooler cannot fit beneath it ([M.2 HAT+ docs](https://www.raspberrypi.com/documentation/accessories/m2-hat-plus.html)). So the stack that works is Pi 5, Active Cooler, standard M.2 HAT+, DAC+ HD on top. Whether the 16 mm header leaves enough pin length to seat the DAC's socket is **(unverified)**. A second stacking header may be needed.
- **The Pimoroni NVMe Base mounts under the Pi** and leaves the top free for a HAT ("pass-thru" bolts are included). It takes 2230 to 2280 drives, and Pimoroni publishes tested, "maybe" and avoid lists ([Pimoroni NVMe Base](https://shop.pimoroni.com/products/nvme-base)).
- **The owner declined "the hat" on 2026-10-28**, together with the RTC battery (observed). That decision covered the NVMe HAT. Whether a board under the Pi counts as "the hat" is the owner's call (Open question 2). The settled BOM below therefore avoids any new board on the Pi.
- **PoE is a poor fit.** The home's mesh router supplies no PoE, so PoE needs an injector. The original Raspberry Pi PoE+ HAT does not fit the Pi 5, because the PoE header moved ([CNX](https://cnx-software.com/?p=124146)). The third-party Pi 5 PoE HATs (Waveshare (F) and (H), Uctronics) bring their own fans and sit on the GPIO header the DAC needs ([The Pi Hut, Waveshare PoE HAT (F)](https://thepihut.com/products/poe-hat-for-raspberry-pi-5-with-cooling-fan)). Without an EEPROM they follow no HAT+ class. REJECT.

**Test T4 (read-only, on the gateway):** `cat /proc/device-tree/hat/product /proc/device-tree/hat/vendor 2>/dev/null` shows which HAT the firmware read, and `sudo i2cdetect -y 1` should show `4c` and `62` (UU when the driver holds them). With an M.2 HAT+ fitted on a later build, `sudo i2cdetect -y 0` (the ID bus, if exposed) should show both `50` and `51` **(unverified that the ID bus is exposed as bus 0 on the Pi 5)**.

### F5. Power: what a 5 A supply actually buys

- **USB budget.** "Raspberry Pi 5 provides 1.6 A of power to downstream USB peripherals when connected to a power supply capable of 5 A at +5 V (25 W). When connected to any other compatible power supply, Raspberry Pi 5 restricts downstream USB devices to 600 mA." The board's typical active draw is 800 mA, and the fan connector "pulls from the same current limit as USB peripherals" ([Raspberry Pi power supply docs](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#power-supply)). The gateway's PSU is detected as 5 A (observed).
- **PCIe budget.** The M.2 HAT+ supplies up to 3 A at 3.3 V to the M.2 device, separate from the USB 1.6 A ([M.2 HAT+ docs](https://www.raspberrypi.com/documentation/accessories/m2-hat-plus.html)). A forum reply in the Raspberry Pi SSD launch thread reads the 512 GB drive's label as 3.3 V 2.0 A; the product brief gives no power figure **(unverified)**. That would be a rating, not a draw.
- **The failing disk is the budget's biggest item.** A 2.5-inch bus-powered drive spins up at roughly 0.9 to 1.8 A on 5 V (two unrelated datasheets; the exact figure for the owner's drive was not found, **unverified**). With that drive, a USB NVMe enclosure and a USB NIC, the 1.6 A limit is within reach at spin-up. Moving the media library to a **self-powered** (3.5-inch, or a powered hub) enclosure takes the largest load off the Pi's budget and off its 5 V rail.
- **CM5 numbers.** Typical draw is 400 mA idle and 900 mA operating, 1.3 mA with `PMIC_EN` low, and each onboard 3.3 V and 1.8 V regulator can feed 600 mA to peripherals ([CM5 datasheet §3.3-3.4](https://datasheets.raspberrypi.com/cm5/cm5-datasheet.pdf)).
- **The off state.** A Pi 5 draws 1 to 1.4 W "turned off" unless `POWER_OFF_ON_HALT=1` ([power supply docs](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#power-supply)). On CM5 that setting defaults to 1 ([bootloader config docs](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#POWER_OFF_ON_HALT)), so a `halt` or `poweroff` on a CM5 appliance leaves it off until someone presses the power button. With the default `WAIT_FOR_POWER_BUTTON=0` it still boots by itself after a power cut.
- **Measuring the margin.** `vcgencmd pmic_read_adc` reads the input voltage and the PMIC rails. It does not see USB, HAT or NVMe current, because those branches hang off 5 V directly ([jfikar/RPi5-power](https://github.com/jfikar/RPi5-power)). Use `EXT5V_V` as the margin indicator. Undervoltage is flagged below 4.63 V (±5%) ([power supply docs](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#power-supply)).

**Test T5 (mildly intrusive: one minute of CPU load):** `vcgencmd get_config usb_max_current_enable` should report `1`. Then `vcgencmd get_throttled` should be `0x0`; bit 16 (`0x10000`) means undervoltage has occurred since boot. Next, while `stress-ng --cpu 4 --timeout 60` runs and the USB disk is busy (`dd if=/dev/sdX of=/dev/null bs=1M count=2000`), sample `vcgencmd pmic_read_adc EXT5V_V` each second. Pass: never below 4.90 V (a margin I chose, about 0.27 V above the warning threshold) and `get_throttled` still `0x0`. Run it when the TV is off.

### F6. Storage endurance: nobody publishes the number that matters, so measure the write rate

- **SD cards.** The October pass already noted that SD cards publish no endurance rating; the owner's USB disk failed SMART on 2026-10-25 (observed).
- **The Raspberry Pi SSD brief publishes IOPS, not TBW.** It gives 256 GB 40k/70k IOPS, 512 GB 50k/90k, 1 TB 90k/90k (4 kB random read/write), M.2 2230, PCIe Gen 3, NVMe 1.4, 0 to 70 °C ambient, and "in production until at least January 2032". List prices were $30, $45 and $70 when the brief was published (July 2025). It gives no TBW, no power figures and no DRAM or HMB detail ([product brief](https://datasheets.raspberrypi.com/ssd/raspberry-pi-ssd-product-brief.pdf)). The CM5 datasheet gives eMMC sizes (16, 32 or 64 GB) and "up to 400 MB/s", also with no endurance figure ([CM5 datasheet](https://datasheets.raspberrypi.com/cm5/cm5-datasheet.pdf)). Memory-driven price rises in February 2026 apply to boards and modules with 2 GB or more; the post does not mention SSDs ([Raspberry Pi, 2026-02-02](https://www.raspberrypi.com/news/more-memory-driven-price-rises/)).
- **Known-good drives** come from lists, not from Raspberry Pi. Pimoroni marks as tested, among others, Crucial P3 Plus, Kingston KC3000, Samsung 980 and 980 Pro, Sabrent Rocket 4.0 and WD Black SN750 SE. It puts WD SN740 and SN770, Samsung 970 EVO Plus and Patriot P300/P310 under "maybe", and most WD Green/Blue/Red drives under "avoid" ([Pimoroni NVMe Base](https://shop.pimoroni.com/products/nvme-base)). Geekworm reports Micron 2450 and 2200 as detected but unable to boot ([Geekworm wiki](https://wiki.geekworm.com/NVMe_SSD_boot_with_the_Raspberry_Pi_5)). The 2025-10-08 bootloader added 4K-native-sector NVMe boot ([rpi-eeprom 2712 notes](https://github.com/raspberrypi/rpi-eeprom/blob/master/firmware-2712/release-notes.md)).
- **What tvgw writes.** Pcaps are capped at `PCAP_MAX_GB=1.5` over `PCAP_DAYS=7`, so at most about 0.2 GB a day. The store uses a rollback journal with `synchronous=FULL` (design decision 10), and the journal is now persistent (observed). The total is unknown, so measure it (T6). For scale: even 10 GB a day is 3.65 TB a year, a small fraction of any current consumer NVMe's rating. Endurance is not the constraint for an NVMe boot disk. It *is* for an SD card, and for torrents if they ever land on the boot disk.

**Test T6 (read-only, over 24 h):** write down field 7 of `/sys/block/mmcblk0/stat` (sectors written) at a known time, and again 24 hours later. `(b - a) * 512 / 1e9` is GB written per day. With NVMe, use `sudo nvme smart-log /dev/nvme0 | grep -E 'data_units_written|percentage_used'`; one data unit is 512,000 bytes. Divide the drive's TBW by the daily figure for its life. Run T6 before choosing the SSD size.

### F7. Thermals and the 2.9 GHz overclock: quiet and overclocked are in tension

- **Raspberry Pi's numbers at stock (2.4 GHz)**, all from [Heating and cooling Raspberry Pi 5](https://www.raspberrypi.com/news/heating-and-cooling-raspberry-pi-5/) (2023-10-04):
  - With no cooling, a sustained load sits at the 85 °C limit and throttles.
  - With the Active Cooler, the fan holds about 60 °C, with peaks of 62 to 63 °C.
  - With the Active Cooler under an M.2 HAT+, it settles at about 64 °C.
  - With the official case fan, the maximum is about 72 °C lid off and 74 °C lid on.
  - Throttling starts at 80 °C. The fan comes on at 60 °C, speeds up at 67.5 °C and reaches full speed at 75 °C.
- **Fanless cases at stock.** The Flirc case delays throttling (it began after 4 min 24 s, against 1 min 20 s in the official case) but does not prevent it under sustained load ([Martin Rowan, Flirc](https://www.martinrowan.co.uk/2024/01/flirc-raspberry-pi-5-case/)). EDATEC's CNC fanless cases peaked at 67.5 °C in a 30-minute four-core test and did not throttle in a 6-hour retest. Their GPIO and PoE headers need extensions to clear the metal ([Martin Rowan, EDATEC](https://www.martinrowan.co.uk/2024/02/edatec-raspberry-pi-5-fanless-enclosures/)). Neither test was overclocked.
- **The gateway at 2.9 GHz.** It runs `arm_freq=2900`, `over_voltage_delta=50000`, `gpu_freq=950` since 2026-11-01, and peaked at 74 °C in a 60-second all-core load (observed). That is about 11 °C above the Active Cooler's stock plateau, into the fan's "speeding up" band and 6 °C short of the soft throttle. Third-party figures for 3.0 GHz on the Active Cooler run 60 to 70 °C ([raspberry.tips](https://raspberry.tips/en/raspberrypi-tutorials/overclock-raspberry-pi-5)) **(unverified; methods vary)**. Raspberry Pi engineers: "We don't characterise the overclocked range - you are on your own" ([raspberrypi/firmware#1876](https://github.com/raspberrypi/firmware/issues/1876)). Jeff Geerling's early board could not finish benchmarks at 3.0 GHz ([Geerling](https://www.jeffgeerling.com/blog/2023/overclocking-and-underclocking-raspberry-pi-5/)).
- **What the gateway needs.** tvgw's heaviest work is the hourly tshark pass and ingest. It is bursty, single-threaded in places, and has no deadline shorter than an hour. The overclock serves the desktop, VLC and xrdp on the same Pi, not the gateway.
- **Conclusion.** A fanless case and 2.9 GHz do not go together. A fanless case at stock clocks is fine for the gateway's load. The Active Cooler at stock is effectively silent at gateway load, because it idles below the 60 °C fan threshold. The appliance image ships stock clocks. On the owner's multi-role Pi the overclock is the owner's decision (approved 2026-11-01); its cost is fan noise under load and an unknown share of the 2026-10-31 reset (F8).
- **Firmware that helps a hot, unattended box.** The 2026-09-24 bootloader starts SDRAM "with the worst case refresh rate (for high temperatures)" and lets the temperature monitor relax it ([rpi-eeprom 2712 notes](https://github.com/raspberrypi/rpi-eeprom/blob/master/firmware-2712/release-notes.md)). The gateway's EEPROM is 2026-10-23 (observed), so it already has this. A new board must be updated to at least the 2026-09-25 default release before it goes into service.

### F8. The hardware watchdog: trixie's one-minute default is correct, and `get_rsts` cannot name the cause of a reset

- **The hardware limit is 16 s, but the watchdog core extends it.** The driver sets `.max_hw_heartbeat_ms = WDOG_TICKS_TO_MSECS(PM_WDOG_TIME_SET)`, with `PM_WDOG_TIME_SET = 0x000fffff` in 1/65536 s ticks: 15,999 ms ([bcm2835_wdt.c, rpi-6.18.y](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/drivers/watchdog/bcm2835_wdt.c)). Because the driver sets `max_hw_heartbeat_ms` and not a hard `max_timeout`, the watchdog core "will send heartbeats to the watchdog driver if 'timeout' is larger than max_hw_heartbeat_ms, unless WDOG_ACTIVE is set and userspace failed to send a heartbeat for at least 'timeout' seconds" ([kernel watchdog API](https://docs.kernel.org/watchdog/watchdog-kernel-api.html)). The core's worker pings at half the hardware period, about every 8 s ([watchdog_dev.c](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/drivers/watchdog/watchdog_dev.c)).
- **What that means in practice.** Trixie's `RuntimeWatchdogSec=1m` (`/usr/lib/systemd/system.conf.d/40-rpi-enable-watchdog.conf`, observed) is a real one-minute watchdog. A hung systemd resets the board after 60 s plus at most 16 s. A hung kernel, where the worker itself stops, resets it within 16 s.
- **I disagree with the October pass here.** It proposed `RuntimeWatchdogSec=10s` because "bcm2835 maximum about 15 s". That limit applies to the hardware, not to the timeout systemd can ask for. Ten seconds only adds false resets under heavy I/O stalls, and each reset leaves the TV dark for about a minute. Keep the default.
- **`vcgencmd get_rsts` does not distinguish a watchdog timeout from a reboot.** A maintainer explained that "you cannot distinguish a watchdog reboot from an explicit reboot" because the reboot path itself uses the watchdog. From power-on the register reads `1000`; after `sudo reboot` it reads `20` ([raspberrypi/linux#1586](https://github.com/raspberrypi/linux/issues/1586)). Bit 5 is HADWRF, the watchdog-full-reset flag. The owner's note that `get_rsts=20` after the 2026-10-31 20:20 reset points at a watchdog (observed) therefore proves only that the reset was not a cold power-on **(inference; the power-on bit's behaviour on Pi 5 is unverified)**. A 2025-10-08 bootloader fix also stopped the firmware from setting PM_RSTS bit 5 by accident when stopping the watchdog ([rpi-eeprom 2712 notes](https://github.com/raspberrypi/rpi-eeprom/blob/master/firmware-2712/release-notes.md)), so older readings were noisier still.
- **Discriminate resets with the journal and pstore.** Now that the journal is persistent and `dtoverlay=ramoops` is set (observed), these two tell the cases apart (the overlay maps itself to `ramoops-pi5` on BCM2712 through `overlay_map.dts` ([overlay_map.dts](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm/boot/dts/overlays/overlay_map.dts))):
  - A clean reboot ends the previous boot's journal with systemd's shutdown lines.
  - A watchdog timeout ends it mid-stream.
  - A panic leaves a file in `/var/lib/systemd/pstore/`.
- **Boot-time watchdog.** `BOOT_WATCHDOG_TIMEOUT=N`, added 2025-06-20, resets the board when the OS has not started within N seconds. It is cancelled when the Arm CPU starts, and `BOOT_WATCHDOG_PARTITION` can send the retry to another partition ([bootloader config docs](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#BOOT_WATCHDOG_TIMEOUT); [notes](https://github.com/raspberrypi/rpi-eeprom/blob/master/firmware-2712/release-notes.md)). This covers the one gap systemd's watchdog cannot: a boot that hangs before Linux. For an unattended gateway, `BOOT_WATCHDOG_TIMEOUT=120` is cheap insurance.
- **CM5 specifics.**
  - Reboots of CM5 parts without Wi-Fi stalled up to about 60 s on an unused SDIO interface; this was fixed in `pieeprom-2025-02-11` and the issue was closed 2026-03-09 ([raspberrypi/linux#6647](https://github.com/raspberrypi/linux/issues/6647)).
  - `POWER_OFF_ON_HALT` defaults to 1 on CM5 (F5). A stray `poweroff` therefore needs a button press, and the hardware watchdog does not help, because the driver's power-off path deliberately boots "partition 63", which means halt ([bcm2835_wdt.c](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/drivers/watchdog/bcm2835_wdt.c)).

**Test T7 (read-only):** run `sudo wdctl`; expect `Identity: Broadcom BCM2835 Watchdog timer` and `Timeout: 60 seconds`. Then run `systemctl show -p RuntimeWatchdogUSec,RebootWatchdogUSec`. After the next unexpected reset, run `journalctl -b -1 -n 40 --no-pager` and `ls /var/lib/systemd/pstore/`. On a bench board, never on the gateway, check the `get_rsts` readings: cold power-on, then `sudo reboot`, then `echo c | sudo tee /proc/sysrq-trigger` with `kernel.panic=10`.

### F9. The RTC battery is low value here; I partly disagree with the October pass

- **The Pi 5 RTC runs without a battery while 5 V is present.** "The RTC is still usable even when there's no backup battery attached." The official cell is a rechargeable lithium-manganese coin cell, and charging needs `dtparam=rtc_bbat_vchg=3000000`. Raspberry Pi warns against primary lithium cells, because "the RTC backup current consumption is higher than most dedicated RTC modules" ([Raspberry Pi RTC docs](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#real-time-clock-rtc)).
- **The CM5 datasheet says the opposite for the module.** It states "typical CR2032 lasts > 3 years when CM5 is unpowered" ([CM5 datasheet](https://datasheets.raspberrypi.com/cm5/cm5-datasheet.pdf)). So the CR1220 or CR2032 holders on CM5 carriers are fine as they are.
- **What a battery adds here is narrow.** Without one, the clock is lost only on a power cut. `systemd-timesyncd` then restores the time of the last sync from its clock file, which is minutes to hours behind, and NTP corrects it as soon as the uplink is up. A clock that is hours behind does not break TLS certificate checks, which span months.
- **Verdict.** The October pass ranked the battery ADOPT NOW. I rank it optional, a few dollars and no code, and the owner has declined it. The clock that matters for tvgw is the TV's (the SDP clock hosts), not the Pi's.

### F10. rpi-image-gen in late 2026: mature enough, with three traps

- **Releases.** v2.6.0 (2026-05-22), v2.7.0 (2026-06-26), v2.8.0 (2026-08-13), v2.9.0 (2026-10-23) ([rpi-image-gen releases](https://github.com/raspberrypi/rpi-image-gen/releases)).
- **What it is.** YAML configs plus layers and hooks. It runs as a normal user on mmdebstrap, bdebstrap, genimage and `podman unshare`. Its device layers include `pi5` and `cm5`, and its image layouts are `mbr`, `gpt` and `none`. The README lists native Debian bookworm and trixie arm64 as the supported hosts ([README](https://github.com/raspberrypi/rpi-image-gen)).
- **It builds on GitHub's hosted arm64 runners.** Its own CI does: `runs-on: ubuntu-24.04-arm`, with `./rpi-image-gen build -c ./config/trixie-minbase.yaml` and `trixie-minbase-ab.yaml`, plus a QEMU job on `ubuntu-24.04` ([build.yml](https://github.com/raspberrypi/rpi-image-gen/blob/master/.github/workflows/build.yml)). Arm64 hosted runners are GA and free for public repositories since 2025-08-07 ([GitHub changelog](https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/)). A February 2026 report says standard arm64 runners now also work in private repositories ([Classmethod](https://dev.classmethod.jp/articles/github-actions-arm64-private-repos/)) **(unverified against GitHub's own changelog; tvgw's repository is private)**.
- **Local .deb files.** A `packages:` list in the config takes both apt names and paths such as `pkgs/mypkg_1.0_arm64.deb` ([examples/debstore](https://github.com/raspberrypi/rpi-image-gen/tree/master/examples/debstore)). The nfpm package from the packaging branch drops straight in.
- **SBOM.** The `sbom-base` layer runs syft. Its hook installs `SYFT_VER=v1.51.0` with `curl -sSfL https://get.anchore.io/syft | sh` when the host has no syft ([sbom05-syft hook](https://github.com/raspberrypi/rpi-image-gen/blob/master/layer/sbom/sbom.d/hooks/sbom05-syft)). For the supply-chain branch: preinstall a hash-pinned syft on the runner, so the hook never pipes a script into a shell. I found no built-in CVE scanner in the tree; the October pass's "SBOM and CVE list" is half right (CVE scanning **unverified**).
- **A/B layout.** The `image-rota` layer (v6.3.0) builds a GPT layout with A and B boot and system slots, a read-only erofs (or ext4) root, a read-only `/boot/firmware`, and an ext4 `/persistent`. `/home` and the journal are shared across slots. **`/var` is per slot by default** (`/persistent/slots/<slot>/var`), and other paths survive a slot change only if a layer declares them in `/etc/rpi-image-gen/slot-shared.d/*.conf` (format `Version=1`, `Path=...`). Slot switching uses Raspberry Pi tryboot (`rpi-slot-tryboot`) and works from SD, eMMC or NVMe ([image-rota](https://raspberrypi.github.io/rpi-image-gen/layer/image-rota.html), [ab-slots.adoc](https://github.com/raspberrypi/rpi-image-gen/blob/master/layer/rpi/device/ab-slots.adoc), [network-manager slot-shared.conf](https://github.com/raspberrypi/rpi-image-gen/blob/master/layer/net-misc/network-manager.d/customize.overlay/etc/rpi-image-gen/slot-shared.d/network-manager.conf)). The bootloader gained A/B updates of its own on 2026-05-13 ([notes](https://github.com/raspberrypi/rpi-eeprom/blob/master/firmware-2712/release-notes.md)).
- **OTA through Raspberry Pi Connect** exists as an "experimental remote update capability", either with an embedded auth key or the device identity in OTP ([examples/ota](https://github.com/raspberrypi/rpi-image-gen/tree/master/examples/ota)).

The three traps for tvgw:

1. **A read-only root breaks today's install model.** `install.sh` writes the dnsmasq and nginx configuration, the units and `/etc/tvgw/tvgw.conf` at install time, and AdGuard Home rewrites its own YAML under `/opt/AdGuardHome`. On an `image-rota` root, every one of those paths must be either rendered at build time or declared slot-shared: `/etc/tvgw`, `/var/lib/tvgw`, `/var/log/tvgw`, `/opt/AdGuardHome` (or AdGuard's work directory), `/var/lib/misc` for dnsmasq's leases, and `/etc/NetworkManager/system-connections`. Miss one and a slot switch silently resets the store, the leases or the TV's address reservation.
2. **Rollback meets schema migrations.** If slot B's tvgw migrated `tvgw.db` to a newer schema and B is then rolled back to A, A's older code opens a newer store. tvgw must refuse a store whose schema is newer than it knows, and say so in `tvgw verify`, before A/B is safe.
3. **Raspberry Pi Connect OTA opens a vendor cloud channel into the firewall.** That is the opposite of what this box is for. REJECT for tvgw.

**Verdict:** v1 of the image is **non-A/B** (`trixie-minbase.yaml` style, ext4 read-write root), updated with apt from the signed repository the packaging branch builds. A/B is a v2 goal once traps 1 and 2 are closed.

### F11. First boot on trixie: cloud-init, or Raspberry Pi's new rpi-preseed, and the netplan question settled

- **Imager 2.x knows five formats.** Imager's `init_format` values are `none`, `systemd` (`firstrun.sh`), `cloudinit`, `cloudinit-rpi`, and `rpi-preseed`. With `rpi-preseed`, Imager "writes a single `rpi-preseed.toml` file to the FAT boot partition (read from `/boot/firmware/rpi-preseed.toml`)". The TOML covers hostname, the account, SSH, Wi-Fi (as a NetworkManager connection), locale, Connect enrolment and interfaces, and "no `cmdline.txt` entry is added". Bookworm images and the first trixie release (2025-10-01) use `systemd`; current trixie images use `cloudinit-rpi`. Imager 1.x cannot customise trixie ([os_customisation_formats.md](https://github.com/raspberrypi/rpi-imager/blob/main/doc/os_customisation_formats.md)). Imager v2.0.11 (2026-08-14) added the rpi-preseed format ("Add rpi-preseed support", #1659); v2.0.12 (2026-10-08) is current ([rpi-imager releases](https://github.com/raspberrypi/rpi-imager/releases)).
- **cloud-init on Pi OS.** Since the 2025-11-24 image, `user-data`, `network-config` and `meta-data` sit on the boot partition, and "Netplan is now the primary source of truth for networking on Raspberry Pi OS" ([Raspberry Pi, 2025-11-27](https://www.raspberrypi.com/news/cloud-init-on-raspberry-pi-os/)). The Pi archive carries `cloud-init 25.2-1~bpo13+1+rpt20` (Pi archive index, read 2026-11-01).
- **rpi-preseed is Raspberry Pi's own and is now packaged.** It is "a greenfield, cloud-init-free first-boot OS customisation system", POSIX shell, "Prototype. Not yet production-hardened" ([raspberrypi/rpi-preseed](https://github.com/raspberrypi/rpi-preseed)). Version `0.2.1` (`Architecture: all`, maintainer "Raspberry Pi OS Team") is in the trixie Pi archive, with `Conflicts: cloud-init`; its changelog is signed by a raspberrypi.com address and dated 2026-10-29 ([debian/changelog](https://github.com/raspberrypi/rpi-preseed/blob/main/debian/changelog)). Its units:
  - `rpi-preseed.service` runs before any login surface, with `ConditionPathExists=/boot/firmware/rpi-preseed.toml` and `ConditionPathExists=!/var/lib/rpi-preseed/applied`.
  - `rpi-preseed-runcmd-early.service` runs before `network-pre.target` with a 30 s budget.
  - `rpi-preseed-runcmd-late.service` runs `After=network-online.target time-sync.target` with `TimeoutStartSec=infinity`, so "nothing blocks on it".

  The example TOML has `[runcmd] early = [...]`, `late = [...]`, `late_retries = 3` ([systemd units](https://github.com/raspberrypi/rpi-preseed/tree/main/systemd), [example](https://github.com/raspberrypi/rpi-preseed/blob/main/examples/rpi-preseed.toml)).
- **Settled: on Raspberry Pi OS, NetworkManager is netplan-backed.** The Pi archive's `network-manager 1.52.1-1+rpt4` **Depends on `libnetplan1` and `netplan.io`**. Debian trixie's `network-manager 1.52.1-1` depends on neither (both apt indexes, read 2026-11-01). So on Pi OS, `nmcli con add` (which is how `install.sh` creates `tv-lan`) goes through NetworkManager's netplan integration. That is the Ubuntu behaviour, where connections are written as `/etc/netplan/90-NM-<uuid>.yaml` **(unverified on Pi OS; T8 checks it)**. The October pass left this open. It matters for the image: rpi-image-gen's NetworkManager layer shares only `/etc/NetworkManager/system-connections` and `/var/lib/NetworkManager` across slots, not `/etc/netplan`. And netplan's `generate` step "clears `.yaml` and `.yml` files in `/etc/netplan/`" according to the cloud-init post's comments.

**Test T8 (read-only, on the gateway):** `apt-cache policy network-manager netplan.io | grep -E 'Installed|\*\*\*'`, then `ls -la /etc/netplan/`, then `nmcli -f NAME,UUID,FILENAME connection show`. If `tv-lan`'s FILENAME is under `/run/NetworkManager/system-connections/netplan-*`, the connection lives in netplan YAML, and both the image and `tvgw setup` must treat `/etc/netplan` as state. The gateway was upgraded in place from bookworm (observed), so it may show either.

### F12. How others ship: Pi-hole, OpenWrt, Home Assistant OS

| Project | What it ships | Unattended install | Updates | Lesson for tvgw |
|---|---|---|---|---|
| Pi-hole | No OS image. A one-step script, a git checkout or Docker ([docs](https://docs.pi-hole.net/main/basic-install/)) | `basic-install.sh --unattended` with a preseeded `/etc/pihole/pihole.toml` (v6) or a legacy `setupVars.conf` ([basic-install.sh](https://github.com/pi-hole/pi-hole/blob/master/automated%20install/basic-install.sh)) | `pihole -up` | The package plus an answers file is the product; an image is optional. Copy `--unattended` plus a preseeded TOML |
| OpenWrt | Per-target images (bcm27xx/bcm2712 covers Pi 5, Pi 500 and CM5) through the Firmware Selector; 25.12.0 stable in March 2026 with Attended Sysupgrade (ASU) built in ([24.10.2 notes](https://forum.openwrt.org/t/openwrt-24-10-2-service-release/235046), [Help Net Security](https://www.helpnetsecurity.com/2026/03/09/openwrt-25-12-0-released/)) | uci-defaults scripts baked into the image | `sysupgrade` keeps config; ASU rebuilds the image with the user's packages | A small read-mostly root with config kept separately is what makes upgrades safe. tvgw's `/etc/tvgw` plus `/var/lib/tvgw` split is the same idea |
| Home Assistant OS | Buildroot OS. GPT: boot, kernel and system A/B, bootstate, overlay, data ([partition docs](https://developers.home-assistant.io/docs/operating-system/partition)) | First-run onboarding in the browser | RAUC bundles signed by HA's release CA, checked against `/etc/rauc/keyring.pem`. The Supervisor marks a slot good after it starts, otherwise the bootloader falls back. "Raspberry Pi 5 uses the firmware's tryboot mechanism, through a custom RAUC backend" ([update system](https://contributors.home-assistant.io/os/operating-system/update-system/)) | A/B needs a health check that marks the slot good. For tvgw that is `tvgw verify` all `OK`, and that is the gate before A/B (F10, trap 2) |

---

## 2. Where this pass disagrees with the October pass

1. **Appliance board.** The CM5-DUAL-ETH-MINI has no M.2 and spends the PCIe lane on its second NIC (F3). The reference board should be a carrier whose second port is USB-attached, so NVMe stays possible: CM5-DUAL-ETH-BASE or BOX-A.
2. **Watchdog.** Keep trixie's `RuntimeWatchdogSec=1m`. The 16 s hardware limit does not cap the systemd timeout, because the watchdog core pings on systemd's behalf (F8). Add `BOOT_WATCHDOG_TIMEOUT` for boot hangs.
3. **RTC battery.** Optional, not ADOPT NOW (F9), and declined by the owner.
4. **2.5 GbE HATs.** The October pass listed these for prototyping. With a 100 Mb/s TV port and a sub-10 Mb/s average, REJECT (F1).
5. **"rpi-image-gen emits an SBOM and CVE list."** It emits an SBOM through syft; I found no CVE scanner in the tree (F10).
6. **"cloud-init `runcmd`" as the unattended path.** It works on Pi OS images. For a tvgw-built image, though, rpi-preseed (no cloud-init, no netplan regeneration, Raspberry Pi-maintained, Imager-native since 2.0.11) plus a tvgw-owned first-boot unit is the cleaner pair (F11).
7. **"Test netplan's handling of `tv-lan` on a fresh image".** Half settled: Pi OS's NetworkManager is built against netplan, Debian's is not (F11). T8 settles the rest.

---

## 3. The settled bill of materials

### Build A: the owner's next build (quiet, two ports, NVMe, audio, no new HAT)

| Part | Choice | Why | Price (list where known) |
|---|---|---|---|
| Board | Keep the Pi 5 8 GB | Already in service with an EEPROM newer than every fix cited here (observed) | owned |
| Cooling | Keep the Active Cooler; **stock clocks** for quiet | Holds about 60 °C at stock, and the fan stays off at gateway load (F7) | owned |
| PSU | Keep the 27 W (5 V 5 A) USB-C supply | Needed for the 1.6 A USB budget (F5) | owned |
| Boot disk | **USB 3 NVMe enclosure** on one blue USB port, holding a drive from Pimoroni's tested list (for example Crucial P3 Plus or Kingston KC3000, 500 GB), or a 2230 Raspberry Pi SSD 256/512 GB in a 2230-capable enclosure | No board on the GPIO header (owner decision); independent xHCI from the NIC (F3); endurance not a constraint (F6) | SSD $30-45 (Raspberry Pi list price, July 2025); enclosure and other drives: check |
| Second port | **USB 3 RTL8153-based gigabit adapter** on the other blue port, for the wired uplink if a wire exists; the TV stays on onboard `eth0` | `r8152` is in-tree and has the larger installed base; AX88179A has ID and naming problems (F3) | check |
| Audio | Keep the HiFiBerry DAC+ HD on the GPIO header | No conflict with anything in this BOM (F4) | owned |
| Media disk | Move the library into a **self-powered** enclosure; replace the failing drive | Frees the USB budget and the 5 V rail (F5) | check |
| Case | One that holds the Active Cooler and a full-size HAT. HiFiBerry's universal steel case for Pi 5 lists its DACs ([The Pi Hut](https://thepihut.com/products/steel-case-for-hifiberry-dac-digi-amp-and-raspberry-pi-5)); whether the Active Cooler fits inside is **(unverified)** | | check |
| Boot order | The default `0xf41` tries SD first, then USB mass storage. Set `BOOT_ORDER=0xf14` (USB first, SD as the fallback) with `sudo rpi-eeprom-config --edit`, so the old SD card can stay in as the rollback | [bootloader docs](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#BOOT_ORDER) | |

**If the owner lifts the HAT veto (Build A2):** replace the USB enclosure with the official **M.2 HAT+ (standard, not Compact)** and a 2230 Raspberry Pi SSD. Stack it as Pi, then Active Cooler, then M.2 HAT+ on its 16 mm header, then the DAC+ HD (F4). Set `BOOT_ORDER=0xf416` for NVMe first, and keep the PCIe link at the default Gen 2 ([PCIe docs](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#boot-from-pcie)). This frees the USB budget and gives native NVMe boot. The M.2 HAT+ cost $12 at launch ([Tom's Hardware](https://www.tomshardware.com/raspberry-pi/raspberry-pi-launches-dollar12-m2-hat-for-raspberry-pi-5)).

### Build B: the reference appliance for the image (no audio)

| Part | Choice | Why |
|---|---|---|
| Module | CM5 with eMMC (32 GB) and Wi-Fi, 2 or 4 GB RAM | eMMC boots with no adapter. Wi-Fi keeps a radio uplink as the fallback when no wire exists. tvgw needs at most 2 GB (October pass) |
| Carrier | Waveshare CM5-DUAL-ETH-BASE, as the BOX-A metal-case kit | GbE from the CM5 PHY for the TV, a USB-attached 2.5 GbE for the uplink, M.2 free for NVMe, RTC header, PWM fan header, 7-36 V DC in, $54.99-69.99 (F3) |
| Storage | eMMC for the OS; optional 2230/2242 NVMe for `/var/lib/tvgw` | Endurance (F6) |
| EEPROM | ≥ the 2026-09-25 default release | SDRAM high-temperature refresh (F7); CM5 no-Wi-Fi reboot fix is in every release since 2025-02-11 (F8) |
| Bootloader config | `BOOT_WATCHDOG_TIMEOUT=120`; keep `WAIT_FOR_POWER_BUTTON=0`; know that `POWER_OFF_ON_HALT=1` is the CM5 default | F5, F8 |

Build B doubles as the second hardware CI target, beside the owner's Pi. Interface names differ on it, which is exactly what the templated-interface work in the packaging branch is for.

**The structural alternative, said once.** Every incident on this gateway that was not tvgw's own came from the other jobs on the same Pi:

- the in-place OS upgrade;
- `needrestart` restarting services;
- the volatile journal;
- the overclocked reset;
- the failing torrent disk;
- PIA's routing rules masking a tvgw routing bug (observed).

Build B as the gateway, with the existing Pi 5 kept as the media box (DAC, AirPlay, VLC, Samba, torrents), removes all of those couplings. It costs one more box at the TV.

---

## 4. The settled image pipeline

1. **Inputs.** The signed tvgw `.deb` from the packaging branch. AdGuard Home's release tarball, pinned by SHA-256 in a custom layer (AdGuard is not a Debian package). A config `image/tvgw-trixie.yaml`:

   ```yaml
   include:
     file: trixie-minbase.yaml        # v1: ext4, read-write root, no A/B
   device:
     layer: rpi5                       # second config with: cm5
     hostname: tvgw
   image:
     name: tvgw-trixie-arm64
   packages:
     - pkgs/tvgw_<version>_arm64.deb
     - rpi-preseed
     - nftables
     - dnsmasq
     - nginx
     - libnginx-mod-stream
     - tcpdump
     - tshark
     - conntrack
     - ethtool
   layer:
     sbom: sbom-base
   ```

   The key names follow rpi-image-gen's examples; check them against `rpi-image-gen layer --describe` before use **(unverified in this exact form)**. Do not include `cloud-init`: rpi-preseed conflicts with it.

2. **Build** on `ubuntu-24.04-arm` (F10), never on the gateway's self-hosted runner, which is root on the firewall (October pass §10). Pin `rpi-image-gen` to the `v2.9.0` commit `d2d5705bcb37284c4b08c0ce43c039b1f1004e25` (from the tag ref, read 2026-11-01). Preinstall a hash-pinned syft. Set `SOURCE_DATE_EPOCH` as rpi-image-gen's CI does. Publish `tvgw-trixie-arm64.img.xz`, its SHA-256, the extracted-image SHA-256 and the SBOM as release assets.

3. **First boot, the OS part.** rpi-preseed reads `/boot/firmware/rpi-preseed.toml`: user, SSH keys (`ssh_import_id = ["gh:<user>"]` is supported), Wi-Fi, locale and time zone. Imager writes this file when the repository entry says `rpi-preseed` (F11). Leave the TOML's `[ethernet]` section out. tvgw owns the TV port.

4. **First boot, the tvgw part.** A unit shipped in the .deb, `/usr/lib/systemd/system/tvgw-firstboot.service`:

   ```ini
   [Unit]
   Description=tvgw unattended setup from the boot partition
   After=network-online.target rpi-preseed-runcmd-late.service
   Wants=network-online.target
   ConditionPathExists=/boot/firmware/tvgw-answers.toml
   ConditionPathExists=!/var/lib/tvgw/.firstboot-done

   [Service]
   Type=oneshot
   ExecStart=/usr/bin/tvgw setup --non-interactive --answers /boot/firmware/tvgw-answers.toml
   ExecStartPost=/bin/sh -c 'mv /boot/firmware/tvgw-answers.toml /var/lib/tvgw/tvgw-answers.applied.toml && chmod 600 /var/lib/tvgw/tvgw-answers.applied.toml && touch /var/lib/tvgw/.firstboot-done'
   TimeoutStartSec=30min

   [Install]
   WantedBy=multi-user.target
   ```

   The answers file belongs to the `tvgw setup` branch. Its shape, as this pass would ask for it:

   ```toml
   schema = 1
   profile = "lg-webos"
   tv_port = "auto"            # the onboard port; or an interface name or a MAC
   uplink = "auto"             # the port that gets a DHCP default route; else wlan0
   uplink_mode = "direct"
   tv_discovery = "first-dhcp-client"   # pin the first device that leases on tv_port
   analyst_apply = "off"       # never enable autonomy from a file on a FAT partition
   timezone = "Etc/UTC"          # or the owner's Area/City
   ```

   The unit relies on the fail-closed design (decision 5). Until setup finishes, forwarding stays off and the TV is dark, never unfiltered.

   **No secrets go in the answers file.** `/boot/firmware` is FAT, so whoever holds the card can read it, and a deleted file can be recovered from flash. The Anthropic key and the LG pairing key are added afterwards over SSH, as today.

5. **Distribution.** A repository JSON in Imager's v4 format, hosted next to the release:

   ```json
   {"os_list": [{
     "name": "tvgw (Raspberry Pi OS trixie, arm64)",
     "description": "A Raspberry Pi gateway between one smart TV and the internet",
     "url": "https://github.com/<owner>/tvgw/releases/download/<tag>/tvgw-trixie-arm64.img.xz",
     "extract_size": 0, "extract_sha256": "<sha256>",
     "image_download_size": 0, "image_download_sha256": "<sha256>",
     "release_date": "<yyyy-mm-dd>",
     "devices": ["pi5-64bit", "cm5"],
     "init_format": "rpi-preseed"
   }]}
   ```

   Users then run `rpi-imager --repo https://<host>/tvgw-os-list.json`, or choose the custom repository in Imager 2.0's settings ([Raspberry Pi, 2025-12-11](https://www.raspberrypi.com/news/how-to-add-your-own-images-to-imager/)). The device tag names are **(unverified)**; copy them from Imager's own `os_list_imagingutility_v4.json`. Both SHA-256 fields are required for a public repository.

6. **Smoke test before release.** rpi-preseed's own test suite boots Pi OS Lite arm64 under QEMU (`make qemu-check`) ([rpi-preseed README](https://github.com/raspberrypi/rpi-preseed)). The same approach can boot the tvgw image to `multi-user.target` and run `tvgw verify --offline` inside the CI network namespace **(PROTOTYPE; booting a Pi kernel under QEMU's `virt` machine is unverified)**. The real test is Build B on the bench.

---

## 5. What to build here

Ranked by value for risk. Effort: S under a day, M a few days, L a week or more. Risk is to the running gateway.

| # | What | Effort | Risk to the running gateway |
|---|---|---|---|
| 1 | **Run tests T1, T2, T4, T6, T7, T8** (all read-only) and write the results into the hardware notes. T2 decides whether the EEE item (#2) is needed. T6 sizes the SSD. T8 decides how `tvgw setup` and the image treat `/etc/netplan` | S | None |
| 2 | If T2 shows flapping: `dtparam=eee=off` in `config.txt`, a reboot, and a hardware-suite assertion on `ethtool --show-eee eth0`. Owner decision because of the reboot | S | Low: about a minute dark, fail closed |
| 3 | Move the media library to a self-powered enclosure and replace the failing drive; then run T5 | S | Low; Samba and qBittorrent move, tvgw does not |
| 4 | Add `BOOT_WATCHDOG_TIMEOUT=120` to the EEPROM config; keep `RuntimeWatchdogSec=1m`; add a hardware test that `wdctl` reports 60 s | S | Low; takes effect on the next reboot |
| 5 | Build A: NVMe boot over USB. Clone the SD card to the NVMe drive (`rpi-clone`, or `dd` with the gateway's services stopped), set `BOOT_ORDER=0xf14`, then boot it. Keep the SD card untouched in the slot as the rollback | M | Medium: a boot-device change. The rollback is "pull the USB drive" |
| 6 | Build A: the wired uplink through the RTL8153, when a wire exists. Name it with a systemd `.link` file (`[Match] PermanentMACAddress=…`, `[Link] Name=wan0`), set `WAN_IF=wan0` and keep `wlan0` configured as a manual fallback | S-M | Medium: an uplink cutover. Do it while the TV is off |
| 7 | **Image v1:** `image/tvgw-trixie.yaml`, `tvgw-firstboot.service`, the answers-file contract with the setup branch, the Imager JSON, and an arm64 CI job that builds and publishes | M | None (off-box) |
| 8 | Build B on the bench: flash image v1, run the hardware suite, then make it the second hardware CI target | M | None |
| 9 | Stock clocks for the gateway role (`arm_freq` back to default). Owner decision; only if the owner wants quiet over desktop speed, or the reset recurs | S | Low; one reboot |
| 10 | Image v2 (A/B): slot-shared declarations for every tvgw path, a "store schema newer than code" refusal in `tvgw verify`, and slot promotion only after `tvgw verify` is all `OK` | L | None until adopted |

**Do not do:** PoE HATs (F4); 2.5 GbE for the TV or uplink (F1); PCIe Gen 3 (F3); Raspberry Pi Connect OTA on the gateway (F10); the overclock in the image (F7); a fanless case at 2.9 GHz (F7); cloud-init and rpi-preseed in the same image (they conflict, F11); secrets in `tvgw-answers.toml`.

---

## 6. Open questions

1. **Can a cable reach the Pi?** A run to the router, or a mesh satellite with an Ethernet port within reach of the TV, decides whether the second NIC matters at all (F1). The owner knows; this pass cannot.
2. **Does "no HAT" cover a board under the Pi** (Pimoroni NVMe Base), or only the stack on top? If neither is acceptable, Build A's USB enclosure stands.
3. **Does the CX advertise EEE at 100 Mb/s, and does the gateway's port flap?** T1 and T2.
4. **Is `tv-lan` a keyfile or netplan YAML on the gateway?** T8. And does rpi-image-gen's minbase pull the netplan-linked `network-manager` from the Pi archive or Debian's plain one? Run `dpkg -l network-manager netplan.io` inside a built image.
5. **Which Pi 5 boards carry the alternate Ethernet PHY?** The 2026-09 bootloader added "support for alternate ethernet PHYs on Pi5" and MXL PHY LED handling ([notes](https://github.com/raspberrypi/rpi-eeprom/blob/master/firmware-2712/release-notes.md)). A Pi 5 bought now may have a different PHY, so F2's EEE behaviour may differ on it. **(unverified: vendor and revision not found)**
6. **Does the Active Cooler fit inside HiFiBerry's Pi 5 steel case with a DAC+ HD**, and does a 16 mm header give the DAC enough pin length over an M.2 HAT+? A test fit answers both.
7. **What do the Raspberry Pi SSD and CM5 eMMC endure (TBW)?** Neither is published (F6).
8. **Can tvgw's private repository use the standard `ubuntu-24.04-arm` runners, and at what cost?** Check GitHub's current changelog, or make the image-build workflow a separate public repository.
9. **Was the 2026-10-31 reset a watchdog timeout, a panic or a power event?** The persistent journal and pstore will answer at the next occurrence (F8). Until then, the overclock is a suspect, not a cause.

---

## Sources

Raspberry Pi primary:

- Power supply, USB current, `POWER_OFF_ON_HALT`, undervoltage: https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#power-supply (source: https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/raspberry-pi/power-supplies.adoc)
- RTC and battery: https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/raspberry-pi/rtc.adoc
- PCIe, Gen 3 warning, `BOOT_ORDER=0xf416`, `PCIE_PROBE`: https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/raspberry-pi/pcie.adoc
- NVMe boot: https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/raspberry-pi/boot-nvme.adoc
- Bootloader configuration (`BOOT_WATCHDOG_TIMEOUT`, `PSU_MAX_CURRENT`, `WAIT_FOR_POWER_BUTTON`, `PARTITION`): https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/raspberry-pi/eeprom-bootloader.adoc
- M.2 HAT+ and M.2 HAT+ Compact: https://www.raspberrypi.com/documentation/accessories/m2-hat-plus.html
- HAT+ specification (build 2024-12-05): https://datasheets.raspberrypi.com/hat/hat-plus-specification.pdf
- CM5 datasheet: https://datasheets.raspberrypi.com/cm5/cm5-datasheet.pdf
- Raspberry Pi SSD product brief (July 2025): https://datasheets.raspberrypi.com/ssd/raspberry-pi-ssd-product-brief.pdf and https://www.raspberrypi.com/products/ssd/
- Heating and cooling Raspberry Pi 5 (2023-10-04): https://www.raspberrypi.com/news/heating-and-cooling-raspberry-pi-5/
- Memory-driven price rises (2026-02-02): https://www.raspberrypi.com/news/more-memory-driven-price-rises/
- I/O controllers (RP1 USB): https://www.raspberrypi.com/documentation/computers/io-controllers.html
- Cloud-init on Raspberry Pi OS (2025-11-27): https://www.raspberrypi.com/news/cloud-init-on-raspberry-pi-os/
- How to add your own images to Imager (2025-12-11): https://www.raspberrypi.com/news/how-to-add-your-own-images-to-imager/
- rpi-eeprom 2712 release notes: https://github.com/raspberrypi/rpi-eeprom/blob/master/firmware-2712/release-notes.md

Kernel and issue trackers:

- Overlay README, rpi-6.18.y (`eee`, `rtc_bbat_vchg`, `pciex1_gen`, `watchdog`, `ramoops`, `hifiberry-dacplushd`): https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm/boot/dts/overlays/README
- Overlay map (ramoops → ramoops-pi5): https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm/boot/dts/overlays/overlay_map.dts
- HiFiBerry DAC+ HD overlay: https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm/boot/dts/overlays/hifiberry-dacplushd-overlay.dts
- bcm2712_defconfig: https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm64/configs/bcm2712_defconfig
- bcm2835 watchdog driver: https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/drivers/watchdog/bcm2835_wdt.c
- Watchdog core: https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/drivers/watchdog/watchdog_dev.c
- Kernel watchdog API: https://docs.kernel.org/watchdog/watchdog-kernel-api.html
- Pi 5 EEE link flapping on rpi-6.18.y: https://github.com/raspberrypi/linux/issues/7511
- Pi 5 10 Mb half-duplex drops (RP1 MAC bug): https://github.com/raspberrypi/linux/issues/7115
- get_rsts cannot distinguish watchdog from reboot: https://github.com/raspberrypi/linux/issues/1586
- CM5 without Wi-Fi hangs on reboot: https://github.com/raspberrypi/linux/issues/6647
- NVMe boot behind a PCIe switch: https://github.com/raspberrypi/firmware/issues/1833
- Overclocked range not characterised: https://github.com/raspberrypi/firmware/issues/1876
- ASIX naming on 6.6.20: https://github.com/raspberrypi/bookworm-feedback/issues/239
- AX88179A ID missing in OpenWrt 6.12: https://github.com/openwrt/openwrt/issues/23085
- RTL8153 Tx timeouts (linux-usb, 2026-01): https://ratatoskr.run/linux-usb/2026/01/8892827/t

Image and first boot:

- rpi-image-gen: https://github.com/raspberrypi/rpi-image-gen (releases, `.github/workflows/build.yml`, `examples/debstore`, `examples/ota`, `layer/sbom`, `layer/rpi/device/ab-slots.adoc`)
- image-rota layer: https://raspberrypi.github.io/rpi-image-gen/layer/image-rota.html
- rpi-imager releases: https://github.com/raspberrypi/rpi-imager/releases
- Imager customisation formats: https://github.com/raspberrypi/rpi-imager/blob/main/doc/os_customisation_formats.md
- rpi-preseed: https://github.com/raspberrypi/rpi-preseed (README, `systemd/`, `examples/rpi-preseed.toml`, `debian/changelog`)
- Raspberry Pi apt index, trixie arm64 (read 2026-11-01): http://archive.raspberrypi.com/debian/dists/trixie/main/binary-arm64/Packages.gz
- Debian apt index, trixie arm64 (read 2026-11-01): https://deb.debian.org/debian/dists/trixie/main/binary-arm64/Packages.xz
- GitHub arm64 runners for public repositories (2025-08-07): https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/
- arm64 runners in private repositories (secondary): https://dev.classmethod.jp/articles/github-actions-arm64-private-repos/

Other projects:

- Pi-hole install docs: https://docs.pi-hole.net/main/basic-install/ and installer: https://github.com/pi-hole/pi-hole/blob/master/automated%20install/basic-install.sh
- OpenWrt 24.10.2: https://forum.openwrt.org/t/openwrt-24-10-2-service-release/235046 ; 25.12.0: https://www.helpnetsecurity.com/2026/03/09/openwrt-25-12-0-released/
- Home Assistant OS partitions: https://developers.home-assistant.io/docs/operating-system/partition ; update system: https://contributors.home-assistant.io/os/operating-system/update-system/

Vendors and measurements:

- Waveshare CM5-DUAL-ETH-BASE: https://www.waveshare.com/cm5-dual-eth-base.htm ; CM5-DUAL-ETH-MINI: https://www.waveshare.com/cm5-dual-eth-mini.htm
- Geekworm X1501: https://geekworm.com/products/x1501 ; NVMe boot wiki: https://wiki.geekworm.com/NVMe_SSD_boot_with_the_Raspberry_Pi_5
- Pimoroni NVMe Base and drive lists: https://shop.pimoroni.com/products/nvme-base
- HiFiBerry DAC2 HD / DAC+ HD datasheet: https://www.hifiberry.com/docs/data-sheets/datasheet-dac-hd/ ; Pi 5 compatibility: https://www.hifiberry.com/blog/pi5-compatibility-with-hifiberry-products/ ; Pi 5 steel case: https://thepihut.com/products/steel-case-for-hifiberry-dac-digi-amp-and-raspberry-pi-5
- PoE on Pi 5: https://cnx-software.com/?p=124146 ; Waveshare PoE HAT (F): https://thepihut.com/products/poe-hat-for-raspberry-pi-5-with-cooling-fan
- Martin Rowan, Flirc: https://www.martinrowan.co.uk/2024/01/flirc-raspberry-pi-5-case/ ; EDATEC: https://www.martinrowan.co.uk/2024/02/edatec-raspberry-pi-5-fanless-enclosures/
- Jeff Geerling, overclocking: https://www.jeffgeerling.com/blog/2023/overclocking-and-underclocking-raspberry-pi-5/
- raspberry.tips overclock guide (secondary): https://raspberry.tips/en/raspberrypi-tutorials/overclock-raspberry-pi-5
- jfikar/RPi5-power (`pmic_read_adc` limits): https://github.com/jfikar/RPi5-power
- M.2 HAT+ launch price: https://www.tomshardware.com/raspberry-pi/raspberry-pi-launches-dollar12-m2-hat-for-raspberry-pi-5
- HAT stacking forum thread: https://forums.raspberrypi.com/viewtopic.php?t=372508
- LG TV Ethernet speed reports: https://bbs.io-tech.fi/threads/oled-tv.1254/post-8999787 , https://forum.serviio.org/viewtopic.php?p=128533 , https://www.bestbuy.com/site/questions/lg-65-class-c3-series-oled-evo-4k-uhd-smart-webos-tv-2023/6535929/question/b5321f4e-1f50-3cfa-a9fc-94302c0fadbc
- USB autosuspend and RTL8153: https://bbs.archlinux.org/viewtopic.php?id=280781 ; https://forum.libreelec.tv/thread/28119-usb3-to-gigabit-ethernet-adapter-on-rpi4-5-troubles/?postID=188299
- AX88179 cdc_ncm binding: https://forums.gentoo.org/viewtopic-t-1175217.html
- RP1 datasheet summary: https://www.cnx-software.com/2023/10/07/raspberry-pi-rp1-datasheet-block-diagram/
