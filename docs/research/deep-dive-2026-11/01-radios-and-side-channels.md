# Radios and side channels: what can leave an LG CX without crossing the cable

*Research proposal, 2026-11-01. Nothing here is implemented, and nothing here is a decision. It goes with [state-of-the-art-2026-10.md](../state-of-the-art-2026-10.md) (the "October survey"), which covered only the wired path. Where this section disagrees with that survey or with the docs, it says so in [Where this disagrees with the October survey](#where-this-disagrees-with-the-october-survey).*

**Method.** Web research done on 2026-11-01. Primary sources were preferred: LG's own pages and its 2026-09-12 privacy statement, the community-maintained settings dump for the CX in `bscpylgtv`, FCC test data, Linux kernel and BlueZ sources, Debian package lists and peer-reviewed papers. No host was touched. **(unverified)** means only one secondary source, a search-result snippet whose page would not load, or my own inference supports the claim. **(observed)** means the repository says so. Placeholders such as `<TV_IP>`, `<TV_WIFI_MAC>` and `<card>` stand for site values. None are given here.

---

## Bottom line

The cable isolates IP and nothing else. Besides `eth0`, the CX has four other ways to exchange data: an 802.11ac Wi-Fi radio, which also runs Wi-Fi Direct for Screen Share; a Bluetooth 5.0 radio, which carries the BLE Magic Remote, BLE "turn on via Bluetooth" and Bluetooth audio; four HDMI ports with CEC and eARC; and its speakers. None of these can reach the internet without help. Wi-Fi needs an access point to join. Bluetooth needs a phone or app that relays. HDMI and sound need a second device. So the realistic risks are narrower than "radios bypass the gateway", and three of them matter here:

1. **"Wi-Fi off" is a menu state. Nobody has shown it turns the radio off.**
   - webOS treats Wi-Fi Direct as a separate subsystem with its own enable flag and "listen" state.
   - No consumer setting on the CX, and no LAN-API key, reports the radio's state.
   - LG's own 2026-09-12 statement says the TV processes nearby access-point names and signal strengths, when the relevant agreements are accepted.
   - If the radio is still up, the TV's ports and pairing service can be reached over the air. That would undo the containment the October survey credits to the cable.
2. **The CX can advertise over BLE**, and any phone app with Bluetooth-scan permission can see it.
3. **HDMI device identity** goes to UEI's QuickSet cloud. tvgw already blocks that (decision 16), but the CX exposes a setting, `other.ueiEnable`, that may stop it at the source.

The LAN API cannot settle the radio question, so it takes one RF audit: a USB monitor-mode dongle on the Pi, plus a phone, for one evening.

The cheapest and most valuable build is a `tvcheck` v2. It would read about fifteen more keys the CX already exposes, among them the consent flags behind the Voice Information and Viewing Information agreements (`eulaStatus.voiceAllowed`, `acrAllowed` and others) and `network.bleAdvertisingOnOff`, and raise a red line whenever one flips.

Ultrasonic beacons are the least likely risk. The only systematic search of TV audio found none, and the audio compression used by streaming services usually strips that band.

---

## Findings

### 1. What the CX can transmit and receive besides the cable

| Path | Evidence | What it could carry out | Does the gateway see it? |
|---|---|---|---|
| Wi-Fi, 802.11ac | LG's CX spec sheet: "Wifi: Yes (802.11ac)", "Wi-Fi TV On: Yes", "Screen Share: Yes" ([LG UK, OLED65CX5LB](https://www.lg.com/uk/tvs/oled-tv/oled65cx5lb/)) | Traffic over any network it joins; a Wi-Fi Direct group for Miracast; AP scan results | No. It is a different interface |
| Bluetooth 5.0, including BLE | Same sheet: "Bluetooth: Yes (V5.0)", "Bluetooth Surround Ready", "**Bluetooth Low Energy On**: Yes", "Auto Notification: Yes (Bluetooth easy paring)" | Advertising (presence), links to the remote, phones and speakers | No |
| Magic Remote MR20 (the CX's remote) | B&H: pairs "using 2.4 GHz Bluetooth technology" ([B&H](https://www.bhphotovideo.com/c/product/1572691-REG/lg_mr20ga_aus_magic_remote.html)). An FCC test report for test model `AMT-AKB75855501-MR20GA-...` lists "2402-2480 MHz, Bluetooth V4.2, 40 channels at 2 MHz spacing, GFSK", which is the Bluetooth LE channel plan ([device.report PDF](https://device.report/m/6d88a1973f5b75166d3f67c6e83a6f427ec295e5c0d018fc8a91d48e1457e221.pdf); seen as a search snippet only, because the page is behind a bot wall, **unverified**). On Linux it pairs as Bluetooth HID `000f:3412` ([dangowrt/lg-magic](https://github.com/dangowrt/lg-magic), [brainrom/lg-magic](https://github.com/brainrom/lg-magic), 2025) | Button presses, pointer, and push-to-talk audio to the TV | No |
| HDMI-CEC and eARC, four ports | "Simplink (HDMI CEC): Yes", "eARC (HDMI 2)" on the spec sheet. No HDMI Ethernet Channel is listed | Inbound: device names, vendor IDs and the picture itself | Only what the TV later sends over IP |
| IR | The Magic Remote falls back to IR, for example while the TV is off ([AVS Forum](https://www.avsforum.com/threads/lg-magic-remote-copying-ir-functions.2943286/)). The CX has an `option.irBlaster` key ([bscpylgtv CX dump](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md)) | Commands into the TV, and to set-top boxes for Universal Control | Not relevant (one-way, line of sight) |
| Speakers | Every TV has them | Near-ultrasonic beacons to phones | No |
| Microphone | **None in the TV.** The CX is not a far-field model (`far_field_mic = false` in the profile, observed). Its only microphone is the remote's push-to-talk | Speech, through the remote | Only the back-end lookups that follow |

Which Wi-Fi/Bluetooth chip the CX uses is **unverified**. LG's combo module LGSBWAC92 ("used in several models of LG TVs") is a MediaTek MT7668AUN on USB, with vendor ID 0x043e ([LKML patch, 2020-10](https://lkml.iu.edu/hypermail/linux/kernel/2010.1/07984.html)). That fits the October survey's observation that the CX's Wi-Fi MAC carries a module maker's prefix rather than LG's. The radio set holds either way: Wi-Fi ac plus Bluetooth 5.0. The QuickSet white paper mentions 802.15.4 (RF4CE). Nothing found puts an 802.15.4 radio in the CX or in the MR20.

### 2. Wi-Fi: "off" in the menu does not show the radio is off

**What the sources say.**

- **Wi-Fi Direct is a subsystem of its own in webOS.** The webOS Luna API `com.webos.service.wifi` has `p2p/setstate`, which "enables or disables the Wi-Fi Direct connection, as well as [sets] listen and persistent modes"; "enabling listen state will make this device visible on other Wi-Fi direct devices". Its example group is `"frequency": 5180, "owner": true, "ssid": "DIRECT-vG-[LG] webOS TV WEBOS1"` ([webOS OSE wifi API](https://www.webosose.org/docs/reference/ls2-api/com-webos-service-wifi/)). That is webOS OSE, the open-source relative of the TV's OS, so it shows the design and does not prove CX firmware.
- **LG's own documentation treats Wi-Fi Direct and the Wi-Fi Connection as separate menu items.** Older guides list "Wired Connection, Wi-Fi Connection, and Wi-Fi Direct" as separate entries ([LG W7 quick setup guide](https://www.canadianappliance.ca/pdf/lg/oled-tv/OLED77W7P-quick-setup-guide-english-4611k-1.pdf); [LG Wi-Fi Direct help](https://www.lg.com/ph/support/product-help/CT20192009-1437135133738)). LG's US help tells users to set "[Wi-Fi Screen Share] to [On]" ([LG US](https://www.lg.com/us/support/help-library/lg-tv-smartphone-connection-how-can-i-enable-wifi-direct-on-my-tv--20154726879782)). webOS 5 has no visible Wi-Fi Direct toggle (**unverified**; check the CX menu).
- **Owners report the P2P side staying up.**
  - On a 43NANO (2023-06-10), a neighbour's phone "tries to establish a WiFi Direct connection to my TV like 850 times a day", and the poster found no switch for it. The one suggested fix, "turn WiFi switch off that disables WiFi direct", was never confirmed ([lgwebos.com](https://www.lgwebos.com/topic/9745-turn-off-wifi-direct-on-43nano/)).
  - In 2018 another owner wrote that the TV "appear[s] [in Windows projection devices] only when I turn off TV's wifi connection". In 2019 someone else wrote "DO NOT DISABLE WI-FI" to keep Screen Share working ([lgwebos.com](https://www.lgwebos.com/topic/2189-screen-share-with-windows-10/page/3/)).
  - These are anecdotes from older firmware that contradict each other. Their only use is to show the question is open.
- **The radio is used for more than joining a network.**
  - LG's statement of 2026-09-12: "Nearby Wi-Fi access-point information and signal-strength information are processed separately from device discovery. In markets where ACR is available and enabled, this information may be used to help estimate the TV's approximate location … This processing occurs only when the relevant agreements have been accepted." ([LG US newsroom](https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs)).
  - The Gamers Nexus and Level1Techs investigation of LG OLEDs, the G5 among them, reported that the sets "gathered the names and signal strengths of neighboring Wi-Fi networks along with location data" ([Notebookcheck, 2026-09-07](https://www.notebookcheck.net/LG-smart-TVs-caught-logging-audio-with-screen-off-and-snooping-on-local-devices.1391214.0.html)). The coverage implies a wired set, but whether the radio was scanning while the TV was on Ethernet is **unverified**.
- **No LAN-API read reports the radio's state on the CX.**
  - The CX settings dump (firmware 04.63.25, webOS 5.6.1) has exactly six keys in its `network` category: `allowMobileDeviceAccess`, `bleAdvertisingOnOff`, `deviceName`, `ipv6Enable`, `sscNetworkKey`, `wolwowlOnOff` ([bscpylgtv CX dump](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md)).
  - The only Wi-Fi key anywhere in it is `commercial.wifiScreenShareEn`, a hotel-mode setting.
  - LG documents `com.palm.connectionmanager/getStatus`, which returns `wifi.state` and a `wifiDirect` object, for on-TV apps only ([LG developer reference](https://webostv.developer.lge.com/develop/references/connection-manager)). It is not in the public SSAP endpoint list ([bscpylgtv endpoints](https://github.com/chros73/bscpylgtv/blob/master/bscpylgtv/endpoints.py)), and the Luna side door is refused on 04.64 (observed, profile note).
  - Even `wifi.state = disconnected` would describe the association. It says nothing about the radio.

**What follows.**

- *Exfiltration over Wi-Fi* needs an association. The owner has made the TV forget its networks (README quick start, step 5), so the realistic residue is joining an open network automatically (**unverified** that webOS ever does) and re-joining after a factory reset or setup wizard. Directed probe requests would reveal any network the TV still remembers, and so would a monitor capture.
- *Attack surface* is the real issue. If P2P listen is up, the TV's IP services (SSAP on 3000 and 3001) can be reached by any device that forms a Wi-Fi Direct group with it. Forming a group normally needs a confirmation on the TV (**unverified**: the CX's exact Screen Share prompt behaviour). The 2026 pre-auth chain on 3001 was on webOS 7.5.7, not the CX's webOS 5 ([The Hacker News, via the October survey](https://thehackernews.com/2026/10/lg-smart-tvs-vulnerable-to-pre-auth.html)). The principle still stands: the cable contains only what arrives by cable.
- *AP-scan data* leaves only inside agreement-gated ACR uploads. Live Plus is off, and ACR hosts are blocked. The gateway has this covered whatever the radio does.

**The test** (it settles the question for this firmware; one evening; low risk). Passive scans send nothing, so only *active* transmissions can be ruled out. Wi-Fi Direct listen does answer probes, so the active step below catches it.

Hardware: a USB Wi-Fi adapter with an in-kernel MediaTek driver, such as MT7612U (`mt76x2u`) or MT7921AU (`mt7921u`). The maintainer of the main Linux USB Wi-Fi guide says the "in-kernel Mediatek drivers work in a textbook, standards compliant manner" for monitor mode, unlike the Realtek out-of-tree ones ([morrownr/Monitor_Mode](https://github.com/morrownr/Monitor_Mode)). **Never put `wlan0` into monitor mode: it is the uplink that carries the TV's 60-70 GB a day** (decision 1).

```sh
# 0. Find the dongle (call it wlan1) and keep NetworkManager off it.
iw dev
sudo nmcli device set wlan1 managed no
sudo ip link set wlan1 down && sudo iw dev wlan1 set type monitor && sudo ip link set wlan1 up

# 1. Positive control, 10 min: turn the TV's Wi-Fi ON (no saved network) to learn
#    what its frames look like and confirm <TV_WIFI_MAC> (Settings > All Settings >
#    Support > TV Information shows the MAC; LG help CT10000018-20155444682287).
# 2. Negative control, 10 min: the TV unplugged at the wall.
# 3. The test: the TV on (Active), Wi-Fi off, Ethernet up. Then the same in standby.
#    Dwell on the P2P social channels and the usual GO channels.
for ch in 1 6 11 36 149; do
  sudo iw dev wlan1 set channel "$ch"
  sudo timeout 600 tcpdump -i wlan1 -w "/var/tmp/rf-$(date +%H%M)-ch$ch.pcap"
done

# 4. While step 3 runs, do the active check from outside the TV:
#    an Android phone at Settings > Wi-Fi > Wi-Fi Direct (search), and a Windows
#    laptop at Win+K (Cast). Record whether "[LG] webOS TV" appears.

# 5. Read the result.
for f in /var/tmp/rf-*.pcap; do
  echo "== $f"
  tshark -r "$f" -Y 'wlan.ta == <TV_WIFI_MAC> || frame contains "webOS" || wlan.ssid contains "DIRECT-" || wifi_p2p' \
    -T fields -e frame.time -e wlan.ta -e wlan.fc.type_subtype -e wlan.ssid -e radiotap.dbm_antsignal | head -50
done
```

| Result in step 3 | Meaning | Action |
|---|---|---|
| No frame from `<TV_WIFI_MAC>` and none containing "webOS", and the phone and laptop do not list the TV, in both power states | The radio transmits nothing, Wi-Fi Direct included | Record it as dated evidence in the profile; repeat after each firmware change |
| Probe requests with an empty SSID only | The radio is up and scanning actively | Treat Wi-Fi as on; ask LG; consider the hardware option below |
| Probe requests that name an SSID | The TV still remembers a network | Forget it on the TV; red-line material |
| Beacons or probe responses with a `DIRECT-…[LG] webOS TV` SSID or a P2P IE | Wi-Fi Direct listen or group owner is active: the isolation gap above | Ask whether Screen Share can be turned off; until then, assume nearby devices can reach the TV |

The Wi-Fi Direct device address is often the MAC with the locally-administered bit set. That is why the filter also matches on content (`"webOS"`, `DIRECT-`) and not only on `wlan.ta`.

Hardware fallback, if the radio stays up and the owner wants it gone: the module in some LG TVs is a separate USB board (LGSBWAC92 above). Unplugging its internal cable would take away Wi-Fi and Bluetooth together, and with them the Magic Remote. That is a physical change, close in spirit to decision 4's "do not modify the TV", so it is listed only so the owner knows it exists.

### 3. Bluetooth and BLE

**The remote.** The MR20 is a Bluetooth LE HID device (sources in §1). On recent TVs, the service that handles it is `/usr/sbin/lginput2`. It keeps one Magic Remote at a time and checks the model year: a 2025 TV logs "LGE MR20 is old mrcu! (2020)" ([magic-remote-unlock](https://github.com/dinohusejnovic/magic-remote-unlock)). The microphone audio travels remote to TV over this encrypted BLE link. What the TV does with it is in §5. Nobody has published the voice GATT service; the Linux drivers saw HID report `0xFD` only, and guess that `0xF9` or `0x01` "maybe [are] used … like MIC" ([brainrom/lg-magic](https://github.com/brainrom/lg-magic)).

**What the TV itself does over BLE.**

- **BLE wake from a phone.** On webOS 5 the path is "General > Mobile TV On", with a "Turn on via Bluetooth" switch. ThinQ can power on "webOS 4.5 or later" TVs "with Bluetooth support" (LG Bangladesh and Egypt help pages, text seen as search snippets; **unverified**). The US help confirms the feature on webOS 6: "[TV ON WITH MOBILE] → Toggle on both [TURN ON via WI-FI] and [TURN ON via BLUETOOTH]". It also says Android may use Bluetooth and iPhone Wi-Fi only ([LG US ThinQ help](https://www.lg.com/us/support/help-library/how-to-set-up-the-lg-thinq-app-on-your-lg-smart-tv--20152745625356)). For a phone to wake a TV, the TV's BLE controller has to stay powered in standby.
- **`network.bleAdvertisingOnOff`** exists on the CX and read `"off"` in the reference dump ([bscpylgtv CX dump](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md); also listed by [LGTVCompanion](https://github.com/JPersson77/LGTVCompanion/blob/master/Docs/Commandline.md)). By its name it is the BLE advertising switch behind "Turn on via Bluetooth". That mapping is **unverified**; test T-BLE-2 settles it.
- **Speaker discovery.** The spec sheet's "Auto Notification (Bluetooth easy pairing)" and the keys `general.blueToothSpeakerMode`, `sound.btSpeakerMode` and `sound.btDotAutoScan` point to BLE *scanning* for LG speakers. A passive scan cannot be seen from outside.
- **ThinQ provisioning of a TV does not use BLE.** LG's US help needs "both your smartphone and TV … connected to the same network" and mentions Bluetooth only for power-on ([LG US](https://www.lg.com/us/support/help-library/how-to-set-up-the-lg-thinq-app-on-your-lg-smart-tv--20152745625356)). BLE provisioning is how LG onboards appliances. Behind tvgw, the phone and the TV are never on the same network, so ThinQ cannot pair with the TV at all.

**What a phone app can learn.**

- If the TV advertises, every phone in range receives its BLE address (public, or random and rotating), a name if one is included (webOS uses names of the form `[LG] webOS TV <model>` in its Bluetooth service ([webOS OSE Bluetooth guide](https://www.webosose.org/docs/guides/development/connectivity/bluetooth-guide/))), and manufacturer data tagged with company ID `0x00C4`, which is LG Electronics ([Bluetooth SIG assigned numbers](https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/company_identifiers/company_identifiers.yaml)).
- Android treats this as location data: "on Android 11 and lower, a Bluetooth scan could potentially be used to gather information about the location of the user", and apps must assert `neverForLocation` to say they will not do that ([Android developers](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions)).
- The realistic threat is presence and proximity: an ad SDK in a household or visitor's phone sees "an LG TV of model X, here, every evening". A public BD_ADDR is also a stable identifier that never changes. Bulk data cannot move this way unless an LG app on the phone connects to the TV, and behind tvgw the only LG app that could is ThinQ, used for power-on.

**Measurements.**

- **T-BLE-1, 5 minutes, phone only.** Run nRF Connect (Android or iOS) next to the TV in three states: on, standby, and unplugged as the control. Filter on manufacturer `0x00C4` or on "LG". Record the address type and whether the address changes between scans.
- **T-BLE-2, 20 minutes, on the Pi.** BlueZ 5.82 in trixie ships `bluetoothctl`, `btmon`, `btmgmt` and `hcitool` ([Debian trixie bluez file list](https://packages.debian.org/trixie/arm64/bluez/filelist)). Use a USB Bluetooth dongle (`hci1`) for anything longer than a one-off. The Pi 5's onboard Bluetooth shares the CYW43455 combo chip and its antenna with the Wi-Fi uplink, and users report Wi-Fi throughput falling when Bluetooth is busy, with coexistence parameters in the brcmfmac firmware config ([RPi-Distro firmware-nonfree #33](https://github.com/RPi-Distro/firmware-nonfree/issues/33)). Commands:
  ```sh
  sudo btmon -i hci1 -w /var/tmp/ble.btsnoop &      # raw HCI capture
  sudo bluetoothctl --timeout 300 scan le            # if two controllers: run `select <hci1 address>` first in bluetoothctl
  sudo pkill btmon
  btmon -r /var/tmp/ble.btsnoop | grep -B10 -A6 'Company: LG Electronics (196)'
  #  read "Address type: Public|Random", the name, RSSI
  ```
  Then turn "Turn on via Bluetooth" on and off, re-read `network.bleAdvertisingOnOff` over the LAN API each time (§7), and repeat. The pass result is no LG advertiser with the switch off, in either power state.
- **T-BLE-3, optional, does the remote stream audio with consent declined?** Use Sniffle, NCC Group's BLE sniffer, on a Sonoff CC2652P dongle (listed hardware; Python 3.9+; writes pcap for Wireshark) ([nccgroup/Sniffle](https://github.com/nccgroup/Sniffle)). Sniffle follows a connection only from its connection request, so pull the remote's batteries, start `sniff_receiver.py -m top -r -40 -o /var/tmp/remote.pcap` with the remote held close, put the batteries back, and wait for it to reconnect. Then press the microphone button three times, 30 s apart. The link is encrypted, so read only the *rate*: Wireshark I/O graph of `btle.data_header.length > 0`. If data PDUs jump to more than 5× the idle rate for more than 1 s after each press, the remote streamed audio to a TV that then sent nothing (the README's 2026-10-26 wire observation). If the rate stays flat, the TV never opened the microphone. Either answer is new information. If the remote uses LE privacy, `-m top` may miss it; then use `-S` with a string from its advertising.

### 4. HDMI-CEC and eARC

**What the TV learns from a source.**

- Over CEC: the source's OSD name (up to 14 characters), its IEEE vendor ID and its physical address. These are standard messages; see `cec_msg_set_osd_name`, `cec_msg_device_vendor_id` and `cec_msg_report_physical_addr` in the kernel's [cec-funcs.h](https://github.com/raspberrypi/linux/blob/rpi-6.12.y/include/uapi/linux/cec-funcs.h).
- Over HDMI InfoFrames: a vendor name of 8 characters and a product description of 16 in the SPD InfoFrame (`struct hdmi_spd_infoframe { … char vendor[8]; char product[16]; … }` in [hdmi.h](https://github.com/raspberrypi/linux/blob/rpi-6.12.y/include/linux/hdmi.h)).
- The picture itself. LG says ACR "may operate on … HDMI-connected devices" once the Viewing Information agreement is accepted ([LG, 2026-09-12](https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs)).
- The TV's input list (`tv/getExternalInputList` over SSAP) is where the result shows up, as labels and connected flags.

**What leaves over the network because of it.**

- UEI's QuickSet "uses various device signatures across HDMI, IP, and Zigbee rf4ce networks as an input" and matches the fingerprints against a cloud "device knowledge graph" ([QuickSet technology](https://quicksetcloud.com/technology/)). The white paper names "HDMI, IP, … 802.15.4, Bluetooth, and … Infrared" ([QuickSet white paper, 2018](https://quicksetcloud.com/wp-content/uploads/2018/05/QuickSet_White_Paper_Smart_Entertainment_In_The_Smart_Home.pdf)).
- LG made QuickSet "the standard for device discovery and control" on webOS ([BIS Infotech, 2021-03-02](https://www.bisinfotech.com/ueis-quickset-cloud-now-used-for-lgs-webos-tv-platform/)). LG's help says webOS 5.0 and newer "will automatically execute the Universal Control Setting under certain conditions" (search snippet from LG US help; **unverified**).
- This is the CX's roughly 45-second poll of `ueiwsp.com` that decision 16 blocks (observed). So HDMI identity is the one side channel already proven to reach the network, and it is already contained.
- The CX exposes `other.ueiEnable` (`"off"` in the reference dump), next to `simplinkEnable`, which tvgw already reads, and `simplinkAutoPowerOn` ([bscpylgtv CX dump](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md)). Whether `ueiEnable` is the Universal Control / Auto Device Detection switch is **unverified**. Test T-CEC-1 settles it.

**What does not exist.** No IP path over HDMI has been found on the CX. LG lists no HDMI Ethernet Channel, and eARC "uses two pins … the same pins intended for the HDMI Ethernet Channel" (secondary sources summarised in a search; [HDMI.org eARC](https://hdmi.org/spec21Sub/EnhancedAudioReturnChannel) describes only audio and discovery). A source cannot exfiltrate through the TV over HDMI. The TV can only *learn* from it.

**Measurements.**

- **T-CEC-1, a day, no hardware.** If the owner does not use Universal Control, turn it off on the TV (Settings > All Settings > Connection > Device Connection Settings > Universal Control Settings / Auto Device Detection; the label varies, per LG's webOS 5 help pages). Read `other.ueiEnable` before and after. Pass: `tvgw sql "select strftime('%H', t, 'unixepoch') h, count(*) from dns where name like '%ueiwsp.com' and t > strftime('%s','now','-1 day') group by 1"` goes from about 80 an hour to 0. Adjust the column names to the store's `dns` table.
- **T-CEC-2, Pi side, limited.** The Pi 5's own HDMI CEC adapter, `vc4-hdmi`, registers `CEC_CAP_DEFAULTS | CEC_CAP_CONNECTOR_INFO` and has no `CEC_CAP_MONITOR_ALL` ([vc4_hdmi.c](https://github.com/raspberrypi/linux/blob/rpi-6.12.y/drivers/gpu/drm/vc4/vc4_hdmi.c)). Cabled to the TV, it sees only broadcasts and messages addressed to itself: `cec-ctl -d /dev/cec0 --playback -o probe` then `cec-ctl -d /dev/cec0 -M`. To watch the whole bus between the TV and a real source, an inline Pulse-Eight USB-CEC adapter does advertise `CEC_CAP_MONITOR_ALL` ([pulse8-cec.c](https://github.com/raspberrypi/linux/blob/rpi-6.12.y/drivers/media/cec/usb/pulse8/pulse8-cec.c)); then run `cec-ctl --monitor-all`. Low value unless the owner wants to see exactly what names the TV collects. The SSAP input list gives most of it for free (§7).

### 5. The microphone and the Voice Information agreement

**What happens on the CX.**

- The TV has no microphone. The remote's is push-to-talk (profile, observed).
- LG's 2026-09-12 statement:
  - "Voice recognition operates only when the relevant Voice Information Agreement has been accepted."
  - Speech-to-text starts after a wake word or the microphone button.
  - A session ends after about 10 s of silence, about 18 s at most.
  - "Audio is no longer collected once the voice recognition session ends."
  - "Voice-recognition results and related technical logs may be generated."
  - "Nearby sounds or speech occurring at the same time as a user's command may sometimes appear" in results.
  - It does not say whether speech-to-text runs on the TV or on a server ([LG US newsroom](https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs)).
- With the agreement declined, a press shows a consent prompt, and the wire showed no traffic (README, 2026-10-26, observed). Whether the remote still sends audio to the TV is what T-BLE-3 above answers.

**The agreement can be read by machine.** On the CX, the empty settings category `""` holds `eulaStatus`. It includes `voiceAllowed`, `voice2Allowed`, `acrAllowed`, `acrOnAllowed`, `acrAdAllowed`, `customAdAllowed`, `thirdPartySharingAllowed`, `remoteDiagAllowed`, `chpAllowed`, `marketingOnAllowed` and `networkAllowed`, all `false` in the reference dump except `networkAllowed` ([bscpylgtv CX dump](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md); `eulaStatus` is also in LGTVCompanion's `get_system_settings` list, [LGTVCompanion](https://github.com/JPersson77/LGTVCompanion/blob/master/Docs/Commandline.md)).

That changes what tvgw can watch. Today it watches `option.livePlus`, a feature switch. `eulaStatus` is the *consent record* behind it. A firmware update that brings the Texas-settlement consent pop-up (October survey §6.3), or one accidental "Agree" on a guest's remote press, flips a flag here even when `livePlus` stays off. Which agreement `voice2Allowed` covers is **unverified** (perhaps a second-party assistant).

Other voice keys the CX exposes: `option.turnOnByVoice` (`"off"`), `general.voiceLongDistance` (`"on"` in the dump; probably far-field-related and inert on a CX, **unverified**) and `option.voiceRecognitionLanguage`.

**Store and forward is a reason to keep the wall.** On G5-class sets, Gamers Nexus found that with Ethernet unplugged "the set continued saving voice input locally and uploaded the stored files once network access was restored" ([Notebookcheck](https://www.notebookcheck.net/LG-smart-TVs-caught-logging-audio-with-screen-off-and-snooping-on-local-devices.1391214.0.html)). LG disputes the central claims. Two consequences for tvgw:

1. "No traffic at the moment of the press" does not prove "nothing was captured" on every model.
2. A voice back-end blocked for months could see a burst the day its block is lifted. The profile's voice blocks should be marked never-auto-unblock: decision 20's machinery only adds blocks, and that should stay true for these names. The brief should also look for voice-back-end lookups in the hour after any WAN outage ends.

Neither applies strongly to a CX with consent declined, but both are cheap.

### 6. Ultrasonic beacons and audio ACR

**What is known.**

- **The only systematic search of TV audio** is Arp, Quiring, Wressnegger and Rieck, IEEE EuroS&P 2017 ([paper](https://vamos.mlsec.org/docs/2017a-eurosp.pdf)):
  - Beacons sit at 18-20 kHz and use M-FSK (SilverPush, Lisnr).
  - 234 Android apps carried SilverPush, "constantly listening".
  - 4 of 35 stores broadcast Shopkick beacons.
  - About 6 days of TV streams from 7 countries contained **no** beacons.
  - Compression removes the band: "for MP3 a bitrate of 320 kb/s allows frequencies up to 20 kHz, while a common bitrate of 128 kb/s removes ultrasonic frequencies entirely", and YouTube stereo reaches "up to 18.5 kHz". Several DVB-T channels had nothing above 17 kHz.
- **The link to LG is the ACR vendor.**
  - Alphonso, whose provisioning host the CX still calls with Live Plus off (observed, blocked), ran a phone SDK in 250+ games that listened to TV audio through the phone's microphone ([Betanews, 2018-01-02](https://betanews.com/2018/01/02/alphonso-mobile-audio-targeted-ads), reporting the New York Times).
  - LG took a controlling stake in Alphonso in January 2021 ([LG newsroom](https://www.lg.com/global/newsroom/news/media-entertainment-solution/lg-acquires-controlling-stake-in-tv-data-and-measurement-firm-alphonso/)).
  - Whether that SDK still ships is **unverified**.
  - Here the TV is only a loudspeaker. The gateway cannot see this channel. The defence is microphone permissions on household phones.
- **2025-2026:** no new peer-reviewed study of ultrasonic beacons in TV content was found. Recent blog posts recycle the 2017 numbers. A search that finds nothing is not proof, so this stays **unverified (negative)**.

**What this means here.** The TV plays streaming apps over HTTPS. Their audio is AAC or Dolby at bitrates where 18-20 kHz often survives poorly, which lowers the odds further. The risk is real only if a phone app with microphone permission is listening. It is not a gateway problem, and nothing continuous is worth building. A one-off check costs an evening.

**The test** (T-US-1). It is privacy-preserving: it keeps band energies only, never audio, because the TV's sound is itself a record of what the household watches, and a room microphone also hears speech.

- *Acoustic:* a USB measurement microphone that is flat to 20 kHz (for example, a miniDSP UMIK-1 at 48 kHz). Prove the chain first: play `sox -n -r 48000 /tmp/t.wav synth 5 sine 19000` from a phone next to the microphone, and confirm a peak.
- *Digital, the better option if the TV feeds a soundbar by optical:* a USB S/PDIF receiver captures exactly what the TV outputs. Set the TV's digital output to PCM (`sound.soundOutputDigital = pcm`).

```sh
arecord -l                                   # find <card>
# 10 minutes per programme or ad break, keeping only the high band's statistics:
sox -q -t alsa plughw:<card>,0 -r 48000 -c 1 -n trim 0 600 sinc 18k-21k stat 2>&1 | grep -E 'RMS +amplitude|Maximum amplitude'
sox -q -t alsa plughw:<card>,0 -r 48000 -c 1 -n trim 0 600 sinc 2k-8k  stat 2>&1 | grep 'RMS +amplitude'
```

Flag a capture when the 18-21 kHz RMS is within 30 dB of the 2-8 kHz RMS (20·log10 of the ratio > −30), or when a per-second FFT shows a peak in 18-21 kHz more than 20 dB above that band's median that lasts 2 s or longer (beacons are tonal). A 30-line numpy loop over 1-second `rfft` windows does the second check while discarding samples. Run it across 2-3 hours of ad breaks on the apps the household uses. A clean result rules out beacons for those services on that day, nothing more.

### 7. What the LAN API already offers (the cheapest win)

`tvgw tvcheck` reads 8 keys today (`READS` in `src/tvgw/lgwebos.py`, observed). The CX exposes these as well, all read-only through the same `settings/getSystemSettings` call it already uses (key names and reference values from the [bscpylgtv CX dump](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md), firmware 04.63.25; **04.64 may differ**, so treat a missing key as "unknown", never as "off"):

| Category | Keys | Why |
|---|---|---|
| `""` | `eulaStatus` (flatten: `voiceAllowed`, `voice2Allowed`, `acrAllowed`, `acrOnAllowed`, `acrAdAllowed`, `customAdAllowed`, `thirdPartySharingAllowed`, `remoteDiagAllowed`, `marketingOnAllowed`) | The consent record. Any `true` is a red line |
| `network` | `bleAdvertisingOnOff`, `allowMobileDeviceAccess`, `ipv6Enable` | BLE beacon switch; mobile access; IPv6 intent (the gateway drops it anyway) |
| `other` | `ueiEnable`, `simplinkAutoPowerOn` | QuickSet at the source; CEC wake |
| `option` | `turnOnByVoice`, `quickStartMode`, `irBlaster`, `enableIpControl`, `enableSDDP` | Voice wake; standby power state; IR blasting; Control4 IP control and SDDP discovery |
| `general` | `voiceLongDistance`, `blueToothSpeakerMode` | Voice and Bluetooth features |
| `sound` | `soundOutput`, `eArcSupport`, `btSpeakerMode`, `btDotAutoScan` | Shows when audio goes over Bluetooth (`bt_soundbar`, `tv_speaker_bluetooth`) or eARC |
| SSAP `tv/getExternalInputList` | `label`, `connected` per input | The HDMI inventory QuickSet fingerprints. **Keep it local**: it is a list of household devices, the same class of data the October survey keeps out of the analyst's pack |

How to check by hand first. The CLI parses JSON lists, as in its README's `get_configs "[\"tv.model.*\"]" true`. If it does not accept an empty category argument, use Python.

```sh
K=/var/lib/tvgw/lgtv-keys.sqlite; C=/opt/tvgw-venv/bin/bscpylgtvcommand
sudo $C -p $K <TV_IP> get_system_settings network '["bleAdvertisingOnOff","allowMobileDeviceAccess","ipv6Enable","wolwowlOnOff"]' true
sudo $C -p $K <TV_IP> get_system_settings other   '["ueiEnable","simplinkEnable","simplinkAutoPowerOn"]' true
sudo $C -p $K <TV_IP> get_system_settings option  '["turnOnByVoice","quickStartMode","irBlaster","enableIpControl","enableSDDP"]' true
sudo $C -p $K <TV_IP> get_system_settings sound   '["soundOutput","eArcSupport","btSpeakerMode","btDotAutoScan"]' true
sudo $C -p $K <TV_IP> get_system_settings ""      '["eulaStatus"]' true
sudo $C -p $K <TV_IP> get_inputs true
```

---

## Where this disagrees with the October survey

1. **"Only the Pi can reach the TV's ports, so the isolation already contains this"** (October survey §3.1, on the 2026 pairing-port chain). This holds only for IP over the cable. Until the RF audit in §2 shows that Wi-Fi Direct is down with Wi-Fi off, the claim should read "contains it for wired attackers". Bluetooth is a separate attack surface the cable does not touch at all.
2. **"Make the TV forget its Wi-Fi networks, so it has no unfiltered way out"** (README quick start, step 5, and decision 2). That is necessary but not sufficient. It removes the egress path, not the radio: AP scanning (LG, 2026-09-12) and P2P listen need no saved network. The step should add: "then turn Wi-Fi off, and verify with the RF audit".
3. **`acr_setting` key path** in the proposed `[[privacy_setting]]` record (October survey §6.4). On webOS the stronger signal is the consent flag (`eulaStatus.acrAllowed`), not the feature switch (`option.livePlus`). The record should carry both: `feature_key` and `consent_key`.
4. **The October survey's model of the TV is network-only**: hardware §7 lists NICs, not radios. Profiles v2 should gain a `[radios]` block (`wifi = "802.11ac"`, `wifi_direct = true`, `bluetooth = "5.0"`, `remote = "BLE"`, `mic = "remote-ptt"`, `hdmi_cec = true`), each with its source, so a Samsung or Roku profile states the same facts.
5. **On the README's microphone finding** ("no network activity" on a press): it is correct and well tested at the network layer, but it answers "did anything leave", not "was anything captured". T-BLE-3 answers the second question, and the store-and-forward report (§5) is why it is worth asking.

---

## What to build here

Ranked by value for effort. Effort: S (an evening to two days), M (a week), L (more). Risk is to the running gateway.

| # | What | Effort | Risk | Acceptance test |
|---|---|---|---|---|
| 1 | **`tvcheck` v2**: add the §7 keys to `READS`, flatten `eulaStatus` into `eulaStatus.<flag>` lines, and add red lines `consent flag true` and `bleAdvertisingOnOff != off`. Absent keys become `unknown` and never raise a red line. Feeds the existing tvcheck history, so the brief's Firmware/settings-change logic picks up flips | S | Low. Read-only SSAP calls on the hourly job; a timeout already leaves `TvReading` partly filled | A unit test with a recorded reply; on the Pi, `tvgw tvcheck` lists the new keys, and toggling "Turn on via Bluetooth" on the TV flips `network.bleAdvertisingOnOff` within the hour |
| 2 | **RF audit runbook** (`docs/radio-audit.md`): §2 and §3's T-BLE-1/2, with the result tables, run once and after every firmware change. Results go into the profile as dated `[radios]` evidence | S (doc) plus one evening, and a USB Wi-Fi dongle of about $20-40 | Low, if the dongle is used and NetworkManager is told not to manage it. **High if anyone touches `wlan0`** | Positive control seen; negative control empty; a verdict per row of the §2 table |
| 3 | **QuickSet off at the source** (T-CEC-1) | S | Low; a TV setting, reversible. The cost is the Universal Control feature, already lost under decision 16 | `ueiwsp.com` lookups drop to about 0 an hour, and the query-log noise and the analyst's pack shrink with them |
| 4 | **HDMI inventory diff**: store a hash of the `get_inputs` labels with each tvcheck reading. The brief shows "HDMI inputs changed" (count only, no labels) and any new name looked up within 10 minutes of the change. Labels stay in the root-only TV history, never in the pack | S-M | Low | Plugging in a new source produces one brief line; the pack has no label text (`tvgw analyst --dry-run`) |
| 5 | **Voice-wall guard**: mark the profile's voice back-end category never-auto-unblock (lint: a machine rule may never be an `@@` exception for it), plus a brief line for voice-back-end lookups within an hour after an uplink outage | S | Low | Lint test; a namespace test in the CI virtual gateway (in flight) |
| 6 | **Remote-microphone BLE test** (T-BLE-3) | S-M; a Sonoff CC2652P dongle of about $25, plus flashing Sniffle | Low; a separate radio | A PDU-rate plot around three presses, with a verdict |
| 7 | **BLE census service**, only if T-BLE-1/2 finds the TV advertising: a daily 5-minute passive scan on a USB dongle, writing a single `ble_seen(day, address_type, rssi_max)` row and a brief line | M | Low-medium. A new root service with HCI access; never on the onboard controller (Wi-Fi coexistence) | The row appears on days the switch is on and not otherwise |
| 8 | **Ultrasonic one-off** (T-US-1) | S-M; a measurement microphone or a USB S/PDIF input | Low | Positive control passes; a verdict per service sampled |

**Do not build:**

- monitor mode on `wlan0`;
- continuous scanning on the onboard Bluetooth;
- anything that records raw room or TV audio;
- a Developer Mode app on the TV to call `connectionmanager/getStatus`. It needs an LG developer account signed in on the TV and session renewals, it changes the TV against the spirit of decision 4, and it would report association state, not radio state;
- RF jamming of any kind, which is illegal in the US ([FCC jammer enforcement](https://www.fcc.gov/general/jammer-enforcement)).

---

## Open questions

1. **Does Wi-Fi off stop Wi-Fi Direct listen on 04.64, in Active and in standby?** The RF audit answers this (§2). If it does not, can Screen Share be disabled anywhere in the CX menu? Ask LG support, and cite the 43NANO thread.
2. **Is `network.bleAdvertisingOnOff` the "Turn on via Bluetooth" switch, and what does the advertisement carry?** T-BLE-2 answers this. Is the TV's BLE address public, and is it its Wi-Fi MAC plus or minus one, which would link the two? Compare with the MAC under Support > TV Information.
3. **Does the MR20 stream audio to the TV when Voice Information is declined?** T-BLE-3 answers this.
4. **Is `other.ueiEnable` the Universal Control switch, and does turning it off stop the 45-second QuickSet poll?** T-CEC-1 answers this.
5. **Which agreement is `voice2Allowed`?** It appears in the dump without a label. The on-TV agreement list (Settings > Support > Privacy & Terms) and a read before and after declining each item would map it.
6. **Do the §7 keys exist on 04.64 with the same names?** The dump is from 04.63.25. The first `tvcheck` v2 run on the Pi answers this.
7. **Does any allowed LG channel carry the HDMI inventory or AP-scan results inside TLS?** This cannot be answered without decryption (decision 3). The proxy is request size and timing: a must-allow host whose upload size steps up the hour after a new HDMI source appears.

---

## Sources

LG (vendor)
- LG UK, OLED65CX5LB specifications (radios, Bluetooth LE On, Screen Share, Universal Control, MR20): https://www.lg.com/uk/tvs/oled-tv/oled65cx5lb/
- LG US newsroom, "Understanding Privacy On LG Smart TVs", 2026-09-12: https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs
- LG US help, set up the LG ThinQ app with an LG TV (same network; TV On With Mobile; Android Bluetooth, iPhone Wi-Fi): https://www.lg.com/us/support/help-library/how-to-set-up-the-lg-thinq-app-on-your-lg-smart-tv--20152745625356
- LG Bangladesh and Egypt help pages, webOS 5 "Mobile TV On" and "webOS 4.5 or later … with Bluetooth support" (text from search results; page bodies did not render): https://lg.com/bd/support/product-help/CT40008206-20151500013405 , https://lg.com/eg_en/support/product-help/CT20124005-20151500013423
- LG US help, enable Wi-Fi Direct ("Wi-Fi Screen Share"): https://www.lg.com/us/support/help-library/lg-tv-smartphone-connection-how-can-i-enable-wifi-direct-on-my-tv--20154726879782
- LG Philippines help, Wi-Fi Direct function: https://www.lg.com/ph/support/product-help/CT20192009-1437135133738
- LG quick setup guide, OLED77W7P (separate Wi-Fi Direct menu): https://www.canadianappliance.ca/pdf/lg/oled-tv/OLED77W7P-quick-setup-guide-english-4611k-1.pdf
- LG US help, find the MAC address (webOS 5: Support > TV Information): https://www.lg.com/us/support/help-library/how-to-find-the-mac-address-on-your-lg-tv-CT10000018-20155444682287
- LG webOS TV developer reference, Connection Manager (`getStatus`, `wifiDirect`): https://webostv.developer.lge.com/develop/references/connection-manager
- LG newsroom, controlling stake in Alphonso (2021): https://www.lg.com/global/newsroom/news/media-entertainment-solution/lg-acquires-controlling-stake-in-tv-data-and-measurement-firm-alphonso/

webOS and LAN-API sources
- bscpylgtv, available settings for the OLED CX, firmware 04.63.25: https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md
- bscpylgtv, SSAP and Luna endpoints: https://github.com/chros73/bscpylgtv/blob/master/bscpylgtv/endpoints.py
- LGTVCompanion, command line (`get_system_settings` keys including `bleAdvertisingOnOff`, `ueiEnable`, `eulaStatus`): https://github.com/JPersson77/LGTVCompanion/blob/master/Docs/Commandline.md
- webOS OSE, `com.webos.service.wifi` (P2P enable and listen state; `DIRECT-vG-[LG] webOS TV` example): https://www.webosose.org/docs/reference/ls2-api/com-webos-service-wifi/
- webOS OSE, Bluetooth guide: https://www.webosose.org/docs/guides/development/connectivity/bluetooth-guide/

Remote and radio hardware
- B&H, LG MR20GA Magic Remote: https://www.bhphotovideo.com/c/product/1572691-REG/lg_mr20ga_aus_magic_remote.html
- FCC test report for MR20GA variants (BLE channel plan; search snippet only): https://device.report/m/6d88a1973f5b75166d3f67c6e83a6f427ec295e5c0d018fc8a91d48e1457e221.pdf
- dangowrt/lg-magic, LG Magic Remote Linux driver: https://github.com/dangowrt/lg-magic
- brainrom/lg-magic (2025): https://github.com/brainrom/lg-magic
- magic-remote-unlock (`lginput2`, remote model-year check): https://github.com/dinohusejnovic/magic-remote-unlock
- LKML, btusb support for LG LGSBWAC92 / MT7668AUN (2020-10): https://lkml.iu.edu/hypermail/linux/kernel/2010.1/07984.html
- AVS Forum, Magic Remote IR fallback: https://www.avsforum.com/threads/lg-magic-remote-copying-ir-functions.2943286/

Owner reports and press, 2018-2026
- lgwebos.com, "Turn off WiFi Direct on 43NANO" (2023-06): https://www.lgwebos.com/topic/9745-turn-off-wifi-direct-on-43nano/
- lgwebos.com, "Screen Share with Windows 10", page 3 (2018-2019): https://www.lgwebos.com/topic/2189-screen-share-with-windows-10/page/3/
- Notebookcheck, Gamers Nexus and Level1Techs LG findings (2026-09-07): https://www.notebookcheck.net/LG-smart-TVs-caught-logging-audio-with-screen-off-and-snooping-on-local-devices.1391214.0.html
- Betanews, Alphonso phone-microphone SDK (2018-01-02): https://betanews.com/2018/01/02/alphonso-mobile-audio-targeted-ads

Standards, kernels and tools
- Bluetooth SIG company identifiers (0x00C4 is LG Electronics): https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/company_identifiers/company_identifiers.yaml
- Android developers, Bluetooth permissions: https://developer.android.com/develop/connectivity/bluetooth/bt-permissions
- Debian trixie, bluez 5.82 file list: https://packages.debian.org/trixie/arm64/bluez/filelist
- RPi-Distro firmware-nonfree issue 33 (brcmfmac Bluetooth/Wi-Fi coexistence): https://github.com/RPi-Distro/firmware-nonfree/issues/33
- morrownr, Monitor_Mode: https://github.com/morrownr/Monitor_Mode
- NCC Group, Sniffle: https://github.com/nccgroup/Sniffle
- Raspberry Pi kernel, `vc4_hdmi.c` (CEC capabilities): https://github.com/raspberrypi/linux/blob/rpi-6.12.y/drivers/gpu/drm/vc4/vc4_hdmi.c
- Raspberry Pi kernel, `pulse8-cec.c` (`CEC_CAP_MONITOR_ALL`): https://github.com/raspberrypi/linux/blob/rpi-6.12.y/drivers/media/cec/usb/pulse8/pulse8-cec.c
- Linux, `cec-funcs.h` and `hdmi.h` (CEC messages; SPD InfoFrame fields): https://github.com/raspberrypi/linux/blob/rpi-6.12.y/include/uapi/linux/cec-funcs.h , https://github.com/raspberrypi/linux/blob/rpi-6.12.y/include/linux/hdmi.h
- HDMI.org, eARC: https://hdmi.org/spec21Sub/EnhancedAudioReturnChannel

QuickSet
- QuickSet technology: https://quicksetcloud.com/technology/
- QuickSet white paper (2018): https://quicksetcloud.com/wp-content/uploads/2018/05/QuickSet_White_Paper_Smart_Entertainment_In_The_Smart_Home.pdf
- BIS Infotech, QuickSet Cloud on webOS (2021-03-02): https://www.bisinfotech.com/ueis-quickset-cloud-now-used-for-lgs-webos-tv-platform/

Ultrasonic
- Arp, Quiring, Wressnegger, Rieck, "Privacy Threats through Ultrasonic Side Channels on Mobile Devices", IEEE EuroS&P 2017: https://vamos.mlsec.org/docs/2017a-eurosp.pdf
