# framesniff

A command-line tool for network exploration and analysis, focused on capturing and manipulating frames across different layers and communication standards (Wi-Fi (IEEE 802.11 / DLT_IEEE802_11_RADIO), Ethernet (IEEE 802.3 / EN10MB), Bluetooth HCI / DLT_BLUETOOTH_HCI_H4). Designed to enable in-depth analysis of wireless network protocols, as well as exploration of devices and the frames they transmit.

The current focus is on developing support for the IEEE 802.11 standard. Bluetooth and Ethernet are not yet supported.

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

## Overview

framesniff allows you to:

* Capture frames with storage and display filters.
* Scan in station or monitor mode (with optional channel hopping).
* Generate Hashcat-compatible files (format `22000`) from JSON containing EAPOL/PMKID data.
* Convert raw hexadecimal packets or frames into pcap.
* Send/inject raw (hex) frames through an interface.

## Main features currently available

* `set-monitor <ifname>` / `set-station <ifname>` — switch interface mode.
* `scan-monitor` — real-time monitor-mode scanning with channel hopping support.
* `sniff <ifname>` — capture frames with options for DLT, filters, count, timeout, JSON output, and more.
* `generate-22000` — convert JSON (EAPOL/PMKID) into a `hashcat.22000` file.
* `hextopcap` — generate a pcap file from JSON containing raw hexadecimal packets.
* `send-raw <ifname>` — transmit raw (hex) frames/packets through an interface.

## Supported formats / DLTs

* `DLT_IEEE802_11_RADIO` — 802.11 frames with radiotap headers.
* `EN10MB` — Ethernet (pcap linktype EN10MB).
* `DLT_BLUETOOTH_HCI_H4` — Bluetooth HCI (H4).

## Requirements

* Operating system: Linux.
* Permissions: many operations require root privileges (monitor-mode capture, interface mode changes, raw frame injection).
* Python 3.13.
* Optional tools for inspecting results (e.g., Wireshark/tshark) to open generated pcap files if needed.

## Installation (suggested)

1. Clone the repository:

```bash
git clone https://github.com/gusprojects008/framesniff/framesniff.git
cd framesniff
```

Run `setup.sh`, enter the Python virtual environment, and explore the program’s features:

```bash
./setup.sh
source venv/bin/activate
sudo venv/bin/python framesniff.py --help
```

2. Example of an offline brute-force attack on EAPOL frame MICs from WPA2-Personal networks.

## Legal Notice

***Please use these techniques and the knowledge provided only in controlled environments where you have explicit authorization, whether for study, exploration, development, or simply to satisfy curiosity. I am not responsible for any misuse of this tool. It is being developed strictly for educational and professional purposes.
And seriously, it is FAR easier to just ask the network owner for the password, or work (preferably honestly) and pay for your own ISP, than to spend hours studying and burning computational resources only to obtain the network password (PSK) with no further purpose.***

* ### 🧠 Check out my blog explaining how Wi-Fi networks work and my mind map of common Wi-Fi attack techniques:

  * [How wireless communications work](https://gustavoaraujo.pages.dev/blogs/como-funcionam-as-comunica%C3%A7%C3%B5es-sem-fio)
  * [Wi-Fi mind maps](https://github.com/gusprojects008/mapas-mentais/blob/main/markdowns/ataques-redes-wifi.md)

**After starting the sniff on the target frequency, it is recommended to send deauthentication frames to APs or devices without PMF (Protected Management Frames) enabled. To do this, first capture a deauth frame using this program or Wireshark, open its raw hexadecimal content in a text or hex editor, then use `hextopcap` to convert it into a pcap. Open the pcap in Wireshark, inspect the hexdump, and adjust the hexadecimal fields accordingly to match the target AP’s BSSID and the device’s MAC address.**

---

View detailed information for each frame (including raw hexadecimal content) after the capture performed by `scan-monitor` or `sniff`.
Check vendor-specific information for additional AP details such as version numbers, model, and UUID, which can sometimes be used to search for vulnerabilities.

---

Switch to monitor mode:

```bash
sudo venv/bin/python framesniff.py set-monitor wlan0
```

**This will display all nearby APs and devices, updated in real time, including their associations. To inspect devices not associated with any AP, analyze the `scan-monitor` output file (generated after the operation), which contains all frames captured during the scan.**

***Pay close attention to the WPS status. If enabled (YES), check the WPS configuration in the scan output file saved after stopping the program. Press Ctrl+S or F12 to save the TUI-captured data. Depending on the WPS modes supported, brute-force and Pixie Dust attacks may be possible. Tools like [bully](https://github.com/kimocoder/bully) can perform these attacks, though the AP may lock WPS authentication temporarily.***

```bash
sudo venv/bin/python framesniff.py scan-monitor wlan0 --dlt DLT_IEEE802_11_RADIO
```

After detecting the target AP and device, set your monitor interface to their frequency or channel:

```bash
sudo venv/bin/python framesniff.py set-frequency wlan0 2417
```

Capture EAPOL frames:

```bash
sudo venv/bin/python framesniff.py sniff wlan0 --dlt DLT_IEEE802_11_RADIO --store-filter "mac_hdr.fc.type == 2 and mac_hdr.mac_src.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.mac_dst.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.bssid == 'aa:bb:cc:dd:ee:ff' and llc.type == '0x888e' and body.eapol" --display-filter "mac_hdr, body" -o eapol-frames-attack.json
```

Generate hashcat 22000 file:

***If the captured EAPOL frames include a PMKID (usually in message 1), you can perform a faster brute-force attack. See the `generate-22000` help for details.***

```bash
venv/bin/python framesniff.py generate-22000 --bitmask 2 --ssid MyNetwork --input eapol-frames-attack.json --output hashcat.22000
hashcat -m 22000 hashcat.22000 wordlist.txt --show
```

---

Other usage modes:

Convert raw hexadecimal frames/packets to pcap:

```bash
venv/bin/python framesniff.py hextopcap --dlt DLT_IEEE802_11_RADIO -i raw_packets.json -o output.pcap
```

Send raw frames:

```bash
sudo venv/bin/python framesniff.py send-raw wlan0 -i raw_packets.json --count 10 --interval 0.5
```

## JSON file structure — examples

### `send-raw` / `hextopcap` — input format

```json
{
  "raw": [
    "00112233445566aabbccddeeff...",
    "dead beef..."
  ]
}
```

### `generate-22000` — bitmask 1 (PMKID)

```json
{
  "ap_mac": "aa:bb:cc:dd:ee:ff",
  "sta_mac": "11:22:33:44:55:66",
  "pmkid": "e4f3... (32 hex chars)"
}
```

### `generate-22000` — bitmask 2 (raw EAPOL messages)

```json
{
  "raw": [
    "0103005f02030a...",
    "0103005f02030a..."
  ]
}
```
