# framesniff

A command-line tool for network exploration and analysis, focusing on capturing and manipulating frames across different layers and communication standards (Wi-Fi (IEEE 802.11 / DLT_IEEE802_11_RADIO), Ethernet (IEEE 802.3 / DLT_EN10MB), Bluetooth HCI / DLT_BLUETOOTH_HCI_H4). Designed to enable in-depth analysis of wired and wireless network protocols, as well as exploration of the devices and frames transmitted by them.

The current focus is on development for IEEE 802.11 support. Bluetooth and Ethernet are not supported yet.

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

## Overview

framesniff allows you to:

* Capture frames using store and display filters.
* Perform scans in station or monitor mode (with optional channel hopping).
* Generate hashcat-compatible files (format `22000`) from JSON containing EAPOL/PMKID data.
* Convert raw hexadecimal packets or frames into pcap files.
* Send/inject raw frames (hex) through an interface.

## Main features (currently)

* `set-monitor <ifname>` / `set-station <ifname>` — switch interface mode.
* `scan-monitor` — real-time monitor-mode scan with channel hopping support.
* `sniff <ifname>` — capture frames with options for DLT, filters, count, timeout, save to JSON, and other options.
* `generate-22000` — convert JSON (EAPOL/PMKID) into a `hashcat.22000` file.
* `hextopcap` — produce a pcap file from JSON containing raw hexadecimal packets.
* `send-raw <ifname>` — send raw frames/packets in hexadecimal through an interface.

## Supported formats / DLTs

* `DLT_IEEE802_11_RADIO` — 802.11 frames with radiotap header.
* `EN10MB` — Ethernet (pcap linktype EN10MB).
* `DLT_BLUETOOTH_HCI_H4` — Bluetooth HCI (H4).

## Requirements

* Operating system: Linux.
* Permissions: Many operations require root privileges (monitor-mode capture, changing interface mode, sending frames).
* Python 3.13.
* Optional tools for inspecting results (e.g., Wireshark/tshark) to open generated pcap files if needed.

## Installation (suggested)

1. Clone the repository:

```bash
git clone https://github.com/gusprojects008/framesniff/framesniff.git
cd framesniff
```

See the program features:

```bash
python framesniff.py --help
```

2. Example of an offline brute-force attack against MICs (Message Integrity Codes) of EAPOL frames from WPA2-Personal networks.

## Legal Notice

***Please use the techniques and knowledge shared here only in controlled environments where you have authorization to act — for study, exploration, development, or simple curiosity. I am not responsible for misuse of the tool; it was and is being developed strictly for educational and professional purposes.
And seriously: it is MUCH easier to ask the network owner for the password, or to work (preferably honestly) and pay for an ISP (Internet Service Provider), than to spend hours studying and using computational resources just to obtain the network password (PSK) with no further intent.***

* ### 🧠 See my blog about how Wi-Fi networks work and my mind map about main Wi-Fi attack methods

  * [How wireless networks work](https://gustavoaraujo.pages.dev/blogs/como-funcionam-as-comunica%C3%A7oes-sem-fio)
  * [Mind maps about Wi-Fi networks](https://github.com/gusprojects008/mapas-mentais/blob/main/markdowns/ataques-redes-wifi.md)

**After starting the sniff on the targets' frequency, it is recommended to send some deauthentication frames to APs or devices that do not have PMF (Protected Management Frames) enabled. Before capturing any deauthentication frame via the program's sniff or Wireshark, open the frame's hexadecimal content in a text or hex editor and use `hextopcap` to convert it to pcap so it can be opened and viewed in Wireshark. Using Wireshark's hexdump, review the fields and modify the frame's hexadecimal characters according to the hexdump correspondence. Configure the frame to match the target AP's BSSID and the target device's MAC.**

---

View more detailed information about each frame (including the raw hexadecimal content of each) after a capture performed by `scan-monitor` or `sniff`.
Check the vendor-specific information to learn more about the AP, including version numbers, model and UUID; with these and other details you can search for additional information about the device, and in some cases find potential exploits.

---

Switch to monitor mode:

```bash
sudo python framesniff.py set-monitor wlan0
```

**This will display all nearby APs and devices with real-time updates, including their associations. To inspect devices that were not associated with an AP, I recommend analyzing the `scan-monitor` result file (generated after the operation ends), which contains all frames captured during the `scan-monitor` run.**

***Pay attention to and verify the WPS status. If enabled (YES), see more information about the WPS configuration in the `scan-monitor` output file, which will be saved after the program terminates. Depending on the WPS operation modes supported, brute-force attacks such as Pixie Dust may be possible. Tools like [bully](https://github.com/kimocoder/bully) can perform these, but in some cases the AP may lock WPS authentication completely, returning to normal only after several hours.***

```bash
sudo python framesniff.py scan-monitor wlan0 --dlt DLT_IEEE802_11_RADIO --hopping-interval 5.0 --bands 2.4
```

After detecting and gathering information about the target AP(s) and device(s), set the monitor interface to the same frequency or channel the AP (WPA2-Personal) and the target device are using.

```bash
sudo python framesniff.py set-frequency wlan0 2417
```

Capture EAPOL frames (sniff):

```bash
sudo python framesniff sniff wlan0 --dlt DLT_IEEE802_11_RADIO --store-filter "mac_hdr.fc.type == 2 and mac_hdr.mac_src.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.mac_dst.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.bssid == 'aa:bb:cc:dd:ee:ff' and llc.type == '0x888e' and body.eapol" --display-filter "mac_hdr, body" -o eapol-frames-attack.json
```

Generate a hashcat 22000 file:

***If you inspect the captured EAPOL frames and identify the PMKID (usually in EAPOL frame 1), you can use it to speed up brute-force attacks. For more details, consult the `generate-22000` help.***

```bash
python framesniff.py generate-22000 --bitmask 2 --ssid MyNetwork --input eapol-frames-attack.json --output hashcat.22000
hashcat -m 22000 hashcat.22000 wordlist.txt --show
```

---

Other usage modes:

Convert raw hexadecimal frames or packets to pcap:

```bash
python framesniff.py hextopcap --dlt DLT_IEEE802_11_RADIO -i raw_packets.json -o output.pcap
```

Send raw frames:

```bash
sudo python framesniff.py send-raw wlan0 -i raw_packets.json --count 10 --interval 0.5
```

## JSON file structure — examples

### `send-raw` / `hextopcap` — input format

```json
{ 
  "raw": [ 
    "00112233445566aabbccddeeff...", 
    "deadbeef..." 
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

---

## FUTURE IDEAS AND IMPLEMENTATIONS

This section contains some insights I gained during development; they may or may not be implemented and require review and further study to decide if they should be implemented in practice.

* Monitor-mode capture will be performed only from raw sockets; analysis, decryption, etc., will be done from LLC payloads. In other words, sniffing will occur only in monitor mode. I am not sure whether I will implement options to capture at specific L3, L4, or L7 layers, as I believe that would complicate some other functions and the program's purpose.
* Option for the user to send properly encrypted frames so the AP can accept them.
* Allow the user to provide a JSON file with the necessary information to decrypt protected frames, such as:
  `{1: {"bssid": "", "ssid": "", "psk": "", "clients": {1: {"mac": "", "handshake": ""}}}}` — this for WPA2 PSK networks. It would still be necessary to study how this would work for WPA3 and other WPA2/WPA3 modes like enterprise, etc.
* Function to let the user perform channel hopping across a specific set of channels; the user can define which channels will not be used or pass specific bands (0 for 2.4 GHz, 1 for 5 GHz, 2 for 2.4 GHz and 5 GHz) and thus skip channels that should not be used.
* With `createpkt`, allow the user to modify and build a frame/packet from provided templates, or edit a specific sequence or packet from a JSON file containing all raw hexadecimal packets they want to edit `{"raw": ["12345abcef", "12345abcef"]}` and open it in a packet editing GUI. The user can save a specific packet they are editing or all packets they were editing; they can always choose the output filename where the final raw hexadecimal packet(s) will be written. Final file format would be:
  `{"unique identifier of that specific packet or frame": "", "raw": "0123456789101112131415abcdef"}`.
* `pcaptohex` takes each raw frame from a pcap file and writes its raw hexadecimal content to a `.json` file usable by the program.
* Basic interface manipulation functions without requiring `iw`, using the `wnlpy` module, which is under development.
* Possibly remove the channel-hopping function from `monitor-scan` and make it independent; i.e., the user would have to call it separately, allowing a more robust configuration.
* In channel-hopping, allow the user to define channel width.
* Consider handling virtual monitor interfaces.
* Document the expression standard for filtering. I recommend capturing frames with `sniff` and then analyzing the resulting JSON.
* Based on provided functions, document usage examples and possibilities; e.g., analyze captured frames with Wireshark using `hextopcap` (to convert frames captured with framesniff to pcap), or capture raw frames with `sniff` and use `send-frames` to resend all captured raw frames, enabling recreation/simulation of previously captured traffic.
* Use GitHub docs.

---

## WHAT IS MISSING? FIX/ADD

* Parse and analyze all marked parameters (as many as possible).
* Full analysis of country information.
* Full analysis of RM capabilities.
* Full analysis of ERP and TIM information.
* Full analysis for extended capabilities.
* Format AP and client tables as real tables.
* Analyze features of corrected parameters.
* Fix `set_frequency` and channel-hopping functions.
* Refactor all parsers to include ALL parsed data, including values, tags, lengths, etc.—everything present in the frame or packet, not only the relevant fields.
* Review parsers and their outputs.
* Implement module for frame/packet generation/editing.
* Add more checks for error detection.
* Make error messages more traceable and user-friendly.
* Use more logging for operational messages.
* Review all code.
* Verify the operation of all features and ensure they work correctly.
* Develop a TUI for sniffing, similar to tshark.
* Develop a TUI for `createpkt`.
* Improve `argparse` in `sniff.py`, using types, etc.
* Put security checks at critical points in the program.
* Add videos and images to the documentation.
* Fix MAC header parser.
