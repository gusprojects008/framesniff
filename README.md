# framesniff

A command-line tool for network exploration and analysis, focusing on capturing and manipulating frames across different layers and communication standards (Wi-Fi (IEEE 802.11 / DLT_IEEE802_11_RADIO), Ethernet (IEEE 802.3 / DLT10MB), Bluetooth HCI / DLT_BLUETOOTH_HCI_4). Designed to enable in-depth analysis of wireless network protocols, as well as exploration of the devices and frames transmitted by them.

The current focus is on development to support the IEEE 802.11 standard. Bluetooth and Ethernet are not yet supported.

## License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

## Overview

framesniff allows you to:

* Capture frames applying storage and display filters.
* Scan in station or monitor mode (with optional channel hopping).
* Generate hashcat-compatible files (`22000` format) from JSON containing EAPOL/PMKID data.
* Convert raw hexadecimal packets or frames to pcap.
* Send raw (hex) frames over an interface.

## Current main features

* `set-monitor <ifname>` / `set-station <ifname>` — toggle interface mode.
* `scan-monitor` — scan in real-time monitor mode with channel hopping support. * `sniff <ifname>` — capture frames with DLT options, filters, count, timeout, saving to JSON, and other options.
* `generate-22000` — convert JSON (EAPOL/PMKID) to a `hashcat.22000` file.
* `hextopcap` — generate a pcap file from JSON containing packets in raw hexadecimal.
* `send-raw <ifname>` — send frames/packets in raw hexadecimal over an interface.

## Supported Formats / DLTs

* `DLT_IEEE802_11_RADIO` — 802.11 frames with a radiotap header.
* `EN10MB` — Ethernet (pcap linktype EN10MB).
* `DLT_BLUETOOTH_HCI_H4` — Bluetooth HCI (H4).

## Requirements

* Operating System: Linux.
* Permissions: Many operations require root privileges (capturing in monitor mode, changing interface mode, sending frames).
* Python 3.13.
* Optional tools for inspecting results (e.g., Wireshark/tshark) to open generated pcap files if necessary.

## Installation (suggestion)

1. Clone the repository:

```bash
git clone https://github.com/gusprojects008/framesniff/framesniff.git
cd framesniff
```
See the features the program provides:

```bash
python framesniff.py --help
```
2. Example of an offline brute force attack on MICs (Message Integrity Code) of EAPOL frames from WPA2-Personal networks.

## Legal Notice
***Please use these techniques and knowledge in controlled environments where you are authorized to work, whether for study, exploration, development, or even just to satisfy your curiosity. I am not responsible for any misuse of the tool; it was and is being developed strictly for educational and professional purposes. And seriously, it's MUCH easier to ask the network owner for the password, or work (preferably honestly) and earn money to hire an ISP (Internet Service Provider), than to spend hours studying and wasting computing resources just to get the network password (PSK) without any further aspirations.***

- ### 🧠 See my blog about how Wi-Fi networks work and my mind map about the main Wi-Fi network attack methods
- [How wireless networks work](https://gustavoaraujo.pages.dev/blogs/como-funcionam-as-comunica%C3%A7oes-sem-fio)
- [Mind maps about Wi-Fi networks](https://github.com/gusprojects008/mapas-mentais/blob/main/markdowns/ataques-redes-wifi.md)

**After starting to sniff on the target frequency, it is recommended to send a few frames of Deauthentication for networks or devices that do not have PMF (Protection Management Frames) enabled. Before capturing any deauthentication frame using the program sniff or Wireshark, it is recommended that you open the frame's hexadecimal content in a text editor or hex editor. Use hextopcap to convert it to pcap so it can be opened and viewed by Wireshark. Using Wireshark's hexdump, go through the fields and modify the frame's hexadecimal characters according to the Wireshark hexdump's correspondence. To do this, configure it to match the target AP's BSSID and the target device's MAC address.**

***
View more detailed information about each frame (including the raw hexadecimal content of each) after the capture is made using scan-monitor or sniff. Check the vendor-specific information for more information about the AP, including version numbers, model, and UUID. This and other information can help you find more information about the device, and even exploits in some cases.
***

Switch to monitor:

```bash
sudo python framesniff.py set-monitor wlan0
```
Scan in monitor mode (with TUI and hopping):

**Will display all nearby APs and devices, including their associations.**

***Pay attention and check the WPS status. If enabled (YES), see more information about the WPS configuration in the scan-monitor output file, which will be saved after the program closes. Press Ctrl+s or F12 to save the information captured by the TUI (Text User Interface). Depending on the supported WPS operating mode, it is possible to brute-force the remote number and, in a short period of time (2 to 8 hours), discover the PSK (Pre-Shered Key). Tools like [bully](https://github.com/kimocoder/bully) can do this, but in some cases the AP may enter full blocking mode for WPS authentication, only to return to normal after a few hours.***

```bash
sudo python framesniff.py scan-monitor wlan0 --dlt DLT_IEEE802_11_RADIO --hopping-interval 5.0 --bands 2.4
```

After detecting and obtaining information from the AP(s) and target device(s), configure an interface monitor for the same frequency or channel as the AP (WPA2-Personal) and target device.

```bash
sudo python framesniff.py set-frequency wlan0 2417
```

Capture EAPOL frames (sniff):

```bash
sudo python framesniff.py sniff wlan0 --dlt DLT_IEEE802_11_RADIO --store-filter "mac_hdr.fc.type == 2 and mac_hdr.mac_src.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.mac_dst.mac in ('aa:bb:cc:dd:ee:ff', 'ab:cd:ef:ab:cd:ef') and mac_hdr.bssid.mac == 'aa:bb:cc:dd:ee:ff' and llc.type == '0x888e' and body.eapol" --display-filter "mac_hdr, body" -o eapol-frames-attack.json
```

Generate hashcat file 22000:

***If you analyze the captured EAPOL frames and identify the PMKID (usually in EAPOL frame 1), you can use it to bruteforce faster. For more details see the generate-22000 help.***

```bash
python framesniff.py generate-22000 --bitmask 2 --ssid MyNetwork --input eapol-frames-attack.json --output hashcat.22000
```

Convert JSON hex to pcap:

```bash
python framesniff.py hextopcap --dlt DLT_IEEE802_11_RADIO -i raw_packets.json -o output.pcap
```

Send raw frames:

```bash
sudo python framesniff.py send-raw wlan0 -i raw_packets.json --count 10 --interval 0.5
```

## JSON file structure — examples

### `send-raw` / `hextopcap` — format Prohibited

```json
{ 
"raw": [ 
"00112233445566aabbccddeeff...", 
"0011222..." 
]
}
```

### `generate-22000` — bitmask 1 (PMKID)

```json
{ 
"ap_mac": "aa:bb:cc:dd:ee:ff", 
"sta_mac": "11:22:33:44:55:66"
"pmkid": "e4f3... (32 hex chars)", 
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

## IDEAS AND FUTURE IMPLEMENTATIONS
This section contains some insights I gained during development, but there's no guarantee they will be implemented; they need to be reviewed, and further research is needed to decide whether they will be implemented in practice.

* Capture in monitor mode will only be done from raw sockets; analysis, decryption, etc., will be done from LLC payloads. In other words, sniffing will only occur in monitor mode. I'm not sure if I'll implement an option for capturing at specific layers l3, l4, and l7, as I think it would complicate some other functions and the program's purpose.
* Option for the user to send properly encrypted frames so the AP can receive them. * Allow the user to provide a JSON file with the information needed to decrypt protected frames, information such as:
`{1: {"bssid": "", "ssid": "", "psk": "", "clients": {1: {"mac": "", "handshake": ""}}}}` — this is for WPA2 PSK networks. Further research would be needed to see how this would work for WPA3 networks and other WPA2/WPA3 modes, such as enterprise, etc.
* A feature that allows the user to channel-hop within a specific channel range; the user can define which channels will not be used or can skip specific bands (0 for 2.4 GHz, 1 for 5 GHz, 2 for 2.4 GHz and 5 GHz) and thus skip the channels that will not be used. * With `createpkt`, it allows the user to modify and build a frame/packet from provided templates, or modify a specific sequence or packet from a JSON file containing all the raw hex packets they want to edit `{"raw": ["12345abcef", "12345abcef"]}` and open it in the graphical packet editing interface. The user can save a specific packet they are editing or all the packets they were editing; for this, they can always choose the name of the output file where the raw hex packet(s) will be written. The format of these final files will be:
`{"unique identifier of this specific packet or frame": "", "raw": "0123456789101112131415abcdef"}`.
* `pcaptohex` takes each raw frame from a pcap file and writes its raw hexadecimal content to a `.json` file that can be used by the program.
* Basic functions for interface manipulation without the need for `iw`, using the `wnlpy` module, which is under development.
* Possibly remove the channel-hopping function from `monitor-scan` and make it independent; that is, the user would have to call it separately, thus allowing for more robust configuration.
* In the channel-hopping function, allow the user to set the channel width.
* Consider what to do in cases of virtual monitor interfaces.
* Instruct users on the standard for filtering expressions. I recommend capturing frames with the `sniff` function and then parsing the JSON result.
* Based on the functions I provide, instruct them on the forms and possibilities of use; For example: analyze captured frames with Wireshark using the `hextopcap` function (to convert frames captured with framesniff to pcap), or capture raw frames with `sniff` and use the `send-frames` function to resend all captured raw frames, thus allowing you to regenerate/simulate previously captured traffic.
* Use GitHub docs.

---

## WHAT'S MISSING? FIX/ADD

* Parse all tagged parameters (as many as possible).
* Complete parsing of country info.
* Complete parsing of RM capabilities.
* Complete parsing of ERP info, TIM.
* Complete parsing for extended capabilities.
* Format AP and client tables into real tables.
* Parse the capabilities of the fixed parameters.
* Fix `set_frequency` and channel hopping functions.
* Refactor all parsers to include ALL parsed data, including values, tags and lengths etc... everything that is in the frame or packet, not only the relevant information.
* Review parsers and their output.
* Implement module for generation/editing of frames/packets.
* Add more checks for error detection.
* Make error messages more traceable and user-friendly.
* Use more logging for operation messages.
* Review all code.
* Review the operation of all features, and verify whether they are functioning properly.
* Develop a TUI interface for sniff, which will be similar to tshark.
* Develop a TUI interface for createpkt.
* Improve argparse in the sniff.py frame, using type etc...
* Leave safety checks at critical points in the program.
* Analyze all marked parameters (as much as possible).
* Complete analysis of country information.
* Complete analysis of RM resources.
* Complete analysis of ERP and TIM information.
* Complete analysis of extended resources.
* Format AP and client tables into real tables.
* Analyze the resources of the corrected parameters.
* Fix the `set_frequency` and channel hopping functions. * Refactor all parsers to include ALL parsed data, including values, tags, lengths, etc.—everything in the frame or packet, not just the relevant information.
* Revise the parsers and their outputs.
* Implement a module for generating/editing frames/packet.
* Add more checks for error detection.
* Make error messages more traceable and easier to use.
* Use more logging for operation messages.
* Review all code.
* Review the operation of all features and verify that they are working correctly.
* Develop a TUI interface for sniff, which will be similar to tshark.
* Develop a TUI interface for createpkt.
* Improve argparse in the sniff.py framework, using type, etc.
* Include safety checks in critical points of the program.
* Add videos and images to the documentation.
* Fix the mac header parser.
