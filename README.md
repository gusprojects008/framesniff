# PRE-README

## See the development branch:
[Development branch](https://github.com/gusprojects008/framesniff/tree/development)

## DOCUMENTAR

The current focus is on the Wi-Fi 802.11 standard at the L2 layer of the OSI model.

Instruct users about the standard for filtering expressions. I recommend capturing frames with the `sniff` function, and then analyzing the JSON result.
Based on the functions I provide, instruct the ways and possibilities of use; for example: analyze captured frames with Wireshark via the `hextopcap` function (to convert frames captured with framesniff to pcap), or capture raw frames with `sniff` and use the `send-frames` function to resend all captured raw frames, thus being able to regenerate/simulate the captured traffic.

For now there is no user-friendly raw hexadecimal packet editor, so to modify the raw hexadecimal packet I recommend converting the raw hexadecimal content into a pcap file, open it in Wireshark, enable raw packet view, go through the fields and modify the packet in a text editor according to the fields and values shown in Wireshark. To implement a raw hexadecimal packet editor, it would be necessary to add all values of all parsed packet fields, so as to implement a friendly TUI that consumes the data returned by the parsers and provides an interface to expose packet information and modify their hexadecimal field values (it will simply be a hex editor with field names next to them to ease understanding).

Section to indicate future implementations.
Use GitHub docs.
Provide a basic tutorial for brute-force testing of Wi-Fi WPA2-Personal passwords by capturing EAPOL frames and using the `generate-22000` function.

---

## IDEAS AND FUTURE IMPLEMENTATIONS

This section contains some insights I have during development, but they are not necessarily certain to be implemented; they need to be reviewed and more study is required to decide whether to implement them in practice.

* Monitor-mode capture will be done only from raw sockets; parsing, decryption, etc. will be done from LLC payloads. In other words, sniffing will only occur in monitor mode.
* Option for the user to send correctly encrypted frames so the AP can receive them.
* Allow the user to provide a JSON file with the information necessary to decrypt protected frames, information such as:
  `{1: {"bssid": "", "ssid": "", "psk": "", "clients": {1: {"mac": "", "handshake": ""}}}}` — this for WPA2 PSK networks. It would still be necessary to study how this would work for WPA3 networks, and other WPA2/WPA3 modes like enterprise, etc.
* Function to allow the user to perform channel hopping across a specific channel range; the user may set which channels will not be used, or they may pass specific bands (0 for 2.4 GHz, 1 for 5 GHz, 2 for 2.4 GHz and 5 GHz), and thereby pass the channels that will not be used.
* With `createpkt`, allow the user to modify and construct a frame/packet from provided templates, or modify a sequence or a specific packet from a JSON file containing all the raw hexadecimal packets they want to edit `{"raw": ["12345abcef", "12345abcef"]}`, and open it in the packet editing TUI. They will be able to save a specific packet they are editing, or all that they were editing; for that, they will always be able to choose the output filename where the raw hexadecimal packet(s) will be written. The format of those final files will be:
  `{"unique identifier of that specific packet or frame": {"raw": "0123456789101112131415abcdef"}}`.
* `pcaptohex` takes each raw frame from a pcap file and writes its raw hexadecimal content into a `.json` file that can be used by the program.
* Basic functions for interface manipulation without the need for `iw`, instead using the `wnlpy` module which is under development.
* Possibly remove the channel hopping function from `monitor-scan` and make it independent; that is, the user would have to call it separately.
* In the channel hopping function, allow the user to define channel width.
* Verification for virtual monitor interfaces.

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
