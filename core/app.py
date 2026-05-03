import subprocess
import re
import sys
import time
import json
import socket
import threading
import struct
import os
from logging import getLogger
import dpkt
from cli_core.system import check_root
from cli_core.files import new_file_path, iter_from_json
from core.common.validation import (verify_supported_dlts, check_interface_mode)
from core.common.parser import raw_packet_extractor, bytes_encoder, normalize_bytes, calc_offset_from_fmt, clear_field, clean_hex_string
from core.common.filter_engine import apply_filters, get_nested
from core.common.sockets import create_raw_socket
from core.common.constants.hashcat import *
from core.layers.l2.ieee802.dot1x.constants import *
from core.layers.registry import (get_parser, get_dlt_value)

logger = getLogger(__name__)

class Hashcat:
    GENERATORS = {
        WPA_PBKDF2_PMKID_EAPOL: "_generate_22000"
    }

    @classmethod
    def generate(cls, hformat, **kwargs):
        generator_name = cls.GENERATORS.get(hformat)

        if not generator_name:
            raise ValueError(f"Unsupported hashcat format: {hformat}")

        generator = getattr(cls, generator_name)
        return generator(hformat=hformat, **kwargs)

    @staticmethod
    def _generate_22000(htype: int, ssid: str, input_fullpath: str, hformat: str = None, output_fullpath: str = None):
        def _build_eapol_line(ssid: str, input_fullpath: str):
            eapol_msg1 = None
            eapol_msg2 = None
        
            for i, (_, fbytes) in enumerate(iter_from_json(input_fullpath, raw_packet_extractor())):
                if i == 0:
                    eapol_msg1 = fbytes
                elif i == 1:
                    eapol_msg2 = fbytes
                    break
        
            if not eapol_msg1 or not eapol_msg2:
                raise ValueError("Need at least 2 EAPOL frames")
        
            parser = get_parser("DLT_IEEE802_11_RADIO")
        
            msg1 = parser(eapol_msg1)
            msg2 = parser(eapol_msg2)
        
            msg2_mac = get_nested("mac_hdr", msg2)
        
            ap_mac = msg2_mac["bssid"]["value"].hex()
            sta_mac = (msg2_mac["sa"]["value"] or msg2_mac["ta"]["value"]).hex()
        
            msg1_eapol = get_nested("body.llc.payload", msg1)
            msg2_eapol = get_nested("body.llc.payload", msg2)
        
            logger.warning(f"{msg1_eapol}\n{msg2_eapol}")

            anonce = get_nested("key_nonce", msg1_eapol)
            mic = get_nested("key_mic", msg2_eapol)
            key_data = get_nested("key_data._metadata_.raw", msg2_eapol) 

            payload_meta = get_nested("body.llc.payload._metadata_", msg2)
            fields = list(msg2_eapol.keys())

            try:
                mic_index = fields.index("key_mic")
            except ValueError:
                raise ValueError("'key_mic' not found in EAPOL")
            
            tokens = payload_meta["tokens"]
            eapol_len = calc_offset_from_fmt(tokens, len(tokens)) 

            full_eapol = bytes.fromhex(payload_meta["raw"] + key_data)
            
            eapol_zero_mic_bytes = clear_field(full_eapol, payload_meta, mic_index, EAPOL_KEY_MIC_LENGTH)

            return f"WPA*02*{mic}*{ap_mac}*{sta_mac}*{ssid}*{anonce}*{eapol_zero_mic_bytes.hex()}*00"

        def _build_pmkid_line(ssid: str, input_fullpath: str):
            with open(input_fullpath, "r", encoding="utf-8") as f:
                data = json.load(f)
                pmkid = clean_hex_string(data.get("pmkid"))
                ap_mac = clean_hex_string(data.get("ap_mac"))
                sta_mac = clean_hex_string(data.get("sta_mac"))
                if not all([pmkid, ap_mac, sta_mac]):
                    raise ValueError("Missing PMKID data")
                return f"WPA*01*{pmkid}*{ap_mac}*{sta_mac}*{ssid}***00"

        HTYPE_GENERATORS = {
            HC22000_PMKID: _build_pmkid_line,
            HC22000_EAPOL: _build_eapol_line
        }
        
        if not input_fullpath:
            raise ValueError("Input file must be provided.")
        
        if not ssid:
            raise ValueError("SSID must be provided.")
        
        ssid = ssid.encode().hex()
        
        try:
            line = HTYPE_GENERATORS[htype](ssid, input_fullpath)
            logger.info(line)
            if output_fullpath:
                with open(new_file_path(output_fullpath, f"hashcat_{hformat}_{htype}"), "w") as output_file:
                    output_file.write(line)
            return line
        except Exception as e:
            logger.error(f"Exception: {e}")

class Operations:
    def __init__(self, context):
        self.ctx = context
        self.dispatch_table = {
            "list-interfaces": lambda args: self.list_interfaces(),
            "list-interface": lambda args: self.list_interface(args.ifname),
            "set-monitor": lambda args: self.set_monitor(args.ifname),
            "set-station": lambda args: self.set_station(args.ifname),
            "scan-station": lambda args: self.scan_station_mode(
                ifname=args.ifname,
                output_fullpath=args.output
            ),
            "set-frequency": lambda args: self.set_frequency(
                ifname=args.ifname,
                frequency_mhz=args.frequency,
                channel=args.channel,
                channel_width=args.width
            ),
            "generate-channel-hopping-config": lambda args: self.generate_channel_hopping_config(
                bands=args.bands,
                channel_width=args.width,
                dwell=args.dwell,
                output_fullpath=args.output
            ),
            "channel-hopping": lambda args: self.channel_hopper(
                ifname=args.ifname,
                channel_hopping_config_path=args.channel_hopping_config_filename,
                allowed=args.allowed,
                disallowed=args.disallowed,
                timeout=args.timeout
            ),
            "sniff": lambda args: self.sniff(
                dlt=args.dlt,
                ifname=args.ifname,
                store_filter=args.store_filter,
                display_filter=args.display_filter,
                count=args.count,
                timeout=args.timeout,
                display_interval=args.display_interval,
                simple_output=args.simple_output,
                output_fullpath=args.output
            ),
            "generate-hashcat": lambda args: self.generate_hashcat(
                args.hformat,
                **{k: v for k, v in vars(args).items() if k not in ('command', 'hformat')}
            ),
            "hextopcap": lambda args: self.write_pcap_from_json(
                dlt=args.dlt,
                input_fullpath=args.input_fullpath,
                output_fullpath=args.output
            ),
            "send-raw": lambda args: self.send_raw(
                ifname=args.ifname,
                input_fullpath=args.input_fullpath,
                count=args.count,
                interval=args.interval,
                timeout=args.timeout
            ),
            "scan-monitor": lambda args: self.scan_monitor_mode(
                ifname=args.ifname,
                dlt=args.dlt,
                channel_hopping=args.channel_hopping,
                channel_hopping_interval=args.dwell,
                timeout=args.timeout,
            ),
        }

    def dispatch(self):
        args = self.ctx.config["argparse"]["args"]
        handler = self.dispatch_table.get(args.command)

        if not handler:
            raise ValueError(f"Unknown command: {args.command}")

        return handler(args)

    def sniff(
        self,
        dlt: str = "DLT_IEEE802_11_RADIO",
        ifname: str = None,
        store_filter: str = None,
        display_filter: str = None,
        count: int = None,
        timeout: float = None,
        display_interval: float = 0.0,
        store_callback: callable = None,
        display_callback: callable = None,
        stop_event: threading.Event = None,
        simple_output: bool = False,
        output_fullpath: str = None,
        test: bool = False,
        input_fullpath: str = None,
    ):
        if not test:
            check_root()
            check_interface_mode(ifname, "monitor")

        try:
            parser = get_parser(dlt)
        except ValueError as e:
            logger.error(e)
            return

        output_fullpath = new_file_path(output_fullpath, "framesniff-capture.json")
        frame_processed_counter = 0
        frames_stored_counter = 0
        frames_displayed_counter = 0
        last_display_time = 0.0
        start_time = time.time()

        def _process_frame(frame: bytes, output_file) -> bool:
            nonlocal frame_processed_counter, frames_stored_counter, frames_displayed_counter, last_display_time

            try:
                parsed_frame = parser(frame)
            except Exception as e:
                logger.debug(f"Parser error: {e}", exc_info=True)
                return False

            frame_processed_counter += 1
            parsed_frame["counter"] = frame_processed_counter
            parsed_frame["raw"] = frame.hex()

            store_result, display_result = apply_filters(store_filter, display_filter, parsed_frame)

            if store_result:
                if simple_output:
                    dump = json.dumps(parsed_frame, default=bytes_encoder, separators=(",", ":"))
                else:
                    dump = json.dumps(parsed_frame, default=bytes_encoder, indent=2)

                output_file.write(dump + "\n")

                if frames_stored_counter % 100 == 0:
                    output_file.flush()

                frames_stored_counter += 1

                if store_callback:
                    store_callback(parsed_frame)

            if display_result:
                frames_displayed_counter += 1
                if display_callback:
                    display_callback(display_result)
                else:
                    current_time = time.time()
                    if current_time - last_display_time >= display_interval:
                        try:
                            log_out = json.dumps(display_result, default=bytes_encoder, ensure_ascii=False)
                            logger.info(f"[{frame_processed_counter}] {log_out}")
                        except Exception:
                            logger.warning(f"[{frame_processed_counter}] {display_result}")
                        last_display_time = current_time

            return True

        def _should_stop() -> bool:
            if stop_event and stop_event.is_set():
                logger.info("Stop event received, finishing...")
                return True
            if timeout and (time.time() - start_time) >= timeout:
                logger.info(f"Timeout of {timeout}s reached.")
                return True
            if count is not None and frames_stored_counter >= count:
                return True
            return False

        def _log_summary():
            elapsed = time.time() - start_time
            logger.info(
                f"Capture finished.\n"
                f"  Elapsed time     : {elapsed:.2f}s\n"
                f"  Frames processed : {frame_processed_counter}\n"
                f"  Frames stored    : {frames_stored_counter}\n"
                f"  Frames displayed : {frames_displayed_counter}"
            )

        if test:
            if not input_fullpath:
                raise ValueError("Input file path (input_fullpath) is required when test=True.")

            logger.info(
                f"Starting OFFLINE processing...\n"
                f"Input        : {input_fullpath}\n"
                f"Store filter : {store_filter}\n"
                f"Display filter: {display_filter}\n"
                f"Output       : {output_fullpath}"
            )

            try:
                with open(output_fullpath, "a") as output_file:
                    for _cleaned_hex, frame in iter_from_json(input_fullpath, raw_packet_extractor()):
                        if _should_stop():
                            break
                        _process_frame(frame, output_file)
            except Exception as e:
                logger.critical(f"Unexpected error in offline sniff: {e}", exc_info=True)
            finally:
                _log_summary()

            return

        sock = create_raw_socket(ifname)

        try:
            logger.info(
                f"Starting capture on {ifname}... (Press Ctrl+C to stop)\n"
                f"Store filter  : {store_filter}\n"
                f"Display filter: {display_filter}\n"
                f"Output path   : {output_fullpath}\n"
                f"Timeout       : {timeout} seconds"
            )

            with open(output_fullpath, "a") as output_file:
                while True:
                    if _should_stop():
                        break

                    try:
                        frame, _ = sock.recvfrom(65535)
                        _process_frame(frame, output_file)
                    except KeyboardInterrupt:
                        logger.info("Capture interrupted by user.")
                        break
                    except Exception as e:
                        logger.error(f"Error processing frame: {e}")
                        continue

        except Exception as e:
            logger.critical(f"Unexpected error in sniff: {e}", exc_info=True)

        finally:
            _log_summary()
            sock.close()
            if stop_event:
                stop_event.set()

    def generate_hashcat(self, hformat, **kwargs):
        return Hashcat.generate(hformat, **kwargs)

    def write_pcap_from_json(self, dlt: str, input_fullpath: str, output_fullpath: str):
        linktype = get_dlt_value(dlt)
        output_fullpath = new_file_path(output_fullpath, "packets.pcap")
        with open(output_fullpath, "wb") as out:
            writer = dpkt.pcap.Writer(out, linktype=linktype)
            count = 0
            for hexstr, b in iter_from_json(input_fullpath, raw_packet_extractor()):
                writer.writepkt(b, ts=time.time())
                count += 1
                logger.info(f"{count} packet writed: {b[:50]}...")
            writer.close()
            logger.info(f"Output file: {output_fullpath}")

    def send_raw(self, ifname: str, input_fullpath: str, count: int = 1, interval: float = 1.0, timeout: float = None):
        sock = create_raw_socket(ifname)
        if timeout is not None:
            sock.settimeout(timeout)
        try:
            for cleaned, raw_bytes in iter_from_json(input_fullpath, raw_packet_extractor()):
                for i in range(count):
                    try:
                        bytes_sent = sock.send(raw_bytes)
                        logger.info(f"Frame sent ({i+1}/{count}): {bytes_sent} bytes")
                        if i < count - 1:
                            time.sleep(interval)
                    except socket.error as e:
                        logger.error(f"Failed to send frame: {e}")
                        break
                    except Exception as e:
                        logger.critical(f"Unexpected error: {e}")
                        break
        finally:
            sock.close()

    def scan_monitor_mode(self, ifname: str, dlt: str = "DLT_IEEE802_11_RADIO", channel_hopping: bool = True, channel_hopping_interval: float = 4.0, timeout: float = None, stop_event=None):
        from core.tui.scan_monitor import scan_monitor
        logger.info("press ctrl+s or <F12> to save tui information!")
        scan_monitor(ifname=ifname, dlt=dlt, channel_hopping=channel_hopping,
            channel_hopping_interval=channel_hopping_interval, timeout=timeout, stop_event=stop_event)

    def set_frequency(self, ifname: str, frequency_mhz: int = None, channel: int = None, channel_width: int = None) -> bool:
        attempts = []

        if channel is not None:
            attempts.append(["iw", ifname, "set", "channel", str(channel)])

        elif frequency_mhz is not None:
            if channel_width:
                attempts.append(["iw", ifname, "set", "freq", str(frequency_mhz), str(channel_width)])
            attempts.append(["iw", ifname, "set", "freq", str(frequency_mhz)])

        last_err = None

        for cmd in attempts:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != 0:
                    last_err = f"{' '.join(cmd)} -> returncode {proc.returncode} stderr:{proc.stderr.strip()}"
                    logger.error(last_err)
                    continue
                return True
            except Exception as e:
                last_err = f"Unexpected error running {' '.join(cmd)}: {e}"
                logger.error(last_err)

        return False

    def get_channels(self, bands: list[int | float] = [2.4]) -> dict:
        channel_map = {}
        normalized_bands = []
        for b in bands:
            try:
                if b > 1000:
                    b = round(b / 1000, 1)
                normalized_bands.append(b)
            except Exception as e:
                logger.warning(f"Ignoring invalid band value {b}: {e}")
        if 2.4 in normalized_bands:
            channel_map[2.4] = [(ch, 2407 + ch * 5) for ch in range(1, 14)]
        if 5 in normalized_bands:
            channel_map[5] = [
                (36, 5180), (40, 5200), (44, 5220), (48, 5240),
                (52, 5260), (56, 5280), (60, 5300), (64, 5320),
                (100, 5500), (104, 5520), (108, 5540), (112, 5560),
                (116, 5580), (120, 5600), (124, 5620), (128, 5640),
                (132, 5660), (136, 5680), (140, 5700), (144, 5720),
                (149, 5745), (153, 5765), (157, 5785), (161, 5805), (165, 5825)
            ]
        if 6 in normalized_bands:
            base_freq = 5955
            channel_map[6] = [(ch, base_freq + 5 * (ch - 1)) for ch in range(1, 234)]
        return channel_map

    def generate_channel_hopping_config(
        self,
        bands: list[int | float] = [2.4],
        channel_width: int = 20,
        dwell: int | float = 4.0,
        output_fullpath: str = None
    ) -> dict:
        try:
            logger.info(f"Generating channel hopping config for bands {bands} (dwell={dwell}s)...")
            channel_map = self.get_channels(bands)
            config = {}
            for band, entries in channel_map.items():
                config[str(band)] = {}
                for ch, freq in entries:
                    config[str(band)][str(ch)] = {
                        "frequency": freq,
                        "dwell": dwell,
                        "channel_width": channel_width
                    }
            if output_fullpath:
                with open(output_fullpath, "w", encoding="utf-8") as file:
                    json.dump(config, file, indent=4)
                logger.info(f"Config file saved to: {output_fullpath}")
            logger.debug(f"Generated config: {config}")
            return config
        except Exception as e:
            logger.error(f"Failed to generate channel hopping config: {e}")
            return {}

    def channel_hopper(
        self,
        ifname: str,
        channel_hopping_config_path: str = None,
        channel_hopping_config: dict = None,
        allowed: list[int] = None,
        disallowed: list[int] = None,
        callback: callable = None,
        stop_event=None,
        timeout: float = None,
    ):
        config = None
        if channel_hopping_config_path:
            try:
                with open(channel_hopping_config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load channel hopping config: {e}")
                return
        elif channel_hopping_config:
            config = channel_hopping_config
        else:
            logger.error("Either 'channel_hopping_config_path' or 'channel_hopping_config' must be provided.")
            return
        channels_to_scan: list[tuple[int, int, float, int, int]] = []
        for band_str, channels in config.items():
            try:
                band = float(band_str)
            except Exception as e:
                logger.warning(f"Ignoring invalid band key '{band_str}': {e}")
                continue
            for ch_str, params in channels.items():
                try:
                    if not isinstance(params, dict):
                        raise ValueError(f"Invalid params type: {type(params)}")

                    ch = int(ch_str)

                    freq = params.get("frequency")
                    if freq is None:
                        raise ValueError("Missing frequency")

                    dwell = params.get("dwell", 5.0)
                    if dwell is None:
                        dwell = 5.0

                    width_val = params.get("channel_width", 20)
                    width = int(width_val) if width_val is not None else 20

                    logger.debug(f"Parsed channel: ch={ch}, allowed={allowed}, disallowed={disallowed}")

                    if allowed and ch not in allowed:
                        continue

                    if disallowed and ch in disallowed:
                        continue

                    channels_to_scan.append((ch, freq, band, dwell, width))

                except Exception as e:
                    logger.warning(
                        f"Skipping invalid channel entry '{ch_str}' (params={params}): {e}"
                    )
        if not channels_to_scan:
            logger.warning("No valid channels to scan.")
            return
        idx = 0
        start_time = time.time()
        try:
            while True:
                if timeout is not None and (time.time() - start_time) >= timeout:
                    logger.info(f"Channel hopping timed out after {timeout} seconds.")
                    break
                if stop_event and stop_event.is_set():
                    logger.info("Stop event detected, stopping channel hopper.")
                    break
                ch, freq, band, dwell, width = channels_to_scan[idx]
                success = self.set_frequency(ifname, freq, channel=ch, channel_width=width)
                if success:
                    logger.info(
                        f"Channel set -> ch={ch} freq={freq}MHz band={band}GHz width={width} dwell={dwell}s"
                    )
                else:
                    logger.error(f"Failed to set channel {ch} ({freq}MHz)")
                if callback:
                    try:
                        callback(channel=ch, band=band)
                    except Exception as e:
                        logger.error(f"Channel hopper callback error: {e}")
                idx = (idx + 1) % len(channels_to_scan)
                time.sleep(dwell)
        except KeyboardInterrupt:
            logger.info("Channel hopping interrupted by user.")
        except Exception as e:
            logger.error(f"Unexpected error in channel hopper: {e}")
        finally:
            logger.info("Channel hopper finished.")

    def list_interfaces(self) -> str:
        logger.info(" In development, see https://github.com/gusprojects008/wnlpy")
        result = subprocess.run(
            ["iw", "dev"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        logger.info(result.stdout.strip())

    def list_interface(self, ifname: str) -> str:
        logger.info(" In development, see https://github.com/gusprojects008/wnlpy")
        result = subprocess.run(
            ["iw", "dev", ifname, "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        logger.info(result.stdout.strip())

    def set_monitor(self, ifname: str):
        self._set_interface_mode("monitor", ifname)

    def set_station(self, ifname: str):
        self._set_interface_mode("station", ifname)

    def scan_station_mode(self, ifname: str = None, output_fullpath: str = None):
        logger.info(" In development, see https://github.com/gusprojects008/wnlpy\n")

        logger.info(f" Scanning WiFi networks on {ifname}...\n")

        try:
            result = subprocess.run(
                ["iw", "dev", ifname, "scan"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            logger.critical(f"Error during scan: {e}")
            return
        except FileNotFoundError:
            logger.error("Error: 'iw' command not found. Please install wireless tools.")
            return

        def _extract_value(block: str, pattern: str) -> str:
            match = re.search(pattern, block)
            return match.group(1) if match else "N/A"

        def _get_security_type(block: str) -> str:
            if "WPA3" in block or "SAE" in block:
                return "WPA3"
            elif "WPA2" in block or "RSN:" in block:
                return "WPA2"
            elif "WPA:" in block:
                return "WPA"
            elif "privacy" in block:
                return "WEP"
            else:
                return "OPEN"

        def _get_wps_status(block: str) -> str:
            if "WPS:" not in block:
                return "Disabled"
            status = "Enabled"
            state_match = re.search(r"Wi-Fi Protected Setup State:\s*(\d+)\s*\((\w+)\)", block)
            if state_match:
                status += f" ({state_match.group(2)})"
            methods_match = re.search(r"Config methods:\s*(.+)", block)
            if methods_match:
                status += f" - {methods_match.group(1)}"
            if "AP setup locked: 0x01" in block:
                status += " [LOCKED]"
            return status

        def _print_network_summary(block: str, num: int):
            bssid = _extract_value(block, r"^([0-9a-f:]{17})")
            ssid = _extract_value(block, r"SSID:\s*(.+)") or "Hidden"
            signal = _extract_value(block, r"signal:\s*([-\d.]+)\s*dBm")
            channel = _extract_value(block, r"DS Parameter set:\s*channel\s*(\d+)")
            frequency = _extract_value(block, r"freq:\s*([\d.]+)")

            security = _get_security_type(block)
            wps_info = _get_wps_status(block)
            vendor = _extract_value(block, r"Manufacturer:\s*(.+)")

            encryption = []
            if "CCMP" in block:
                encryption.append("AES")
            if "TKIP" in block:
                encryption.append("TKIP")

            logger.info(
                f"┌─── NETWORK #{num} {'─' * 50}\n"
                f"│ SSID: {ssid}\n"
                f"│ BSSID: {bssid}\n"
                f"│ Signal: {signal} dBm | Channel: {channel} | Freq: {frequency} MHz\n"
                f"│ Security: {security}"
            )

            if encryption:
                logger.info(f"│ Encryption: {', '.join(encryption)}")

            if vendor and vendor != "Unknown":
                logger.info(f"│ Vendor: {vendor}")

            logger.info(f"│ WPS: {wps_info}")

            flags = []
            if "WPA3" in block or "SAE" in block:
                flags.append("WPA3")
            if "Management frame protection: required" in block:
                flags.append("PMF-Required")
            elif "Management frame protection: capable" in block:
                flags.append("PMF-Capable")

            if flags:
                logger.info(f"│ Security Flags: {', '.join(flags)}")

            logger.info(f"└{'─' * 60}")

        output_fullpath = str(new_file_path(output_fullpath, "station-scan-result.txt"))

        if result.stdout:
            with open(output_fullpath, "w") as file:
                file.write(result.stdout)

            blocks = result.stdout.strip().split("\nBSS ")
            network_count = 0

            for block in blocks[1:]:
                network_count += 1
                _print_network_summary(block, network_count)

            logger.info(f"\nTotal networks found: {network_count}")

    def _set_interface_mode(self, mode: str, ifname: str):
        logger.info(" In development, see https://github.com/gusprojects008/wnlpy")
        try:
            commands = [
                ["ip", "link", "set", ifname, "down"],
                ["iw", "dev", ifname, "set", "type", mode],
                ["ip", "link", "set", ifname, "up"],
            ]
            for cmd in commands:
                subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(
                f"{e.stderr.strip() if e.stderr else 'Unknown error'}"
            )
        except Exception as e:
            logger.error(f"error configure {ifname} to {mode} mode: {e}")
