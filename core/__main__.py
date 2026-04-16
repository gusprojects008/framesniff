import time
import json
import threading
from logging import getLogger
from core.common.function_utils import (new_file_path, setup_logging)
from core.common.filter_engine import apply_filters
from core.common.parser_utils import iter_packets_from_json, bytes_encoder
from core.layers.registry import get_parser
from core.user_operations import Operations, Hashcat

setup_logging(True)
logger = getLogger(__name__)

ENABLE_SYSTEM_TESTS = True
TEST_INTERFACE = "wlp0s20f3"
RUN_ALL = False
INTERACTIVE_MODE = True

def sniff_offline(
    dlt: str = "DLT_IEEE802_11_RADIO",
    input_fullpath: str = None,
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
):
    if not input_fullpath:
        raise ValueError("Input file path (input_fullpath) is required.")

    try:
        parser = get_parser(dlt)
    except ValueError as e:
        logger.error(f"Error getting parser: {e}")
        return

    output_fullpath = new_file_path(output_fullpath, "framesniff-offline-capture.json")
    
    frame_counter = 0
    last_display_time = 0.0
    start_time = time.time()

    logger.info(
        f"Starting OFFLINE processing...\n"
        f"Input: {input_fullpath}\n"
        f"Store Filter: {store_filter}\n"
        f"Display Filter: {display_filter}\n"
        f"Output: {output_fullpath}"
    )

    try:
        with open(output_fullpath, "a") as f:
            for cleaned_hex, raw_bytes in iter_packets_from_json(input_fullpath):
                
                if stop_event and stop_event.is_set():
                    logger.info("Stop event received, finishing...")
                    break

                if timeout and (time.time() - start_time) >= timeout:
                    logger.info(f"Timeout of {timeout}s reached.")
                    break

                try:
                    parsed_frame = parser(raw_bytes)
                except Exception as e:
                    logger.debug(f"Parser error (Frame {frame_counter}): {e}")
                    continue

                parsed_frame["counter"] = frame_counter
                parsed_frame["raw"] = cleaned_hex
                
                store_result, display_result = apply_filters(store_filter, display_filter, parsed_frame)

                if store_result:
                    if simple_output:
                        dump = json.dumps(parsed_frame, default=bytes_encoder, separators=(",", ":"))
                    else:
                        dump = json.dumps(parsed_frame, default=bytes_encoder, indent=2)

                    f.write(dump + "\n")
                    
                    if frame_counter % 100 == 0:
                        f.flush()
  
                    frame_counter += 1

                    if store_callback:
                        store_callback(parsed_frame)

                if display_result:
                    if display_callback:
                        display_callback(display_result)
                    else:
                        current_time = time.time()
                        if current_time - last_display_time >= display_interval:
                            try:
                                log_out = json.dumps(display_result, default=bytes_encoder, ensure_ascii=False)
                                logger.info(f"[{frame_counter}] {log_out}")
                            except Exception as log_err:
                                logger.warning(f"[{frame_counter}] {display_result}")
                            
                            last_display_time = current_time

                if count is not None and frame_counter >= count:
                    break

    except KeyboardInterrupt:
        logger.info("Processing interrupted by user.")
    except Exception as e:
        logger.critical(f"Unexpected error in sniff_offline: {e}", exc_info=True)
    finally:
        logger.info(f"Offline processing completed. {frame_counter} frames analyzed.")
        if stop_event:
            stop_event.set()

def run_test(name: str, func, *args, **kwargs):
    if not should_run_test(name):
        logger.info(f"[SKIPPED] {name}")
        return

    logger.info(f"\n[TEST START] {name}")
    try:
        result = func(*args, **kwargs)
        logger.info(f"[TEST OK] {name} {result}")
        return result
    except Exception as e:
        logger.error(f"[TEST FAIL] {name}: {e}", exc_info=True)
    finally:
        logger.info(f"[TEST END] {name}\n")

def run_blocking_test(name: str, func, timeout: float = 10, **kwargs):
    if not should_run_test(name):
        logger.info(f"[SKIPPED] {name}")
        return

    logger.info(f"\n[TEST START] {name}")

    stop_event = threading.Event()

    def target():
        try:
            func(stop_event=stop_event, **kwargs)
        except Exception as e:
            logger.error(f"[THREAD ERROR] {name}: {e}", exc_info=True)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()

    try:
        thread.join(timeout)

        if thread.is_alive():
            logger.warning(f"[TIMEOUT] {name} exceeded {timeout}s, stopping...")
            stop_event.set()
            thread.join(2)

    except KeyboardInterrupt:
        logger.warning(f"[INTERRUPTED] {name} (Ctrl+C)")
        stop_event.set()
        thread.join(2)

    logger.info(f"[TEST END] {name}\n")

def should_run_test(name: str) -> bool:
    global RUN_ALL

    if not INTERACTIVE_MODE or RUN_ALL:
        return True

    choice = input(f"Run test '{name}'? [y/n/a]: ").strip().lower()

    if choice == "a":
        RUN_ALL = True
        return True

    return choice in ("y", "yes")

def run_tests():
    test_input = "/home/gus/Documents/framesniff/core/tests/frames.json"
    store_filter = "mac_hdr.fc.type == 2 and mac_hdr.sa.mac in ('5c:62:8b:80:83:8a', '56:8e:aa:1c:37:87') and mac_hdr.da.mac in ('5c:62:8b:80:83:8a', '56:8e:aa:1c:37:87') and mac_hdr.bssid.mac == '5c:62:8b:80:83:8a' and body.llc.name == 'eapol'"
    display_filter = "body.llc.payload"
    simple_output = False


    run_test(
        "sniff_offline basic",
        sniff_offline,
        dlt="DLT_IEEE802_11_RADIO",
        input_fullpath=test_input,
        simple_output=simple_output
    )

    run_test(
        "sniff_offline filter eapol",
        sniff_offline,
        dlt="DLT_IEEE802_11_RADIO",
        input_fullpath=test_input,
        store_filter=store_filter,
        display_filter=display_filter,
    )

    run_test(
        "write_pcap_from_json",
        Operations.write_pcap_from_json,
        dlt="DLT_IEEE802_11_RADIO",
        input_fullpath=test_input,
        output_fullpath="test_output"
    )

    run_test(
        "generate hashcat format",
        Hashcat.generate_22000,
        ssid="LOPES",
        input_fullpath=test_input
    )

    run_test(
        "get_channels",
        Operations.get_channels,
        bands=[2.4, 5]
    )

    run_test(
        "generate_channel_hopping_config",
        Operations.generate_channel_hopping_config,
        bands=[2.4],
        output_fullpath="test_channel_config.json"
    )

    if ENABLE_SYSTEM_TESTS:
        logger.warning("SYSTEM TESTS ENABLED — this will modify system/network state")

        run_test(
            "list interfaces",
            Operations.list_network_interfaces
        )

        run_test(
            "interface info",
            Operations.list_network_interface,
            TEST_INTERFACE
        )

        run_test(
            "set monitor mode",
            Operations.set_monitor,
            TEST_INTERFACE
        )

        run_test(
            "set channel",
            Operations.set_frequency,
            TEST_INTERFACE,
            channel=6
        )

        run_test(
            "set frequency",
            Operations.set_frequency,
            TEST_INTERFACE,
            frequency_mhz=2437
        )

        run_test(
            "channel hopping config (runtime)",
            Operations.generate_channel_hopping_config,
            bands=[2.4]
        )

        run_test(
            "channel hopper (short run)",
            Operations.channel_hopper,
            ifname=TEST_INTERFACE,
            channel_hopping_config=Operations.generate_channel_hopping_config([2.4]),
            timeout=5
        )

        run_test(
            "send_raw (1 frame)",
            Operations.send_raw,
            ifname=TEST_INTERFACE,
            input_fullpath=test_input,
            count=1
        )

        run_blocking_test(
            "sniff (live test)",
            Operations.sniff,
            timeout=10,
            dlt="DLT_IEEE802_11_RADIO",
            ifname=TEST_INTERFACE,
            store_filter=None,
            display_filter=None
        )

        run_blocking_test(
            "scan_monitor (TUI)",
            Operations.scan_monitor,
            ifname=TEST_INTERFACE,
            dlt="DLT_IEEE802_11_RADIO",
            channel_hopping=True,
            channel_hopping_interval=2,
            timeout=10
        )

    else:
        logger.info("System tests disabled")

def main():
    run_tests()

if __name__ == "__main__":
    main()
