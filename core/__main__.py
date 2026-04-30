import time
import json
import threading
from logging import getLogger
from core.common.filter_engine import apply_filters
from core.common.constants.hashcat import *

from core.bootstrap import init

config = {
    "module_dependencies": ["rich", "dpkt", "textual"],
    "system_dependencies": ["ip", "iw"],
    "args": None
}

result = init(config)
operations = result.operations

ENABLE_SYSTEM_TESTS = True
TEST_INTERFACE = "wlp0s20f3"
RUN_ALL = False
INTERACTIVE_MODE = True

logger = getLogger(__name__)

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
            func(timeout=timeout, stop_event=stop_event, **kwargs)
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
    eapol_store_filter = "mac_hdr.fc.type == 2 and mac_hdr.sa.addr in ('5c:62:8b:80:83:8a', '56:8e:aa:1c:37:87') and mac_hdr.da.addr in ('5c:62:8b:80:83:8a', '56:8e:aa:1c:37:87') and mac_hdr.bssid.addr == '5c:62:8b:80:83:8a' and body.llc.name == 'eapol'"
    eapol_display_filter = "body.llc.payload"
    test_display_filter = "rt_hdr.present_bitmaps.0"
    test_store_filter = "rt_hdr.present_bitmaps.0"
    simple_output = False

    run_test(
        "sniff test basic",
        operations.sniff,
        simple_output=simple_output,
        test=True,
        input_fullpath=test_input,
    )

    run_test(
        "sniff test filter test",
        operations.sniff,
        simple_output=simple_output,
        store_filter=test_store_filter,
        display_filter=test_display_filter,
        test=True,
        input_fullpath=test_input,
    )

    run_test(
        "sniff test filter eapol test",
        operations.sniff,
        simple_output=simple_output,
        store_filter=eapol_store_filter,
        display_filter=eapol_display_filter,
        test=True,
        input_fullpath=test_input,
    )

    run_test(
        "write_pcap_from_json",
        operations.write_pcap_from_json,
        dlt="DLT_IEEE802_11_RADIO",
        input_fullpath=test_input,
        output_fullpath="test_output"
    )

    run_test(
        "generate hashcat format 22000 (PMKID)",
        operations.generate_hashcat,
        hformat=22000,
        htype=1,
        ssid="LOPES",
        input_fullpath="/home/gus/Documents/framesniff/core/tests/test_pmkid.json"
    )

    run_test(
        "generate hashcat format 22000 (EAPOL M1+M2)",
        operations.generate_hashcat,
        hformat=22000,
        htype=2,
        ssid="LOPES",
        input_fullpath=test_input
    )

    run_test(
        "get_channels",
        operations.get_channels,
        bands=[2.4, 5]
    )

    run_test(
        "generate_channel_hopping_config",
        operations.generate_channel_hopping_config,
        bands=[2.4],
        output_fullpath="test_channel_config.json"
    )

    if ENABLE_SYSTEM_TESTS:
        logger.warning("SYSTEM TESTS ENABLED — this will modify system/network state")

        run_test(
            "list interfaces",
            operations.list_interfaces
        )

        run_test(
            "interface info",
            operations.list_interface,
            TEST_INTERFACE
        )

        run_test(
            "set station mode",
            operations.set_station,
            TEST_INTERFACE
        )

        run_test(
            "set monitor mode",
            operations.set_monitor,
            TEST_INTERFACE
        )

        run_test(
            "set channel",
            operations.set_frequency,
            TEST_INTERFACE,
            channel=6
        )

        run_test(
            "set frequency",
            operations.set_frequency,
            TEST_INTERFACE,
            frequency_mhz=2437
        )

        run_test(
            "channel hopping config (runtime)",
            operations.generate_channel_hopping_config,
            bands=[2.4]
        )

        run_test(
            "channel hopper (short run)",
            operations.channel_hopper,
            ifname=TEST_INTERFACE,
            channel_hopping_config=operations.generate_channel_hopping_config([2.4]),
            timeout=5
        )

        run_test(
            "send_raw (1 frame)",
            operations.send_raw,
            ifname=TEST_INTERFACE,
            input_fullpath=test_input,
            count=1
        )

        run_blocking_test(
            "sniff (live test)",
            operations.sniff,
            timeout=10,
            dlt="DLT_IEEE802_11_RADIO",
            ifname=TEST_INTERFACE,
            store_filter=None,
            display_filter=None
        )

        run_blocking_test(
            "scan_monitor (TUI)",
            operations.scan_monitor_mode,
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
