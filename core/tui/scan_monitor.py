import asyncio
import threading
import queue
import time
import os
from logging import getLogger
from core.common.tui_utils import export_tui_to_txt
from core.common.parser_utils import freq_to_channel
from core.layers.l2.ieee802.dot11.constants import *
from core.common.function_utils import import_module
import_module("textual")
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Header, Footer, Static, Label, DataTable
from textual.reactive import reactive
from textual.worker import Worker
from textual import work

logger = getLogger(__name__)

log_filepath = None

for handler in logger.handlers:
    if isinstance(handler, logging.FileHandler):
        log_filepath = handler.baseFilename

class Tui(App):
    CSS = """
    Screen {
        background: $surface;
    }
    
    #header {
        background: $accent;
        color: $text;
        padding: 0 1;
        text-style: bold;
    }
    
    #error-panel {
        background: $error;
        color: $text;
        padding: 0 1;
        text-style: bold;
        display: none;
    }
    
    .section-title {
        background: $primary;
        color: $text;
        padding: 0 1;
        text-style: bold;
    }
    
    DataTable {
        height: 1fr;
    }
    
    .networks-container {
        height: 1fr;
        border: solid $primary;
        margin: 1 0;
    }
    
    Container {
        height: 100%;
    }
    """

    current_channel = reactive(1)
    current_band = reactive("2.4")
    frames_processed = reactive(0)
    networks_count = reactive(0)
    clients_count = reactive(0)
    error_message = reactive("")
    duration = reactive(0)

    DISPLAY_FIELDS = [
        "rt_hdr.dbm_antenna_signal",
        "mac_hdr.fc.type", 
        "mac_hdr.fc.subtype",
        "mac_hdr.bssid.mac",
        "mac_hdr.bssid.vendor", 
        "mac_hdr.sa.mac",
        "mac_hdr.sa.vendor",
        "body.tagged_parameters.ssid",
        "body.tagged_parameters.current_channel",
        "body.fixed_parameters.capabilities_information",
        "body.tagged_parameters.rsn_information",
        "body.tagged_parameters.vendor_specific"
    ]
    
    def __init__(self, ifname: str = None, dlt: str = None, channel_hopping: bool = True, channel_hopping_interval: float = 4.0, timeout: float = None, Operations: object = None):

        super().__init__()
        self.ifname = ifname
        self.dlt = dlt
        self.channel_hopping = channel_hopping
        self.channel_hopping_interval = channel_hopping_interval
        self.bands = [2.4]
        self.channel_hopping_config = Operations.generate_channel_hopping_config(bands=self.bands, dwell=self.channel_hopping_interval)
        self.timeout = timeout
        self.Operations = Operations
        
        self.display_queue = queue.Queue()
        self.error_queue = queue.Queue()
        self.networks = {}
        self.clients = {}
        self.associations = {}
        
        self.running = True
        self.start_time = time.time()
        
        self.sniff_thread = None
        self.hopper_thread = None
        self.sniff_stop_event = None
        self.hopper_stop_event = None

        self.output_fullpath = "scan-monitor-tui-capture.txt"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static(id="header"),
            Static(id="error-panel"),
            Container(
                VerticalScroll(
                    Static("NETWORKS:", classes="section-title"),
                    DataTable(id="networks-table"),
                    Static("CLIENTS:", classes="section-title"), 
                    DataTable(id="clients-table"),
                    classes="networks-container"
                ),
            ),
        )
        yield Footer()

    def on_mount(self) -> None:
        networks_table = self.query_one("#networks-table", DataTable)
        networks_table.add_columns("BSSID", "SSID", "VENDOR", "CH", "PWR", "ENC", "CLIENTS", "WPS", "BCNS")
        
        clients_table = self.query_one("#clients-table", DataTable) 
        clients_table.add_columns("MAC", "VENDOR", "CH", "PWR", "FRAMES", "BSSID", "SSID")

        self.set_interval(0.1, self.process_queued_frames)
        self.set_interval(0.5, self.update_display)
        self.start_scanning()

    def start_scanning(self) -> None:
        self.start_sniff_thread()
        if self.channel_hopping:
            self.start_channel_hopper_thread()

    def start_sniff_thread(self) -> None:
        def sniff_thread():
            try:
                self.sniff_stop_event = threading.Event()
                def display_callback(display_data):
                    try:
                        self.display_queue.put(display_data)
                    except Exception:
                        self.error_queue.put("Display callback error")
                        logger.error("Display callback error")
                display_filter_str = ', '.join(self.DISPLAY_FIELDS)
                logger.info(display_filter_str)
                self.Operations.sniff(
                    ifname=self.ifname,
                    dlt=self.dlt,
                    store_filter=f"(mac_hdr.fc.type == {MGMT} and mac_hdr.fc.subtype in ({MGMT_PROBE_RESPONSE}, {MGMT_BEACON})) or mac_hdr.fc.type == {DATA}",
                    display_filter=display_filter_str,
                    display_interval=1.0,
                    timeout=self.timeout,
                    store_callback=None,
                    display_callback=display_callback,
                    stop_event=self.sniff_stop_event,
                    output_fullpath="scan-monitor.json"
                )
            except Exception as e:
                error_msg = "Sniff thread error"
                self.error_queue.put(error_msg)
                logger.debug(f"Sniff thread error: {e}")

        self.sniff_thread = threading.Thread(target=sniff_thread, daemon=True, name="sniffer")
        self.sniff_thread.start()
        logger.info(f"Sniff thread started: {self.sniff_thread.name}")

    def start_channel_hopper_thread(self) -> None:
        def hopper_thread():
            logger.info("Channel hopper thread starting...")
            try:
                self.Operations.channel_hopper(
                    ifname=self.ifname,
                    channel_hopping_config=self.channel_hopping_config,
                    callback=self.update_current_channel,
                    timeout=self.timeout
                )
            except Exception as error:
                logger.error(f"Channel hopper thread error: {error}")
        
        self.hopper_thread = threading.Thread(target=hopper_thread, daemon=True, name="channel_hopper")
        self.hopper_thread.start()
        logger.info(f"Channel hopper thread started: {self.hopper_thread.name}")

    def update_current_channel(self, channel: int, band: str) -> None:
        self.current_channel = channel
        self.current_band = band

    def process_display_data(self, display_data):
        broadcast = "ff:ff:ff:ff:ff:ff"
        try:
            signal = display_data.get('rt_hdr.dbm_antenna_signal') or -100
            frame_type = display_data.get('mac_hdr.fc.type')
            subtype = display_data.get('mac_hdr.fc.subtype')
            bssid_mac = display_data.get('mac_hdr.bssid.mac') or "N/A"
            bssid_vendor = display_data.get('mac_hdr.bssid.vendor')
            src_mac = display_data.get('mac_hdr.sa.mac') or "N/A"
            src_vendor = display_data.get('mac_hdr.sa.vendor')
            ssid = display_data.get('body.tagged_parameters.ssid') or 'N/A'
            capabilities = display_data.get('body.fixed_parameters.capabilities_information') or 0
            rsn_info = display_data.get('body.tagged_parameters.rsn_information')
            vendor_specific = display_data.get('body.tagged_parameters.vendor_specific', {})
            freq = display_data.get('rt_hdr.channel_freq')

            if freq:
                channel = freq_to_channel(freq)
            else:
                channel = self.current_channel
    
            if frame_type is None:
                return
    
            security_info = self.detect_security(capabilities, rsn_info, vendor_specific)
    
            if frame_type == MGMT and subtype in [MGMT_PROBE_RESPONSE, MGMT_BEACON] and bssid_mac and bssid_mac != broadcast:
                if bssid_mac not in self.networks:
                    self.networks[bssid_mac] = {
                        'ssid': ssid,
                        'channel': channel,
                        'signal': signal,
                        'beacons': 1,
                        'vendor': bssid_vendor,
                        'last_seen': time.time(),
                        'security': security_info
                    }
                else:
                    net = self.networks[bssid_mac]
                    net['beacons'] += 1
                    net['signal'] = max(net['signal'], signal)
                    net['last_seen'] = time.time()
                    net['ssid'] = ssid
                    net['channel'] = channel
    
            if src_mac and src_mac != broadcast and src_mac != bssid_mac:
                if src_mac in self.networks:
                    return
    
                associated_bssid = self.associations.get(src_mac)
                if associated_bssid:
                    channel = self.networks.get(associated_bssid, {}).get('channel', channel)
    
                if src_mac not in self.clients:
                    self.clients[src_mac] = {
                        'vendor': src_vendor,
                        'channel': channel,
                        'signal': signal,
                        'frames': 1,
                        'last_seen': time.time()
                    }
                else:
                    cli = self.clients[src_mac]
                    cli['frames'] += 1
                    cli['channel'] = channel
                    cli['signal'] = max(cli['signal'], signal)
                    cli['last_seen'] = time.time()
    
                if frame_type == 2 and bssid_mac and bssid_mac != broadcast:
                    self.associations[src_mac] = bssid_mac
                else:
                    if subtype in [10, 12]:
                        self.associations.pop(src_mac, "N/A")
    
            self.frames_processed += 1
    
        except Exception as error:
            self.error_queue.put(f"Display data processing error: {error}")
            logger.error("Display data processing error")

    def detect_security(self, capabilities, rsn_info, vendor_specific):
        try:
            wps_detected = False
            
            if vendor_specific:
                for oui, vendor_data in vendor_specific.items():
                    if oui == OUI_MICROSOFT:
                        for entry_id, entry_data in vendor_data.items():
                            if "WPS" in entry_data.get('description'):
                                wps_detected = True
                                break
            if rsn_info:
                akm_suites = rsn_info.get('akm_suites', {})
                auth = "PSK"
            
                for suite_id, suite_data in akm_suites.items():
                    akm_type = suite_data.get('akm_type')
            
                    # WPA3 Personal (SAE / FT-SAE)
                    if akm_type in (RSN_AKM_SAE, RSN_AKM_FT_SAE):
                        return {
                            'enc': 'WPA3',
                            'cipher': 'GCMP',
                            'auth': 'SAE',
                            'wps': wps_detected
                        }
            
                    # WPA3 Enhanced Open
                    if akm_type == RSN_AKM_OWE:
                        return {
                            'enc': 'WPA3',
                            'cipher': 'CCMP',
                            'auth': 'OWE',
                            'wps': wps_detected
                        }
            
                    # WPA3 Enterprise (Suite-B)
                    if akm_type in (RSN_AKM_SUITE_B_8021X, RSN_AKM_SUITE_B_192_8021X):
                        return {
                            'enc': 'WPA3',
                            'cipher': 'GCMP',
                            'auth': 'MGT',
                            'wps': wps_detected
                        }
            
                    # WPA2 Enterprise
                    if akm_type in (
                        RSN_AKM_8021X,
                        RSN_AKM_FT_8021X,
                        RSN_AKM_8021X_SHA256
                    ):
                        auth = "MGT"
            
                    # WPA2 Personal
                    if akm_type in (
                        RSN_AKM_PSK,
                        RSN_AKM_FT_PSK,
                        RSN_AKM_PSK_SHA256
                    ):
                        auth = "PSK"
            
                return {
                    'enc': 'WPA2',
                    'cipher': 'CCMP',
                    'auth': auth,
                    'wps': wps_detected
                }

            
            if vendor_specific:
                for oui, vendor_data in vendor_specific.items():
                    if oui == '00:50:f2':
                        for entry_id, entry_data in vendor_data.items():
                            if entry_data.get('type') == 1:
                                return {'enc': 'WPA', 'cipher': 'TKIP', 'auth': 'PSK', 'wps': wps_detected}
            
            if capabilities and isinstance(capabilities, dict):
                if capabilities.get('privacy'):
                    return {'enc': 'WEP', 'cipher': 'WEP', 'auth': '', 'wps': wps_detected}
            
            return {'enc': 'OPEN', 'cipher': '', 'auth': '', 'wps': wps_detected}
            
        except Exception as error:
            logger.error(f"Security detection error: {error}")
            return {'enc': 'UNKN', 'cipher': '', 'auth': '', 'wps': False}

    def process_queued_frames(self):
        max_frames_per_cycle = 100
        processed_count = 0
        
        while processed_count < max_frames_per_cycle:
            try:
                display_data = self.display_queue.get_nowait()
                try:
                    self.process_display_data(display_data)
                    processed_count += 1
                except Exception as e:
                    logger.error(f"Error processing display data: {e}", exc_info=True)
                    self.error_queue.put(f"Frame processing error: {str(e)[:100]}")
            except queue.Empty:
                break
    
    
    def process_errors(self):
        try:
            while not self.error_queue.empty():
                error_msg = self.error_queue.get_nowait()
                self.error_message = f"{error_msg}\nMore details in {log_filepath}"
                logger.error(error_msg)
        except Exception:
            logger.error("Error processing errors")

    def update_display(self):
        self.process_errors()
        self.duration = time.time() - self.start_time
        self.networks_count = len(self.networks)
        self.clients_count = len(self.clients)
        
        queue_size = self.display_queue.qsize()
        
        hop_status = "ON" if self.channel_hopping else "OFF"
        header_text = (
            f"Network Scanner | Chan: {self.current_channel}({self.current_band}GHz) | "
            f"Frames: {self.frames_processed} | Queue: {queue_size} | "
            f"Networks: {self.networks_count} | Clients: {self.clients_count} | "
            f"Hopping: {hop_status} | Duration: {int(self.duration)}s"
        )

        self.query_one("#header", Static).update(header_text)
        
        error_panel = self.query_one("#error-panel", Static)
        if self.error_message:
            error_panel.update(f"ERROR: {self.error_message}")
            error_panel.display = True
        else:
            error_panel.display = False
        
        networks_table = self.query_one("#networks-table", DataTable)
        networks_table.clear()
        for bssid, info in sorted(self.networks.items(), key=lambda x: x[1]['signal'], reverse=True):
            client_count = sum(1 for client, ap in self.associations.items() if ap == bssid)
            security = info['security']
            wps_status = "YES" if security.get('wps', False) else "NO"
            channel = info['channel']
            signal = info['signal']
            beacons = info['beacons']
            ssid = info['ssid']
            vendor = info['vendor']
            
            networks_table.add_row(
                bssid, ssid, vendor, str(channel), str(signal), 
                security['enc'], str(client_count), wps_status, str(beacons)
            )
        
        clients_table = self.query_one("#clients-table", DataTable)
        clients_table.clear()
        for client_mac, info in sorted(self.clients.items(), key=lambda x: x[1]['signal'], reverse=True):
            associated_bssid = self.associations.get(client_mac)
            
            bssid_display = associated_bssid or "N/A"
            ssid = "N/A"
            
            if associated_bssid and associated_bssid in self.networks:
                network_info = self.networks[associated_bssid]
                ssid = network_info.get('ssid', "N/A")
            
            channel = info.get('channel', "N/A")
            signal = info.get('signal', -100)
            frames = info.get('frames', 0)
            vendor = info.get('vendor', "N/A")
        
            clients_table.add_row(
                client_mac, 
                vendor, 
                str(channel), 
                str(signal), 
                str(frames), 
                bssid_display, 
                ssid
            )

    def on_key(self, event):
        if event.key in ("q", "Q", "ctrl+c"):
            self.exit_application()
        if event.key in ("f12", "ctrl+s"):
            export_tui_to_txt(self, self.output_fullpath)

    def exit_application(self):
        self.running = False
        
        if hasattr(self, 'sniff_stop_event') and self.sniff_stop_event:
            self.sniff_stop_event.set()
            logger.info("Sniff stop event set")
        
        if hasattr(self, 'hopper_stop_event') and self.hopper_stop_event:
            self.hopper_stop_event.set()
            logger.info("Hopper stop event set")
        
        for thread_name, thread in [
            ("sniffer", self.sniff_thread),
            ("channel_hopper", self.hopper_thread)
        ]:
            if thread and thread.is_alive():
                logger.info(f"Waiting for {thread_name} thread to finish...")
                thread.join(timeout=3.0)
                if thread.is_alive():
                    logger.warning(f"{thread_name} thread did not finish in time")
        
        logger.info("Network Monitor finished!")
        self.exit()

def scan_monitor(ifname, dlt, channel_hopping, channel_hopping_interval, timeout, Operations):
    app = Tui(
        ifname=ifname,
        dlt=dlt,
        channel_hopping=channel_hopping,
        channel_hopping_interval=channel_hopping_interval,
        timeout=timeout,
        Operations=Operations
    )
    app.run()
