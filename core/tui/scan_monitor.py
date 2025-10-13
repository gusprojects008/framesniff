import asyncio
import threading
from typing import Any
import queue
import time
import os
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Header, Footer, Static, Label, DataTable
from textual.reactive import reactive
from textual.worker import Worker
from textual import work
from core.common.useful_functions import export_tui_to_txt, freq_to_channel

class NetworkScannerTUI(App):
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
        "mac_hdr.mac_src.mac",
        "mac_hdr.mac_src.vendor",
        "body.tagged_parameters.ssid",
        "body.tagged_parameters.current_channel",
        "body.fixed_parameters.capabilities_information",
        "body.tagged_parameters.rsn_information",
        "body.tagged_parameters.vendor_specific"
    ]
    
    def __init__(self, ifname: str = None, dlt: str = None, channel_hopping: bool = True,
                 channel_hopping_interval: float = 5.0, bands: [str] = ["2.4", "5"],
                 timeout: float = None, logging: Any = None, Operations: Any = None):

        super().__init__()
        self.ifname = ifname
        self.dlt = dlt
        self.channel_hopping = channel_hopping
        self.channel_hopping_interval = channel_hopping_interval
        self.bands = bands
        self.timeout = timeout
        self.logging = logging
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

        self.output_filename = "scan-monitor-tui-capture.txt"

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
                        self.logging.exception("Display callback error")
                display_filter_str = ', '.join(self.DISPLAY_FIELDS)
                self.logging.info(display_filter_str)
                self.Operations.sniff(
                    ifname=self.ifname,
                    dlt=self.dlt,
                    store_filter="(mac_hdr.fc.type == 0 and mac_hdr.fc.subtype in (5, 8)) or mac_hdr.fc.type == 2",
                    display_filter=display_filter_str,
                    display_interval=0.0,
                    timeout=self.timeout,
                    store_callback=None,
                    display_callback=display_callback,
                    stop_event=self.sniff_stop_event,
                    output_filename="scan-monitor.json"
                )
            except Exception:
                error_msg = "Sniff thread error"
                self.error_queue.put(error_msg)
                self.logging.exception("Sniff thread error")
        self.sniff_thread = threading.Thread(target=sniff_thread, daemon=True, name="sniffer")
        self.sniff_thread.start()
        self.logging.info(f"Sniff thread started: {self.sniff_thread.name}")

    def start_channel_hopper_thread(self) -> None:
        def hopper_thread():
            self.logging.info("Channel hopper thread starting...")
            try:
                self.Operations.channel_hopper_sync(
                    ifname=self.ifname,
                    channel_hopping_interval=self.channel_hopping_interval,
                    bands=self.bands,
                    callback=self.update_current_channel
                )
            except Exception as error:
                self.logging.error(f"Channel hopper thread error: {error}")
        
        self.hopper_thread = threading.Thread(target=hopper_thread, daemon=True, name="channel_hopper")
        self.hopper_thread.start()
        self.logging.info(f"Channel hopper thread started: {self.hopper_thread.name}")

    def update_current_channel(self, channel: int, band: str) -> None:
        self.current_channel = channel
        self.current_band = band

    def process_display_data(self, display_data):
        broadcast = "ff:ff:ff:ff:ff:ff"
        try:
            signal = display_data.get('rt_hdr.dbm_antenna_signal')
            frame_type = display_data.get('mac_hdr.fc.type')
            subtype = display_data.get('mac_hdr.fc.subtype')
            bssid_mac = display_data.get('mac_hdr.bssid.mac')
            bssid_vendor = display_data.get('mac_hdr.bssid.vendor')
            src_mac = display_data.get('mac_hdr.mac_src.mac')
            src_vendor = display_data.get('mac_hdr.mac_src.vendor')
            ssid = display_data.get('body.tagged_parameters.ssid', '[Hidden]')
            channel_fallback= display_data.get('body.tagged_parameters.current_channel', self.current_channel)
            channel = freq_to_channel(display_data.get('rt_hdr.channel_freq')) or channel_fallback
            capabilities = display_data.get('body.fixed_parameters.capabilities_information', 0)
            rsn_info = display_data.get('body.tagged_parameters.rsn_information')
            vendor_specific = display_data.get('body.tagged_parameters.vendor_specific', {})
            
            if signal is None or frame_type is None:
                return
            
            security_info = self.detect_security(capabilities, rsn_info, vendor_specific)
            
            if frame_type == 0 and subtype in [5, 8] and bssid_mac:
                if bssid_mac != broadcast and bssid_mac not in self.clients:
                    if bssid_mac not in self.networks:
                        self.networks[bssid_mac] = {
                            'ssid': ssid or "[Hidden]",
                            'channel': channel,
                            'signal': -100,
                            'beacons': 0,
                            'vendor': bssid_vendor,
                            'last_seen': time.time(),
                            'security': security_info
                        }
                    
                    net = self.networks[bssid_mac]
                    net['beacons'] += 1
                    net['signal'] = max(net['signal'], signal or -100)
                    net['last_seen'] = time.time()
                    net['ssid'] = ssid or "[Hidden]"
            
            if (src_mac and bssid_mac) != broadcast and src_mac not in self.networks and src_mac != bssid_mac:
                if src_mac not in self.clients:
                    self.clients[src_mac] = {
                        'vendor': src_vendor,
                        'channel': channel,
                        'signal': -100,
                        'frames': 0,
                        'last_seen': time.time()
                    }
                cli = self.clients[src_mac]
                cli['frames'] += 1
                cli['channel'] = channel
                cli['signal'] = max(cli['signal'], signal or -100)
                cli['last_seen'] = time.time()
                self.associations[src_mac] = bssid_mac
            self.frames_processed += 1
        except Exception as error:
            self.error_queue.put(f"Display data processing error: {error}")
            self.logging.exception("Display data processing error")

    def detect_security(self, capabilities, rsn_info, vendor_specific):
        try:
            wps_detected = False
            
            if vendor_specific:
                for oui, vendor_data in vendor_specific.items():
                    if oui == '00:50:f2':
                        for entry_id, entry_data in vendor_data.items():
                            if entry_data.get('description') == 'Microsoft Corporation WPS':
                                wps_detected = True
                                break
            if rsn_info:
                akm_suites = rsn_info.get('akm_suites', {})
                auth = "PSK"
                for suite_id, suite_data in akm_suites.items():
                    akm_type = suite_data.get('akm_type')
                    if akm_type in [1, 3, 5, 12]:
                        auth = "MGT"
                    elif akm_type in [8, 9, 18]:
                        return {'enc': 'WPA3', 'cipher': 'GCMP', 'auth': 'SAE', 'wps': wps_detected}
                
                return {'enc': 'WPA2', 'cipher': 'CCMP', 'auth': auth, 'wps': wps_detected}
            
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
            self.logging.error(f"Security detection error: {error}")
            return {'enc': 'UNKN', 'cipher': '', 'auth': '', 'wps': False}

    def process_queued_frames(self):
        max_frames_per_cycle = 100
        processed_count = 0
        while not self.display_queue.empty() and processed_count < max_frames_per_cycle:
            try:
                display_data = self.display_queue.get_nowait()
                self.process_display_data(display_data)
                processed_count += 1
            except queue.Empty:
                break
    
    def process_errors(self):
        try:
            while not self.error_queue.empty():
                error_msg = self.error_queue.get_nowait()
                self.error_message = f"{error_msg}\nMore details in framesniff.log"
                self.logging.error(error_msg)
        except Exception:
            self.logging.exception("Error processing errors")

    def update_display(self):
        self.process_errors()
        self.duration = time.time() - self.start_time
        self.networks_count = len(self.networks)
        self.clients_count = len(self.clients)
        
        queue_size = self.display_queue.qsize()
        
        hop_status = "ON" if self.channel_hopping else "OFF"
        header_text = f"Network Scanner | Chan: {self.current_channel}({self.current_band}GHz) | Frames: {self.frames_processed} | Queue: {queue_size} | Networks: {self.networks_count} | Clients: {self.clients_count} | Time: {self.duration:.0f}s | Hop: {hop_status}"
    
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
            channel = info['channel'] if info['channel'] is not None else '?'
            signal = info['signal'] if info['signal'] is not None else -100
            beacons = info['beacons'] if info['beacons'] is not None else 0
            ssid = info['ssid'] if info['ssid'] is not None else '[Hidden]'
            vendor = info['vendor'] if info['vendor'] is not None else 'Unknown'
            
            networks_table.add_row(
                bssid, ssid, vendor, str(channel), str(signal), 
                security['enc'], str(client_count), wps_status, str(beacons)
            )
        
        clients_table = self.query_one("#clients-table", DataTable)
        clients_table.clear()
        for client_mac, info in sorted(self.clients.items(), key=lambda x: x[1]['signal'], reverse=True):
            associated_bssid = self.associations.get(client_mac, '')
            if associated_bssid:
                network_info = self.networks.get(associated_bssid, {})
                ssid = network_info.get('ssid', '(unknown)')
                bssid_display = associated_bssid
            else:
                ssid = '(not associated)'
                bssid_display = 'N/A'

            channel = info['channel'] or self.current_channel
            signal = info['signal'] if info['signal'] is not None else -100
            frames = info['frames'] if info['frames'] is not None else 0
            vendor = info['vendor'] if info['vendor'] is not None else 'Unknown'
            
            clients_table.add_row(
                client_mac, vendor, channel, str(signal), str(frames), bssid_display, ssid
            )

    def on_key(self, event):
        if event.key in ("q", "Q", "ctrl+c"):
            self.exit_application()
        if event.key in ("f12", "ctrl+s"):
            export_tui_for_txt(self, self.output_filename)

    def exit_application(self):
        self.running = False
        if hasattr(self, 'sniff_stop_event') and self.sniff_stop_event:
            self.sniff_stop_event.set()
            print("Stop event set for sniff thread")
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2.0)
            if self.sniff_thread.is_alive():
                print("Sniff thread still alive after timeout")
        self.logging.info(f"Network Monitor finished!")
        print(f"Network Monitor finished!\nSee the logs in {self.logging}")
        self.exit()


def scan_monitor(ifname: str = None, dlt: str = None, channel_hopping: bool = True,
                 channel_hopping_interval: float = 5.0, bands: [str] = ["2.4", "5"],
                 timeout: float = None, logging: Any = None, Operations: Any = None):
    app = NetworkScannerTUI(
        ifname=ifname,
        dlt=dlt,
        channel_hopping=channel_hopping,
        channel_hopping_interval=channel_hopping_interval,
        bands=bands,
        timeout=timeout,
        logging=logging,
        Operations=Operations
    )
    app.run()
