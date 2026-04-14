import sys

def import_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        raise ImportError(f'''\n
    Error when trying to import {module_name}, run the following commands:\n
    python -m venv venv
    source venv/bin/activate
    pip install {module_name}
    ./venv/bin/python {' '.join(sys.argv)}
''')

import os
import subprocess
import re
import logging
from logging import FileHandler, Formatter, getLogger
import_module("rich")
from rich.logging import RichHandler
import time
from pathlib import Path
import json

logger = getLogger(__name__)

def check_root():
    if os.geteuid() != 0:
       raise PermissionError(f"This program requires root permissions to run.\nRun: sudo {' '.join(sys.argv)}")

def check_interface_mode(ifname: str, mode: str) -> bool:
    try:
        result = subprocess.run(['iw', 'dev', ifname, 'info'],
                              capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Interface {ifname} not found or iw command failed")
        match = re.search(r'type\s+(\w+)', result.stdout)
        if match:
            if match.group(1).lower() == mode:
               return True
            else:
                raise Exception(f"error, set the interface to {mode}:\n RUN: sudo framesniff.py set-{mode} -i {ifname}")
        raise RuntimeError(f"Could not determine interface type for {ifname}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("iw command timed out")
    except FileNotFoundError:
        raise RuntimeError("iw command not found")
    except Exception as error:
        raise RuntimeError(f"Error checking interface mode: {error}")

def verify_supported_dlts(dlt: str = None):
    linktypes = [
        "DLT_IEEE802_11_RADIO",
        "DLT_EN10MB",
        "DLT_BLUETOOTH_HCI_H4"
    ]
    if dlt not in linktypes:
        raise ValueError(f"Unsupported DLT: {dlt}\nSupported DLTs:\n{', '.join(linktypes)}")

def finish_capture(sock, start_time: int, captured_frames: list, output_file_path: str):
    def _bytes_encoder(obj):
        if isinstance(obj, bytes):
            return obj.hex()
        raise TypeError(f"Type {type(obj)} not serializable")
    sock.close()
    capture_duration = time.time() - start_time
    logger.info(f"Finish capture called with {len(captured_frames)} frames")
    logger.info(f"Output path: {output_file_path}")
    if captured_frames:
        try:
            with open(output_file_path, "w") as file:
                json.dump(captured_frames, file, indent=2, default=_bytes_encoder)
            logger.info(f"Captured {len(captured_frames)} frames in {capture_duration:.2f}s")
            logger.info(f"Saved to: {output_file_path}")
        except Exception as e:
            logger.error(f"Error saving file: {e}")
    else:
        logger.info("No frames captured")

ifname_to_ifindex = lambda ifname : index_pack(socket.if_nametoindex(ifname))

def new_file_path(base: str = None, ext: str = None, filename: str = None) -> Path:
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    if not filename:
        if base and ext:
            return Path(f"{base}-{timestamp}{ext}")
        elif base:
            return Path(f"{base}-{timestamp}")
        else:
            return Path(f"{timestamp}")
    else:
        return Path(f"{timestamp}-{filename}")

def setup_logging(verbose: bool) -> Path | None:
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    log_file_path = None

    console_handler = RichHandler(
        rich_tracebacks=True,
        show_time=False,
        show_path=False
    )

    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(Formatter("%(asctime)s %(message)s"))

    logger.addHandler(console_handler)

    if verbose:
        log_file_path = str(new_file_path("framesniff", ".log"))

        file_handler = FileHandler(log_file_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )

        logger.addHandler(file_handler)

    return log_file_path
