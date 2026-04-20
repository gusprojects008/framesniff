import sys
import os
import subprocess
import re
import logging
from logging import FileHandler, Formatter, getLogger
import time
from pathlib import Path
import json
import tempfile
import shutil

logger = getLogger(__name__)

ifname_to_ifindex = lambda ifname : index_pack(socket.if_nametoindex(ifname))

def import_module(module_name):
    try:
        __import__(module_name)
    except ImportError:
        raise ImportError(f'''\n
    Error when trying to import {module_name}, run the following commands:\n
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    .venv/bin/python {' '.join(sys.argv)}
''')

def check_dependencies(module_dependencies: list = None, executable_dependencies: list = None):
    if module_dependencies:
        for dependency in module_dependencies:
            import_module(dependency)
    if executable_dependencies:
        for dependency in executable_dependencies:
            if not shutil.which(dependency):
                raise FileNotFoundError(f"{dependency} not found...")

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

def new_file_path(fullpath: str = None, fullpath_fallback: str = "framesniff") -> Path:
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    p = Path(fullpath if fullpath else fullpath_fallback)
    suffix = p.suffix
    stem = p.with_suffix("")
    return Path(f"{stem}-{timestamp}{suffix}")

def setup_logging(verbose: bool) -> Path | None:
    from rich.logging import RichHandler

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    log_file_path = None

    console_handler = RichHandler(
        rich_tracebacks=True,
        show_time=False,
        show_path=False
    )

    #console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(Formatter("%(asctime)s %(message)s"))

    logger.addHandler(console_handler)

    if verbose:
        log_file_path = str(new_file_path("framesniff.log"))

        file_handler = FileHandler(log_file_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )

        logger.addHandler(file_handler)

    return log_file_path
