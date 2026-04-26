from pathlib import Path

def interfaces_completer(prefix, **kwargs):
    try:
        return [
            iface.name 
            for iface in Path("/sys/class/net").iterdir() 
            if iface.is_dir() and iface.name.startswith(prefix)
        ]
    except Exception:
        return []
