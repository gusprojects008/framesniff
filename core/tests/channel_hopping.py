import time
import subprocess
ifname = "wlan0"
channels = [1, 6, 11]
while True:
    for ch in channels:
        print(f"Setting channel {ch}")
        proc = subprocess.run(["sudo", "iw", "dev", ifname, "set", "channel", str(ch)],
                              capture_output=True, text=True)
        print(proc.stdout, proc.stderr)
        time.sleep(2)
