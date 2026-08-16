import subprocess
import sys
import time

TARGET = "examples/06_verifiable_audit_trail.py"
LINE_DELAY = 0.10
HEADER_DELAY = 0.9

proc = subprocess.Popen(
    [sys.executable, "-u", TARGET],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)

for line in proc.stdout:
    line = line.rstrip("\n")
    print(line)
    sys.stdout.flush()
    if line.strip().startswith("---") or "===" in line or line.strip().lower().startswith("step"):
        time.sleep(HEADER_DELAY)
    else:
        time.sleep(LINE_DELAY)

proc.wait()