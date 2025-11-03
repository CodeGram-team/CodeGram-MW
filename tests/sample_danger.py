# tests/sample_violate.py
# This file intentionally contains patterns that a static analyzer should flag.
# IMPORTANT: all "dangerous" actions are placed under `if False:` so they DO NOT run.

# 1) risky imports
import subprocess        # should trigger "process execution" rule
import socket           # should trigger "network access" rule
import ctypes           # should trigger "native/native-call" rule

# 2) dynamic execution (eval/exec)
payload = "print('dynamic!')"
def run_dynamic(x):
    # dynamic execution usage (detector should flag 'eval'/'exec')
    eval(x)

# 3) __import__ usage (often used for evasion)
if False:
    # unreachable guard to avoid running at test-time
    m = __import__("os")
    m.system("echo would-be-dangerous")

# 4) subprocess invocation example (safe here: echo)
if False:
    subprocess.Popen(["/bin/echo", "this would launch a subprocess"])

# 5) possible infinite-loop pattern (detected by regex)
# note: placed inside False-guard so it won't actually loop at run-time
if False:
    while True:
        pass

def harmless_wrapper():
    # regular function to keep file syntactically valid
    return "ok"

if __name__ == "__main__":
    print("violate-sample loaded (static only)")
