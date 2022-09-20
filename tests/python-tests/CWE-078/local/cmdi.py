import os
import subprocess

i = input("Enter command: ")

# direct input
subprocess.call(i, shell=True)
# format string
subprocess.call(f"bash -c {i}", shell=True)


# Env variable
e = os.environ.get("LOCAL_DATA")
subprocess.call("bash -c " + e + " --help", shell=True)
