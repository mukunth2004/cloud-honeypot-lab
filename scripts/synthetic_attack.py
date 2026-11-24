"""Send harmless test commands to OUR OWN Cowrie honeypot to trigger the detection rule.

Usage: python scripts/synthetic_attack.py <honeypot-public-ip> [number-of-commands]
Only run this against your own honeypot.
"""
import datetime
import sys
import time

import paramiko


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


host = sys.argv[1]
count = int(sys.argv[2]) if len(sys.argv) > 2 else 25

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(
    host, port=22, username="root", password="123",
    look_for_keys=False, allow_agent=False, timeout=10,
)
print(f"{now()}  connected to {host}")

shell = client.invoke_shell()
time.sleep(1.0)
if shell.recv_ready():
    shell.recv(65535)

for i in range(1, count + 1):
    shell.send("uname -a\n")
    print(f"{now()}  command {i} of {count} sent")
    time.sleep(0.4)
    while shell.recv_ready():
        shell.recv(65535)

shell.send("exit\n")
time.sleep(0.5)
client.close()
print(f"{now()}  done")