# test_ics_attack.py
# ICS/SCADA Attack Simulation Script - Scapy Raw Packet Version (sendp fix)
# Usage: sudo ./venv/bin/python3 test_ics_attack.py --test all
# Get your IP with: ipconfig getifaddr en0

import argparse, time, subprocess
from scapy.all import IP, TCP, UDP, Raw, Ether, sendp

IFACE = "en0"

def get_target():
    result = subprocess.run(["ipconfig", "getifaddr", "en0"], capture_output=True, text=True)
    return result.stdout.strip()

# ── Attack 1: Modbus Write Register (FC=6) ────────────────────────────────────
def attack_modbus_write(target):
    print(f"\n[1] Modbus Write Register (FC=6) → {target}:502")
    payload = b"\x00\x01\x00\x00\x00\x06\x01\x06\x00\x01\xDE\xAD"
    for i in range(10):
        sendp(Ether()/IP(src=target, dst=target)/TCP(dport=502)/Raw(load=payload),
              iface=IFACE, verbose=0)
        time.sleep(0.1)
    print("   ✅ Done – expect HIGH alert: Modbus Write Register (FC=6)")

# ── Attack 2: Modbus Illegal Function Code (FC=90) ───────────────────────────
def attack_modbus_illegal_fc(target):
    print(f"\n[2] Modbus Illegal Function Code (FC=90) → {target}:502")
    payload = b"\x00\x01\x00\x00\x00\x06\x01\x5a\x00\x01\x00\x01"
    for i in range(5):
        sendp(Ether()/IP(src=target, dst=target)/TCP(dport=502)/Raw(load=payload),
              iface=IFACE, verbose=0)
        time.sleep(0.1)
    print("   ✅ Done – expect CRITICAL alert: Modbus Illegal Function Code")

# ── Attack 3: DNP3 Direct Operate ─────────────────────────────────────────────
def attack_dnp3(target):
    print(f"\n[3] DNP3 Direct Operate → {target}:20000")
    payload = (
        b"\x05\x64\x18\xc4\x01\x00\x02\x00\x00\x00"
        b"\xc0\x03\x0c\x01\x28"
        b"\x00\x00\x00\x00\x01\x00"
    )
    for i in range(5):
        sendp(Ether()/IP(src=target, dst=target)/UDP(dport=20000)/Raw(load=payload),
              iface=IFACE, verbose=0)
        time.sleep(0.1)
    print("   ✅ Done – expect HIGH alert: DNP3 Direct Operate")

# ── Attack 4: S7comm CPU Stop ─────────────────────────────────────────────────
def attack_s7_cpu_stop(target):
    print(f"\n[4] S7comm CPU Stop → {target}:102")
    payload = (
        b"\x03\x00\x00\x21\x1d\xd0\x00\x01\x00\xc0\x01\x0a"
        b"\x32\x01\x00\x00\x00\x00\x00\x10\x00\x00\x29"
        b"\x00\x00\x00\x00\x00\x09\x50\x5f\x50\x52\x4f\x47"
    )
    for i in range(5):
        sendp(Ether()/IP(src=target, dst=target)/TCP(dport=102)/Raw(load=payload),
              iface=IFACE, verbose=0)
        time.sleep(0.1)
    print("   ✅ Done – expect CRITICAL alert: S7comm CPU Stop Command")

# ── Attack 5: RCE Attempt (powershell payload) ────────────────────────────────
def attack_rce(target):
    print(f"\n[5] RCE Attempt (PowerShell payload) → {target}:4444")
    payload = b"GET /shell HTTP/1.1\r\nHost: target\r\n\r\npowershell -enc ZQBjAGgAbwAgAHQAZQBzAHQA"
    for i in range(3):
        sendp(Ether()/IP(src=target, dst=target)/TCP(dport=4444)/Raw(load=payload),
              iface=IFACE, verbose=0)
        time.sleep(0.2)
    print("   ✅ Done – expect CRITICAL alert: RCE Attempt")

# ── Attack 6: SMBv1 Exploit (EternalBlue signature) ───────────────────────────
def attack_smb(target):
    print(f"\n[6] SMBv1 Exploit signature → {target}:445")
    payload = b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"
    for i in range(3):
        sendp(Ether()/IP(src=target, dst=target)/TCP(dport=445)/Raw(load=payload),
              iface=IFACE, verbose=0)
        time.sleep(0.2)
    print("   ✅ Done – expect CRITICAL alert: SMBv1 Exploit")

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICS/SCADA Attack Simulator")
    parser.add_argument("--target", default=None, help="Target IP (default: auto-detect en0)")
    parser.add_argument("--test", default="all",
                        choices=["all", "modbus_write", "illegal_fc", "dnp3", "s7", "rce", "smb"])
    args = parser.parse_args()

    target = args.target or get_target()
    if not target:
        print("❌ Could not detect IP. Run: ipconfig getifaddr en0 and pass with --target")
        exit(1)

    print("=" * 60)
    print("  ICS/SCADA Attack Simulator (Scapy sendp — Layer 2)")
    print(f"  Target : {target}  |  Interface : {IFACE}")
    print("  Make sure app is in Active Detect mode + Signature ON!")
    print("=" * 60)

    if args.test in ("all", "modbus_write"):  attack_modbus_write(target)
    if args.test in ("all", "illegal_fc"):    attack_modbus_illegal_fc(target)
    if args.test in ("all", "dnp3"):          attack_dnp3(target)
    if args.test in ("all", "s7"):            attack_s7_cpu_stop(target)
    if args.test in ("all", "rce"):           attack_rce(target)
    if args.test in ("all", "smb"):           attack_smb(target)

    print("\n✅ All simulations complete. Check the Triage Console.")