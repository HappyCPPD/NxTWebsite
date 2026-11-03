# Ghost in the Wire

**Event:** HICyberCon CTF 2026
**Category:** forensics
**Flag:** `hiCTF{1cmp_3xf1l_d3t3ct3d}`

---

**Category:** network forensics · **Artifact:** `extracted/ghost_traffic.pcap` (30 packets)

## Hint
> "…anomalous ICMP traffic … Something is being exfiltrated through the wire…"

## Solve
Follow the ICMP echo-request payloads. Packets 3-28 come from `10.13.37.1` and each
carries **one byte** of exfiltrated data in its payload; the other ICMP traffic
(192.168.1.100, which even pings `server1` with `70696e672066726f6d2073657276657231` =
"ping from server1") is noise.

```bash
tshark -r ghost_traffic.pcap -Y 'icmp.type==8' -T fields -e frame.number -e ip.src -e data.data
# frame 3 -> 68, 4 -> 69, 5 -> 43, 6 -> 54, 7 -> 46, 8 -> 7b, 9 -> 31, ...
python3 - <<'EOF'
import subprocess
out = subprocess.check_output(["tshark","-r","ghost_traffic.pcap","-Y",
        "icmp.type==8 && ip.src==10.13.37.1","-T","fields","-e","data.data"], text=True)
print(bytes.fromhex("".join(out.split())).decode())
EOF
```

Output: `hiCTF{1cmp_3xf1l_d3t3ct3d}` (the leading `1` is a leet "i" - the payload
bytes really are `31 63 6d 70` = "1cmp").

## Flag
```
hiCTF{1cmp_3xf1l_d3t3ct3d}
```
