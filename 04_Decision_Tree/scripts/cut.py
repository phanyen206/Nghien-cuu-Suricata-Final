import dpkt, socket
from pathlib import Path

PCAP = Path(r"D:\CIC-IDS2017\PCAP\Friday-WorkingHours.pcap")
OUTDIR = Path(r"D:\CIC-IDS2017\slices"); OUTDIR.mkdir(exist_ok=True)
ATK = socket.inet_aton("172.16.0.1")
C2  = socket.inet_aton("205.174.165.73")
BASE = 1499385600
t = lambda h, m: BASE + h*3600 + m*60

SLICES = {  # ten: (danh_sach_khoang, loc_benign)
    "scan_A":     ([(t(17,51), t(17,57))], False),
    "scan_B":     ([(t(18,8),  t(18,11))], False),
    "scan_U":     ([(t(18,11), t(18,16))], False),
    "scan_C":     ([(t(18,22), t(18,25))], False),
    "scan_small": ([(t(16,52), t(17,20))], False),
    "ddos":       ([(t(18,56), t(19,17))], False),
    "benign_train": ([(t(16,7), t(16,52)), (t(17,20), t(17,44))], True),
    "benign_test":  ([(t(18,25), t(18,56))], True),
}

files, writers, counts = {}, {}, {}
for name in SLICES:
    files[name] = open(OUTDIR / f"{name}.pcap", "wb")
    writers[name] = dpkt.pcap.Writer(files[name], snaplen=65535)
    counts[name] = 0

with PCAP.open("rb") as f:
    magic = f.read(4); f.seek(0)
    rd = (dpkt.pcapng.Reader(f) if magic == b"\x0a\x0d\x0d\x0a"
          else dpkt.pcap.Reader(f))
    for ts, buf in rd:
        for name, (ranges, filt) in SLICES.items():
            if not any(a <= ts < b for a, b in ranges):
                continue
            if filt:
                try:
                    ip = dpkt.ethernet.Ethernet(buf).data
                    if isinstance(ip, dpkt.ip.IP) and (
                        ip.src in (ATK, C2) or ip.dst in (ATK, C2)):
                        continue
                except Exception:
                    pass
            writers[name].writepkt(buf, ts)
            counts[name] += 1

for fh in files.values():
    fh.close()
for name, n in counts.items():
    print(f"{name:14} {n:>10,} goi")