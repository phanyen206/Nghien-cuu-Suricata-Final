import csv, os, socket
from pathlib import Path
from collections import defaultdict
import dpkt

BASE = Path(os.environ.get("CIC_DIR", r"D:\CIC-IDS2017"))
SLICES = BASE / "slices"
OUT = BASE / "features"
OUT.mkdir(exist_ok=True)

WIN = 10                      # do dai cua so (giay)
ATK, C2 = "172.16.0.1", "205.174.165.73"
NAMES = ["scan_A", "scan_B", "scan_U", "scan_C", "scan_small",
         "ddos", "benign_train", "benign_test"]

def is_local(ip):
    return ip.startswith("192.168.10.") or ip == ATK

def new_rec():
    return {"syn": 0, "w1024": 0, "ports_by_dst": defaultdict(set),
            "udp": 0, "udp_ports": set(), "icmp": 0, "icmp_dst": set(),
            "other": 0}

def process(name):
    recs = defaultdict(new_rec)            # (src, win) -> dac trung gui di
    recv = defaultdict(lambda: [0, 0])     # (host, win) -> [synack, rst] nhan duoc
    path = SLICES / f"{name}.pcap"
    with path.open("rb") as f:
        magic = f.read(4); f.seek(0)
        rd = (dpkt.pcapng.Reader(f) if magic == b"\x0a\x0d\x0d\x0a"
              else dpkt.pcap.Reader(f))
        for ts, buf in rd:
            try:
                ip = dpkt.ethernet.Ethernet(buf).data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                if src == C2 or dst == C2:
                    continue
                w = int(ts // WIN)
                p = ip.p
                if p == 6:
                    t = ip.data
                    fl = t.flags
                    syn, ack, rst = fl & dpkt.tcp.TH_SYN, fl & dpkt.tcp.TH_ACK, fl & dpkt.tcp.TH_RST
                    if syn and not ack and is_local(src):
                        r = recs[(src, w)]
                        r["syn"] += 1
                        r["ports_by_dst"][dst].add(t.dport)
                        if t.win == 1024:
                            r["w1024"] += 1
                    elif syn and ack and is_local(dst):
                        recv[(dst, w)][0] += 1
                    elif rst and is_local(dst):
                        recv[(dst, w)][1] += 1
                elif p == 17:
                    u = ip.data
                    if is_local(src) and u.sport >= 1024:   # bo goi tra loi cua dich vu
                        r = recs[(src, w)]
                        r["udp"] += 1
                        r["udp_ports"].add(u.dport)
                elif p == 1:
                    if is_local(src) and ip.data.type == 8:
                        r = recs[(src, w)]
                        r["icmp"] += 1
                        r["icmp_dst"].add(dst)
                else:
                    if is_local(src):
                        recs[(src, w)]["other"] += 1
            except Exception:
                continue

    rows = []
    for (src, w), r in recs.items():
        n_syn = r["syn"]
        ports = set().union(*r["ports_by_dst"].values()) if r["ports_by_dst"] else set()
        sa, rs = recv.get((src, w), [0, 0])
        if name.startswith("benign"):
            label = "benign"
        elif src == ATK:
            label = {"scan_small": "scan_small", "ddos": "ddos"}.get(name, "scan")
        else:
            label = "benign"
        rows.append({
            "slice": name, "src": src, "win": w, "minute": (w * WIN) // 60,
            "label": label,
            "n_syn": n_syn,
            "uniq_dst_ports": len(ports),
            "uniq_dst_ips": len(r["ports_by_dst"]),
            "max_ports_one_dst": max((len(s) for s in r["ports_by_dst"].values()), default=0),
            "synack_ratio": min(sa / n_syn, 1.0) if n_syn else 1.0,
            "rst_ratio": min(rs / n_syn, 1.0) if n_syn else 0.0,
            "frac_win1024": r["w1024"] / n_syn if n_syn else 0.0,
            "n_udp": r["udp"], "udp_uniq_ports": len(r["udp_ports"]),
            "n_icmp": r["icmp"], "n_other": r["other"],
        })
    return rows

if __name__ == "__main__":
    allrows = []
    for n in NAMES:
        if not (SLICES / f"{n}.pcap").exists():
            print("Bo qua (khong co file):", n); continue
        rows = process(n)
        allrows += rows
        pos = sum(1 for r in rows if r["label"] != "benign")
        print(f"{n:14} {len(rows):7,} mau | nhan tan cong: {pos:5,}")
    out = OUT / "features.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(f, fieldnames=list(allrows[0].keys()))
        wr.writeheader(); wr.writerows(allrows)
    print("Da ghi:", out)
