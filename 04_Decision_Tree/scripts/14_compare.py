import os
from pathlib import Path
from datetime import datetime, timezone
import pandas as pd

BASE = Path(os.environ.get("CIC_DIR", r"D:\CIC-IDS2017"))
ATK = "172.16.0.1"
FE = BASE / "features"

feat = pd.read_csv(FE / "features.csv")
pred = pd.read_csv(FE / "dt_predictions.csv")
al = pd.read_csv(FE / "alerts_scan.tsv", sep="\t", header=None, dtype=str,
                 names=["run", "slice", "ts", "src", "dst", "sid", "sig"])

hhmm = lambda m: datetime.fromtimestamp(int(m) * 60, timezone.utc).strftime("%H:%M")
feat["hm"] = feat.minute.map(hhmm)
pred["hm"] = pred.minute.map(hhmm)
al["hm"] = al.ts.str[11:16]
al["scan"] = al.sig.str.startswith("ET SCAN") | (al.sid.astype(int) >= 9000000)
al["dos"] = al.sig.str.startswith("ET DOS")

SLICES = ["scan_A", "scan_B", "scan_C", "scan_U", "scan_small", "ddos"]
DT_SETS = list(pred["set"].unique())
RUNS = ["run1", "run1b", "run2"]
rows = []
for s in SLICES:
    atk = set(feat[(feat.slice == s) & (feat.src == ATK)].hm)
    row = {"tap": s, "so_phut_tan_cong": len(atk)}
    for st in DT_SETS:
        p = pred[(pred.slice == s) & (pred.src == ATK) & (pred["set"] == st)]
        row["DT_" + st] = "(train)" if p.empty else len(set(p[p.pred == 1].hm) & atk)
    for r in RUNS:
        a = al[(al.run == r) & (al.slice == s) & al.scan & ((al.src == ATK) | (al.dst == ATK))]
        row["SUR_" + r] = len(set(a.hm) & atk)
    d = al[(al.run == "run1") & (al.slice == s) & al.dos & ((al.src == ATK) | (al.dst == ATK))]
    row["ET_DOS_run1"] = len(set(d.hm) & atk)
    rows.append(row)

res = pd.DataFrame(rows)
pd.set_option("display.width", 250)
print("SO PHUT TAN CONG DUOC PHAT HIEN (muc phut, IP 172.16.0.1)")
print("Rieng dong ddos: cot DT_ va SUR_ la so phut bi goi NHAM la quet (mong muon 0);")
print("ET_DOS_run1 la so phut ET Open nhan dung la tan cong DoS.\n")
print(res.to_string(index=False))

print("\nBAO NHAM TREN LUU LUONG BINH THUONG (phut-IP khac nhau)")
for sl in ["benign_train", "benign_test"]:
    tot = feat[feat.slice == sl][["src", "hm"]].drop_duplicates().shape[0]
    out = [f"{sl}: tong phut-IP = {tot}"]
    p = pred[(pred.slice == sl)]
    for st in DT_SETS:
        q = p[(p["set"] == st) & (p.pred == 1)][["src", "hm"]].drop_duplicates().shape[0] if not p.empty else "(train)"
        out.append(f"DT_{st}={q}")
    for r in RUNS:
        a = al[(al.run == r) & (al.slice == sl) & al.scan][["src", "hm"]].drop_duplicates().shape[0]
        out.append(f"SUR_{r}={a}")
    print(" | ".join(out))

res.to_csv(FE / "bang_so_sanh.csv", index=False)
print("\nDa luu:", FE / "bang_so_sanh.csv")
