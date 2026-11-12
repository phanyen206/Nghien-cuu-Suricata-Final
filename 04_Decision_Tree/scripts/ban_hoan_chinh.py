import os
from pathlib import Path
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

BASE = Path(os.environ.get("CIC_DIR", r"D:\CIC-IDS2017"))
FEATURE_DIR = BASE / "features"
FEATURE_DIR.mkdir(parents=True, exist_ok=True)
df = pd.read_csv(FEATURE_DIR / "features.csv")

BEHAV = [
    "n_syn", "uniq_dst_ports", "uniq_dst_ips", "max_ports_one_dst",
    "synack_ratio", "rst_ratio", "n_udp", "udp_uniq_ports",
    "n_icmp", "n_other"
]

SETS = {
    "HANH_VI": BEHAV,
    "HANH_VI+WINDOW": BEHAV + ["frac_win1024"],
    "KHONG_KHOI_LUONG": [
        "uniq_dst_ports", "uniq_dst_ips", "max_ports_one_dst",
        "synack_ratio", "rst_ratio", "udp_uniq_ports"
    ],
    "CHI_WINDOW": ["frac_win1024"]
}

df["y"] = df["label"].isin(["scan", "scan_small"]).astype(int)
train = df[df["slice"].isin(["scan_A", "benign_train"])].copy()
test = df[df["slice"].isin(["scan_B", "scan_C", "benign_test"])].copy()
extra = {
    name: df[df["slice"] == name].copy()
    for name in ["scan_U", "scan_small", "ddos"]
}

if train.empty or test.empty:
    raise ValueError("Train hoac Test dang rong. Hay kiem tra cot slice.")

all_features = sorted(set(f for fs in SETS.values() for f in fs))
missing = [col for col in all_features if col not in df.columns]
if missing:
    raise ValueError(f"Thieu cac cot dac trung: {missing}")
if df[all_features].isna().any().any():
    raise ValueError("Du lieu co gia tri NaN. Can xu ly truoc khi huan luyen.")

print("=" * 70)
print("THONG TIN TAP DU LIEU")
print("=" * 70)
print(f"Tong so mau: {len(df):,}")
print(f"Train: {len(train):,} mau | {train.y.sum():,} scan")
print(f"Test : {len(test):,} mau | {test.y.sum():,} scan")
for name, d in extra.items():
    print(f"{name}: {len(d):,} mau | {d.y.sum():,} scan")


def minute_table(d, pred):
    temp = d[["src", "minute", "y"]].copy()
    temp["pred"] = np.asarray(pred)
    g = temp.groupby(["src", "minute"], as_index=False).agg(
        truth=("y", "max"), pred=("pred", "max")
    )
    g["gio_UTC"] = pd.to_datetime(
        g["minute"] * 60, unit="s", utc=True
    ).dt.strftime("%H:%M")
    return g


metrics_results = []
confusion_results = {}
importance_results = {}
minute_results = {}
allpred = []

for name, feats in SETS.items():
    print("\n" + "=" * 70)
    print(f"BO DAC TRUNG: {name}")
    print("=" * 70)

    clf = DecisionTreeClassifier(
        max_depth=3, class_weight="balanced", random_state=42
    )
    clf.fit(train[feats], train["y"])

    print("\nCAU TRUC CAY QUYET DINH:\n")
    print(export_text(clf, feature_names=feats))

    imp = sorted(zip(feats, clf.feature_importances_), key=lambda x: -x[1])
    importance_results[name] = {a: b for a, b in imp if b > 0}
    print("DO QUAN TRONG DAC TRUNG:")
    for feature, value in imp:
        if value > 0:
            print(f"{feature:25s}: {value:.4f}")

    p = clf.predict(test[feats])
    pr, rc, f1, _ = precision_recall_fscore_support(
        test["y"], p, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(
        test["y"], p, labels=[0, 1]
    ).ravel()

    metrics_results.append({
        "Bo_dac_trung": name, "Precision": pr, "Recall": rc, "F1": f1,
        "TP": tp, "FN": fn, "FP": fp, "TN": tn
    })
    confusion_results[name] = (tn, fp, fn, tp)

    print("\nKET QUA TEST - MOI CUA SO 10 GIAY")
    print(f"TP = {tp:,}")
    print(f"FN = {fn:,}")
    print(f"FP = {fp:,}")
    print(f"TN = {tn:,}")
    print(f"Precision = {pr:.4f}")
    print(f"Recall    = {rc:.4f}")
    print(f"F1        = {f1:.4f}")

    mt = minute_table(test, p)
    minute_results[name] = mt.copy()
    atk = mt[mt["truth"] == 1]
    ben = mt[mt["truth"] == 0]
    print("\nKET QUA THEO IP - PHUT")
    print(f"Phat hien dung: {int((atk.pred == 1).sum()):,}/{len(atk):,} IP-phut tan cong")
    print(f"Bo sot: {int((atk.pred == 0).sum()):,}/{len(atk):,} IP-phut tan cong")
    print(f"Bao nham: {int((ben.pred == 1).sum()):,}/{len(ben):,} IP-phut benign")
    print("\nDANH SACH IP-PHUT TAN CONG:")
    print(atk[["src", "gio_UTC", "truth", "pred"]].to_string(index=False))

    for n, d in extra.items():
        if d.empty:
            print(f"\n[{n}] Khong co du lieu")
            continue
        pe = clf.predict(d[feats])
        m = minute_table(d, pe)
        attack_windows = int(d["y"].sum())
        detected_windows = int(pe[d["y"].values == 1].sum())
        a = m[m["truth"] == 1]
        b = m[m["truth"] == 0]
        detected_minutes = int(a["pred"].sum())
        false_minutes = int(b["pred"].sum())
        print(f"\n[{n}]")
        print(f"Cua so Scan phat hien: {detected_windows:,}/{attack_windows:,}")
        print(f"Phut-IP Scan phat hien: {detected_minutes:,}/{len(a):,}")
        print(f"Phut-IP lop 0 bi bao nham: {false_minutes:,}/{len(b):,}")
        if n == "ddos":
            print("Luu y: DDOS duoc gan nhan 0 trong bai toan phan loai Scan/Benign, khong phai lop tan cong Scan.")

    allpred.append(test.assign(set=name, pred=p))
    for n, d in extra.items():
        if not d.empty:
            pe = clf.predict(d[feats])
            allpred.append(d.assign(set=name, pred=pe))

summary = pd.DataFrame(metrics_results)
print("\n" + "=" * 70)
print("TONG HOP KET QUA CAC BO DAC TRUNG")
print("=" * 70)
print(summary.round(4).to_string(index=False))
summary.to_csv(FEATURE_DIR / "dt_summary.csv", index=False, encoding="utf-8-sig")

fig, axes = plt.subplots(2, 2, figsize=(13, 10))
for ax, (name, values) in zip(axes.flat, confusion_results.items()):
    tn, fp, fn, tp = values
    cm = np.array([[tn, fp], [fn, tp]])
    ax.imshow(cm, cmap="Blues")
    ax.set_title(name, fontsize=12, fontweight="bold")
    ax.set_xlabel("Du doan")
    ax.set_ylabel("Thuc te")
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Benign", "Scan"])
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Benign", "Scan"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    fontsize=12, color="black")
plt.suptitle("CONFUSION MATRIX - DECISION TREE", fontsize=15, fontweight="bold")
plt.tight_layout()
plt.savefig(FEATURE_DIR / "01_confusion_matrix.png", dpi=200, bbox_inches="tight")
plt.show()

result_df = summary.set_index("Bo_dac_trung")[["Precision", "Recall", "F1"]]
ax = result_df.plot(kind="bar", figsize=(12, 6), ylim=(0, 1), width=0.75)
ax.set_title("SO SANH HIEU NANG 4 BO DAC TRUNG", fontsize=14, fontweight="bold")
ax.set_xlabel("Bo dac trung")
ax.set_ylabel("Gia tri")
ax.set_xticklabels(ax.get_xticklabels(), rotation=15)
ax.grid(axis="y", alpha=0.3)
ax.legend(title="Chi so")
plt.tight_layout()
plt.savefig(FEATURE_DIR / "02_compare_metrics.png", dpi=200, bbox_inches="tight")
plt.show()

fig, axes = plt.subplots(2, 2, figsize=(15, 10))
for ax, (name, values) in zip(axes.flat, importance_results.items()):
    if not values:
        ax.set_title(name + " - Khong co dac trung duoc su dung")
        continue
    names = list(values.keys())
    scores = list(values.values())
    ax.barh(names, scores)
    ax.invert_yaxis()
    ax.set_title(name, fontsize=12, fontweight="bold")
    ax.set_xlabel("Feature importance")
    ax.grid(axis="x", alpha=0.3)
plt.suptitle("FEATURE IMPORTANCE - DECISION TREE", fontsize=15, fontweight="bold")
plt.tight_layout()
plt.savefig(FEATURE_DIR / "03_feature_importance.png", dpi=200, bbox_inches="tight")
plt.show()

fig, axes = plt.subplots(2, 2, figsize=(16, 10))
for ax, (name, mt) in zip(axes.flat, minute_results.items()):
    timeline = mt.groupby("minute", as_index=False).agg(
        Tan_cong_thuc_te=("truth", "sum"),
        Du_doan_duong=("pred", lambda x: int(
            ((x == 1) & (mt.loc[x.index, "truth"] == 1)).sum()
        )),
        Bao_dong_nham=("pred", lambda x: int(
            ((x == 1) & (mt.loc[x.index, "truth"] == 0)).sum()
        ))
    )
    timeline["time"] = pd.to_datetime(timeline["minute"] * 60, unit="s", utc=True)
    ax.plot(timeline["time"], timeline["Tan_cong_thuc_te"], marker="o", label="Tan cong thuc te")
    ax.plot(timeline["time"], timeline["Du_doan_duong"], marker="x", label="Phat hien dung")
    ax.plot(timeline["time"], timeline["Bao_dong_nham"], marker="s", label="Bao dong nham")
    ax.set_title(name, fontsize=12, fontweight="bold")
    ax.set_xlabel("Thoi gian UTC")
    ax.set_ylabel("So IP-phut")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    ax.tick_params(axis="x", rotation=30)
plt.suptitle("DIEN BIEN PHAT HIEN TAN CONG THEO THOI GIAN", fontsize=15, fontweight="bold")
plt.tight_layout()
plt.savefig(FEATURE_DIR / "04_attack_timeline.png", dpi=200, bbox_inches="tight")
plt.show()

predictions = pd.concat(allpred, ignore_index=True)
predictions.to_csv(FEATURE_DIR / "dt_predictions.csv", index=False, encoding="utf-8-sig")

print("\n" + "=" * 70)
print("HOAN TAT HUAN LUYEN VA DANH GIA DECISION TREE")
print("=" * 70)
print("\nCAC FILE DA LUU:")
for file in [
    "dt_summary.csv", "dt_predictions.csv", "01_confusion_matrix.png",
    "02_compare_metrics.png", "03_feature_importance.png", "04_attack_timeline.png"
]:
    print(" -", FEATURE_DIR / file)
print("\nTat ca ket qua nam trong:", FEATURE_DIR)
