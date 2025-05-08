import pandas as pd
import numpy as np
import random
import uuid
from datetime import datetime, timedelta

# reproducibility
np.random.seed(21704)
random.seed(21704)

def gen_data(n=40000, noise_pct=0.05):
    recs = []
    types = ["DDoS", "Intrusion", "Malware"]
    pkt_types = ["Control", "Data"]
    trf_types = ["HTTP", "DNS", "FTP", "SSH"]

    for i in range(n):
        t = types[i % 3]
        ts = datetime(2023, 1, 1) + timedelta(seconds=random.randint(0, 86400 * 30))

        if t == "DDoS":
            dur = np.random.uniform(1, 80)
            pkts = int(np.random.uniform(1000, 3000))
            syn = np.random.uniform(0.1, 0.5)
            plen = np.random.normal(200, 80)
            ano = np.random.uniform(65, 90)
            proto = random.choice(["UDP", "ICMP", "TCP"])
            trf = random.choice(trf_types)
            sev = "High"
            act = random.choice(["Blocked", "Logged"])
        elif t == "Intrusion":
            dur = np.random.uniform(100, 250)
            pkts = int(np.random.uniform(500, 2200))
            syn = np.random.uniform(0.3, 0.7)
            plen = np.random.normal(350, 120)
            ano = np.random.uniform(45, 75)
            proto = "TCP"
            trf = random.choice(trf_types)
            sev = random.choice(["Medium", "High"])
            act = random.choice(["Logged", "Blocked"])
        else:  # Malware
            dur = np.random.uniform(300, 1800)
            pkts = int(np.random.uniform(150, 1800))
            syn = np.random.uniform(0.0, 0.4)
            plen = np.random.normal(600, 200)
            ano = np.random.uniform(20, 60)
            proto = "TCP"
            trf = random.choice(["HTTP", "FTP", "DNS"])
            sev = random.choice(["Low", "Medium"])
            act = random.choice(["Logged", "Ignored"])

        pps = pkts / max(dur, 1)
        recs.append({
            "id": str(uuid.uuid4()),
            "ts": ts,
            "dur": round(dur, 2),
            "pkts": pkts,
            "pps": round(pps, 2),
            "syn": round(syn, 3),
            "plen": round(max(plen, 1), 2),
            "ano": round(ano, 2),
            "proto": proto,
            "pkt_type": random.choice(pkt_types),
            "trf_type": trf,
            "sev": sev,
            "act": act,
            "label": t
        })

    df = pd.DataFrame(recs)

    # noise: 20% missing in numeric cols
    for c in ["plen", "ano", "pps", "syn"]:
        df.loc[np.random.rand(len(df)) < 0.20, c] = np.nan

    # 10% duplicates
    df = pd.concat([df, df.sample(frac=0.10, random_state=21704)], ignore_index=True)

    # 5% outliers
    for c in ["plen", "ano", "pps", "pkts"]:
        idx = df.sample(frac=0.05, random_state=21704).index
        df.loc[idx, c] = df[c].max() * 10

    # 5% label flips
    mask = np.random.rand(len(df)) < noise_pct
    df.loc[mask, "label"] = df.loc[mask, "label"].apply(
        lambda x: random.choice([o for o in types if o != x])
    )

    # shuffle & save
    df = df.sample(frac=1, random_state=21704).reset_index(drop=True)
    df.to_csv("synthetic_cyber_attacks.csv", index=False)
    print("Saved synthetic_cyber_attacks.csv")

    return df

# Generate dataset
df = gen_data()
