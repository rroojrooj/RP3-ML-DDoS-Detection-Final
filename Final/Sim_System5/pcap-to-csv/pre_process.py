import os
import subprocess
import io
import pandas as pd
import numpy as np
from datetime import datetime
from scipy.stats import entropy
import warnings
import shutil

warnings.filterwarnings("ignore")

from datetime import datetime




REQUIRED_FEATURES = [
    'timestamp', 'Dst Port', 'protocol', 'Flow Duration',
    'Flow Duration_rolling_mean', 'Flow Duration_rolling_std',
    'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
    'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Max', 'Fwd IAT Min',
    'SYN Flag Cnt', 'pkts_ratio', 'byte_per_duration', 'entropy_pkt_len',
    'Subflow Fwd Byts', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
    'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Max', 'Bwd IAT Min',
    'Flow Bytes/s', 'Flow Packets/s', 'label'
]


def ensure_tshark_installed():
    if shutil.which("tshark") is None:
        print("tshark not found; installing via apt-get...")
        subprocess.run(["apt-get", "update"], check=True)
        subprocess.run(["apt-get", "install", "-y", "tshark"], check=True)
        print("tshark installed.")
    else:
        print("tshark is already installed.")



def convert_protocol_to_numeric(proto):
    if isinstance(proto, str):
        proto_lower = proto.lower()
        if "tcp" in proto_lower:
            return 6
        elif "udp" in proto_lower:
            return 17
    return 0


def count_syn_flags(flags_series):
    cnt = 0
    for flag in flags_series:
        try:
            val = int(flag, 0)  # hex if prefixed with "0x"
            if val & 0x02:  # SYN flag bit
                cnt += 1
        except Exception:
            continue
    return cnt


def format_timestamp(ts):
    return int(ts.strftime("%Y%m%d%H%M%S") + ts.strftime("%f")[:3])


####################################################################

def convert_pcap_to_dataframe(pcap_file):
    command = [
        "tshark",
        "-r", pcap_file,
        "-T", "fields",
        "-E", "separator=,",
        "-E", "header=y",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "tcp.flags",
        "-e", "frame.number"
    ]
    print("Converting pcap to DataFrame using tshark (in-memory)...")
    tshark_out = subprocess.check_output(command).decode('utf-8')
    df = pd.read_csv(io.StringIO(tshark_out))
    print("Packet DataFrame shape:", df.shape)
    return df


####################################################################
# Compute keys and determine direction with heuristic swap if forward is very low.

def add_flow_keys_and_direction(df):
    # Convert ports to integers
    df["tcp.srcport"] = pd.to_numeric(df["tcp.srcport"], errors="coerce").fillna(0).astype(int)
    df["tcp.dstport"] = pd.to_numeric(df["tcp.dstport"], errors="coerce").fillna(0).astype(int)

    # Compute keys
    df["fwd_key"] = df.apply(
        lambda row: (row["ip.src"], row["tcp.srcport"], row["ip.dst"], row["tcp.dstport"], row["frame.protocols"]),
        axis=1)
    df["rev_key"] = df.apply(
        lambda row: (row["ip.dst"], row["tcp.dstport"], row["ip.src"], row["tcp.srcport"], row["frame.protocols"]),
        axis=1)
    df["canonical_key"] = df.apply(lambda row: (
        min(str(row["ip.src"]), str(row["ip.dst"])),
        min(row["tcp.srcport"], row["tcp.dstport"]),
        max(str(row["ip.src"]), str(row["ip.dst"])),
        max(row["tcp.srcport"], row["tcp.dstport"]),
        row["frame.protocols"]
    ), axis=1)

    # Initially, label as forward if fwd_key equals canonical_key, else backward.
    df["direction"] = df.apply(lambda row: "forward" if row["fwd_key"] == row["canonical_key"] else "backward", axis=1)

    # Heuristic swap: if forward count is very low (e.g. < 10% of total for that canonical key), swap the labels.
    def adjust_direction(group):
        if group.shape[0] == 0:
            return group
        fwd = group[group["direction"] == "forward"]
        bwd = group[group["direction"] == "backward"]
        if fwd.shape[0] < 0.1 * group.shape[0]:
            # Swap forward and backward
            group.loc[fwd.index, "direction"] = "backward"
            group.loc[bwd.index, "direction"] = "forward"
        return group

    df = df.groupby("canonical_key", group_keys=False).apply(adjust_direction)
    print("Forward packet count:", df[df["direction"] == "forward"].shape[0])
    print("Backward packet count:", df[df["direction"] == "backward"].shape[0])
    return df


####################################################################
# custom aggregation per canonical key

def custom_aggregate_flow(group):
    key = group.iloc[0]["canonical_key"]

    fwd = group[group["direction"] == "forward"]
    bwd = group[group["direction"] == "backward"]

    fwd_count = fwd.shape[0]
    bwd_count = bwd.shape[0]

    fwd_sum = fwd["frame.len"].astype(float).sum() if fwd_count > 0 else 0
    bwd_sum = bwd["frame.len"].astype(float).sum() if bwd_count > 0 else 0

    fwd_max = fwd["frame.len"].astype(float).max() if fwd_count > 0 else 0
    fwd_min = fwd["frame.len"].astype(float).min() if fwd_count > 0 else 0
    fwd_mean = fwd["frame.len"].astype(float).mean() if fwd_count > 0 else 0
    fwd_std = fwd["frame.len"].astype(float).std() if fwd_count > 1 else 0

    bwd_max = bwd["frame.len"].astype(float).max() if bwd_count > 0 else 0
    bwd_min = bwd["frame.len"].astype(float).min() if bwd_count > 0 else 0

    fwd_time_min = fwd["frame.time_epoch"].astype(float).min() if fwd_count > 0 else np.inf
    fwd_time_max = fwd["frame.time_epoch"].astype(float).max() if fwd_count > 0 else 0
    bwd_time_min = bwd["frame.time_epoch"].astype(float).min() if bwd_count > 0 else np.inf
    bwd_time_max = bwd["frame.time_epoch"].astype(float).max() if bwd_count > 0 else 0

    overall_time_min = min(fwd_time_min, bwd_time_min)
    overall_time_max = max(fwd_time_max, bwd_time_max)

    fwd_syn = count_syn_flags(fwd["tcp.flags"]) if fwd_count > 0 else 0

    agg = {
        "canonical_key": key,
        "fwd_count": fwd_count,
        "bwd_count": bwd_count,
        "fwd_sum": fwd_sum,
        "bwd_sum": bwd_sum,
        "fwd_max": fwd_max,
        "fwd_min": fwd_min,
        "fwd_mean": fwd_mean,
        "fwd_std": fwd_std,
        "bwd_max": bwd_max,
        "bwd_min": bwd_min,
        "fwd_time_min": fwd_time_min,
        "fwd_time_max": fwd_time_max,
        "bwd_time_min": bwd_time_min,
        "bwd_time_max": bwd_time_max,
        "overall_time_min": overall_time_min,
        "overall_time_max": overall_time_max,
        "fwd_syn": fwd_syn
    }
    return pd.Series(agg)


def aggregate_flows(df):
    flows = df.groupby("canonical_key").apply(custom_aggregate_flow).reset_index(drop=True)
    return flows


####################################################################
# 32 

def map_flows_to_final_features(df):
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Timestamp
    ts = df["overall_time_min"].fillna(0)
    ts_dt = pd.to_datetime(ts, unit="s", errors="coerce").fillna(pd.Timestamp(0))
    df["timestamp"] = df["overall_time_min"].apply(
        lambda t: format_timestamp(pd.to_datetime(t, unit="s")))  # call our format function

    # 4th element of canonical_key
    df["Dst Port"] = df["canonical_key"].apply(lambda k: float(k[3]) if isinstance(k, tuple) else 0)

    # from canonical_key element 5
    df["protocol"] = df["canonical_key"].apply(
        lambda k: float(convert_protocol_to_numeric(k[4])) if isinstance(k, tuple) else 0)

    # (overall_time_max - overall_time_min)*1e6
    df["Flow Duration"] = (df["overall_time_max"] - df["overall_time_min"]).fillna(0) * 1e6

    #  rolling mean and std across flows (by timestamp)
    df.sort_values("timestamp", inplace=True, ignore_index=True)
    df["Flow Duration_rolling_mean"] = df["Flow Duration"].rolling(window=10, min_periods=1).mean().fillna(0)
    df["Flow Duration_rolling_std"] = df["Flow Duration"].rolling(window=10, min_periods=1).std().fillna(0)

    # Fwd Bwd count
    df["Tot Fwd Pkts"] = df["fwd_count"].fillna(0).astype(float)
    df["Tot Bwd Pkts"] = df["bwd_count"].fillna(0).astype(float)

    # Fwd Bwd sum
    df["TotLen Fwd Pkts"] = df["fwd_sum"].fillna(0).astype(float)
    df["TotLen Bwd Pkts"] = df["bwd_sum"].fillna(0).astype(float)

    # Fwd Pkt Len stats
    df["Fwd Pkt Len Max"] = df["fwd_max"].fillna(0).astype(float)
    df["Fwd Pkt Len Min"] = df["fwd_min"].fillna(0).astype(float)
    df["Fwd Pkt Len Mean"] = df["fwd_mean"].fillna(0).astype(float)
    df["Fwd Pkt Len Std"] = df["fwd_std"].fillna(0).astype(float)

    # Bwd Pkt Len stats
    df["Bwd Pkt Len Max"] = df["bwd_max"].fillna(0).astype(float)
    df["Bwd Pkt Len Min"] = df["bwd_min"].fillna(0).astype(float)

    # if fwd_count > 1, (fwd_time_max - fwd_time_min)*1e6/(fwd_count -1)
    df["Fwd IAT Mean"] = np.where(df["fwd_count"] > 1,
                                  (df["fwd_time_max"] - df["fwd_time_min"]) * 1e6 / (df["fwd_count"] - 1),
                                  0)
    df["Fwd IAT Tot"] = np.where(df["fwd_count"] > 1,
                                 df["Fwd IAT Mean"] * (df["fwd_count"] - 1),
                                 0)
    df["Fwd IAT Max"] = df["Fwd IAT Mean"]
    df["Fwd IAT Min"] = df["Fwd IAT Mean"]

    # fwd_syn
    df["SYN Flag Cnt"] = df["fwd_syn"].fillna(0).astype(float)

    # if bwd_count > 0, fwd_count/bwd_count, else 1
    df["pkts_ratio"] = np.where(df["bwd_count"] > 0, df["fwd_count"] / df["bwd_count"], 1)

    # (TotLen Fwd + TotLen Bwd) / (Flow Duration in seconds)
    sec = df["Flow Duration"] / 1e6
    df["byte_per_duration"] = np.where(sec > 0, (df["TotLen Fwd Pkts"] + df["TotLen Bwd Pkts"]) / sec, 0)

    # entropy from distribution of Fwd Pkt Len Mean (20 bins)
    bins_arr = np.floor(df["Fwd Pkt Len Mean"] / 10)
    if np.all(bins_arr == 0):
        ent_val = 0
    else:
        hist_counts, _ = np.histogram(bins_arr, bins=20)
        ent_val = entropy(hist_counts) if hist_counts.sum() > 0 else 0
    df["entropy_pkt_len"] = ent_val

    # ... use TotLen Fwd Pkts
    df["Subflow Fwd Byts"] = df["TotLen Fwd Pkts"]

    # if bwd_count > 1, (bwd_time_max - bwd_time_min)*1e6/(bwd_count -1)
    df["Bwd IAT Tot"] = np.where(df["bwd_count"] > 1,
                                 (df["bwd_time_max"] - df["bwd_time_min"]) * 1e6,
                                 0)
    df["Bwd IAT Mean"] = np.where(df["bwd_count"] > 1,
                                  df["Bwd IAT Tot"] / (df["bwd_count"] - 1),
                                  0)
    df["Bwd IAT Max"] = df["Bwd IAT Mean"]
    df["Bwd IAT Min"] = df["Bwd IAT Mean"]

    # (TotLen Fwd + TotLen Bwd) / (Flow Duration in sec)
    df["Flow Bytes/s"] = np.where(sec > 0, (df["TotLen Fwd Pkts"] + df["TotLen Bwd Pkts"]) / sec, 0)
    # Flow Packets/s: (Tot Fwd Pkts + Tot Bwd Pkts) / (Flow Duration in sec)
    df["Flow Packets/s"] = np.where(sec > 0, (df["Tot Fwd Pkts"] + df["Tot Bwd Pkts"]) / sec, 0)


    #df["label"] = 0
    return df




##############################################################################
# Ensure all column exists

def complete_missing_columns(df, required_cols=REQUIRED_FEATURES):
    for col in required_cols:
        if col not in df.columns:
            df[col] = 0
    return df


##############################################################################
# pcap flow
def process_flows_from_pcap(pcap_file):
    print("Converting pcap to DataFrame using tshark (in-memory)...")
    command = [
        "tshark",
        "-2",
        "-r", pcap_file,
        "-T", "fields",
        "-E", "separator=,",
        "-E", "header=y",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "tcp.flags",
        "-e", "frame.number"
    ]

    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode != 0:
        print("tshark encountered an issue:", result.stderr.strip())
        # If the stdout is not empty, attempt to proceed anyway
        if not result.stdout.strip():
            raise Exception(f"tshark failed without output: <{result.stderr.strip()}>")
    out = result.stdout

    df_packets = pd.read_csv(io.StringIO(out))
    print("Packet DataFrame shape:", df_packets.shape)

    df_packets = add_flow_keys_and_direction(df_packets)
    flows = aggregate_flows(df_packets)
    print("Aggregated flows shape:", flows.shape)

    flows_final = map_flows_to_final_features(flows)
    flows_final = complete_missing_columns(flows_final)
    flows_final = flows_final[REQUIRED_FEATURES]
    return flows_final





#new
def assign_label_from_timeline(flows_df, timeline_csv="output/attack_timeline.csv"):
    import pandas as pd

    timeline_df = pd.read_csv(timeline_csv, header=None, names=["time_str", "attack_name"])

    # Remove N in timestamp, convert it to an integer
    def parse_time_str(s):
        return int(s)
    
    timeline_df["time_int"] = timeline_df["time_str"].apply(parse_time_str)

    timeline_df.sort_values("time_int", inplace=True)
    timeline_df.reset_index(drop=True, inplace=True)

    intervals = []
    for i in range(len(timeline_df)):
        start_t = timeline_df.loc[i, "time_int"]
        attack_n = timeline_df.loc[i, "attack_name"]
        if i < len(timeline_df) - 1:
            end_t = timeline_df.loc[i+1, "time_int"]
        else:
            end_t = int("9"*20)  # Covers flows after the last recorded attack timestamp
        intervals.append((start_t, end_t, attack_n))
    
    print("Attack intervals:", intervals)
    
    def get_label(flow_ts):
        for (st, et, attack_label) in intervals:
            if st <= flow_ts < et:
                return attack_label
        return "ERROR"

    flows_df["label"] = flows_df["timestamp"].apply(get_label)
    return flows_df






###############################################################################
def main():
    print("Processing pcap file...")
    ensure_tshark_installed()
    pcap_file = "output/capture.pcap"
    output_csv = "output/capture.csv"

    flows_final = process_flows_from_pcap(pcap_file)
    print("Final flows DataFrame shape:", flows_final.shape)

    #new
    flows_final = assign_label_from_timeline(flows_final, "output/attack_timeline.csv")
    
    flows_final.to_csv(output_csv, index=False)
    print("Final CSV saved to:", output_csv)

main()








