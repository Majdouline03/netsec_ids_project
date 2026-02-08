import pandas as pd
from src.engine.feature_extraction import *

def detect_port_scan(df: pd.DataFrame, window_seconds: int = 10, port_threshold: int = 10) -> pd.DataFrame:
    """
    Detect port scanning behavior.

    A source IP is flagged if it contacts >= port_threshold unique destination ports
    within the same time window.

    Returns a DataFrame of alerts (one row per suspicious src_ip per window).
    """
    ports_df = unique_dst_ports_per_pair(df, window_seconds=window_seconds)

    #print("\n[DEBUG] Top unique dst ports per src_ip per window:")
    print(ports_df.sort_values("unique_dst_ports", ascending=False).head(20).to_string(index=False))
    #print("[DEBUG] Max unique dst ports:", ports_df["unique_dst_ports"].max() if len(ports_df) else None)

    alerts = ports_df[ports_df["unique_dst_ports"] >= port_threshold].copy()
    alerts["rule_name"] = "PORT_SCAN"
    def sev(n):
        if n >= 30: return "HIGH"
        if n >= 15: return "MEDIUM"
        return "LOW"
    alerts["severity"] = alerts["unique_dst_ports"].apply(sev)
    alerts["reason"] = alerts["unique_dst_ports"].apply(
        lambda n: f"Source contacted {n} unique destination ports within {window_seconds}s window"
    )

    alerts = alerts.rename(columns={"window_start": "timestamp_start"})
    alerts["timestamp_end"] = alerts["timestamp_start"] + pd.to_timedelta(window_seconds, unit="s")

    alerts["dst_port"] = None
    alerts["protocol"] = "TCP/UDP"

    return alerts[[
        "timestamp_start", "timestamp_end",
        "src_ip", "dst_ip", "dst_port", "protocol",
        "rule_name", "severity", "reason", "unique_dst_ports"
    ]]


def detect_packet_flood(df: pd.DataFrame,
                        window_seconds: int = 1,
                        pkt_threshold: int = 500) -> pd.DataFrame:
    """
    Detect DoS-like packet flooding.

    Flags (src_ip -> dst_ip) pairs that send >= pkt_threshold packets
    within the same time window.
    """
    flood_df = packets_per_pair(df, window_seconds=window_seconds)

    alerts = flood_df[flood_df["pkt_count"] >= pkt_threshold].copy()
    alerts["rule_name"] = "PACKET_FLOOD"

    def sev(n: int) -> str:
        if n >= pkt_threshold * 3:
            return "HIGH"
        if n >= pkt_threshold * 2:
            return "MEDIUM"
        return "LOW"

    alerts["severity"] = alerts["pkt_count"].apply(sev)
    alerts["reason"] = alerts["pkt_count"].apply(
        lambda n: f"High packet rate: {n} packets within {window_seconds}s window (possible flooding)"
    )

    alerts = alerts.rename(columns={"window_start": "timestamp_start"})
    alerts["timestamp_end"] = alerts["timestamp_start"] + pd.to_timedelta(window_seconds, unit="s")

    alerts["dst_port"] = None
    alerts["protocol"] = "ANY"

    return alerts[[
        "timestamp_start", "timestamp_end",
        "src_ip", "dst_ip", "dst_port", "protocol",
        "rule_name", "severity", "reason", "pkt_count"
    ]]

def detect_bruteforce(df: pd.DataFrame,
                      window_seconds: int = 60,
                      attempt_threshold: int = 20) -> pd.DataFrame:
    """
    Detect brute-force attacks based on repeated failed connection attempts.
    """
    fail_df = failed_connection_attempts(df, window_seconds)

    alerts = fail_df[fail_df["failed_attempts"] >= attempt_threshold].copy()
    alerts["rule_name"] = "BRUTE_FORCE"

    def sev(n: int) -> str:
        if n >= attempt_threshold * 3:
            return "HIGH"
        if n >= attempt_threshold * 2:
            return "MEDIUM"
        return "LOW"

    alerts["severity"] = alerts["failed_attempts"].apply(sev)
    alerts["reason"] = alerts["failed_attempts"].apply(
        lambda n: f"{n} failed connection attempts within {window_seconds}s window"
    )

    alerts = alerts.rename(columns={"window_start": "timestamp_start"})
    alerts["timestamp_end"] = alerts["timestamp_start"] + pd.to_timedelta(window_seconds, unit="s")
    alerts["protocol"] = "TCP"

    return alerts[[
        "timestamp_start", "timestamp_end",
        "src_ip", "dst_ip", "dst_port", "protocol",
        "rule_name", "severity", "reason", "failed_attempts"
    ]]

def detect_syn_flood(df: pd.DataFrame,
                     window_seconds: int = 1,
                     syn_threshold: int = 200,
                     ratio_threshold: float = 3.0) -> pd.DataFrame:
    """
    Detect SYN flood (client->server) by looking for many SYN-only packets with low SYN-ACK response.

    Criteria (per src_ip -> dst_ip -> window):
      - syn_only_count >= syn_threshold
      - (syn_only_count / max(synack_count, 1)) >= ratio_threshold
    """
    feats = syn_flood_features(df, window_seconds=window_seconds)

    if feats.empty:
        return pd.DataFrame(columns=[
            "timestamp_start", "timestamp_end",
            "src_ip", "dst_ip", "dst_port", "protocol",
            "rule_name", "severity", "reason",
            "syn_only_count", "synack_count", "syn_synack_ratio"
        ])

    feats["syn_synack_ratio"] = feats["syn_only_count"] / feats["synack_count"].replace(0, 1)

    alerts = feats[
        (feats["syn_only_count"] >= syn_threshold) &
        (feats["syn_synack_ratio"] >= ratio_threshold)
    ].copy()

    alerts["rule_name"] = "SYN_FLOOD"

    def sev(row) -> str:
        s = row["syn_only_count"]
        r = row["syn_synack_ratio"]
        if s >= syn_threshold * 3 and r >= ratio_threshold * 2:
            return "HIGH"
        if s >= syn_threshold * 2 and r >= ratio_threshold:
            return "MEDIUM"
        return "LOW"

    alerts["severity"] = alerts.apply(sev, axis=1)
    alerts["reason"] = alerts.apply(
        lambda row: (
            f"SYN flood suspicion: {row['syn_only_count']} SYN-only vs "
            f"{row['synack_count']} SYN-ACK in {window_seconds}s "
            f"(ratio={row['syn_synack_ratio']:.2f})"
        ),
        axis=1
    )

    alerts = alerts.rename(columns={"window_start": "timestamp_start"})
    alerts["timestamp_end"] = alerts["timestamp_start"] + pd.to_timedelta(window_seconds, unit="s")

    alerts["dst_port"] = None
    alerts["protocol"] = "TCP"

    return alerts[[
        "timestamp_start", "timestamp_end",
        "src_ip", "dst_ip", "dst_port", "protocol",
        "rule_name", "severity", "reason",
        "syn_only_count", "synack_count", "syn_synack_ratio"
    ]]

def detect_anomalous_packet_rate_per_ip(df: pd.DataFrame,
                                        window_seconds: int = 1,
                                        z_threshold: float = 3.0,
                                        min_packets: int = 50) -> pd.DataFrame:
    """
    Detect anomalous packet rate per source IP using z-score against the window baseline.

    For each window:
      - pkt_count per src_ip is computed
      - mean/std across src_ips in that window is computed
      - z = (pkt_count - mean) / std
    Alert if:
      - pkt_count >= min_packets
      - z >= z_threshold
    """
    rates = packets_per_src_ip(df, window_seconds=window_seconds)

    if rates.empty:
        return pd.DataFrame(columns=[
            "timestamp_start", "timestamp_end",
            "src_ip", "dst_ip", "dst_port", "protocol",
            "rule_name", "severity", "reason",
            "pkt_count", "window_mean", "window_std", "z_score"
        ])

    # Compute baseline stats per window
    stats = (
        rates.groupby("window_start")["pkt_count"]
        .agg(window_mean="mean", window_std="std")
        .reset_index()
    )

    merged = rates.merge(stats, on="window_start", how="left")

    # Avoid division by zero (std can be 0 if only one src_ip in that window)
    merged["window_std"] = merged["window_std"].fillna(0)
    merged["z_score"] = merged.apply(
        lambda row: 0.0 if row["window_std"] == 0 else (row["pkt_count"] - row["window_mean"]) / row["window_std"],
        axis=1
    )

    alerts = merged[
        (merged["pkt_count"] >= min_packets) &
        (merged["z_score"] >= z_threshold)
    ].copy()

    alerts["rule_name"] = "ANOMALOUS_PKT_RATE"

    def sev(z: float) -> str:
        if z >= 6:
            return "HIGH"
        if z >= 4:
            return "MEDIUM"
        return "LOW"

    alerts["severity"] = alerts["z_score"].apply(sev)
    alerts["reason"] = alerts.apply(
        lambda r: (
            f"Anomalous packet rate: {r['pkt_count']} pkts/{window_seconds}s "
            f"vs baseline mean={r['window_mean']:.2f}, std={r['window_std']:.2f} "
            f"(z={r['z_score']:.2f})"
        ),
        axis=1
    )

    alerts = alerts.rename(columns={"window_start": "timestamp_start"})
    alerts["timestamp_end"] = alerts["timestamp_start"] + pd.to_timedelta(window_seconds, unit="s")

    alerts["dst_ip"] = None
    alerts["dst_port"] = None
    alerts["protocol"] = "ANY"

    return alerts[[
        "timestamp_start", "timestamp_end",
        "src_ip", "dst_ip", "dst_port", "protocol",
        "rule_name", "severity", "reason",
        "pkt_count", "window_mean", "window_std", "z_score"
    ]]

def detect_abnormal_protocol_usage(df: pd.DataFrame,
                                   window_seconds: int = 5,
                                   delta: float = 0.50,
                                   min_total_packets: int = 50,
                                   min_proto_packets: int = 20) -> pd.DataFrame:
    """
    Detect abnormal protocol usage per src_ip by comparing per-IP protocol share
    to the global protocol share in the same time window.

    Alert if, for some protocol:
      - total_count >= min_total_packets
      - proto_count >= min_proto_packets
      - share_ip(proto) - share_global(proto) >= delta

    Example: if global UDP share is 0.10 and an IP has UDP share 0.75,
    deviation = 0.65 -> suspicious.
    """
    per_src = protocol_distribution_per_src(df, window_seconds=window_seconds)

    if per_src.empty:
        return pd.DataFrame(columns=[
            "timestamp_start", "timestamp_end",
            "src_ip", "dst_ip", "dst_port", "protocol",
            "rule_name", "severity", "reason",
            "proto_count", "total_count", "share_ip", "share_global", "deviation"
        ])

    # Global distribution per window
    global_counts = (
        per_src.groupby(["window_start", "protocol"])["proto_count"]
        .sum()
        .reset_index(name="global_proto_count")
    )

    global_totals = (
        global_counts.groupby("window_start")["global_proto_count"]
        .sum()
        .reset_index(name="global_total_count")
    )

    global_dist = global_counts.merge(global_totals, on="window_start", how="left")
    global_dist["share_global"] = global_dist["global_proto_count"] / global_dist["global_total_count"].replace(0, 1)
    global_dist = global_dist[["window_start", "protocol", "share_global"]]

    merged = per_src.merge(global_dist, on=["window_start", "protocol"], how="left")
    merged["share_global"] = merged["share_global"].fillna(0.0)

    merged["share_ip"] = merged["share"]
    merged["deviation"] = merged["share_ip"] - merged["share_global"]

    alerts = merged[
        (merged["total_count"] >= min_total_packets) &
        (merged["proto_count"] >= min_proto_packets) &
        (merged["deviation"] >= delta)
    ].copy()

    alerts["rule_name"] = "ABNORMAL_PROTOCOL_USAGE"

    def severity(row) -> str:
        d = row["deviation"]
        # Stronger deviation => higher severity
        if d >= delta + 0.40:
            return "HIGH"
        if d >= delta + 0.20:
            return "MEDIUM"
        return "LOW"

    alerts["severity"] = alerts.apply(severity, axis=1)
    alerts["reason"] = alerts.apply(
        lambda r: (
            f"Abnormal protocol usage: {r['protocol']} share={r['share_ip']:.2f} "
            f"vs global={r['share_global']:.2f} in {window_seconds}s "
            f"(deviation={r['deviation']:.2f}, {r['proto_count']}/{r['total_count']} pkts)"
        ),
        axis=1
    )

    alerts = alerts.rename(columns={"window_start": "timestamp_start"})
    alerts["timestamp_end"] = alerts["timestamp_start"] + pd.to_timedelta(window_seconds, unit="s")

    alerts["dst_ip"] = None
    alerts["dst_port"] = None

    return alerts[[
        "timestamp_start", "timestamp_end",
        "src_ip", "dst_ip", "dst_port", "protocol",
        "rule_name", "severity", "reason",
        "proto_count", "total_count", "share_ip", "share_global", "deviation"
    ]]
