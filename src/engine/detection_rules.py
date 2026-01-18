import pandas as pd
from src.engine.feature_extraction import unique_dst_ports_per_src_ip, unique_dst_ports_per_pair

def detect_port_scan(df: pd.DataFrame, window_seconds: int = 10, port_threshold: int = 10) -> pd.DataFrame:
    """
    Detect port scanning behavior.

    A source IP is flagged if it contacts >= port_threshold unique destination ports
    within the same time window.

    Returns a DataFrame of alerts (one row per suspicious src_ip per window).
    """
    ports_df = unique_dst_ports_per_pair(df, window_seconds=window_seconds)

    print("\n[DEBUG] Top unique dst ports per src_ip per window:")
    print(ports_df.sort_values("unique_dst_ports", ascending=False).head(20).to_string(index=False))
    print("[DEBUG] Max unique dst ports:", ports_df["unique_dst_ports"].max() if len(ports_df) else None)

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