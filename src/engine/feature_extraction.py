import pandas as pd


def add_time_window(df: pd.DataFrame, window_seconds: int) -> pd.DataFrame:
    """
    Adds a 'window_start' column by flooring timestamps into fixed windows.

    Example: window_seconds=10 => 14:03:32 becomes 14:03:30 window start.
    """
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")
    return df


def packets_per_src_ip(df: pd.DataFrame, window_seconds: int = 1) -> pd.DataFrame:
    """
    Count packets per source IP per time window.
    """
    dfw = add_time_window(df, window_seconds)
    out = (
        dfw.groupby(["window_start", "src_ip"], dropna=True)
        .size()
        .reset_index(name="pkt_count")
    )
    return out


def unique_dst_ports_per_src_ip(df: pd.DataFrame, window_seconds: int = 10) -> pd.DataFrame:
    """
    Count number of unique destination ports per source IP per time window.
    (Useful for port scan detection.)
    """
    dfw = add_time_window(df, window_seconds)

    # Only TCP/UDP packets have ports
    dfw = dfw[dfw["dst_port"].notna()].copy()

    out = (
        dfw.groupby(["window_start", "src_ip"], dropna=True)["dst_port"]
        .nunique()
        .reset_index(name="unique_dst_ports")
    )
    return out


def syn_ack_counts(df: pd.DataFrame, window_seconds: int = 1) -> pd.DataFrame:
    """
    Count SYN and ACK flags per source IP per time window.
    Works only when tcp_flags exists and is parsed.
    """
    dfw = add_time_window(df, window_seconds)

    # Keep only rows with TCP flags
    dfw = dfw[dfw["tcp_flags"].notna()].copy()

    # Flags in tshark often look like hex or combined.
    # We'll do simple substring checks for now.
    dfw["is_syn"] = dfw["tcp_flags"].astype(str).str.contains("SYN", case=False, na=False)
    dfw["is_ack"] = dfw["tcp_flags"].astype(str).str.contains("ACK", case=False, na=False)

    out = (
        dfw.groupby(["window_start", "src_ip"], dropna=True)
        .agg(syn_count=("is_syn", "sum"), ack_count=("is_ack", "sum"))
        .reset_index()
    )
    return out
