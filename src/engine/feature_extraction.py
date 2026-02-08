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

def unique_dst_ports_per_pair(df: pd.DataFrame, window_seconds: int = 10) -> pd.DataFrame:
    dfw = add_time_window(df, window_seconds)
    dfw = dfw[dfw["dst_port"].notna() & dfw["src_ip"].notna() & dfw["dst_ip"].notna()].copy()

    out = (
        dfw.groupby(["window_start", "src_ip", "dst_ip"])["dst_port"]
        .nunique()
        .reset_index(name="unique_dst_ports")
    )
    return out

def packets_per_pair(df: pd.DataFrame, window_seconds: int = 1) -> pd.DataFrame:
    """
    Count packets per (src_ip, dst_ip) per time window.
    Useful for targeted flooding detection.
    """
    dfw = add_time_window(df, window_seconds)
    dfw = dfw[dfw["src_ip"].notna() & dfw["dst_ip"].notna()].copy()

    out = (
        dfw.groupby(["window_start", "src_ip", "dst_ip"])
        .size()
        .reset_index(name="pkt_count")
    )
    return out


def _parse_tcp_flags_to_int(flag) -> int | None:
    """
    Parse tcp_flags that may look like '0x00000002' (hex) into an int.
    Returns None if parsing fails.
    """
    if flag is None or (isinstance(flag, float) and pd.isna(flag)):
        return None

    s = str(flag).strip().lower()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        # sometimes tshark gives decimal-like strings
        return int(s)
    except Exception:
        # last try: attempt hex anyway
        try:
            return int(s, 16)
        except Exception:
            return None


def syn_flood_features(df: pd.DataFrame, window_seconds: int = 1) -> pd.DataFrame:
    """
    Compute SYN-only and SYN-ACK counts per (src_ip, dst_ip) per time window.

    syn_only_count: packets where SYN=1 and ACK=0 (initial SYN)
    synack_count: packets where SYN=1 and ACK=1 (SYN/ACK response)

    Note: SYN-ACK packets are from server->client, so we reverse them to match the original (client->server) pair.
    """
    dfw = add_time_window(df, window_seconds)

    dfw = dfw[
        (dfw["protocol"] == "TCP") &
        (dfw["tcp_flags"].notna()) &
        (dfw["src_ip"].notna()) &
        (dfw["dst_ip"].notna())
    ].copy()

    if dfw.empty:
        return pd.DataFrame(columns=[
            "window_start", "src_ip", "dst_ip", "syn_only_count", "synack_count"
        ])

    dfw["flags_int"] = dfw["tcp_flags"].apply(_parse_tcp_flags_to_int)

    # Drop packets where flags couldn't be parsed
    dfw = dfw[dfw["flags_int"].notna()].copy()
    if dfw.empty:
        return pd.DataFrame(columns=[
            "window_start", "src_ip", "dst_ip", "syn_only_count", "synack_count"
        ])

    SYN = 0x02
    ACK = 0x10

    dfw["is_syn"] = dfw["flags_int"].apply(lambda x: (x & SYN) != 0)
    dfw["is_ack"] = dfw["flags_int"].apply(lambda x: (x & ACK) != 0)

    # SYN only: SYN=1, ACK=0
    syn_only = dfw[dfw["is_syn"] & (~dfw["is_ack"])].copy()
    syn_only_counts = (
        syn_only.groupby(["window_start", "src_ip", "dst_ip"])
        .size()
        .reset_index(name="syn_only_count")
    )

    # SYN-ACK: SYN=1, ACK=1 (server->client), reverse pair to match client->server
    synack = dfw[dfw["is_syn"] & dfw["is_ack"]].copy()
    synack["orig_src"] = synack["dst_ip"]
    synack["orig_dst"] = synack["src_ip"]

    synack_counts = (
        synack.groupby(["window_start", "orig_src", "orig_dst"])
        .size()
        .reset_index(name="synack_count")
        .rename(columns={"orig_src": "src_ip", "orig_dst": "dst_ip"})
    )

    out = pd.merge(
        syn_only_counts,
        synack_counts,
        on=["window_start", "src_ip", "dst_ip"],
        how="outer"
    ).fillna(0)

    out["syn_only_count"] = out["syn_only_count"].astype(int)
    out["synack_count"] = out["synack_count"].astype(int)
    return out

def protocol_distribution_per_src(df: pd.DataFrame, window_seconds: int = 5) -> pd.DataFrame:
    """
    For each window and src_ip, compute counts and shares of protocols.

    Output columns:
      window_start, src_ip, protocol, proto_count, total_count, share
    """
    dfw = add_time_window(df, window_seconds)

    dfw = dfw[
        dfw["src_ip"].notna() &
        dfw["protocol"].notna()
    ].copy()

    if dfw.empty:
        return pd.DataFrame(columns=[
            "window_start", "src_ip", "protocol", "proto_count", "total_count", "share"
        ])

    # Count per protocol
    counts = (
        dfw.groupby(["window_start", "src_ip", "protocol"])
        .size()
        .reset_index(name="proto_count")
    )

    totals = (
        dfw.groupby(["window_start", "src_ip"])
        .size()
        .reset_index(name="total_count")
    )

    out = counts.merge(totals, on=["window_start", "src_ip"], how="left")
    out["share"] = out["proto_count"] / out["total_count"].replace(0, 1)

    return out


def _flag_has_syn(x) -> bool:
    """Return True if tcp_flags contains SYN (0x02). Works with '0x00000002' or int-like."""
    if pd.isna(x):
        return False
    s = str(x).strip()
    try:
        v = int(s, 16) if s.lower().startswith("0x") else int(s)
        return (v & 0x02) != 0
    except Exception:
        return False

def failed_connection_attempts(df: pd.DataFrame, window_seconds: int = 60) -> pd.DataFrame:
    """
    Estimate 'failed connection attempts' as repeated TCP SYNs per (src_ip,dst_ip,dst_port)
    within a time window (no ACK requirement). This is a transport-layer heuristic.

    Required columns in df:
      - timestamp (datetime)
      - protocol (e.g., 'TCP')
      - src_ip, dst_ip
      - dst_port
      - tcp_flags (hex string like '0x00000002' or numeric)
    """
    if df.empty:
        return pd.DataFrame(columns=["window_start", "src_ip", "dst_ip", "dst_port", "failed_attempts"])

    # Ensure timestamp is datetime
    d = df.copy()
    d["timestamp"] = pd.to_datetime(d["timestamp"], errors="coerce")
    d = d.dropna(subset=["timestamp", "src_ip", "dst_ip", "dst_port"])

    # Keep TCP SYN packets only
    d = d[(d["protocol"] == "TCP") & (d["tcp_flags"].apply(_flag_has_syn))].copy()

    if d.empty:
        return pd.DataFrame(columns=["window_start", "src_ip", "dst_ip", "dst_port", "failed_attempts"])

    # Floor timestamps to window start
    d["window_start"] = d["timestamp"].dt.floor(f"{window_seconds}s")

    # Count SYNs per tuple per window
    out = (
        d.groupby(["window_start", "src_ip", "dst_ip", "dst_port"])
         .size()
         .reset_index(name="failed_attempts")
         .sort_values(["window_start", "failed_attempts"], ascending=[True, False])
    )

    return out
