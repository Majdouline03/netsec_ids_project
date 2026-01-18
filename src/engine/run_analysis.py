import pandas as pd
from src.engine.pcap_parser import parse_pcap
from src.engine.feature_extraction import packets_per_src_ip, unique_dst_ports_per_src_ip, syn_ack_counts


if __name__ == "__main__":
    pcap_file = "data/raw_pcaps/test.pcap"

    packets = parse_pcap(pcap_file, max_packets=5000)
    df = pd.DataFrame(packets)

    print(f"Parsed packets: {len(df)}")
    print(df.head(5).to_string(index=False))

    print("\n--- Packets per src_ip (1s window) ---")
    print(packets_per_src_ip(df, window_seconds=1).head(10).to_string(index=False))

    print("\n--- Unique dst ports per src_ip (10s window) ---")
    print(unique_dst_ports_per_src_ip(df, window_seconds=10).head(10).to_string(index=False))

    print("\n--- SYN/ACK counts (1s window) ---")
    print(syn_ack_counts(df, window_seconds=1).head(10).to_string(index=False))
