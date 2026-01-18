import pandas as pd
from src.engine.pcap_parser import parse_pcap
from src.engine.detection_rules import detect_port_scan


if __name__ == "__main__":
    pcap_file = "data/raw_pcaps/friday_portscan_ctx_00000_20170707140035.pcap"

    packets = parse_pcap(pcap_file, max_packets=0)  # 0 = no limit
    df = pd.DataFrame(packets)

    print(f"Parsed packets: {len(df)}")

    alerts_portscan = detect_port_scan(df, window_seconds=10, port_threshold=10)

    print("\n--- PORT SCAN ALERTS ---")
    if len(alerts_portscan) == 0:
        print("No port scan detected (expected if PCAP is small or not a scan).")
    else:
        print(alerts_portscan.head(20).to_string(index=False))
        alerts_portscan.to_csv("results/alerts/portscan_alerts.csv", index=False)
        print("\nSaved: results/alerts/portscan_alerts.csv")
