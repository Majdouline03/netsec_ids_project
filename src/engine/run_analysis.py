import pandas as pd
from src.engine.pcap_parser import parse_pcap
from src.engine.detection_rules import *
from src.engine.output_utils import save_alerts


if __name__ == "__main__":
    #pcap_file = "data/raw_pcaps/portscan_dataset.pcap" : alerts_portscan
    #attack_file = "data/raw_pcaps/flood_dataset.pcap" : alerts_flood (5)
    #attack_file = "data/raw_pcaps/synflood_dataset.pcap" : alerts_synflood (19)
    #attack_file = "data/raw_pcaps/abnormal_protocol_anomalous_packet_rate_per_ip_dataset.pcap" : alerts_alerts_proto (9)
    #attack_file = "data/raw_pcaps/abnormal_protocol_anomalous_packet_rate_per_ip_dataset.pcap" : alerts_anomrate (12)
    #attack_file = "data/raw_pcaps/bruteforce_dataset.pcap" : alerts_bruteforce (256)
    attack_file = "data/raw_pcaps/bruteforce_dataset.pcap"

    packets = parse_pcap(attack_file, max_packets=0)  # 0 = no limit
    df = pd.DataFrame(packets)

    print(f"Parsed packets: {len(df)}")

    #alerts_portscan = detect_port_scan(df, window_seconds=10, port_threshold=10)
    #alerts_flood = detect_packet_flood(df, window_seconds=1, pkt_threshold=20)
    #alerts_synflood = detect_syn_flood(df, window_seconds=1, syn_threshold=200, ratio_threshold=3.0)
    #alerts_anomrate = detect_anomalous_packet_rate_per_ip(df, window_seconds=1, z_threshold=3.0, min_packets=50)
    #alerts_proto = detect_abnormal_protocol_usage(df, window_seconds=5, delta=0.50, min_total_packets=50, min_proto_packets=20)
    alerts_bruteforce = detect_bruteforce(df, window_seconds=10, attempt_threshold=8)

    #Save two versions JSON and CSV
    #save_alerts(alerts_portscan, "results/alerts", "portscan_alerts")
    #save_alerts(alerts_flood, "results/alerts", "flood_alerts")
    save_alerts(alerts_bruteforce, "results/alerts", "bruteforce_alerts")
    #save_alerts(alerts_synflood, "results/alerts", "synflood_alerts")
    #save_alerts(alerts_anomrate, "results/alerts", "anom_rate_alerts")
    #save_alerts(alerts_proto, "results/alerts", "protocol_usage_alerts")

    #print(f"PortScan alerts: {len(alerts_portscan)}")
    #print(f"Flood alerts: {len(alerts_flood)}")
    #print(f"SYN Flood alerts: {len(alerts_synflood)}")
    #print(f"Abnormal-protocol alerts: {len(alerts_anomrate)}")
    #print(f"Abnormal-protocol alerts: {len(alerts_proto)}")
    print(f"Brute Force alerts: {len(alerts_bruteforce)}")


    print("\n--- Anomarte ALERTS ---")
    if len(alerts_bruteforce) == 0:
        print("No Brute Force detected")
    else:
        print(alerts_bruteforce.head(20).to_string(index=False))

