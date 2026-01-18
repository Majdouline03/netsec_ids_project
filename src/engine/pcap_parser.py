import pyshark


def parse_pcap(pcap_path: str, max_packets: int = 0):
    """
    Parse a PCAP file and extract packet-level fields needed for IDS rules.

    Args:
        pcap_path: Path to the PCAP file.
        max_packets: If > 0, limits number of packets (useful for quick tests).

    Returns:
        List[dict]: One dict per packet.
    """
    packets_data = []

    capture = pyshark.FileCapture(pcap_path, keep_packets=False)

    for i, packet in enumerate(capture):
        if max_packets and i >= max_packets:
            break

        try:
            ts = packet.sniff_time

            # IP addresses (IPv4)
            src_ip = packet.ip.src if hasattr(packet, "ip") else None
            dst_ip = packet.ip.dst if hasattr(packet, "ip") else None

            # Basic protocol guess
            proto = None
            if hasattr(packet, "transport_layer") and packet.transport_layer:
                proto = packet.transport_layer  # TCP/UDP
            elif hasattr(packet, "highest_layer"):
                proto = packet.highest_layer  # e.g., ARP, ICMP, DNS, etc.

            # Ports (TCP/UDP)
            src_port = None
            dst_port = None
            if hasattr(packet, "tcp"):
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
            elif hasattr(packet, "udp"):
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)

            # TCP flags (only if TCP)
            tcp_flags = None
            if hasattr(packet, "tcp") and hasattr(packet.tcp, "flags"):
                tcp_flags = str(packet.tcp.flags)

            # Packet length
            length = None
            if hasattr(packet, "length"):
                length = int(packet.length)

            packets_data.append({
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "tcp_flags": tcp_flags,
                "length": length,
            })

        except Exception:
            # Skip packets we cannot parse
            continue

    capture.close()
    return packets_data
