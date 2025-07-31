from scapy.all import sniff
from detectors import port_scan, large_packet, suspicious_ip, signature_engine
def handle_packet(packet):
    port_scan.detect(packet)
    large_packet.detect(packet)
    suspicious_ip.detect(packet)
    signature_engine.detect(packet) 


if __name__ == "__main__":
    print("[*] Starting lightweight IDS...")
    print("[*] Listening on interface: lo")
    sniff(iface="lo", prn=handle_packet, store=0)
