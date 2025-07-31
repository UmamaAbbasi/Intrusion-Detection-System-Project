from alert.logger import log_alert

def load_blacklist():
    with open("config/blacklist.txt", "r") as f:
        return set(line.strip() for line in f if line.strip())

blacklisted_ips = load_blacklist()

def detect(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        if src_ip in blacklisted_ips:
            log_alert(f"Connection from blacklisted IP: {src_ip}")
