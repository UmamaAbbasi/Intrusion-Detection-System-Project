from alert.logger import log_alert

PACKET_SIZE_THRESHOLD = 1000  # bytes

def detect(packet):
    if len(packet) > PACKET_SIZE_THRESHOLD:
        src = packet[0][1].src if hasattr(packet[0][1], "src") else "Unknown"
        dst = packet[0][1].dst if hasattr(packet[0][1], "dst") else "Unknown"
        log_alert(f"Large packet detected from {src} to {dst} - Size: {len(packet)} bytes")
