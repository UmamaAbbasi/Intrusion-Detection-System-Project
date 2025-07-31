from alert.logger import log_alert
from collections import defaultdict
import time

ip_port_map = defaultdict(set)
ip_time_map = {}

THRESHOLD = 15  # Number of different ports accessed
TIME_WINDOW = 10  # Time window in seconds

def detect(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        ip = packet["IP"].src
        port = packet["TCP"].dport
        curr_time = time.time()

        # Initialize time if first packet from IP
        if ip not in ip_time_map:
            ip_time_map[ip] = curr_time

        ip_port_map[ip].add(port)

        # Check if time window expired
        if curr_time - ip_time_map[ip] > TIME_WINDOW:
            ip_port_map[ip] = set()
            ip_time_map[ip] = curr_time

        # Trigger alert if port threshold is exceeded
        if len(ip_port_map[ip]) > THRESHOLD:
            log_alert(f"Port scan detected from {ip}")
            ip_port_map[ip] = set()  # reset
