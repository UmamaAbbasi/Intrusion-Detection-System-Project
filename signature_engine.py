from alert.logger import log_alert
import yaml
import os

# Load signatures
def load_signatures():
    with open("rules/signatures.yml", "r") as f:
        data = yaml.safe_load(f)
        return data["rules"]

signatures = load_signatures()

def detect(packet):
    if packet.haslayer("Raw"):
        payload = packet["Raw"].load.decode(errors="ignore").lower()
        for rule in signatures:
            if rule["pattern"].lower() in payload:
                log_alert(f"Signature match: {rule['name']}")
