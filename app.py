import streamlit as st
import pandas as pd
import re

LOG_FILE = "../logs/ids.log"

st.set_page_config(page_title="IDS Dashboard", layout="wide")
st.title("🔐 Lightweight IDS Dashboard")
st.markdown("Real-time Intrusion Detection Alerts")

# ✅ Define function BEFORE calling it
def parse_logs():
    entries = []
    pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - (.*)"

    with open(LOG_FILE, "r") as f:
        for line in f.readlines()[-50:]:  # Last 50 lines only
            match = re.match(pattern, line.strip())
            if match:
                timestamp, level, message = match.groups()
                src_ip = dst_ip = "-"
                size = "-"

                if "from" in message and "to" in message:
                    parts = message.split("from")[1].split("to")
                    src_ip = parts[0].strip()
                    dst_ip = parts[1].split("-")[0].strip()
                    if "Size:" in message:
                        size = message.split("Size:")[-1].strip()
                elif "from" in message:
                    src_ip = message.split("from")[-1].strip()
                elif "IP:" in message:
                    src_ip = message.split("IP:")[-1].strip()

                entries.append({
                    "Timestamp": timestamp,
                    "Alert Type": message.split(":")[0],
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                    "Packet Size": size,
                    "Message": message
                })
    return pd.DataFrame(entries)

# ✅ Call function AFTER it's defined
df = parse_logs()

# ✅ Show data
if df.empty:
    st.info("No alerts yet.")
else:
    st.dataframe(df, use_container_width=True)

# ✅ Optional: Add manual refresh button
if st.button("🔄 Refresh"):
    st.rerun()
