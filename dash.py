import streamlit as st
import json
import time
import os
from datetime import datetime

ALERT_LOG = "alerts.jsonl"

st.set_page_config(
    page_title="OT Security Monitor",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ OT/ICS Real-Time Anomaly Detector")
st.caption("Powered by local Llama on NVIDIA DGX Spark — air-gapped, no cloud")

# Risk level colour map
RISK_COLORS = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"
}

def load_alerts():
    alerts = []
    if os.path.exists(ALERT_LOG):
        with open(ALERT_LOG, "r") as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    pass
    return sorted(alerts, key=lambda x: x["timestamp"], reverse=True)

# Summary metrics row
col1, col2, col3, col4 = st.columns(4)
alerts = load_alerts()
critical = sum(1 for a in alerts if a["risk_level"] == "CRITICAL")
high     = sum(1 for a in alerts if a["risk_level"] == "HIGH")
medium   = sum(1 for a in alerts if a["risk_level"] == "MEDIUM")
total_incidents = sum(len(a["incidents"]) for a in alerts)

col1.metric("🔴 Critical", critical)
col2.metric("🟠 High", high)
col3.metric("🟡 Medium", medium)
col4.metric("📋 Total Incidents", total_incidents)

st.divider()

# Live alert feed
st.subheader("Live Alert Feed")
alert_placeholder = st.empty()

# Auto-refresh every 5 seconds
while True:
    alerts = load_alerts()
    
    with alert_placeholder.container():
        if not alerts:
            st.info("Monitoring... no anomalies detected yet.")
        
        for alert in alerts[:20]:  # Show last 20
            risk = alert["risk_level"]
            icon = RISK_COLORS.get(risk, "⚪")
            ts = alert["timestamp"][:19].replace("T", " ")
            
            with st.expander(
                f"{icon} [{risk}] {ts} — {alert['summary']}",
                expanded=(risk in ["CRITICAL", "HIGH"])
            ):
                for incident in alert["incidents"]:
                    st.markdown(f"**Log:** `{incident.get('log_line', '')}`")
                    
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown(f"**⚙️ Physical Impact:**  \n{incident.get('physical_impact', 'N/A')}")
                        st.markdown(f"**🎯 ATT&CK for ICS:**  \n{incident.get('mitre_attack_ics', 'N/A')}")
                    with c2:
                        st.markdown(f"**📋 IEC 62443 Control:**  \n{incident.get('iec_62443_control', 'N/A')}")
                        st.markdown(f"**✅ Recommended Action:**  \n{incident.get('recommended_action', 'N/A')}")
                    st.divider()
    
    time.sleep(5)
    st.rerun()
