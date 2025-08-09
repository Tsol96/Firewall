
import streamlit as st
import pandas as pd
import numpy as np
import time
from datetime import datetime, timedelta
import json
import io

st.set_page_config(page_title="Adaptive Cloud Firewall - MVP", layout="wide")

# ---- Helper functions ----
def simulate_traffic(n=200, start_time=None):
    if start_time is None:
        start_time = datetime.utcnow() - timedelta(hours=4)
    timestamps = [start_time + timedelta(seconds=60*i) for i in range(n)]
    # normal traffic baseline
    baseline = np.random.poisson(lam=120, size=n)
    # occasional spikes to simulate attacks
    spikes = np.zeros(n)
    for _ in range(np.random.randint(1,4)):
        i = np.random.randint(0, n-20)
        spikes[i:i+10] += np.random.poisson(lam=300, size=10)
    # random anomalous requests from suspicious IPs
    suspicious = np.random.binomial(1, 0.02, size=n) * np.random.randint(100,400,size=n)
    traffic = baseline + spikes + suspicious
    src_ips = [f"192.168.{np.random.randint(0,255)}.{np.random.randint(1,254)}" for _ in range(n)]
    dest_ports = np.random.choice([22,80,443,8080,3306,5900], size=n, p=[0.05,0.35,0.45,0.05,0.05,0.05])
    methods = np.random.choice(["GET","POST","SSH","OTHER"], size=n, p=[0.5,0.2,0.05,0.25])
    df = pd.DataFrame({
        "timestamp": timestamps,
        "requests": traffic,
        "src_ip": src_ips,
        "dest_port": dest_ports,
        "method": methods
    })
    return df

def detect_threats(df, threshold=300):
    # simple rule-based detections for MVP
    df['is_spike'] = df['requests'] > threshold
    # detect repeated suspicious IPs (brute force)
    ip_counts = df['src_ip'].value_counts()
    suspicious_ips = set(ip_counts[ip_counts > 3].index.tolist())
    alerts = []
    for _, row in df[df['is_spike']].iterrows():
        alerts.append({
            "time": row['timestamp'].isoformat(),
            "type": "Traffic Spike (possible DDoS)",
            "src_ip": row['src_ip'],
            "dest_port": int(row['dest_port']),
            "requests": int(row['requests']),
            "severity": "high"
        })
    for ip in suspicious_ips:
        alerts.append({
            "time": datetime.utcnow().isoformat(),
            "type": "Repeated Requests (possible brute force)",
            "src_ip": ip,
            "dest_port": None,
            "requests": int(ip_counts[ip]),
            "severity": "medium"
        })
    return alerts

def adaptive_rules_engine(alerts, current_rules):
    # Simulate adaptive behavior: create or tighten rules based on alerts
    changes = []
    for a in alerts:
        if a['type'].startswith("Traffic Spike"):
            rule = {"action":"rate_limit","target_ip":a['src_ip'],"params":{"max_rps":50}}
            changes.append(("add_or_update", rule))
        elif a['type'].startswith("Repeated Requests"):
            rule = {"action":"block","target_ip":a['src_ip'],"params":{"duration_min":60}}
            changes.append(("add_or_update", rule))
    # apply changes to current_rules (simple dict merge)
    for op, rule in changes:
        key = rule['target_ip']
        current_rules[key] = rule
    history_entries = [{"time": datetime.utcnow().isoformat(), "changes": changes}] if changes else []
    return current_rules, history_entries

# ---- App UI ----
st.title("Adaptive Cloud Firewall — MVP")
st.markdown("""
**What this demo shows:** a lightweight simulation of an adaptive cloud firewall-as-a-service (A-FaaS).
- Real-time traffic simulation
- Rule engine that *adapts* rules based on detected anomalies
- Dashboard, Threat Table, Rule History and JSON export for reporting
""")

col1, col2 = st.columns([2,1])

with col2:
    st.header("Controls")
    st.markdown("Adjust simulation and detection settings")
    n_points = st.slider("Number of traffic points", min_value=50, max_value=1000, value=240, step=10)
    threshold = st.slider("Spike detection threshold (requests)", min_value=200, max_value=800, value=350, step=10)
    run_sim = st.button("Run Simulation")
    if 'rules' not in st.session_state:
        st.session_state['rules'] = {}
    if 'history' not in st.session_state:
        st.session_state['history'] = []

with col1:
    st.header("Live Traffic & Analysis")
    if run_sim:
        progress = st.progress(0)
        df = simulate_traffic(n=n_points)
        alerts = detect_threats(df, threshold=threshold)
        # Run adaptive engine
        st.session_state['rules'], history_entries = adaptive_rules_engine(alerts, st.session_state['rules'])
        st.session_state['history'].extend(history_entries)

        # Show time series
        st.subheader("Traffic (requests per minute)")
        st.line_chart(df.set_index('timestamp')['requests'])

        st.subheader("Top 10 source IPs (by generated requests)")
        ip_counts = df['src_ip'].value_counts().head(10)
        st.bar_chart(ip_counts)

        st.subheader("Detected Alerts")
        if alerts:
            alerts_df = pd.DataFrame(alerts)
            st.dataframe(alerts_df)
        else:
            st.success("No alerts detected in this simulation run.")

        st.subheader("Active Adaptive Rules")
        if st.session_state['rules']:
            rules_df = pd.DataFrame.from_dict(st.session_state['rules'], orient='index')
            st.dataframe(rules_df)
        else:
            st.info("No adaptive rules have been applied yet.")


st.markdown("---")
st.header("Rule History & Reporting")

if st.session_state.get('history'):
    hist_df = pd.DataFrame([{"time":h['time'], "changes": json.dumps(h['changes'])} for h in st.session_state['history']])
    st.dataframe(hist_df)
else:
    st.info("No rule changes recorded yet. Run a simulation to generate rule changes.")

# Export JSON report
st.markdown("### Export security report (JSON)")
if st.button("Generate JSON Report"):
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "alerts": st.session_state.get('last_alerts', []),
        "rules": list(st.session_state.get('rules', {}).values()),
        "history": st.session_state.get('history', [])
    }
    b = io.BytesIO(json.dumps(report, indent=2).encode('utf-8'))
    st.download_button("Download JSON report", data=b, file_name="adaptive_firewall_report.json", mime="application/json")

st.markdown("---")
st.write("**Notes for facilitator:** This MVP intentionally uses simulated data and simple rule logic to demonstrate core product behaviour: detection → adaptive response → rule persistence. For a pilot we propose: (1) connect to real flow logs (NetFlow/IPFIX), (2) integrate with cloud provider APIs (AWS WAF, Azure Firewall) or edge proxies, and (3) extend ML models for anomaly detection.")

st.markdown("**MVP Author:** _Prepared for pilot/demo — Adaptive Cloud Firewall - MVP_")
