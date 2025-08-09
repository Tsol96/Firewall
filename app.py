
import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
import json, io, random, time

st.set_page_config(page_title="Adaptive Cloud Firewall — MVP v2", layout="wide")

# ------------------ Helpers ------------------
def gen_ip(v4=True):
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def simulate_netflow(n=600, start_time=None, attack_scenario=None):
    if start_time is None:
        start_time = datetime.utcnow() - timedelta(hours=6)
    rows = []
    for i in range(n):
        timestamp = start_time + timedelta(seconds=30*i)
        src_ip = gen_ip()
        dst_ip = "10.0.0." + str(random.randint(1,50))
        src_port = random.randint(1024,65535)
        dst_port = random.choice([22,80,443,8080,3306,5900,3389])
        protocol = random.choice(["TCP","UDP","ICMP"])
        packets = np.random.poisson(10)
        byte_size = max(40, int(np.random.normal(1200,300)))
        duration = max(1, int(np.random.exponential(1.5)))
        rows.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packets": packets,
            "bytes": byte_size,
            "duration": duration
        })
    df = pd.DataFrame(rows)
    # insert attack patterns if requested
    if attack_scenario == "DDoS":
        t0 = random.randint(50, n-100)
        for j in range(t0, t0+80):
            df.loc[j, "packets"] += random.randint(200,800)
            df.loc[j, "bytes"] += random.randint(20000,80000)
            df.loc[j, "src_ip"] = gen_ip()
    elif attack_scenario == "BruteForce":
        # one IP tries many times to SSH
        attacker = gen_ip()
        indices = random.sample(range(n), k=30)
        for idx in indices:
            df.loc[idx, "src_ip"] = attacker
            df.loc[idx, "dst_port"] = 22
            df.loc[idx, "packets"] += random.randint(1,5)
    elif attack_scenario == "PortScan":
        attacker = gen_ip()
        indices = random.sample(range(n), k=40)
        for i, idx in enumerate(indices):
            df.loc[idx, "src_ip"] = attacker
            df.loc[idx, "dst_port"] = random.randint(1,1024)
            df.loc[idx, "packets"] = 1
    return df

def detect_anomalies_threshold(df, packet_threshold=2000):
    alerts = []
    df['flow_size'] = df['packets'] * df['bytes']
    spikes = df[df['flow_size'] > packet_threshold]
    for _, r in spikes.iterrows():
        alerts.append({
            "time": r['timestamp'].isoformat(),
            "type": "Large Flow Spike",
            "src_ip": r['src_ip'],
            "dst_port": int(r['dst_port']),
            "packets": int(r['packets']),
            "bytes": int(r['bytes']),
            "severity": "high"
        })
    # repeated connections from same IP
    ip_counts = df['src_ip'].value_counts()
    for ip, cnt in ip_counts.items():
        if cnt > 8:
            alerts.append({
                "time": datetime.utcnow().isoformat(),
                "type": "Repeated Connections (possible brute force)",
                "src_ip": ip,
                "dst_port": None,
                "requests": int(cnt),
                "severity": "medium"
            })
    return alerts

def detect_anomalies_iforest(df):
    alerts = []
    # features for anomaly detection
    X = df[['packets','bytes','duration']].fillna(0)
    # small sample handling
    if len(X) < 20:
        return alerts
    clf = IsolationForest(n_estimators=100, contamination=0.03, random_state=42)
    preds = clf.fit_predict(X)
    df['anomaly_score'] = preds
    anomalies = df[df['anomaly_score'] == -1]
    for _, r in anomalies.iterrows():
        alerts.append({
            "time": r['timestamp'].isoformat(),
            "type": "ML Anomaly",
            "src_ip": r['src_ip'],
            "dst_port": int(r['dst_port']),
            "packets": int(r['packets']),
            "bytes": int(r['bytes']),
            "severity": "high"
        })
    # add frequent IPs as medium suspicion
    ip_counts = df['src_ip'].value_counts()
    for ip, cnt in ip_counts.items():
        if cnt > 10:
            alerts.append({
                "time": datetime.utcnow().isoformat(),
                "type": "Frequent Source IP",
                "src_ip": ip,
                "requests": int(cnt),
                "severity": "medium"
            })
    return alerts

def adaptive_rules_engine(alerts, rules):
    changes = []
    for a in alerts:
        ip = a.get('src_ip')
        if not ip:
            continue
        if a['severity'] == 'high':
            # block for 30 minutes
            rule = {"action":"block","target_ip":ip,"params":{"expire_min":30}, "reason":a['type'], "applied_at": datetime.utcnow().isoformat()}
            rules[ip] = rule
            changes.append(("add_block", rule))
        elif a['severity'] == 'medium':
            # rate limit or challenge
            rule = {"action":"rate_limit","target_ip":ip,"params":{"rps":50, "expire_min":60}, "reason":a['type'], "applied_at": datetime.utcnow().isoformat()}
            rules[ip] = rule
            changes.append(("add_rate_limit", rule))
    # cleanup expired (handled on next run)
    now = datetime.utcnow()
    expired = []
    for ip, r in list(rules.items()):
        applied = datetime.fromisoformat(r['applied_at'])
        expire_min = r['params'].get('expire_min', 60)
        if now > applied + timedelta(minutes=expire_min):
            expired.append(ip)
            del rules[ip]
            changes.append(("expire", {"target_ip": ip}))
    return rules, changes

# ------------------ UI ------------------
st.title("Adaptive Cloud Firewall — MVP v2 (English)")
st.markdown("An enhanced prototype demonstrating detection, adaptive rules, cloud-integration mock, and reporting.")

# Sidebar controls
with st.sidebar:
    st.header("Simulation Controls")
    n_points = st.slider("Traffic points", 100, 2000, 600, step=50)
    attack = st.selectbox("Inject attack scenario", ["None","DDoS","BruteForce","PortScan"])
    detection_mode = st.selectbox("Detection engine", ["Threshold","IsolationForest (ML)"])
    threshold_flow = st.number_input("Threshold flow_size (packets*bytes) for rule-based", value=20000, step=1000)
    run_sim = st.button("Run Simulation")
    st.markdown("---")
    st.header("Demo Actions")
    if st.button("Simulate 'Apply to Cloud' (mock)"):
        st.session_state['last_action'] = {"time": datetime.utcnow().isoformat(), "action": "mock_apply", "status": "ok"}
    st.markdown("Export: JSON / CSV available in main panel.")

# initialize session state
if 'rules' not in st.session_state:
    st.session_state['rules'] = {}
if 'history' not in st.session_state:
    st.session_state['history'] = []
if 'alerts' not in st.session_state:
    st.session_state['alerts'] = []
if 'last_df' not in st.session_state:
    st.session_state['last_df'] = pd.DataFrame()

# Run simulation
if run_sim:
    df = simulate_netflow(n=n_points, attack_scenario=attack if attack != "None" else None)
    st.session_state['last_df'] = df.copy()
    if detection_mode == "Threshold":
        alerts = detect_anomalies_threshold(df, packet_threshold=threshold_flow)
    else:
        alerts = detect_anomalies_iforest(df)
    st.session_state['alerts'] = alerts
    # apply adaptive engine
    st.session_state['rules'], changes = adaptive_rules_engine(alerts, st.session_state['rules'])
    if changes:
        st.session_state['history'].append({"time": datetime.utcnow().isoformat(), "changes": changes})

# Main layout
col1, col2 = st.columns([3,1])
with col1:
    st.subheader("Traffic timeline (requests proxy)")
    if not st.session_state['last_df'].empty:
        ts = st.session_state['last_df'].set_index('timestamp').resample('1T').packets.sum()
        st.line_chart(ts)
    else:
        st.info("Run the simulation from the sidebar to generate traffic.")

    st.subheader("Top Source IPs")
    if not st.session_state['last_df'].empty:
        top_ips = st.session_state['last_df']['src_ip'].value_counts().head(15)
        st.bar_chart(top_ips)
    st.subheader("Alerts (latest)")
    if st.session_state['alerts']:
        st.dataframe(pd.DataFrame(st.session_state['alerts']))
    else:
        st.info("No alerts detected yet.")

with col2:
    st.subheader("Live Metrics")
    if not st.session_state['last_df'].empty:
        total_packets = int(st.session_state['last_df']['packets'].sum())
        st.metric("Total packets (current simulation)", total_packets)
    st.metric("Active Rules", len(st.session_state['rules']))
    blocked = [ip for ip,r in st.session_state['rules'].items() if r['action']=='block']
    st.metric("Blocked IPs", len(blocked))

st.markdown("---")
st.subheader("Active Adaptive Rules")
if st.session_state['rules']:
    rules_df = pd.DataFrame.from_dict(st.session_state['rules'], orient='index')
    rules_df = pd.DataFrame.from_dict(st.session_state['rules'], orient='index')
    st.dataframe(rules_df)
else:
    st.info("No adaptive rules have been applied. Run simulation.")

st.markdown("---")
st.subheader("Rule History & Audit Log")
if st.session_state['history']:
    hist_df = pd.DataFrame(st.session_state['history'])
    st.dataframe(hist_df)
else:
    st.info("Rule history is empty. Simulate attacks to populate history.")

# Export / Reporting
st.markdown("---")
st.subheader("Export / Reporting")
if st.button("Download last traffic CSV"):
    if not st.session_state['last_df'].empty:
        csv = st.session_state['last_df'].to_csv(index=False).encode('utf-8')
        st.download_button("Download traffic.csv", data=csv, file_name="traffic.csv", mime="text/csv")

if st.button("Download alerts JSON"):
    if st.session_state['alerts']:
        b = io.BytesIO(json.dumps(st.session_state['alerts'], indent=2, default=str).encode('utf-8'))
        st.download_button("Download alerts.json", data=b, file_name="alerts.json", mime="application/json")
    else:
        st.info("No alerts to export.")

# Integration Mock
st.markdown("---")
st.subheader("Cloud Integration Mock (no external calls)")
st.markdown("""This demo includes a mock "Apply to Cloud" action that simulates calling cloud provider APIs (AWS WAF / Azure Firewall). 
In a real pilot we'd implement connectors using provider SDKs and IAM roles. Refer to the README for steps.""")

if st.session_state.get('last_action'):
    st.write("Last action:", st.session_state['last_action'])

# Facilitator notes and pilot plan
st.markdown("---")
st.header("Notes for Facilitator & Pilot Plan")
st.markdown("""
**What this prototype demonstrates:** detection → adaptive response → rule persistence → reporting.
**Pilot steps to go from MVP to production-ready pilot:**
1. Connect to real NetFlow/IPFIX or VPC Flow Logs.  
2. Deploy a lightweight collector (e.g., Fluentd/Fluent Bit) and push to processing pipeline.  
3. Integrate with cloud provider firewall APIs (AWS WAF, Azure Firewall) or on-prem edge proxies.  
4. Harden anomaly detection models (feature engineering, thresholds, retraining).  
5. Add authentication, RBAC, audit trails, and SLA monitoring.  
6. 3-month pilot: endpoint in a municipal or SME environment, 1-week setup, 8-week testing, results & ROI report.
""")

st.markdown("**Author:** Prepared for pilot/demo — Adaptive Cloud Firewall — MVP v2")
