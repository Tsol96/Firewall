import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random, json, io, sqlite3, os, time
from sklearn.ensemble import IsolationForest

st.set_page_config(page_title="Adaptive Cloud Firewall — Prototype v3", layout="wide", page_icon="🛡️")

# ------------------- Styling -------------------
st.markdown("""
<style>
body {background-color: #0b1020; color: #d6e3ff;}
.reportview-container .main .block-container{padding-top:1rem;}
.card {background: linear-gradient(90deg,#0f1724,#081226); padding:12px; border-radius:8px; box-shadow: 0 4px 12px rgba(0,0,0,0.5);}
.kpi {font-size:22px; font-weight:600;}
.small {font-size:12px; color:#9fb0ff;}
.table-dark th {background:#0f1724; color:#cfe3ff;}
</style>
""", unsafe_allow_html=True)

# ------------------- Persistence -------------------
DB_PATH = "acfw_v3.db"

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT,
        packets INTEGER, bytes INTEGER, duration INTEGER, country TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, type TEXT, src_ip TEXT, dst_port INTEGER, severity TEXT, meta TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS rules (
        ip TEXT PRIMARY KEY, action TEXT, params TEXT, reason TEXT, applied_at TEXT
    )""")
    conn.commit()
    return conn

conn = init_db()

# ------------------- Simulators & Detectors -------------------
COUNTRIES = ["NL","DE","BE","FR","GB","US","PL","SE","NO","DK","ES","IT"]

def gen_ip():
    return ".".join(str(random.randint(1,254)) for _ in range(4))

def simulate_traffic_store(conn, n=500, attack=None, start_time=None):
    if start_time is None:
        start_time = datetime.utcnow() - timedelta(hours=3)
    rows = []
    for i in range(n):
        ts = (start_time + timedelta(seconds=10*i)).isoformat()
        src = gen_ip()
        dst = "10.0.0." + str(random.randint(1,50))
        port = random.choice([22,80,443,8080,3306,5900,3389])
        proto = random.choice(["TCP","UDP","ICMP"])
        packets = np.random.poisson(8)
        b = max(40, int(np.random.normal(900,280)))
        dur = max(1, int(np.random.exponential(1.2)))
        country = random.choice(COUNTRIES)
        rows.append((ts,src,dst,port,proto,packets,b,dur,country))
    c = conn.cursor()
    c.executemany("INSERT INTO traffic (ts,src_ip,dst_ip,dst_port,protocol,packets,bytes,duration,country) VALUES (?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    # inject attack patterns
    if attack == "DDoS":
        attacker = gen_ip()
        for _ in range(100):
            ts = datetime.utcnow().isoformat()
            c.execute("INSERT INTO traffic (ts,src_ip,dst_ip,dst_port,protocol,packets,bytes,duration,country) VALUES (?,?,?,?,?,?,?,?,?)",
                      (ts, attacker, "10.0.0.1", random.choice([80,443]), "TCP", random.randint(200,800), random.randint(20000,80000), 1, random.choice(COUNTRIES)))
    elif attack == "BruteForce":
        attacker = gen_ip()
        for _ in range(40):
            ts = datetime.utcnow().isoformat()
            c.execute("INSERT INTO traffic (ts,src_ip,dst_ip,dst_port,protocol,packets,bytes,duration,country) VALUES (?,?,?,?,?,?,?,?,?)",
                      (ts, attacker, "10.0.0.2", 22, "TCP", random.randint(1,5), random.randint(40,200), 1, random.choice(COUNTRIES)))
    elif attack == "PortScan":
        attacker = gen_ip()
        for p in range(1,120):
            ts = datetime.utcnow().isoformat()
            c.execute("INSERT INTO traffic (ts,src_ip,dst_ip,dst_port,protocol,packets,bytes,duration,country) VALUES (?,?,?,?,?,?,?,?,?)",
                      (ts, attacker, "10.0.0.3", p, "TCP", 1, 60, 1, random.choice(COUNTRIES)))
    conn.commit()

def fetch_recent(conn, limit=1000):
    df = pd.read_sql_query(f"SELECT * FROM traffic ORDER BY id DESC LIMIT {limit}", conn)
    if not df.empty:
        df['ts'] = pd.to_datetime(df['ts'])
    return df

def detect_threshold(df, flow_threshold=20000):
    alerts = []
    if df.empty:
        return alerts
    df['flow'] = df['packets'] * df['bytes']
    spikes = df[df['flow'] > flow_threshold]
    for _,r in spikes.iterrows():
        alerts.append({"ts": datetime.utcnow().isoformat(), "type":"Large Flow", "src_ip": r['src_ip'], "dst_port": int(r['dst_port']), "severity":"high", "meta": json.dumps({"flow":int(r['flow'])})})
    # frequent sources
    ip_counts = df['src_ip'].value_counts()
    for ip,c in ip_counts.items():
        if c > 12:
            alerts.append({"ts": datetime.utcnow().isoformat(), "type":"Frequent Source", "src_ip": ip, "dst_port": None, "severity":"medium", "meta": json.dumps({"count":int(c)})})
    return alerts

def detect_ml(df):
    alerts = []
    if len(df) < 30:
        return alerts
    X = df[['packets','bytes','duration']].fillna(0)
    clf = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
    pred = clf.fit_predict(X)
    df['anomaly'] = pred
    anomalies = df[df['anomaly']==-1]
    for _,r in anomalies.iterrows():
        alerts.append({"ts": datetime.utcnow().isoformat(), "type":"ML Anomaly", "src_ip": r['src_ip'], "dst_port": int(r['dst_port']), "severity":"high", "meta": json.dumps({"packets":int(r['packets']), "bytes":int(r['bytes'])})})
    return alerts

def persist_alerts(conn, alerts):
    c = conn.cursor()
    for a in alerts:
        c.execute("INSERT INTO alerts (ts,type,src_ip,dst_port,severity,meta) VALUES (?,?,?,?,?,?)", (a['ts'],a['type'],a['src_ip'], a.get('dst_port'), a['severity'], a.get('meta')))
    conn.commit()

def apply_adaptive_rules(conn, alerts):
    c = conn.cursor()
    changes = []
    for a in alerts:
        ip = a['src_ip']
        if a['severity']=='high':
            params = json.dumps({"expire_min":30})
            c.execute("REPLACE INTO rules (ip,action,params,reason,applied_at) VALUES (?,?,?,?,?)", (ip,"block",params,a['type'], datetime.utcnow().isoformat()))
            changes.append(("block", ip, a['type']))
        elif a['severity']=='medium':
            params = json.dumps({"rps":50,"expire_min":60})
            c.execute("REPLACE INTO rules (ip,action,params,reason,applied_at) VALUES (?,?,?,?,?)", (ip,"rate_limit",params,a['type'], datetime.utcnow().isoformat()))
            changes.append(("rate_limit", ip, a['type']))
    conn.commit()
    return changes

# ------------------- UI -------------------
st.title("Adaptive Cloud Firewall — Prototype v3")
st.markdown("A product-like prototype with multi-page UI, persistence, ML detection, Geo-aware mock and pilot readiness.")

tabs = st.tabs(["Dashboard","Threat Intel","Rule Engine","Reports","Settings","Facilitator Notes"])

# ---------- Dashboard ----------
with tabs[0]:
    st.header("Live Dashboard")
    col1, col2, col3, col4 = st.columns(4)
    # show KPIs
    total_traffic = pd.read_sql_query("SELECT SUM(bytes) as total_bytes, COUNT(*) as flows FROM traffic", conn).iloc[0]
    total_bytes = int(total_traffic['total_bytes'] or 0)
    flows = int(total_traffic['flows'] or 0)
    active_rules = pd.read_sql_query("SELECT COUNT(*) as c FROM rules", conn).iloc[0]['c']
    recent_alerts = pd.read_sql_query("SELECT COUNT(*) as c FROM alerts WHERE ts > datetime('now','-1 hour')", conn).iloc[0]['c']
    col1.markdown(f"<div class='card'><div class='kpi'>{flows}</div><div class='small'>Flows ingested</div></div>", unsafe_allow_html=True)
    col2.markdown(f"<div class='card'><div class='kpi'>{total_bytes}</div><div class='small'>Bytes processed</div></div>", unsafe_allow_html=True)
    col3.markdown(f"<div class='card'><div class='kpi'>{active_rules}</div><div class='small'>Active adaptive rules</div></div>", unsafe_allow_html=True)
    col4.markdown(f"<div class='card'><div class='kpi'>{recent_alerts}</div><div class='small'>Alerts last hour</div></div>", unsafe_allow_html=True)

    st.markdown("### Traffic timeline (packets per minute)")
    df_recent = fetch_recent(conn, limit=1000)
    if not df_recent.empty:
        ts = df_recent.set_index('ts').resample('1T').packets.sum()
        st.line_chart(ts)
    else:
        st.info("No traffic ingested yet. Use Settings -> Simulate to create traffic.")

    st.markdown("### Top source countries & IPs")
    if not df_recent.empty:
        country_counts = df_recent['country'].value_counts().head(10)
        st.bar_chart(country_counts)
        st.dataframe(df_recent[['ts','src_ip','dst_port','packets','bytes','country']].head(10))
    st.markdown("---")
    st.button("Refresh Metrics")

# ---------- Threat Intel ----------
with tabs[1]:
    st.header("Threat Intelligence")
    st.markdown("Detected alerts, enriched with mock GeoIP and threat feed scoring.")
    alerts_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 200", conn)
    if not alerts_df.empty:
        st.dataframe(alerts_df)
    else:
        st.info("No alerts. Run detection from Settings.")

    st.markdown("### Enrichment (mock)")
    st.markdown("We enrich alerts with a mock threat score (0-100) and country of origin.")
    if not alerts_df.empty:
        alerts_df['threat_score'] = alerts_df['meta'].apply(lambda x: random.randint(40,98))
        alerts_df['country'] = alerts_df['src_ip'].apply(lambda x: random.choice(COUNTRIES))
        st.dataframe(alerts_df[['ts','type','src_ip','country','severity','threat_score']].head(50))

# ---------- Rule Engine ----------
with tabs[2]:
    st.header("Adaptive Rule Engine")
    st.markdown("Active rules are persisted and can be managed here. Rules include TTL and reason.")
    rules_df = pd.read_sql_query("SELECT * FROM rules", conn)
    if not rules_df.empty:
        st.dataframe(rules_df)
    else:
        st.info("No active adaptive rules. Run detection to auto-apply rules.")

    st.markdown("### Manual Rule Management")
    with st.form("manual_rule"):
        ip = st.text_input("Target IP")
        action = st.selectbox("Action", ["block","rate_limit","allow"])
        params = st.text_area("Params (JSON)", value='{\"expire_min\":60}')
        reason = st.text_input("Reason")
        submitted = st.form_submit_button("Apply Rule")
        if submitted and ip:
            try:
                p = json.dumps(json.loads(params))
            except Exception as e:
                st.error("Params must be valid JSON")
                p = json.dumps({"expire_min":60})
            c = conn.cursor()
            c.execute("REPLACE INTO rules (ip,action,params,reason,applied_at) VALUES (?,?,?,?,?)", (ip,action,p,reason, datetime.utcnow().isoformat()))
            conn.commit()
            st.success("Rule applied")

# ---------- Reports ----------
with tabs[3]:
    st.header("Reports & Export")
    st.markdown("Download traffic, alerts, and rule history for audit & compliance.")
    if st.button("Export traffic CSV (last 1000)"):
        df = fetch_recent(conn, limit=1000)
        b = io.BytesIO(df.to_csv(index=False).encode('utf-8'))
        st.download_button("Download traffic.csv", data=b, file_name="traffic.csv", mime="text/csv")
    if st.button("Export alerts JSON"):
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 1000", conn)
        b = io.BytesIO(df.to_json(orient='records', date_format='iso').encode('utf-8'))
        st.download_button("Download alerts.json", data=b, file_name="alerts.json", mime="application/json")
    if st.button("Export rules JSON"):
        df = pd.read_sql_query("SELECT * FROM rules", conn)
        b = io.BytesIO(df.to_json(orient='records', date_format='iso').encode('utf-8'))
        st.download_button("Download rules.json", data=b, file_name="rules.json", mime="application/json")

# ---------- Settings & Simulation ----------
with tabs[4]:
    st.header("Settings & Simulation")
    st.markdown("Use this panel to simulate traffic, tune detectors and run a demo pilot connector (mock).")
    sim_n = st.number_input("Simulate traffic rows", min_value=100, max_value=5000, value=800, step=50)
    attack = st.selectbox("Attack scenario", ["None","DDoS","BruteForce","PortScan"])
    detect_mode = st.selectbox("Detection mode", ["Threshold","ML"])
    flow_threshold = st.number_input("Flow threshold (packets*bytes)", value=20000, step=1000)
    if st.button("Simulate & Detect"):
        simulate_traffic_store(conn, n=sim_n, attack=attack)
        df = fetch_recent(conn, limit=2000)
        if detect_mode == "Threshold":
            alerts = detect_threshold(df, flow_threshold)
        else:
            alerts = detect_ml(df)
        persist_alerts(conn, alerts)
        changes = apply_adaptive_rules(conn, alerts)
        st.success(f"Simulated {sim_n} rows, detected {len(alerts)} alerts, applied {len(changes)} rule changes.")

    st.markdown("### Mock 'Apply to Cloud' connector")
    st.markdown("This will simulate calling cloud provider APIs and record an action in the DB (mock).")
    if st.button("Mock apply to cloud (AWS/Azure/Cloudflare)"):
        st.session_state['last_apply'] = {"time": datetime.utcnow().isoformat(), "status":"ok", "note":"mock apply executed"}
        st.success("Mock apply: recorded action (no external calls in this demo).")

# ---------- Facilitator Notes ----------
with tabs[5]:
    st.header("Facilitator Notes & Pilot Proposal")
    st.markdown("""
**Prototype v3 highlights:**

- Product-like UX with persistence, ML detection, adaptive rule engine and export
- Ready pilot path: NetFlow/VPC flow logs -> collector -> this service
- Security & compliance: audit-ready exports, TTL rules, mock connector for cloud firewalls
- Next steps for pilot: containerize, secure collector, obtain consent & whitelist, 8-week tuning phase
""")
    st.markdown("**Pilot budget estimate:** ~€35k (incl. engineering, infra, 3-month pilot support)")
    st.markdown("**Contact:** [Your Name] — [email/contact]")

# ------------------- End -------------------
