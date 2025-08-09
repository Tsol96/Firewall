
# Adaptive Cloud Firewall — MVP v2

This repository contains an enhanced MVP for **Adaptive Cloud Firewall-as-a-Service (A-FaaS)**.
It includes:
- traffic simulation (NetFlow-like)
- threshold & ML-based (IsolationForest) detection
- adaptive rule engine (block / rate_limit)
- rule history & audit log
- mock cloud integration and export capabilities

## Quickstart (Streamlit Cloud)
1. Push repo to GitHub.
2. Create Streamlit Cloud app (https://share.streamlit.io) and point to `app.py`.
3. Run simulation from sidebar and use export features.

## Local run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Pilot steps
See in-app 'Notes for Facilitator & Pilot Plan' for recommended pilot path from MVP to production.
