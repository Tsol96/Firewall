
# Adaptive Cloud Firewall — Prototype v3

This prototype is a product-like Streamlit app demonstrating a multi-page Adaptive Cloud Firewall product.
It includes:
- traffic ingestion (simulated NetFlow-like)
- threshold & ML-based detection (IsolationForest)
- persistent rule engine (SQLite) with TTL and manual overrides
- reporting and export
- mock cloud connector for pilot planning

## Run locally
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py

## Deploy to Streamlit Cloud
- Push repo to GitHub
- Create an app in share.streamlit.io pointing to app.py
