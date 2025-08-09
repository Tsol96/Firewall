
# Adaptive Cloud Firewall — MVP (Streamlit)

This repository contains a lightweight MVP for an **Adaptive Cloud Firewall-as-a-Service (A-FaaS)** demo built with Streamlit.
It simulates real-time traffic, detects simple anomalies, and demonstrates an adaptive rule engine that updates firewall rules based on alerts.

## How to run locally
1. Install Python 3.9+ and create a virtual environment
2. Install requirements: `pip install -r requirements.txt`
3. Run: `streamlit run app.py`

## How to deploy to Streamlit Cloud
1. Create a GitHub repository and push these files.
2. Sign in to https://share.streamlit.io with your GitHub account.
3. Add a new app and point to `app.py` on the main branch.
4. Launch — you will get a public URL to share with facilitators.

## Files
- `app.py` — main Streamlit application
- `requirements.txt` — Python dependencies
- `README.md` — this file
