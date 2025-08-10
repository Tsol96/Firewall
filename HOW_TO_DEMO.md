
# How to demo AvanCloud Prototype (step-by-step)

1. Deploy with docker-compose: `docker-compose up --build`
2. Open Streamlit UI at http://localhost:8501
3. Login with admin/adminpass
4. Go to Onboarding Wizard and create a policy - this will create a sample policy and rules.
5. Open Settings and simulate traffic via API or use the backend /api/flows endpoint to POST flows
6. Run detection: Settings -> "Run detection" buttons (or use /api/detect endpoints)
7. View Alerts in Monitoring, and apply rules from Management (apply is mocked but recorded)
8. Export reports from Reports tab and share with facilitator (info@avannow.com)
