
# How to demo this Prototype (step-by-step)

1. Deploy with docker-compose: `docker-compose up --build`
2. Open Streamlit UI at http://localhost:8501
3. Login with admin/adminpass
4. Go to Onboarding Wizard and create a demo policy - this will create a sample rule.
5. Open Settings and simulate traffic or use API to POST flows to /api/flows
6. Run detection: Settings -> "Run detection" buttons (or use /api/detect endpoints)
7. View Alerts in Monitoring, and apply rules from Management (apply is mocked but recorded)
8. Export reports from Reports tab and share with facilitator

API examples (curl):
- Ingest flow:
curl -X POST "http://localhost:8000/api/flows" -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" -d '{"src_ip":"1.2.3.4","dst_ip":"10.0.0.1","dst_port":80,"protocol":"TCP","packets":10,"bytes":500,"duration":1}'

- Run ML detection:
curl -X POST "http://localhost:8000/api/detect/ml" -H "Authorization: Bearer <TOKEN>"

