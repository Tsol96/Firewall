
# Adaptive Cloud Firewall — Onboarding + Full Backend (Prototype)

This project is a prototype of an Adaptive Cloud Firewall with onboarding wizard, a FastAPI backend, and a Streamlit frontend.

## Features
- Frontend: Streamlit onboarding wizard, management, monitoring & reports
- Backend: FastAPI with endpoints for flows, detection, rules CRUD, enforcement mock snippets
- Auth: OAuth2 Password + JWT token (role-based)
- Connectors: Sample code/snippets for AWS, Azure, GCP, Cloudflare (mock)
- Packaging: Dockerfiles and docker-compose for local deployment

## Quickstart (docker-compose)
1. unzip project
2. cd to project root
3. docker-compose up --build
4. Open http://localhost:8501 for frontend and http://localhost:8000/docs for backend API docs

Default admin user: username `admin`, password `adminpass` (change immediately)

