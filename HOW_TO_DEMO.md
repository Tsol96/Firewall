
1. unzip package
2. cd AvanCloud_Final_v3/backend
3. python -m venv .venv; source .venv/bin/activate
4. pip install -r requirements.txt
5. uvicorn main:app --reload --port 8000
6. cd ../frontend; pip install -r requirements.txt; streamlit run app.py
7. Login on Streamlit with admin/adminpass
