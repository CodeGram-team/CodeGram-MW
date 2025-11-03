# Malware & Emoji Tagging Service (FastAPI)

## Run (venv)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080

docker build -t malware-emoji:0.1 .
docker run -d --name malware-emoji -p 8080:8080 malware-emoji:0.1
curl http://localhost:8080/health
