
# HTTP Request Security Analyzer

A passive analyzer for captured or simulated HTTP requests.

## Features
- Security header checks
- Session/token cookie indicators
- Sensitive HTTP methods
- Basic authentication indicator
- CORS origin indicators
- Suspicious input patterns
- Technology disclosure
- Risk scoring and remediation

## Install
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
python -m uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000

## Test
```bash
pytest -q
```

## Safety
Passive analysis only. Use authorized traffic and fake credentials/tokens for demonstrations.
