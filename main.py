from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from app.analyzer import analyze_request

BASE_DIR=Path(__file__).resolve().parent.parent
app=FastAPI(title="HTTP Request Security Analyzer",version="1.0.0",
            description="Passive analysis of captured or simulated HTTP requests.")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["GET","POST"],allow_headers=["*"])

@app.get("/")
def dashboard(): return FileResponse(BASE_DIR/"static"/"index.html")

@app.get("/health")
def health(): return {"status":"ok","service":"HTTP Request Security Analyzer"}

@app.post("/analyze")
def analyze(request:dict): return analyze_request(request)
