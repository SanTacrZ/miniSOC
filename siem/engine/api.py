"""SIEM dashboard API (fastapi) for alerts"""
from fastapi import FastAPI
import pathlib, json, glob
app=FastAPI(title="Mini-SOC SIEM")
@app.get("/alerts")
def alerts():
    alerts=[]
    for f in glob.glob("alerts/*.json") + glob.glob("logs/alerts.jsonl"):
        try:
            if f.endswith(".jsonl"):
                for line in pathlib.Path(f).read_text().splitlines():
                    alerts.append(json.loads(line))
            else:
                alerts.append(json.loads(pathlib.Path(f).read_text()))
        except: pass
    return {"count": len(alerts), "alerts": alerts[-50:]}

@app.get("/health")
def health(): return {"status":"ok"}
