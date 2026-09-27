#!/usr/bin/env python3
import json, ssl, time, urllib.request, urllib.error
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone

URL = "https://50.28.86.131/attest/submit"
OUT = Path(__file__).resolve().parent
ctx = ssl._create_unverified_context()
tests = []

def add(category, name, payload):
    tests.append({"category": category, "name": name, "payload": payload})

partials = [
    {}, {"miner":"bounty1112-test"}, {"miner_id":"bounty1112-test"}, {"challenge":"deadbeef"}, {"signature":"00"},
    {"device":{}}, {"miner":"bounty1112-test","challenge":"deadbeef"}, {"miner":"bounty1112-test","signature":"00"},
    {"miner":"bounty1112-test","device":{}}, {"miner_id":"bounty1112-test","challenge":"deadbeef"},
    {"miner_id":"bounty1112-test","signature":"00"}, {"miner_id":"bounty1112-test","device":{}},
    {"challenge":"deadbeef","signature":"00"}, {"challenge":"deadbeef","device":{}}, {"signature":"00","device":{}},
    {"miner":""}, {"miner_id":""}, {"miner":"bounty1112-test","challenge":""}, {"miner":"bounty1112-test","signature":""},
    {"miner":"bounty1112-test","challenge":"deadbeef","signature":"00"},
    {"miner_id":"bounty1112-test","challenge":"deadbeef","signature":"00"},
    {"miner":"bounty1112-test","challenge":"deadbeef","device":{"arch":"x86_64"}},
    {"miner":"bounty1112-test","signature":"00","device":{"arch":"x86_64"}},
    {"challenge":"deadbeef","signature":"00","device":{"arch":"x86_64"}},
    {"miner":"bounty1112-test","challenge":"deadbeef","signature":"00","device":{}},
]
for i,p in enumerate(partials,1): add("missing_fields", f"missing_{i:02d}", p)

wrong = [
    ("miner",None),("miner",123),("miner",True),("miner",[]),("miner",{}),
    ("miner_id",None),("miner_id",123),("miner_id",False),("miner_id",[]),("miner_id",{}),
    ("challenge",None),("challenge",123),("challenge",True),("challenge",[]),("challenge",{}),
    ("signature",None),("signature",123),("signature",False),("signature",[]),("signature",{}),
    ("device",None),("device","x86_64"),("device",123),("device",[]),("device",True),
]
for i,(field,value) in enumerate(wrong,1):
    p={"miner":"bounty1112-test","challenge":"deadbeef","signature":"00","device":{}}
    p[field]=value
    add("wrong_types", f"wrong_{field}_{i:02d}", p)

sizes=[2048,4096,8192,16384,32768]
fields=["miner","challenge","signature","device_blob","extra"]
for field in fields:
    for sz in sizes:
        p={"miner":"bounty1112-test","challenge":"deadbeef","signature":"00","device":{}}
        if field=="device_blob": p["device"]={"blob":"A"*sz}
        else: p[field]="A"*sz
        add("oversized_input", f"oversized_{field}_{sz}", p)

vectors=[
    "' OR '1'='1","\" OR \"1\"=\"1","'; SELECT 1; --","../../etc/passwd","..\\..\\windows\\system.ini",
    "<script>alert(1)</script>","<img src=x onerror=alert(1)>","{{7*7}}","<%= 7*7 %>","template:7*7",
    "; id","&& whoami","| cat /etc/passwd","shell-substitution-test","command-substitution-test",
    "%00","null-byte-test","%2e%2e%2f","admin'--","1 UNION SELECT 1",
    "{\"$ne\":null}","[$gt]=0","__proto__","constructor.prototype","☃/../test",
]
for i,v in enumerate(vectors,1):
    add("injection_style", f"injection_{i:02d}", {"miner":v,"challenge":"deadbeef","signature":"00","device":{}})

assert len(tests)==100
records=[]; status_counts=Counter(); category_counts=defaultdict(Counter)
start=time.time()
for idx,t in enumerate(tests,1):
    raw=json.dumps(t["payload"],ensure_ascii=False).encode()
    req=urllib.request.Request(URL,data=raw,method="POST",headers={
        "Content-Type":"application/json","Accept":"application/json",
        "User-Agent":"BABYDOV-RustChain-Bounty1112/1.0"})
    ts=datetime.now(timezone.utc).isoformat(); code=0; body=""; err=None; t0=time.time()
    try:
        with urllib.request.urlopen(req,timeout=8,context=ctx) as resp:
            code=resp.status; body=resp.read(4096).decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        code=e.code; body=e.read(4096).decode("utf-8","replace")
    except Exception as e:
        err=f"{type(e).__name__}: {e}"
    elapsed=round(time.time()-t0,3)
    rec={"index":idx,"at_utc":ts,"category":t["category"],"name":t["name"],
         "request_bytes":len(raw),"status":code,"elapsed_s":elapsed,
         "response_preview":body[:800],"transport_error":err}
    records.append(rec); status_counts[str(code)]+=1; category_counts[t["category"]][str(code)]+=1
    with (OUT/"results.jsonl").open("a",encoding="utf-8") as f:
        f.write(json.dumps(rec,ensure_ascii=False)+"\n")
    print(f"{idx:03d}/100 {t['category']:<16} {t['name']:<34} HTTP={code} {elapsed:.3f}s",flush=True)
    time.sleep(0.25)

summary={
    "schema":"babydov.rustchain.bounty1112.fuzz.v1","target":URL,
    "started_at_utc":records[0]["at_utc"],"completed_at_utc":datetime.now(timezone.utc).isoformat(),
    "total_tests":len(records),"total_runtime_s":round(time.time()-start,2),
    "status_counts":dict(status_counts),
    "category_status_counts":{k:dict(v) for k,v in category_counts.items()},
    "transport_errors":sum(1 for r in records if r["transport_error"]),
    "server_5xx_count":sum(1 for r in records if 500 <= r["status"] < 600),
    "success_2xx_count":sum(1 for r in records if 200 <= r["status"] < 300),
    "rate_limited_429_count":sum(1 for r in records if r["status"]==429),
    "max_request_bytes":max(r["request_bytes"] for r in records)}
(OUT/"summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
print("SUMMARY",json.dumps(summary,ensure_ascii=False),flush=True)
