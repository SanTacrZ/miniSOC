#!/usr/bin/env python3
"""
Sigma → Elastic (DSL + EQL) — Exportador para SOC-001..005
Lee siem/rules/sigma_like/*.yml y genera:
- siem/elastic/dsl/*.json   (Elasticsearch Query DSL)
- siem/elastic/eql/*.eql    (EQL para timeline detection)
Uso: python siem/tools/sigma_to_elastic.py --check
"""
import pathlib, yaml, json, argparse, re

RULES = pathlib.Path("siem/rules/sigma_like")
OUT_DSL = pathlib.Path("siem/elastic/dsl")
OUT_EQL = pathlib.Path("siem/elastic/eql")

def sigma_to_dsl(rule: dict) -> dict:
    rid = rule.get("id")
    title = rule.get("title")
    det = rule.get("detection", {})
    sel = det.get("selection", {})
    # Mapeo simple campo Sigma → ECS / minisoc
    # svc: api → svc:api, action: auth_fail → event.action, src_ip, actor etc.
    must=[]
    for k,v in sel.items():
        if isinstance(v, str) and v.startswith(">"):
            # threshold like ">5" no va a DSL, es agregación
            continue
        # normaliza
        field_map = {
            "svc": "minisoc.svc",
            "action": "event.action",
            "result": "event.outcome",
            "src_ip": "source.ip",
            "actor": "user.name",
            "payload_len": "minisoc.payload_len",
            "status_code": "http.response.status_code",
        }
        es_field = field_map.get(k, k)
        # wildcard?
        if isinstance(v, str) and "*" in v:
            must.append({"wildcard": {es_field: v}})
        elif k=="payload_len" and isinstance(v, str) and v.startswith(">"):
            must.append({"range": {es_field: {"gt": int(v[1:])}}})
        else:
            must.append({"match": {es_field: v}})

    # Casos especiales por rule_id
    if rid=="SOC-002-rustyapa-exploit":
        must = [
            {"match": {"minisoc.svc": "rustyapa"}},
            {"bool": {"should": [
                {"range": {"minisoc.payload_len": {"gt": 4096}}},
                {"wildcard": {"minisoc.note": "*;*"}},
                {"wildcard": {"minisoc.note": "*$\\(*"}},
                {"wildcard": {"minisoc.note": "*flag*"}},
            ], "minimum_should_match": 1}}
        ]
    elif rid=="SOC-001-brute-force":
        must = [
            {"match": {"event.action": "auth_fail"}},
            {"match": {"event.outcome": "fail"}},
        ]
        # Agregación se representa como metadata, no DSL filter
    elif rid=="SOC-004-large-payload":
        must = [
            {"bool": {"should": [
                {"match": {"event.action": "suspicious_note"}},
                {"range": {"http.response.bytes": {"gt": 50000}}},
            ]}}
        ]

    dsl = {
        "query": {"bool": {"must": must}},
        "meta": {"rule_id": rid, "title": title, "level": rule.get("level"), "mitre": rule.get("tags", [])}
    }
    # Si es agregación brute-force, añade aggs
    if rid=="SOC-001-brute-force":
        dsl["aggs"] = {"by_ip": {"terms": {"field": "source.ip"}, "aggs": {"count": {"value_count": {"field": "source.ip"}}}}}
        dsl["meta"]["condition"] = "count >5 per source.ip in 60s"
    return dsl

def sigma_to_eql(rule: dict) -> str:
    rid = rule.get("id")
    if rid=="SOC-001-brute-force":
        return '''sequence by source.ip
  [authentication where event.action == "auth_fail" and event.outcome == "fail"] with runs=5
  till [authentication where event.action == "auth_success"]
  // T1110 — 5 fails misma IP, opcional success posterior
'''
    if rid=="SOC-002-rustyapa-exploit":
        return '''any where minisoc.svc == "rustyapa" and (minisoc.payload_len > 4096 or minisoc.note regex~ ";|\\$\\(|flag")
 // T1190 — Rustyapa tags heap spray
'''
    if rid=="SOC-003-priv-esc":
        return '''sequence by user.name
  [http where url.path like "/admin*" and http.response.status_code == 403] with runs=3
 // T1548 — probing admin
'''
    if rid=="SOC-004-large-payload":
        return '''any where event.action == "suspicious_note" or http.response.bytes > 50000
 // T1041 exfil
'''
    if rid=="SOC-005-journal-clear":
        return '''any where event.action == "journal_clear" or minisoc.action == "journal_clear"
 // T1070 defense evasion
'''
    # genérico
    det = rule.get("detection", {}).get("selection", {})
    clauses = " and ".join(f'{k} == "{v}"' for k,v in det.items())
    return f'any where {clauses}\n'

def main(check=False):
    OUT_DSL.mkdir(parents=True, exist_ok=True)
    OUT_EQL.mkdir(parents=True, exist_ok=True)
    rules = list(RULES.glob("*.yml"))
    if not rules:
        print("[!] no rules"); return
    for yf in rules:
        rule = yaml.safe_load(yf.read_text())
        dsl = sigma_to_dsl(rule)
        eql = sigma_to_eql(rule)
        rid = rule.get("id", yf.stem)
        out_dsl = OUT_DSL / f"{rid}.json"
        out_eql = OUT_EQL / f"{rid}.eql"
        out_dsl.write_text(json.dumps(dsl, indent=2))
        out_eql.write_text(eql)
        print(f"[+] {yf.name} -> {out_dsl} + {out_eql}")
        if check:
            # validate JSON
            json.loads(out_dsl.read_text())
            assert "query" in dsl
    print(f"[✓] {len(rules)} Sigma → Elastic exported to {OUT_DSL} and {OUT_EQL}")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args=ap.parse_args()
    main(check=args.check)
