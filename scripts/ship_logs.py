#!/usr/bin/env python3
"""Simula Filebeat: tail logs y reenvía"""
import pathlib, time, json
src = pathlib.Path("logs/siem.jsonl")
dst = pathlib.Path("/tmp/soc_siem.jsonl")
print(f"[*] shipping {src} -> {dst}")
if not src.exists(): print("[!] no src"); exit(0)
for line in src.read_text().splitlines():
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst,"a") as f: f.write(line+"\n")
    print(f" shipped {len(line)}b")
