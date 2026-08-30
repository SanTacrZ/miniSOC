"""Network checks — SC-7"""
from __future__ import annotations
import pathlib, re

def check_open_ssh(tf_dir: pathlib.Path | None = None) -> dict:
    if tf_dir is None:
        tf_dir = pathlib.Path(__file__).parent.parent.parent / "infra" / "terraform"
    fails=[]
    if tf_dir.exists():
        for tf in tf_dir.glob("*.tf"):
            txt=tf.read_text()
            if "0.0.0.0/0" in txt and ("22" in txt or "3389" in txt or "cidr_blocks" in txt):
                # naive but effective for lab
                if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', txt):
                    fails.append(tf.name)
    return {"id":"NET-001","status":"FAIL" if fails else "PASS","severity":"critical","resources":fails, "title":"No 0.0.0.0/0 on 22/3389"}

def check_unrestricted_egress(tf_dir: pathlib.Path | None = None) -> dict:
    if tf_dir is None:
        tf_dir = pathlib.Path(__file__).parent.parent.parent / "infra" / "terraform"
    fails=[]
    if tf_dir.exists():
        for tf in tf_dir.glob("*.tf"):
            if "egress" in tf.read_text() and "0.0.0.0/0" in tf.read_text():
                fails.append(tf.name)
    return {"id":"NET-002","status":"FAIL" if fails else "PASS","severity":"medium","resources":fails, "title":"No unrestricted egress"}

def run_all():
    return [check_open_ssh(), check_unrestricted_egress()]

if __name__=="__main__":
    import json; print(json.dumps(run_all(), indent=2))
