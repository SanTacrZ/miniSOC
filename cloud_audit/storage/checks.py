"""Storage checks — AC-3, SC-28"""
import pathlib

def check_public_bucket(tf_dir: pathlib.Path | None = None) -> dict:
    if tf_dir is None:
        tf_dir = pathlib.Path(__file__).parent.parent.parent / "infra" / "terraform"
    fails=[]
    if tf_dir.exists():
        for tf in tf_dir.glob("*.tf"):
            txt=tf.read_text().lower()
            if "acl" in txt and "public" in txt:
                fails.append(tf.name)
            if "block_public_acls" in txt and "false" in txt:
                fails.append(tf.name)
    return {"id":"STO-001","status":"FAIL" if fails else "PASS","severity":"critical","resources":fails, "title":"S3 not public"}

def check_encryption(tf_dir: pathlib.Path | None = None) -> dict:
    if tf_dir is None:
        tf_dir = pathlib.Path(__file__).parent.parent.parent / "infra" / "terraform"
    fails=[]
    if tf_dir.exists():
        found=False
        for tf in tf_dir.glob("*.tf"):
            if "server_side_encryption" in tf.read_text():
                found=True
        if not found:
            fails.append("no_encryption_config")
    return {"id":"STO-002","status":"FAIL" if fails else "PASS","severity":"high","resources":fails, "title":"Encrypted at rest"}

def run_all():
    return [check_public_bucket(), check_encryption()]

if __name__=="__main__":
    import json; print(json.dumps(run_all(), indent=2))
