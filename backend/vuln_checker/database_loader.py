import json


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_all(scan_path="data/mmdb/scan_parsed.json",
             vuln_path="data/db/vuln_db.json",
             eval_path="data/db/eval_db.json"):
    scan_data = load_json(scan_path)
    vuln_db = load_json(vuln_path)
    eval_db = load_json(eval_path)
    return scan_data, vuln_db, eval_db
