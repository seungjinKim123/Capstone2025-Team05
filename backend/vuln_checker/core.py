from .cve_checker import check_vulnerabilities
from .database_loader import load_all
from .evaluator import evaluate_policies


def run_all_checks():
    scan_data, vuln_db, eval_db = load_all()
    cve_results = check_vulnerabilities(scan_data, vuln_db)
    policy_results = evaluate_policies(scan_data, eval_db)
    return {
        "vulnerabilities": cve_results,
        "policy_violations": policy_results
    }

# ✅ 단독 실행 가능하도록 CLI 블록 추가
if __name__ == "__main__":
    # python3 -m backend.vuln_checker.core
    import json
    import os

    print("🧠 분석 실행 중...")
    results = run_all_checks()

    os.makedirs("data/reports", exist_ok=True)
    output_path = "data/reports/analysis_results.json"

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"✅ 분석 완료 → {output_path}")
