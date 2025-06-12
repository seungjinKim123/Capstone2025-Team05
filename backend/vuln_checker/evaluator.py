import importlib

from .matcher import match_regex


def evaluate_policies(scan_data: dict, eval_db: dict) -> dict:
    results = {}

    for ip, host_data in scan_data.items():
        host_result = {}

        for eval_code, rule in eval_db.items():
            rule_name = rule.get("name")
            rule_desc = rule.get("description")
            rule_match = rule.get("match", [])
            module_name = rule.get("module")

            violations = []

            # 정적 조건 기반 검사
            for match_cond in rule_match:
                for port, port_info in host_data.get("ports", {}).items():
                    if match_eval_condition(port_info, port, match_cond):
                        violations.append(f"{port_info.get('service')} 포트 {port} 조건 일치")

            # 전용 rule 모듈 검사
            if module_name:
                try:
                    module = importlib.import_module(f".rules.{module_name}", package=__package__)
                    module_violations = module.evaluate(ip, host_data)
                    violations.extend(module_violations)
                except Exception as e:
                    print(f"⚠️ {module_name} 실행 실패: {e}")

            if violations:
                host_result[eval_code] = {
                    "name": rule_name,
                    "description": rule_desc,
                    "violations": violations
                }

        if host_result:
            results[ip] = host_result

    return results


def match_eval_condition(port_info: dict, port: str, cond: dict) -> bool:
    # 포트 번호 조건
    if "port" in cond and str(cond["port"]) != str(port):
        return False

    # 서비스 이름
    if "service" in cond and cond["service"] != "*" and port_info.get("service") != cond["service"]:
        return False

    # 정규식 기반 제품명
    if "product_regex" in cond:
        if not match_regex(port_info.get("product", ""), cond["product_regex"]):
            return False

    # 버전 정보 노출 여부
    if cond.get("version_exposure") and port_info.get("version"):
        return True  # 버전이 노출되어 있음

    # 익명 FTP 여부
    if cond.get("allows_anonymous") and port_info.get("scripts"):
        ftp_anon = port_info["scripts"].get("ftp-anon", "")
        if "Anonymous FTP login allowed" in ftp_anon:
            return True

    # 기본 계정 조건은 전용 rule에서 처리
    return False
