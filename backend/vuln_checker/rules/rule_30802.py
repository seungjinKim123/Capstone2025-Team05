from ._utils import contains_version_string


def evaluate(ip: str, host_data: dict) -> list:
    violations = []

    ports = host_data.get("ports", {})

    for port, port_info in ports.items():
        service = port_info.get("service")
        version = port_info.get("version", "")
        scripts = port_info.get("scripts", {})

        # 1. 버전 문자열이 명시되어 있는 경우
        if version:
            violations.append(f"{service} 포트 {port}: 서비스 버전 정보 노출됨 ({version})")

        # 2. NSE script output에서 버전 관련 문자열 노출 여부 탐지
        for script_id, output in scripts.items():
            if contains_version_string(output):
                violations.append(f"{service} 포트 {port}: 스크립트({script_id})에서 버전 정보 노출됨")

    return violations
