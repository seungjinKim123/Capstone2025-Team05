import re
import socket

from ._utils import check_weak_passwords, get_banner


def evaluate(ip: str, host_data: dict) -> list:
    violations = []
    ports = host_data.get("ports", {})

    for port, port_info in ports.items():
        service = port_info.get("service")
        port_num = int(port)

        if service == "ssh":
            # SSH 배너에서 루트 로그인 허용 여부 확인 (간접적)
            banner = get_banner(ip, port_num)
            if banner and "OpenSSH" in banner:
                violations.append(f"SSH 서비스 운영 중 - 보안 설정 검토 필요")

            # SSH 기본 계정 테스트
            default_accounts = [
                {"username": "root", "password": "root"},
                {"username": "root", "password": "123456"},
                {"username": "admin", "password": "admin"},
                {"username": "administrator", "password": "administrator"},
                {"username": "root", "password": "password"},
                {"username": "root", "password": ""},
            ]
            
            weak_accounts = check_weak_passwords(ip, port_num, "ssh", default_accounts)
            for account in weak_accounts:
                violations.append(f"SSH 약한 계정 사용됨: {account}")

            # SSH 설정 파일 점검 (스크립트에서 확인)
            scripts = port_info.get("scripts", {})
            ssh_enum = scripts.get("ssh-enum-algos", "")
            if "weak" in ssh_enum.lower():
                violations.append("SSH 약한 암호화 알고리즘 사용")

    return violations