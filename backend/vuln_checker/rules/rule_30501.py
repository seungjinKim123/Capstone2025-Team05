from ._utils import is_dangerous_service


def evaluate(ip: str, host_data: dict) -> list:
    violations = []
    ports = host_data.get("ports", {})

    # 불필요하거나 위험한 서비스 목록
    unnecessary_services = {
        "finger": 79,
        "echo": 7,
        "discard": 9,
        "daytime": 13,
        "chargen": 19,
        "time": 37,
        "netstat": 15,
        "qotd": 17,  # Quote of the Day
        "tftp": 69,
        "bootps": 67,  # BOOTP Server
        "bootpc": 68,  # BOOTP Client
        "kerberos": 88,
        "pop2": 109,
        "pop3": 110,
        "sunrpc": 111,
        "auth": 113,
        "sftp": 115,
        "uucp": 540,
        "kshell": 544,
        "printer": 515,
        "talk": 517,
        "ntalk": 518,
        "utime": 519,
        "router": 520,
        "timed": 525,
        "courier": 530,
        "conference": 531,
        "netnews": 532,
        "netwall": 533,
        "windowing": 544,
        "new-rwho": 550,
        "cybercash": 551,
        "remotefs": 556
    }

    for port, port_info in ports.items():
        service = port_info.get("service")
        port_num = int(port)
        
        # 명시적으로 불필요한 서비스 체크
        if service in unnecessary_services:
            expected_port = unnecessary_services[service]
            if port_num == expected_port:
                violations.append(f"불필요한 서비스 {service} 포트 {port} 운영 중")
        
        # 위험한 서비스 체크
        if is_dangerous_service(service, port_num):
            violations.append(f"위험한 서비스 {service} 포트 {port} 운영 중")
        
        # 개발/테스트 관련 서비스
        dev_services = ["http-alt", "webcache", "http-proxy"]
        if service in dev_services:
            violations.append(f"개발/테스트 서비스 {service} 포트 {port} 운영 중")

    return violations