def evaluate(ip: str, host_data: dict) -> list:
    violations = []

    ports = host_data.get("ports", {})

    for port, port_info in ports.items():
        service = port_info.get("service")
        port_num = int(port)

        if service == "telnet" and port_num == 23:
            violations.append("기본포트 23에서 Telnet 서비스 운용 중")
        elif service == "ftp" and port_num == 21:
            violations.append("기본포트 21에서 FTP 서비스 운용 중")
        elif service == "rlogin" and port_num == 513:
            violations.append("기본포트 513에서 rlogin 서비스 운용 중")

    return violations
