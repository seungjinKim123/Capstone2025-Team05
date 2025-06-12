# rule_30701.py - 웹 서버 보안 점검
def evaluate(ip: str, host_data: dict) -> list:
    violations = []
    ports = host_data.get("ports", {})

    for port, port_info in ports.items():
        service = port_info.get("service")
        port_num = int(port)
        scripts = port_info.get("scripts", {})

        if service in ["http", "https"]:
            # HTTP 메소드 점검
            http_methods = scripts.get("http-methods", "")
            if "TRACE" in http_methods or "DELETE" in http_methods:
                violations.append(f"HTTP 포트 {port}: 위험한 HTTP 메소드 허용됨")
            
            # 디렉토리 리스팅 점검
            http_enum = scripts.get("http-enum", "")
            if "directory listing" in http_enum.lower():
                violations.append(f"HTTP 포트 {port}: 디렉토리 리스팅 허용됨")
            
            # 서버 정보 노출
            http_headers = scripts.get("http-server-header", "")
            if http_headers and ("Server:" in http_headers):
                violations.append(f"HTTP 포트 {port}: 서버 헤더 정보 노출됨")

    return violations