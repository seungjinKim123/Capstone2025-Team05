# rule_40101.py - 패치 관리 점검
def evaluate(ip: str, host_data: dict) -> list:
    violations = []
    ports = host_data.get("ports", {})

    # 알려진 취약한 버전들 체크
    vulnerable_versions = {
        "Apache httpd": ["2.4.49", "2.4.50", "2.2.34"],
        "OpenSSH": ["7.4", "8.1", "8.7"],
        "nginx": ["1.18.0", "1.19.10"],
        "vsftpd": ["2.3.4", "3.0.0"]
    }

    for port, port_info in ports.items():
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        
        if product and version:
            for vuln_product, vuln_versions in vulnerable_versions.items():
                if vuln_product.lower() in product.lower():
                    if any(vuln_ver in version for vuln_ver in vuln_versions):
                        violations.append(f"포트 {port}: {product} {version} - 알려진 취약한 버전")

    return violations