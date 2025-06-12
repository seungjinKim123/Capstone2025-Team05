from .matcher import match_version


def check_vulnerabilities(scan_data: dict, vuln_db: dict) -> dict:
    results = {}

    for ip, host in scan_data.items():
        ip_results = {}

        for port, port_info in host.get("ports", {}).items():
            service = port_info.get("service")
            product = port_info.get("product")
            version_str = port_info.get("version")

            if not (service and product and version_str):
                continue

            cves = []

            # 서비스 단위 → 제품 단위 탐색
            service_dict = vuln_db.get(service)
            if not service_dict:
                continue

            for prod_key, ver_conditions in service_dict.items():
                if prod_key.lower() in (product or "").lower():
                    for condition, cve_list in ver_conditions.items():
                        if match_version(version_str, condition):
                            cves.extend(cve_list)

            if cves:
                ip_results[port] = {
                    "product": f"{product} {version_str}",
                    "cves": list(set(cves))  # 중복 제거
                }

        if ip_results:
            results[ip] = ip_results

    return results
