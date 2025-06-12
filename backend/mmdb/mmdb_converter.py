import json
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(xml_path: str, output_path: str = "data/mmdb/scan_parsed.json") -> dict:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    result = {}

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip_elem = host.find("address[@addrtype='ipv4']")
        mac_elem = host.find("address[@addrtype='mac']")
        if ip_elem is None:
            continue

        ip = ip_elem.get("addr")
        host_data = {
            "ports": {},
            "os": None,
            "hostname": None,
            "mac": mac_elem.get("addr") if mac_elem is not None else None,
            "uptime": None,
            "distance": None
        }

        # Hostname
        hostname_elem = host.find("hostnames/hostname")
        if hostname_elem is not None:
            host_data["hostname"] = hostname_elem.get("name")

        # Uptime
        uptime_elem = host.find("uptime")
        if uptime_elem is not None:
            seconds = uptime_elem.get("seconds")
            lastboot = uptime_elem.get("lastboot")
            host_data["uptime"] = {
                "seconds": int(seconds) if seconds else None,
                "lastboot": lastboot
            }

        # Distance
        distance_elem = host.find("distance")
        if distance_elem is not None:
            host_data["distance"] = int(distance_elem.get("value"))

        # Ports
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                portid = port.get("portid")
                proto = port.get("protocol")
                state = port.find("state").get("state")

                if state != "open":
                    continue

                service = port.find("service")
                service_info = {
                    "protocol": proto,
                    "state": state,
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "cpe": [],
                    "scripts": {}
                }

                # CPE
                if service is not None:
                    for cpe in service.findall("cpe"):
                        service_info["cpe"].append(cpe.text)

                # Scripts
                for script in port.findall("script"):
                    script_id = script.get("id")
                    script_output = script.get("output")
                    if script_id and script_output:
                        service_info["scripts"][script_id] = script_output

                host_data["ports"][portid] = service_info

        # OS
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                host_data["os"] = osmatch.get("name")

        result[ip] = host_data

    # 저장
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"✅ JSON 변환 완료: {output_path}")
    return result


if __name__ == "__main__":
    # python backend/mmdb/mmdb_converter.py data/scan_results/scan_20250508_181849.xml
    import argparse

    parser = argparse.ArgumentParser(description="🧠 Nmap XML → JSON 변환기 (확장판)")
    parser.add_argument("xml_path", help="Nmap XML 파일 경로")
    parser.add_argument("-o", "--output", default="data/mmdb/scan_parsed.json", help="JSON 저장 경로")

    args = parser.parse_args()
    parse_nmap_xml(args.xml_path, args.output)
