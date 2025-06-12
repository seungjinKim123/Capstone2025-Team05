import argparse
import ipaddress
import re
from pathlib import Path

import pandas as pd

SUPPORTED_EXTENSIONS = [".csv", ".xlsx"]
IP_REGEX = re.compile(r"""
    (?P<ip>\d{1,3}(?:\.\d{1,3}){3})
    (?:\s*-\s*(?P<ip2>\d{1,3}(?:\.\d{1,3}){3}))?
    (?:/\d{1,2})?
""", re.VERBOSE)

def is_valid_ip(ip: ipaddress.IPv4Address) -> bool:
    return not (
        ip.is_multicast or
        ip.is_unspecified or
        ip.is_reserved or
        ip.is_loopback or
        ip.is_link_local
    )

def extract_ip_ranges(file_path: str,
                      output_path: str = "data/ip_ranges/ip_list.txt",
                      cidr_output_path: str = "data/ip_ranges/ip_cidr.txt",
                      expand_single_ip: bool = False) -> int:
    """
    IP 대역 추출 (단일 IP 확장 옵션 추가)
    
    Args:
        expand_single_ip: True면 단일 IP를 C클래스로 확장, False면 단일 IP만 유지
    """
    path = Path(file_path)
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"❌ 지원하지 않는 파일 형식입니다: {path.suffix}")

    if path.suffix.lower() == ".csv":
        df = pd.read_csv(file_path, dtype=str)
    else:
        df = pd.read_excel(file_path, dtype=str)

    ip_list = set()

    for col in df.columns:
        for raw in df[col].dropna():
            matches = IP_REGEX.findall(str(raw))
            for match in matches:
                try:
                    start_ip = match[0]
                    end_ip = match[1] if match[1] else None

                    if "/" in raw:
                        # CIDR 표기법
                        net = ipaddress.ip_network(raw.strip(), strict=False)
                        for ip in net.hosts():
                            if is_valid_ip(ip):
                                ip_list.add(ip)
                            else:
                                print(f"⚠️ 제외된 IP (CIDR): {ip}")

                    elif end_ip:
                        # IP 범위
                        ip_range = ipaddress.summarize_address_range(
                            ipaddress.ip_address(start_ip),
                            ipaddress.ip_address(end_ip)
                        )
                        for subnet in ip_range:
                            for ip in subnet.hosts():
                                if is_valid_ip(ip):
                                    ip_list.add(ip)
                                else:
                                    print(f"⚠️ 제외된 IP (Range): {ip}")

                    else:
                        # 단일 IP
                        ip = ipaddress.ip_address(start_ip)
                        if is_valid_ip(ip):
                            if expand_single_ip:
                                # C 클래스 전체로 확장
                                c_class = ipaddress.ip_network(f"{ip}/24", strict=False)
                                for host_ip in c_class.hosts():
                                    if is_valid_ip(host_ip):
                                        ip_list.add(host_ip)
                                print(f"📈 단일 IP {ip}를 C클래스로 확장: {c_class}")
                            else:
                                # 단일 IP만 추가
                                ip_list.add(ip)
                                print(f"📍 단일 IP 추가: {ip}")
                        else:
                            print(f"⚠️ 제외된 IP (단일): {ip}")

                except Exception as e:
                    print(f"⚠️ 무시된 항목: {raw} ({e})")

    ip_list = sorted(ip_list)
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # 1. 개별 IP 저장
    with open(output_file, "w") as f:
        for ip in ip_list:
            f.write(str(ip) + "\n")

    # 2. CIDR 압축 저장
    if ip_list:
        collapsed = ipaddress.collapse_addresses(ip_list)
        with open(cidr_output_path, "w") as f:
            for net in collapsed:
                f.write(str(net) + "\n")
        cidr_count = len(list(collapsed))
    else:
        # 빈 파일 생성
        with open(cidr_output_path, "w") as f:
            pass
        cidr_count = 0

    print(f"✅ 추출된 IP 수: {len(ip_list)}개 → {output_path}")
    print(f"📦 CIDR 그룹 수: {cidr_count}개 → {cidr_output_path}")
    return len(ip_list)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="📥 문서에서 IP 대역 추출기")
    parser.add_argument("input_file", help="CSV 또는 Excel 파일 경로")
    parser.add_argument("-o", "--output", default="data/ip_ranges/ip_list.txt", help="IP 목록 저장 경로")
    parser.add_argument("-c", "--cidr", default="data/ip_ranges/ip_cidr.txt", help="CIDR 목록 저장 경로")
    parser.add_argument("--expand", action="store_true", help="단일 IP를 C클래스로 확장")

    args = parser.parse_args()
    try:
        extract_ip_ranges(args.input_file, args.output, args.cidr, args.expand)
    except Exception as e:
        print(f"❌ 오류: {e}")