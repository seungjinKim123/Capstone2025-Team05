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
                      expand_to_subnet: bool = True) -> int:
    """
    IP 대역 추출 (단일 IP를 C클래스 서브넷으로 자동 확장)
    
    Args:
        expand_to_subnet: True면 단일 IP를 C클래스(/24)로 확장 (기본값)
    """
    path = Path(file_path)
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"❌ 지원하지 않는 파일 형식입니다: {path.suffix}")

    if path.suffix.lower() == ".csv":
        df = pd.read_csv(file_path, dtype=str)
    else:
        df = pd.read_excel(file_path, dtype=str)

    ip_set = set()
    subnet_set = set()  # CIDR 형태로 저장할 서브넷 집합

    for col in df.columns:
        for raw in df[col].dropna():
            matches = IP_REGEX.findall(str(raw))
            for match in matches:
                try:
                    start_ip = match[0]
                    end_ip = match[1] if match[1] else None

                    if "/" in raw:
                        # CIDR 표기법 - 그대로 사용
                        net = ipaddress.ip_network(raw.strip(), strict=False)
                        subnet_set.add(net)
                        print(f"📦 CIDR 대역 추가: {net}")
                        
                        # 개별 IP도 수집 (출력용)
                        for ip in net.hosts():
                            if is_valid_ip(ip):
                                ip_set.add(ip)

                    elif end_ip:
                        # IP 범위 - 범위를 서브넷으로 변환
                        ip_range = ipaddress.summarize_address_range(
                            ipaddress.ip_address(start_ip),
                            ipaddress.ip_address(end_ip)
                        )
                        for subnet in ip_range:
                            subnet_set.add(subnet)
                            print(f"📦 범위를 서브넷으로 변환: {start_ip}-{end_ip} → {subnet}")
                            
                            # 개별 IP도 수집 (출력용)
                            for ip in subnet.hosts():
                                if is_valid_ip(ip):
                                    ip_set.add(ip)

                    else:
                        # 단일 IP - C클래스 서브넷으로 확장
                        ip = ipaddress.ip_address(start_ip)
                        if is_valid_ip(ip):
                            if expand_to_subnet:
                                # C클래스 전체로 확장 (/24)
                                c_class = ipaddress.ip_network(f"{ip}/24", strict=False)
                                subnet_set.add(c_class)
                                print(f"📈 단일 IP를 C클래스 서브넷으로 확장: {ip} → {c_class}")
                                
                                # C클래스 전체 IP 추가
                                for host_ip in c_class.hosts():
                                    if is_valid_ip(host_ip):
                                        ip_set.add(host_ip)
                            else:
                                # 단일 IP만 추가 (/32)
                                single_ip_net = ipaddress.ip_network(f"{ip}/32")
                                subnet_set.add(single_ip_net)
                                ip_set.add(ip)
                                print(f"📍 단일 IP 추가: {ip}/32")
                        else:
                            print(f"⚠️ 제외된 IP (단일): {ip}")

                except Exception as e:
                    print(f"⚠️ 무시된 항목: {raw} ({e})")

    # 결과 저장
    ip_list = sorted(ip_set)
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # 1. 개별 IP 저장 (스캔용)
    with open(output_file, "w") as f:
        for ip in ip_list:
            f.write(str(ip) + "\n")

    # 2. CIDR 서브넷 저장 (관리용)
    cidr_file = Path(cidr_output_path)
    cidr_file.parent.mkdir(parents=True, exist_ok=True)
    
    if subnet_set:
        # 서브넷들을 최적화하여 중복 제거
        optimized_subnets = list(ipaddress.collapse_addresses(subnet_set))
        
        with open(cidr_file, "w") as f:
            for net in sorted(optimized_subnets):
                f.write(str(net) + "\n")
        
        print(f"✅ 추출된 IP 수: {len(ip_list)}개 → {output_path}")
        print(f"📦 최적화된 서브넷: {len(optimized_subnets)}개 → {cidr_output_path}")
        
        # 서브넷 정보 출력
        for net in sorted(optimized_subnets)[:5]:  # 처음 5개만 표시
            host_count = len(list(net.hosts())) if net.prefixlen < 31 else 1
            print(f"   🌐 {net} (호스트 {host_count}개)")
        
        if len(optimized_subnets) > 5:
            print(f"   ... 및 {len(optimized_subnets) - 5}개 추가 서브넷")
            
    else:
        # 빈 파일 생성
        with open(cidr_file, "w") as f:
            pass
        print(f"⚠️ 추출된 IP가 없습니다.")

    return len(ip_list)


def extract_subnets_only(file_path: str,
                        output_path: str = "data/ip_ranges/subnets.txt") -> int:
    """
    서브넷만 추출하는 함수 (개별 IP 생성 없이)
    """
    path = Path(file_path)
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"❌ 지원하지 않는 파일 형식입니다: {path.suffix}")

    if path.suffix.lower() == ".csv":
        df = pd.read_csv(file_path, dtype=str)
    else:
        df = pd.read_excel(file_path, dtype=str)

    subnet_set = set()

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
                        subnet_set.add(net)

                    elif end_ip:
                        # IP 범위
                        ip_range = ipaddress.summarize_address_range(
                            ipaddress.ip_address(start_ip),
                            ipaddress.ip_address(end_ip)
                        )
                        subnet_set.update(ip_range)

                    else:
                        # 단일 IP → C클래스 서브넷
                        ip = ipaddress.ip_address(start_ip)
                        if is_valid_ip(ip):
                            c_class = ipaddress.ip_network(f"{ip}/24", strict=False)
                            subnet_set.add(c_class)

                except Exception as e:
                    print(f"⚠️ 무시된 항목: {raw} ({e})")

    # 서브넷 최적화 및 저장
    if subnet_set:
        optimized_subnets = list(ipaddress.collapse_addresses(subnet_set))
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w") as f:
            for net in sorted(optimized_subnets):
                f.write(str(net) + "\n")
        
        print(f"✅ 추출된 서브넷: {len(optimized_subnets)}개 → {output_path}")
        return len(optimized_subnets)
    
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="📥 문서에서 IP 대역 추출기 (C클래스 자동 확장)")
    parser.add_argument("input_file", help="CSV 또는 Excel 파일 경로")
    parser.add_argument("-o", "--output", default="data/ip_ranges/ip_list.txt", help="IP 목록 저장 경로")
    parser.add_argument("-c", "--cidr", default="data/ip_ranges/ip_cidr.txt", help="CIDR 목록 저장 경로")
    parser.add_argument("--no-expand", action="store_true", help="단일 IP를 C클래스로 확장하지 않음")
    parser.add_argument("--subnets-only", action="store_true", help="서브넷만 추출 (개별 IP 생성 안함)")

    args = parser.parse_args()
    
    try:
        if args.subnets_only:
            extract_subnets_only(args.input_file, args.cidr)
        else:
            expand_subnet = not args.no_expand  # 기본값은 True (확장함)
            extract_ip_ranges(args.input_file, args.output, args.cidr, expand_subnet)
    except Exception as e:
        print(f"❌ 오류: {e}")