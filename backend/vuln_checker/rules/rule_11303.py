import ipaddress
import re
from pathlib import Path

import pandas as pd

IP_REGEX = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

# 최초 입력 파일에서 IP 목록 추출 (최대 1회 캐싱)
_known_ips = None

def load_known_ips(file_path="data/input/network.csv") -> set:
    global _known_ips
    if _known_ips is not None:
        return _known_ips

    path = Path(file_path)
    if not path.exists():
        print(f"⚠️ 관리대장 파일 없음: {file_path}")
        _known_ips = set()
        return _known_ips

    if path.suffix == ".csv":
        df = pd.read_csv(path, dtype=str)
    else:
        df = pd.read_excel(path, dtype=str)

    ips = set()
    for col in df.columns:
        for cell in df[col].dropna():
            matches = IP_REGEX.findall(str(cell))
            ips.update(matches)

    _known_ips = set(str(ipaddress.ip_address(ip)) for ip in ips if is_valid_ip(ip))
    return _known_ips


def is_valid_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (
            ip_obj.is_loopback or
            ip_obj.is_multicast or
            ip_obj.is_reserved or
            ip_obj.is_unspecified or
            ip_obj.is_link_local
        )
    except:
        return False


def evaluate(ip: str, host_data: dict) -> list:
    known_ips = load_known_ips()
    return [f"{ip} 관리대장 누락됨"] if ip not in known_ips else []
