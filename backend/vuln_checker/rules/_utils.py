import re
import socket
from typing import Any, Dict, List


def contains_version_string(text: str) -> bool:
    """
    텍스트에서 버전 정보가 포함되어 있는지 확인
    """
    if not text:
        return False
    
    version_patterns = [
        r'\d+\.\d+\.\d+',  # x.x.x 형태
        r'\d+\.\d+',       # x.x 형태
        r'v\d+\.\d+',      # vx.x 형태
        r'version\s+\d+',  # version x 형태
        r'release\s+\d+',  # release x 형태
    ]
    
    for pattern in version_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def test_port_connection(ip: str, port: int, timeout: int = 3) -> bool:
    """
    특정 포트로의 연결 테스트
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def get_banner(ip: str, port: int, timeout: int = 3) -> str:
    """
    서비스 배너 정보 획득
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return ""


def check_weak_passwords(ip: str, port: int, service: str, accounts: List[Dict[str, str]]) -> List[str]:
    """
    약한 패스워드 계정 확인 (공통 함수)
    """
    found_accounts = []
    
    for account in accounts:
        username = account.get("username", "")
        password = account.get("password", "")
        
        if service == "ssh":
            if test_ssh_login(ip, port, username, password):
                found_accounts.append(f"{username}/{password}")
        elif service == "telnet":
            if test_telnet_login(ip, port, username, password):
                found_accounts.append(f"{username}/{password}")
        elif service == "mysql":
            if test_mysql_login(ip, port, username, password):
                found_accounts.append(f"{username}/{password}")
                
    return found_accounts


def test_ssh_login(ip: str, port: int, username: str, password: str, timeout: int = 3) -> bool:
    """
    SSH 로그인 테스트
    """
    try:
        import paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=timeout)
        ssh.close()
        return True
    except:
        return False


def test_telnet_login(ip: str, port: int, username: str, password: str, timeout: int = 3) -> bool:
    """
    Telnet 로그인 테스트
    """
    try:
        import telnetlib
        tn = telnetlib.Telnet(ip, port, timeout)
        tn.read_until(b"login: ")
        tn.write(username.encode() + b"\n")
        tn.read_until(b"Password: ")
        tn.write(password.encode() + b"\n")
        result = tn.read_some()
        tn.close()
        return b"$" in result or b"#" in result
    except:
        return False


def test_mysql_login(ip: str, port: int, username: str, password: str, timeout: int = 3) -> bool:
    """
    MySQL 로그인 테스트
    """
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connection_timeout=timeout
        )
        conn.close()
        return True
    except:
        return False


def extract_service_info(port_info: Dict[str, Any]) -> Dict[str, str]:
    """
    포트 정보에서 서비스 관련 정보 추출
    """
    return {
        'service': port_info.get('service', ''),
        'product': port_info.get('product', ''),
        'version': port_info.get('version', ''),
        'state': port_info.get('state', ''),
        'protocol': port_info.get('protocol', '')
    }


def is_dangerous_service(service: str, port: int) -> bool:
    """
    위험한 서비스 판별
    """
    dangerous_services = {
        'telnet': [23],
        'ftp': [21],
        'rlogin': [513],
        'rsh': [514],
        'finger': [79],
        'tftp': [69],
        'snmp': [161, 162],
        'netbios': [137, 138, 139],
        'ldap': [389],
        'nfs': [2049]
    }
    
    if service in dangerous_services:
        return port in dangerous_services[service]
    return False