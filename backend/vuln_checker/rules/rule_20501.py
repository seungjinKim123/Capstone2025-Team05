import socket
from ftplib import FTP

# 선택적으로 psycopg2 설치 필요
try:
    import psycopg2
except ImportError:
    psycopg2 = None

def evaluate(ip: str, host_data: dict) -> list:
    violations = []

    ports = host_data.get("ports", {})

    for port, port_info in ports.items():
        service = port_info.get("service")
        port_num = int(port)

        # ✅ 익명 FTP 접속 확인
        if service == "ftp":
            if test_ftp_anonymous(ip, port_num):
                violations.append("익명 FTP 접속 허용됨")

            # 기본 계정 조합 확인
            for account in [
                {"username": "ftp", "password": "ftp"},
                {"username": "anonymous", "password": ""},
            ]:
                if test_ftp_login(ip, port_num, account["username"], account["password"]):
                    violations.append(f"FTP 기본 계정 사용됨: {account['username']}/{account['password']}")
                    
        # ✅ TELNET 확인
        elif service == "telnet":
            violations.append(f"TELNET 서비스 사용")

        # ✅ PostgreSQL 기본 계정 확인
        elif service == "postgresql" and psycopg2:
            for account in [
                {"username": "postgres", "password": "postgres"},
                {"username": "postgres", "password": "1234"},
                {"username": "admin", "password": "admin"},
            ]:
                if test_postgres_login(ip, port_num, account["username"], account["password"]):
                    violations.append(f"PostgreSQL 기본 계정 사용됨: {account['username']}/{account['password']}")

    return violations


def test_ftp_anonymous(ip, port=21, timeout=3) -> bool:
    try:
        ftp = FTP()
        ftp.connect(ip, port, timeout=timeout)
        ftp.login()  # anonymous by default
        ftp.quit()
        return True
    except:
        return False


def test_ftp_login(ip, port, username, password, timeout=3) -> bool:
    try:
        ftp = FTP()
        ftp.connect(ip, port, timeout=timeout)
        ftp.login(user=username, passwd=password)
        ftp.quit()
        return True
    except:
        return False


def test_postgres_login(ip, port, username, password, timeout=3) -> bool:
    try:
        if psycopg2 is None:
            return False
        conn = psycopg2.connect(host=ip, port=port, user=username, password=password, connect_timeout=timeout)
        conn.close()
        return True
    except:
        return False
