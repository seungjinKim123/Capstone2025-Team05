import socket
import struct


def evaluate(ip: str, host_data: dict) -> list:
    violations = []
    ports = host_data.get("ports", {})

    for port, port_info in ports.items():
        service = port_info.get("service")
        port_num = int(port)

        if service == "snmp" and port_num in [161, 162]:
            violations.append(f"SNMP 서비스 운영 중 - 보안 설정 검토 필요")
            
            # SNMP 기본 커뮤니티 스트링 테스트
            if test_snmp_community(ip, port_num, "public"):
                violations.append("SNMP 기본 커뮤니티 스트링 'public' 사용 중")
            
            if test_snmp_community(ip, port_num, "private"):
                violations.append("SNMP 기본 커뮤니티 스트링 'private' 사용 중")
            
            # 추가 일반적인 커뮤니티 스트링들
            common_communities = ["admin", "manager", "router", "switch", "default"]
            for community in common_communities:
                if test_snmp_community(ip, port_num, community):
                    violations.append(f"SNMP 약한 커뮤니티 스트링 '{community}' 사용 중")

    return violations


def test_snmp_community(ip: str, port: int, community: str, timeout: int = 3) -> bool:
    """
    SNMP 커뮤니티 스트링 테스트
    """
    try:
        # SNMP GET 요청 패킷 생성 (간단한 버전)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # 기본적인 SNMP GET 요청 (sysDescr.0)
        # 실제로는 pysnmp 라이브러리를 사용하는 것이 좋음
        oid = "1.3.6.1.2.1.1.1.0"  # sysDescr
        
        # 간단한 SNMP 패킷 구성 (실제 구현은 더 복잡함)
        sock.sendto(b"\x30\x1e\x02\x01\x00\x04" + bytes([len(community)]) + 
                   community.encode() + b"\xa0\x11\x02\x01\x01\x02\x01\x00\x30\x09\x30\x07\x06\x03\x2b\x06\x01\x05\x00", 
                   (ip, port))
        
        response = sock.recv(1024)
        sock.close()
        
        # 응답이 있으면 커뮤니티 스트링이 유효함
        return len(response) > 0
        
    except:
        return False