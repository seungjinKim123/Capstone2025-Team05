# backend/vuln_checker/core.py 개선안
# 기존 run_all_checks() 함수를 확장하여 파일 경로를 매개변수로 받을 수 있도록 수정

def run_all_checks(scan_parsed_file: str = "data/mmdb/scan_parsed.json"):
    """
    모든 취약점 검사 실행
    
    Args:
        scan_parsed_file: 분석할 스캔 파싱 파일 경로 (기본값: "data/mmdb/scan_parsed.json")
    
    Returns:
        dict: 취약점 분석 결과
    """
    import json
    from pathlib import Path
    from datetime import datetime
    
    try:
        # 1. 파일 존재 및 유효성 확인
        if not Path(scan_parsed_file).exists():
            print(f"❌ 스캔 파일을 찾을 수 없습니다: {scan_parsed_file}")
            return None
        
        file_size = Path(scan_parsed_file).stat().st_size
        if file_size == 0:
            print(f"⚠️  스캔 파일이 비어있습니다: {scan_parsed_file}")
            return {
                "scan_summary": {
                    "total_hosts": 0,
                    "total_vulnerabilities": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "info_count": 0
                },
                "vulnerabilities": [],
                "hosts": [],
                "status": "empty_scan_file",
                "timestamp": datetime.now().isoformat()
            }
        
        # 2. 스캔 데이터 로드
        with open(scan_parsed_file, 'r', encoding='utf-8') as f:
            scan_data = json.load(f)
        
        if not scan_data:
            print(f"⚠️  스캔 데이터가 비어있습니다")
            return {
                "scan_summary": {
                    "total_hosts": 0,
                    "total_vulnerabilities": 0
                },
                "vulnerabilities": [],
                "status": "empty_scan_data",
                "timestamp": datetime.now().isoformat()
            }
        
        # 3. 실제 취약점 분석 로직 실행
        # (기존의 분석 로직을 여기에 구현)
        
        # 예시 분석 결과 구조
        analysis_results = {
            "scan_summary": {
                "total_hosts": len(scan_data.get("hosts", [])) if isinstance(scan_data, dict) else 0,
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0
            },
            "vulnerabilities": [],
            "hosts": scan_data.get("hosts", []) if isinstance(scan_data, dict) else [],
            "recommendations": [
                "정기적인 보안 업데이트를 수행하세요.",
                "불필요한 서비스를 비활성화하세요.",
                "강력한 패스워드 정책을 적용하세요."
            ],
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
            "source_file": scan_parsed_file,
            "file_size": file_size
        }
        
        # 4. 호스트별 취약점 분석
        if isinstance(scan_data, dict) and "hosts" in scan_data:
            for host in scan_data["hosts"]:
                # 각 호스트의 서비스와 포트를 분석
                host_vulnerabilities = analyze_host_vulnerabilities(host)
                analysis_results["vulnerabilities"].extend(host_vulnerabilities)
        
        # 5. 취약점 카운트 업데이트
        update_vulnerability_counts(analysis_results)
        
        print(f"✅ 취약점 분석 완료: {len(analysis_results['vulnerabilities'])}개 취약점 발견")
        
        return analysis_results
        
    except json.JSONDecodeError as e:
        print(f"❌ JSON 파싱 오류: {e}")
        return {
            "scan_summary": {"total_hosts": 0, "total_vulnerabilities": 0},
            "vulnerabilities": [],
            "status": "json_parse_error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        print(f"❌ 취약점 분석 오류: {e}")
        import traceback
        traceback.print_exc()
        return {
            "scan_summary": {"total_hosts": 0, "total_vulnerabilities": 0},
            "vulnerabilities": [],
            "status": "analysis_error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


def analyze_host_vulnerabilities(host: dict) -> list:
    """
    개별 호스트의 취약점 분석
    
    Args:
        host: 호스트 정보 딕셔너리
    
    Returns:
        list: 발견된 취약점 목록
    """
    vulnerabilities = []
    
    # 예시: 개방된 포트 기반 취약점 분석
    if "ports" in host:
        for port in host["ports"]:
            port_num = port.get("port")
            service = port.get("service", "")
            version = port.get("version", "")
            
            # 일반적인 취약 서비스 체크
            if port_num == 21 and "ftp" in service.lower():
                vulnerabilities.append({
                    "host": host.get("ip", "unknown"),
                    "port": port_num,
                    "service": service,
                    "vulnerability": "FTP 서비스 노출",
                    "severity": "medium",
                    "description": "FTP 서비스가 외부에 노출되어 있습니다.",
                    "recommendation": "불필요한 FTP 서비스를 비활성화하거나 방화벽으로 보호하세요."
                })
            
            elif port_num == 23 and "telnet" in service.lower():
                vulnerabilities.append({
                    "host": host.get("ip", "unknown"),
                    "port": port_num,
                    "service": service,
                    "vulnerability": "Telnet 서비스 노출",
                    "severity": "high",
                    "description": "보안이 취약한 Telnet 서비스가 노출되어 있습니다.",
                    "recommendation": "Telnet 대신 SSH를 사용하세요."
                })
            
            elif port_num == 445 and "microsoft-ds" in service.lower():
                vulnerabilities.append({
                    "host": host.get("ip", "unknown"),
                    "port": port_num,
                    "service": service,
                    "vulnerability": "SMB 서비스 노출",
                    "severity": "medium",
                    "description": "SMB 서비스가 외부에 노출되어 있습니다.",
                    "recommendation": "SMB 서비스를 방화벽으로 보호하고 최신 버전으로 업데이트하세요."
                })
    
    return vulnerabilities


def update_vulnerability_counts(analysis_results: dict):
    """
    취약점 심각도별 카운트 업데이트
    
    Args:
        analysis_results: 분석 결과 딕셔너리
    """
    summary = analysis_results["scan_summary"]
    
    # 심각도별 카운트 초기화
    summary["critical_count"] = 0
    summary["high_count"] = 0
    summary["medium_count"] = 0
    summary["low_count"] = 0
    summary["info_count"] = 0
    
    # 취약점 심각도별 카운트
    for vuln in analysis_results["vulnerabilities"]:
        severity = vuln.get("severity", "info").lower()
        
        if severity == "critical":
            summary["critical_count"] += 1
        elif severity == "high":
            summary["high_count"] += 1
        elif severity == "medium":
            summary["medium_count"] += 1
        elif severity == "low":
            summary["low_count"] += 1
        else:
            summary["info_count"] += 1
    
    # 총 취약점 수 업데이트
    summary["total_vulnerabilities"] = len(analysis_results["vulnerabilities"])


# 기존 호환성을 위한 래퍼 함수
def run_all_checks_legacy():
    """기존 코드 호환성을 위한 래퍼 함수"""
    return run_all_checks("data/mmdb/scan_parsed.json")