#!/usr/bin/env python3
"""
취약점 분석 핵심 모듈 - 실제 분석 로직 구현
"""

import json
from pathlib import Path
from datetime import datetime
import re


def run_all_checks(scan_parsed_file: str = "data/mmdb/scan_parsed.json"):
    """
    모든 취약점 검사 실행
    
    Args:
        scan_parsed_file: 분석할 스캔 파싱 파일 경로
    
    Returns:
        dict: 취약점 분석 결과
    """
    try:
        # 1. 파일 존재 및 유효성 확인
        if not Path(scan_parsed_file).exists():
            print(f"❌ 스캔 파일을 찾을 수 없습니다: {scan_parsed_file}")
            return None
        
        file_size = Path(scan_parsed_file).stat().st_size
        if file_size == 0:
            print(f"⚠️  스캔 파일이 비어있습니다: {scan_parsed_file}")
            return create_empty_result()
        
        # 2. 스캔 데이터 로드
        with open(scan_parsed_file, 'r', encoding='utf-8') as f:
            scan_data = json.load(f)
        
        if not scan_data:
            print(f"⚠️  스캔 데이터가 비어있습니다")
            return create_empty_result()
        
        print(f"📊 스캔 데이터 로드 완료: {len(scan_data)}개 호스트")
        
        # 3. 평가 데이터베이스 로드
        eval_db = load_eval_db()
        
        # 4. 호스트별 취약점 분석
        analysis_results = {
            "scan_summary": {
                "total_hosts": len(scan_data),
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0
            },
            "vulnerabilities": [],
            "hosts": [],
            "recommendations": [],
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
            "source_file": scan_parsed_file,
            "file_size": file_size
        }
        
        # 각 호스트 분석
        for ip, host_data in scan_data.items():
            print(f"🔍 분석 중: {ip}")
            host_result = analyze_single_host(ip, host_data, eval_db)
            if host_result["vulnerabilities"]:
                analysis_results["hosts"].append(host_result)
                analysis_results["vulnerabilities"].extend(host_result["vulnerabilities"])
        
        # 5. 취약점 카운트 및 권장사항 업데이트
        update_vulnerability_counts(analysis_results)
        add_recommendations(analysis_results)
        
        print(f"✅ 취약점 분석 완료: {len(analysis_results['vulnerabilities'])}개 취약점 발견")
        
        return analysis_results
        
    except json.JSONDecodeError as e:
        print(f"❌ JSON 파싱 오류: {e}")
        return create_error_result("json_parse_error", str(e))
    except Exception as e:
        print(f"❌ 취약점 분석 오류: {e}")
        import traceback
        traceback.print_exc()
        return create_error_result("analysis_error", str(e))


def load_eval_db():
    """평가 데이터베이스 로드"""
    eval_db_path = "data/db/eval_db.json"
    if Path(eval_db_path).exists():
        with open(eval_db_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    else:
        print(f"⚠️  평가 DB 파일 없음: {eval_db_path}")
        return {}


def analyze_single_host(ip: str, host_data: dict, eval_db: dict) -> dict:
    """단일 호스트 분석"""
    host_result = {
        "ip": ip,
        "hostname": host_data.get("hostname"),
        "os": host_data.get("os"),
        "ports_count": len(host_data.get("ports", {})),
        "vulnerabilities": []
    }
    
    ports = host_data.get("ports", {})
    
    # 각 포트별 분석
    for port, port_info in ports.items():
        service = port_info.get("service", "")
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        scripts = port_info.get("scripts", {})
        
        print(f"  🔍 포트 {port}: {service} {product} {version}")
        
        # 취약점 검사 실행
        port_vulns = []
        
        # 20501: 접근통제 미흡
        vulns_20501 = check_access_control(ip, port, port_info)
        port_vulns.extend(vulns_20501)
        
        # 20503: 취약한 서비스
        vulns_20503 = check_insecure_services(ip, port, port_info)
        port_vulns.extend(vulns_20503)
        
        # 30802: 버전 정보 노출
        vulns_30802 = check_version_disclosure(ip, port, port_info)
        port_vulns.extend(vulns_30802)
        
        # CVE 기반 취약점 (간단 버전)
        vulns_cve = check_known_cves(ip, port, port_info)
        port_vulns.extend(vulns_cve)
        
        host_result["vulnerabilities"].extend(port_vulns)
    
    return host_result


def check_access_control(ip: str, port: str, port_info: dict) -> list:
    """20501: 접근통제 미흡 검사"""
    vulnerabilities = []
    service = port_info.get("service", "")
    scripts = port_info.get("scripts", {})
    
    # FTP 익명 접속 체크
    if service == "ftp":
        ftp_anon = scripts.get("ftp-anon", "")
        if "Anonymous FTP login allowed" in ftp_anon:
            vulnerabilities.append({
                "rule_id": "20501",
                "rule_name": "접근통제 미흡",
                "host": ip,
                "port": port,
                "service": service,
                "severity": "high",
                "description": "FTP 서비스에서 익명 접속이 허용되어 있습니다.",
                "details": ftp_anon.strip(),
                "recommendation": "FTP 익명 접속을 비활성화하고 인증된 사용자만 접근할 수 있도록 설정하세요."
            })
    
    # Telnet 서비스 체크
    elif service == "telnet":
        vulnerabilities.append({
            "rule_id": "20501",
            "rule_name": "접근통제 미흡",
            "host": ip,
            "port": port,
            "service": service,
            "severity": "high",
            "description": "보안이 취약한 Telnet 서비스가 실행 중입니다.",
            "details": "Telnet은 암호화되지 않은 프로토콜입니다.",
            "recommendation": "Telnet을 비활성화하고 SSH를 사용하세요."
        })
    
    return vulnerabilities


def check_insecure_services(ip: str, port: str, port_info: dict) -> list:
    """20503: 취약한 서비스 검사"""
    vulnerabilities = []
    service = port_info.get("service", "")
    port_num = int(port)
    
    # 기본 포트의 취약한 서비스들
    insecure_services = {
        21: "ftp",
        23: "telnet", 
        513: "rlogin",
        79: "finger",
        7: "echo",
        9: "discard",
        69: "tftp"
    }
    
    if port_num in insecure_services and service == insecure_services[port_num]:
        severity = "high" if service in ["telnet", "rlogin"] else "medium"
        vulnerabilities.append({
            "rule_id": "20503",
            "rule_name": "기본포트 사용 및 취약한 서비스 운용",
            "host": ip,
            "port": port,
            "service": service,
            "severity": severity,
            "description": f"보안이 취약한 {service} 서비스가 기본 포트 {port}에서 실행 중입니다.",
            "details": f"{service} 서비스는 보안상 취약합니다.",
            "recommendation": f"{service} 서비스를 비활성화하고 보안 대안을 사용하세요."
        })
    
    return vulnerabilities


def check_version_disclosure(ip: str, port: str, port_info: dict) -> list:
    """30802: 버전 정보 노출 검사"""
    vulnerabilities = []
    service = port_info.get("service", "")
    product = port_info.get("product", "")
    version = port_info.get("version", "")
    
    if version and version.strip():
        vulnerabilities.append({
            "rule_id": "30802", 
            "rule_name": "버전정보 노출",
            "host": ip,
            "port": port,
            "service": service,
            "severity": "low",
            "description": f"{service} 서비스에서 버전 정보가 노출되고 있습니다.",
            "details": f"{product} {version}",
            "recommendation": "서비스 배너에서 버전 정보를 숨기도록 설정하세요."
        })
    
    return vulnerabilities


def check_known_cves(ip: str, port: str, port_info: dict) -> list:
    """알려진 CVE 취약점 검사"""
    vulnerabilities = []
    product = port_info.get("product", "")
    version = port_info.get("version", "")
    
    # 간단한 CVE 체크 (실제로는 vuln_db.json 사용)
    known_vulns = {
        "vsftpd": {
            "3.0.5": [],  # 이 버전은 안전
            "3.0.4": ["CVE-2021-3618"],
            "2.3.4": ["CVE-2011-2523"]
        },
        "OpenSSH": {
            "8.9": [],  # 이 버전은 비교적 안전
            "7.4": ["CVE-2016-10009", "CVE-2016-10012"]
        }
    }
    
    if product and version:
        for vuln_product, vuln_data in known_vulns.items():
            if vuln_product.lower() in product.lower():
                cves = vuln_data.get(version, [])
                for cve in cves:
                    vulnerabilities.append({
                        "rule_id": "CVE",
                        "rule_name": "알려진 보안 취약점",
                        "host": ip,
                        "port": port,
                        "service": port_info.get("service", ""),
                        "severity": "high",
                        "description": f"{product} {version}에서 알려진 보안 취약점이 발견되었습니다.",
                        "details": f"CVE: {cve}",
                        "recommendation": f"{product}를 최신 버전으로 업데이트하세요."
                    })
    
    return vulnerabilities


def update_vulnerability_counts(analysis_results: dict):
    """취약점 심각도별 카운트 업데이트"""
    summary = analysis_results["scan_summary"]
    
    # 심각도별 카운트 초기화
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    # 취약점 심각도별 카운트
    for vuln in analysis_results["vulnerabilities"]:
        severity = vuln.get("severity", "info").lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["info"] += 1
    
    # 결과 업데이트
    summary.update({
        "critical_count": counts["critical"],
        "high_count": counts["high"], 
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "info_count": counts["info"],
        "total_vulnerabilities": len(analysis_results["vulnerabilities"])
    })


def add_recommendations(analysis_results: dict):
    """권장사항 추가"""
    vulns = analysis_results["vulnerabilities"]
    recommendations = set()
    
    # 발견된 취약점에 따른 권장사항
    for vuln in vulns:
        rule_id = vuln.get("rule_id", "")
        
        if rule_id == "20501":
            recommendations.add("익명 접속을 비활성화하고 강력한 인증 정책을 적용하세요.")
            recommendations.add("기본 계정의 패스워드를 변경하거나 비활성화하세요.")
        elif rule_id == "20503":
            recommendations.add("보안이 취약한 서비스를 비활성화하고 보안 대안을 사용하세요.")
            recommendations.add("불필요한 네트워크 서비스를 중지하세요.")
        elif rule_id == "30802":
            recommendations.add("서비스 배너에서 버전 정보를 숨기도록 설정하세요.")
        elif rule_id == "CVE":
            recommendations.add("시스템과 애플리케이션을 최신 버전으로 업데이트하세요.")
    
    # 일반적인 권장사항
    if not recommendations:
        recommendations.add("정기적인 보안 점검을 수행하세요.")
        recommendations.add("네트워크 접근 제어 정책을 검토하세요.")
    
    analysis_results["recommendations"] = list(recommendations)


def create_empty_result():
    """빈 결과 생성"""
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
        "recommendations": ["스캔 결과를 확인하여 취약점을 분석하세요."],
        "status": "empty_scan_data",
        "timestamp": datetime.now().isoformat()
    }


def create_error_result(status: str, error_msg: str):
    """오류 결과 생성"""
    return {
        "scan_summary": {"total_hosts": 0, "total_vulnerabilities": 0},
        "vulnerabilities": [],
        "hosts": [],
        "recommendations": ["시스템 설정을 확인하고 다시 시도하세요."],
        "status": status,
        "error": error_msg,
        "timestamp": datetime.now().isoformat()
    }


# 기존 호환성을 위한 래퍼 함수
def run_all_checks_legacy():
    """기존 코드 호환성을 위한 래퍼 함수"""
    return run_all_checks("data/mmdb/scan_parsed.json")


if __name__ == "__main__":
    # 테스트 실행
    result = run_all_checks()
    if result:
        print(f"\n📊 분석 결과:")
        print(f"   총 호스트: {result['scan_summary']['total_hosts']}")
        print(f"   총 취약점: {result['scan_summary']['total_vulnerabilities']}")
        print(f"   상위 위험: {result['scan_summary']['high_count']}")
        print(f"   중간 위험: {result['scan_summary']['medium_count']}")
        print(f"   낮은 위험: {result['scan_summary']['low_count']}")