#!/usr/bin/env python3
"""
취약점 분석 핵심 모듈 - 실제 분석 로직 구현 (vuln_checker 통합)
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# vuln_checker 모듈 import
try:
    from backend.vuln_checker.database_loader import load_all
    from backend.vuln_checker.cve_checker import check_vulnerabilities
    from backend.vuln_checker.evaluator import evaluate_policies
except ImportError:
    print("⚠️  vuln_checker 모듈을 찾을 수 없습니다. 기본 로직을 사용합니다.")
    load_all = None
    check_vulnerabilities = None
    evaluate_policies = None


def run_all_checks(scan_parsed_file: str = "data/mmdb/scan_parsed.json"):
    """
    모든 취약점 검사 실행 (vuln_checker 모듈 통합)
    
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
        
        # 2. 모든 데이터베이스 로드 (vuln_checker 활용)
        print("📊 데이터베이스 로드 중...")
        
        if load_all:
            scan_data, vuln_db, eval_db = load_all(
                scan_path=scan_parsed_file,
                vuln_path="data/db/vuln_db.json",
                eval_path="data/db/eval_db.json"
            )
        else:
            # 폴백: 직접 로드
            scan_data, vuln_db, eval_db = load_databases_fallback(scan_parsed_file)
        
        if not scan_data:
            print(f"⚠️  스캔 데이터가 비어있습니다")
            return create_empty_result()
        
        print(f"📊 스캔 데이터 로드 완료: {len(scan_data)}개 호스트")
        
        # 3. 취약점 분석 결과 초기화
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
        
        # 4. CVE 기반 취약점 검사
        print("🔍 CVE 기반 취약점 검사 중...")
        cve_results = {}
        if check_vulnerabilities and vuln_db:
            cve_results = check_vulnerabilities(scan_data, vuln_db)
            print(f"   📋 CVE 검사 완료: {len(cve_results)}개 호스트에서 취약점 발견")
        
        # 5. 보안 정책 평가 (11303, 30301 등 포함)
        print("🔍 보안 정책 평가 중...")
        policy_results = {}
        if evaluate_policies and eval_db:
            policy_results = evaluate_policies(scan_data, eval_db)
            print(f"   📋 정책 평가 완료: {len(policy_results)}개 호스트에서 정책 위반 발견")
        
        # 6. 호스트별 종합 분석 결과 생성
        print("📊 종합 결과 생성 중...")
        for ip, host_data in scan_data.items():
            print(f"  🔍 분석 중: {ip}")
            
            host_result = {
                "ip": ip,
                "hostname": host_data.get("hostname"),
                "os": host_data.get("os"),
                "ports_count": len(host_data.get("ports", {})),
                "vulnerabilities": []
            }
            
            # CVE 기반 취약점 추가
            if ip in cve_results:
                cve_vulns = convert_cve_results_to_vulnerabilities(ip, cve_results[ip], host_data)
                host_result["vulnerabilities"].extend(cve_vulns)
            
            # 정책 위반 기반 취약점 추가
            if ip in policy_results:
                policy_vulns = convert_policy_results_to_vulnerabilities(ip, policy_results[ip], host_data)
                host_result["vulnerabilities"].extend(policy_vulns)
            
            # 기본 취약점 검사 추가 (기존 로직 유지)
            basic_vulns = analyze_host_basic_vulnerabilities(ip, host_data)
            host_result["vulnerabilities"].extend(basic_vulns)
            
            # 취약점이 있는 호스트만 결과에 포함
            if host_result["vulnerabilities"]:
                analysis_results["hosts"].append(host_result)
                analysis_results["vulnerabilities"].extend(host_result["vulnerabilities"])
        
        # 7. 취약점 카운트 및 권장사항 업데이트
        update_vulnerability_counts(analysis_results)
        add_comprehensive_recommendations(analysis_results)
        
        print(f"✅ 취약점 분석 완료: {len(analysis_results['vulnerabilities'])}개 취약점 발견")
        
        return analysis_results
        
    except Exception as e:
        print(f"❌ 취약점 분석 오류: {e}")
        import traceback
        traceback.print_exc()
        return create_error_result("analysis_error", str(e))


def load_databases_fallback(scan_parsed_file: str):
    """데이터베이스 직접 로드 (폴백)"""
    print("   📁 직접 로드 모드 사용")
    
    # 스캔 데이터 로드
    with open(scan_parsed_file, 'r', encoding='utf-8') as f:
        scan_data = json.load(f)
    
    # vuln_db 로드
    vuln_db = {}
    vuln_db_path = "data/db/vuln_db.json"
    if Path(vuln_db_path).exists():
        with open(vuln_db_path, 'r', encoding='utf-8') as f:
            vuln_db = json.load(f)
    
    # eval_db 로드
    eval_db = {}
    eval_db_path = "data/db/eval_db.json"
    if Path(eval_db_path).exists():
        with open(eval_db_path, 'r', encoding='utf-8') as f:
            eval_db = json.load(f)
    
    return scan_data, vuln_db, eval_db


def convert_cve_results_to_vulnerabilities(ip: str, cve_data: dict, host_data: dict) -> list:
    """CVE 검사 결과를 취약점 형식으로 변환"""
    vulnerabilities = []
    
    for port, port_cve_data in cve_data.items():
        product = port_cve_data.get("product", "")
        cves = port_cve_data.get("cves", [])
        
        port_info = host_data.get("ports", {}).get(port, {})
        service = port_info.get("service", "unknown")
        
        for cve in cves:
            severity = determine_cve_severity(cve)
            vulnerabilities.append({
                "rule_id": cve,
                "rule_name": "알려진 보안 취약점 (CVE)",
                "host": ip,
                "port": port,
                "service": service,
                "severity": severity,
                "description": f"{product}에서 알려진 보안 취약점이 발견되었습니다.",
                "details": f"CVE: {cve}",
                "recommendation": f"{product}를 최신 버전으로 업데이트하세요."
            })
    
    return vulnerabilities


def convert_policy_results_to_vulnerabilities(ip: str, policy_data: dict, host_data: dict) -> list:
    """정책 평가 결과를 취약점 형식으로 변환"""
    vulnerabilities = []
    
    for rule_id, rule_data in policy_data.items():
        rule_name = rule_data.get("name", f"규칙 {rule_id}")
        rule_desc = rule_data.get("description", "")
        violations = rule_data.get("violations", [])
        
        if violations:
            # 규칙별 심각도 매핑
            severity = determine_rule_severity(rule_id)
            
            # 포트 정보 추출 (가능한 경우)
            port = "N/A"
            service = "system"
            
            # violations에서 포트 정보 파싱 시도
            for violation in violations:
                if "포트" in violation:
                    import re
                    port_match = re.search(r'포트\s+(\d+)', violation)
                    if port_match:
                        port = port_match.group(1)
                        port_info = host_data.get("ports", {}).get(port, {})
                        service = port_info.get("service", "unknown")
                        break
            
            vulnerabilities.append({
                "rule_id": rule_id,
                "rule_name": rule_name,
                "host": ip,
                "port": port,
                "service": service,
                "severity": severity,
                "description": rule_desc,
                "details": "; ".join(violations),
                "recommendation": get_rule_recommendation(rule_id)
            })
    
    return vulnerabilities


def analyze_host_basic_vulnerabilities(ip: str, host_data: dict) -> list:
    """기본 취약점 검사 (기존 로직 유지)"""
    vulnerabilities = []
    ports = host_data.get("ports", {})
    
    for port, port_info in ports.items():
        service = port_info.get("service", "")
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        scripts = port_info.get("scripts", {})
        
        # 접근통제 미흡 (20501)
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
        
        # 취약한 서비스 (20503)
        insecure_services = {
            21: "ftp", 23: "telnet", 513: "rlogin",
            79: "finger", 7: "echo", 9: "discard", 69: "tftp"
        }
        
        port_num = int(port)
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
        
        # 버전 정보 노출 (30802)
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


def determine_cve_severity(cve: str) -> str:
    """CVE 심각도 판정 - 모든 CVE를 Critical로 설정"""
    return "critical"


def determine_rule_severity(rule_id: str) -> str:
    """규칙별 심각도 매핑"""
    severity_map = {
        # 접근통제 관련 - 높은 위험
        "20501": "high",  # 접근통제 미흡
        "20502": "high",  # SSH 약한 인증
        "20503": "high",  # 취약한 서비스
        
        # 관리 관련 - 중간 위험
        "11303": "medium",  # 관리대장 누락
        "30301": "medium",  # 네트워크 관리대장
        "30501": "medium",  # 불필요한 서비스
        "30601": "medium",  # SNMP 보안
        "40101": "high",   # 패치 관리
        
        # 정보노출 관련 - 낮은 위험
        "30802": "low",    # 버전정보 노출
        "30701": "medium", # 웹 서버 보안
    }
    
    return severity_map.get(rule_id, "medium")


def get_rule_recommendation(rule_id: str) -> str:
    """규칙별 권장사항"""
    recommendations = {
        "11303": "모든 자산과 서비스에 대해 관리대장을 작성하고 주기적으로 검토하세요.",
        "30301": "물리적/논리적 연결 장비의 MAC 주소를 식별하고 자산 등록을 철저히 하세요.",
        "20501": "서비스 접근 시 인증체계를 적용하고 기본 계정 및 익명 접근을 제한하세요.",
        "20502": "SSH 루트 로그인을 비활성화하고 키 기반 인증을 사용하세요.",
        "20503": "보안성이 낮은 서비스를 사용하지 않거나, VPN 내에서 사용하며 SSH 등 보안 대체 수단을 사용하세요.",
        "30501": "업무에 필요하지 않은 서비스는 중지하고 필요한 서비스만 운영하세요.",
        "30601": "SNMP 커뮤니티 스트링을 변경하고 읽기 전용으로 설정하세요.",
        "30701": "웹 서버 보안 설정을 강화하고 불필요한 기능을 비활성화하세요.",
        "30802": "서비스 배너, 오류 메시지 등을 통해 버전 정보가 노출되지 않도록 설정하세요.",
        "40101": "정기적인 보안 패치 적용 및 패치 관리 정책을 수립하세요."
    }
    
    return recommendations.get(rule_id, "해당 취약점에 대한 보안 조치를 수행하세요.")


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


def add_comprehensive_recommendations(analysis_results: dict):
    """종합 권장사항 추가"""
    vulns = analysis_results["vulnerabilities"]
    recommendations = set()
    
    # 발견된 취약점 유형별 권장사항
    rule_types = set(vuln.get("rule_id", "")[:3] for vuln in vulns)  # 첫 3자리로 분류
    
    for vuln in vulns:
        rule_id = vuln.get("rule_id", "")
        
        # CVE 관련
        if rule_id.startswith("CVE"):
            recommendations.add("시스템과 애플리케이션을 최신 버전으로 업데이트하세요.")
            recommendations.add("정기적인 보안 패치 적용 정책을 수립하세요.")
        
        # 접근통제 관련 (205xx)
        elif rule_id.startswith("205"):
            recommendations.add("익명 접속을 비활성화하고 강력한 인증 정책을 적용하세요.")
            recommendations.add("기본 계정의 패스워드를 변경하거나 비활성화하세요.")
            recommendations.add("보안이 취약한 서비스를 비활성화하고 보안 대안을 사용하세요.")
        
        # 서비스 관리 관련 (305xx)
        elif rule_id.startswith("305"):
            recommendations.add("불필요한 네트워크 서비스를 중지하세요.")
        
        # 정보노출 관련 (308xx)
        elif rule_id.startswith("308"):
            recommendations.add("서비스 배너에서 버전 정보를 숨기도록 설정하세요.")
        
        # 관리대장 관련 (113xx, 303xx)
        elif rule_id.startswith("113") or rule_id.startswith("303"):
            recommendations.add("자산 관리대장을 작성하고 정기적으로 업데이트하세요.")
    
    # 일반적인 권장사항
    if recommendations:
        recommendations.add("정기적인 보안 점검을 수행하세요.")
        recommendations.add("네트워크 접근 제어 정책을 검토하세요.")
        recommendations.add("보안 모니터링 시스템을 구축하고 운영하세요.")
    else:
        recommendations.add("현재 시스템이 안전하게 설정되어 있습니다.")
        recommendations.add("지속적인 보안 모니터링을 유지하세요.")
    
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
        "scan_summary": {"total_hosts": 0, "total_vulnerabilities": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0},
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
        print(f"   심각 위험: {result['scan_summary']['critical_count']}")
        print(f"   높은 위험: {result['scan_summary']['high_count']}")
        print(f"   중간 위험: {result['scan_summary']['medium_count']}")
        print(f"   낮은 위험: {result['scan_summary']['low_count']}")
        
        if result['vulnerabilities']:
            print(f"\n🔍 발견된 취약점:")
            for vuln in result['vulnerabilities'][:5]:  # 처음 5개만 표시
                print(f"   - [{vuln['rule_id']}] {vuln['rule_name']} ({vuln['severity']})")