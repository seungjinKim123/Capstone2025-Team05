import json
import os
import shutil  # 누락된 import 추가
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Template


def generate_enhanced_html_report(
    results_path: str, 
    eval_db_path: str,
    output_path: str = "data/reports/govscan_report.html",
    template_path: str = None,
    scan_info: Dict[str, Any] = None
) -> str:
    """
    강화된 HTML 보고서 생성
    """
    if template_path is None:
        template_path = Path(__file__).parent / "template" / "enhanced_report_template.html"

    # 데이터 로드
    with open(results_path, encoding="utf-8") as f:
        results = json.load(f)

    with open(eval_db_path, encoding="utf-8") as f:
        eval_db = json.load(f)

    # 보고서 메타데이터
    report_metadata = {
        "report_date": datetime.now().strftime("%Y년 %m월 %d일 %H시 %M분"),
        "scan_range": scan_info.get("ip_range", "전체 네트워크") if scan_info else "전체 네트워크",
        "total_hosts": 0,
        "critical_issues": 0,
        "high_issues": 0,
        "medium_issues": 0,
        "total_cves": 0
    }

    # 보고서 데이터 처리
    report_rows = []
    all_cves = set()
    
    for ip, policies in results.get("policy_violations", {}).items():
        # CVE 정보 수집
        cves = []
        if ip in results.get("vulnerabilities", {}):
            for vuln_info in results["vulnerabilities"][ip].values():
                cves.extend(vuln_info.get("cves", []))
        
        all_cves.update(cves)
        cve_summary = ", ".join(sorted(set(cves)))

        # 지적사항 및 관련 정보 수집
        findings = []
        mitigations = []
        check_scripts = []
        checklists = []
        
        severity_score = 0
        
        for code, info in policies.items():
            rule_info = eval_db.get(code, {})
            
            # 지적사항
            findings.append(f"[{code}] {info['name']}")
            
            # 조치방법
            mitigation = rule_info.get("general_mitigation", "")
            if mitigation:
                mitigations.append(f"<strong>[{code}]</strong> {mitigation}")
            
            # 점검 스크립트 정보
            script_name = rule_info.get("check_script", "")
            if script_name:
                check_scripts.append({
                    "name": f"{code} 점검 스크립트",
                    "filename": script_name,
                    "description": rule_info.get("name", "")
                })
            
            # 체크리스트
            checklist_items = rule_info.get("checklist_items", [])
            checklists.extend([f"[{code}] {item}" for item in checklist_items])
            
            # 심각도 계산
            severity_score += calculate_severity_score(code, info)

        # 전체 심각도 판정
        if severity_score >= 15:
            severity = "critical"
            severity_text = "심각"
            report_metadata["critical_issues"] += 1
        elif severity_score >= 10:
            severity = "high" 
            severity_text = "높음"
            report_metadata["high_issues"] += 1
        else:
            severity = "medium"
            severity_text = "보통"
            report_metadata["medium_issues"] += 1

        report_rows.append({
            "host": ip,
            "role": get_host_role(ip),  # IP로부터 역할 추정
            "issues": findings,
            "cves": cve_summary,
            "mitigation": "<br><br>".join(mitigations),
            "check_scripts": check_scripts,
            "checklists": checklists,
            "severity": severity,
            "severity_text": severity_text
        })

    # 메타데이터 완성
    report_metadata["total_hosts"] = len(report_rows)
    report_metadata["total_cves"] = len(all_cves)

    # 템플릿 렌더링
    with open(template_path, encoding="utf-8") as tpl:
        template = Template(tpl.read())

    html = template.render(
        rows=report_rows,
        **report_metadata
    )

    # 출력 경로 생성 및 저장
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html, encoding="utf-8")

    print(f"✅ 강화된 HTML 보고서 생성 완료 → {output_path}")
    return str(output_file.absolute())


def calculate_severity_score(rule_code: str, violation_info: Dict[str, Any]) -> int:
    """
    위반 사항의 심각도 점수 계산
    """
    severity_map = {
        # 접근통제 관련 - 높은 위험
        "20501": 5,  # 접근통제 미흡
        "20502": 4,  # SSH 약한 인증
        "20503": 4,  # 취약한 서비스
        
        # 정보노출 관련 - 중간 위험
        "30802": 3,  # 버전정보 노출
        "30701": 3,  # 웹 서버 보안
        
        # 관리 관련 - 낮은-중간 위험
        "11303": 2,  # 관리대장 누락
        "30301": 2,  # 네트워크 관리대장
        "30501": 2,  # 불필요한 서비스
        "30601": 3,  # SNMP 보안
        "40101": 4,  # 패치 관리
    }
    
    base_score = severity_map.get(rule_code, 2)
    violation_count = len(violation_info.get("violations", []))
    
    return base_score + min(violation_count, 3)  # 최대 3점 추가


def get_host_role(ip: str) -> str:
    """
    IP 주소로부터 호스트 역할 추정
    """
    # 간단한 휴리스틱 - 실제로는 관리대장에서 가져와야 함
    octets = ip.split('.')
    if len(octets) == 4:
        last_octet = int(octets[3])
        if last_octet == 1:
            return "게이트웨이/라우터"
        elif last_octet < 10:
            return "서버"
        elif last_octet > 100:
            return "클라이언트"
        else:
            return "서버/장비"
    return "미지정"


def generate_scripts_archive(eval_db_path: str, output_dir: str = "data/reports/scripts") -> str:
    """
    점검 스크립트들을 아카이브로 생성
    """
    # script_generator 모듈 import 수정
    try:
        from backend.report.script_generator import generate_check_scripts
    except ImportError:
        from .script_generator import generate_check_scripts
    
    import zipfile

    # 스크립트 생성
    scripts_dir = Path(output_dir) / "generated"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    
    generate_check_scripts(eval_db_path, str(scripts_dir))
    
    # ZIP 아카이브 생성
    archive_path = Path(output_dir) / "check_scripts.zip"
    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for script_file in scripts_dir.glob("*.sh"):
            zipf.write(script_file, script_file.name)
    
    print(f"✅ 점검 스크립트 아카이브 생성 완료 → {archive_path}")
    return str(archive_path)


def create_checklist_document(eval_db_path: str, output_path: str = "data/reports/checklist.txt") -> str:
    """
    통합 체크리스트 문서 생성
    """
    with open(eval_db_path, 'r', encoding='utf-8') as f:
        eval_db = json.load(f)
    
    checklist_content = []
    checklist_content.append("=" * 60)
    checklist_content.append("GovScan 보안점검 체크리스트")
    checklist_content.append("=" * 60)
    checklist_content.append(f"생성일시: {datetime.now().strftime('%Y년 %m월 %d일 %H시 %M분')}")
    checklist_content.append("")
    
    for rule_code, rule_info in sorted(eval_db.items()):
        checklist_content.append(f"[{rule_code}] {rule_info.get('name', '')}")
        checklist_content.append("-" * 50)
        checklist_content.append(f"설명: {rule_info.get('description', '')}")
        checklist_content.append("")
        
        checklist_items = rule_info.get('checklist_items', [])
        for i, item in enumerate(checklist_items, 1):
            checklist_content.append(f"  □ {i}. {item}")
        
        checklist_content.append("")
        checklist_content.append(f"조치방법: {rule_info.get('general_mitigation', '')}")
        checklist_content.append("")
        checklist_content.append("")
    
    # 파일 저장
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text('\n'.join(checklist_content), encoding='utf-8')
    
    print(f"✅ 체크리스트 문서 생성 완료 → {output_path}")
    return str(output_file.absolute())


def generate_comprehensive_report(
    results_path: str,
    eval_db_path: str, 
    output_dir: str = "data/reports",
    scan_info: Dict[str, Any] = None
) -> Dict[str, str]:
    """
    종합 보고서 패키지 생성 (HTML + 스크립트 + 체크리스트)
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 1. HTML 보고서 생성
    html_report = generate_enhanced_html_report(
        results_path=results_path,
        eval_db_path=eval_db_path,
        output_path=str(output_path / f"govscan_report_{timestamp}.html"),
        scan_info=scan_info
    )
    
    # 2. 점검 스크립트 아카이브 생성
    scripts_archive = generate_scripts_archive(
        eval_db_path=eval_db_path,
        output_dir=str(output_path / "scripts")
    )
    
    # 3. 체크리스트 문서 생성
    checklist_doc = create_checklist_document(
        eval_db_path=eval_db_path,
        output_path=str(output_path / f"checklist_{timestamp}.txt")
    )
    
    # 4. JSON 결과 복사 (참조용)
    json_result = output_path / f"analysis_results_{timestamp}.json"
    shutil.copy2(results_path, json_result)
    
    report_package = {
        "html_report": html_report,
        "scripts_archive": scripts_archive,
        "checklist_document": checklist_doc,
        "json_results": str(json_result),
        "timestamp": timestamp
    }
    
    # 패키지 정보 저장
    package_info = output_path / f"report_package_{timestamp}.json"
    with open(package_info, 'w', encoding='utf-8') as f:
        json.dump(report_package, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 종합 보고서 패키지 생성 완료:")
    print(f"   📄 HTML 보고서: {html_report}")
    print(f"   📦 점검 스크립트: {scripts_archive}")
    print(f"   📋 체크리스트: {checklist_doc}")
    print(f"   📊 JSON 결과: {json_result}")
    
    return report_package


# CLI 실행을 위한 메인 함수
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="📊 GovScan 강화된 보고서 생성기")
    parser.add_argument("-r", "--results", default="data/reports/analysis_results.json", 
                       help="분석 결과 JSON 파일")
    parser.add_argument("-e", "--eval", default="data/db/eval_db.json", 
                       help="평가 기준 JSON 파일")
    parser.add_argument("-o", "--output", default="data/reports", 
                       help="출력 디렉토리")
    parser.add_argument("--comprehensive", action="store_true", 
                       help="종합 보고서 패키지 생성")
    parser.add_argument("--scan-range", default="전체 네트워크", 
                       help="스캔 범위 설명")
    
    args = parser.parse_args()
    
    scan_info = {
        "ip_range": args.scan_range,
        "scan_date": datetime.now().isoformat()
    }
    
    if args.comprehensive:
        generate_comprehensive_report(
            results_path=args.results,
            eval_db_path=args.eval,
            output_dir=args.output,
            scan_info=scan_info
        )
    else:
        generate_enhanced_html_report(
            results_path=args.results,
            eval_db_path=args.eval,
            output_path=os.path.join(args.output, "govscan_report.html"),
            scan_info=scan_info
        )