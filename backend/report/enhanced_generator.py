# enhanced_generator.py

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
    강화된 HTML 보고서 생성 (debug_and_fix_report.py 내용 반영)
    """
    
    # 데이터 로드
    with open(results_path, encoding="utf-8") as f:
        analysis_data = json.load(f)

    with open(eval_db_path, encoding="utf-8") as f:
        eval_db = json.load(f)

    # 데이터 추출 및 검증 (debug_and_fix_report.py 로직 적용)
    summary = analysis_data.get("scan_summary", {})
    vulnerabilities = analysis_data.get("vulnerabilities", [])
    hosts = analysis_data.get("hosts", [])
    recommendations = analysis_data.get("recommendations", [])
    
    # 실제 값 확인 및 보정
    total_hosts = max(summary.get("total_hosts", 0), len(hosts))
    total_vulns = max(summary.get("total_vulnerabilities", 0), len(vulnerabilities))
    
    critical_count = summary.get("critical_count", 0)
    high_count = summary.get("high_count", 0)
    medium_count = summary.get("medium_count", 0)
    low_count = summary.get("low_count", 0)
    
    # 실제 카운트가 0인 경우 다시 계산
    if high_count == 0 and medium_count == 0 and low_count == 0 and vulnerabilities:
        print("📊 심각도별 카운트 재계산 중...")
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for vuln in vulnerabilities:
            severity = str(vuln.get("severity", "info")).lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        critical_count = severity_counts["critical"]
        high_count = severity_counts["high"]
        medium_count = severity_counts["medium"]
        low_count = severity_counts["low"]
        
        print(f"   재계산 결과 - 높음: {high_count}, 중간: {medium_count}, 낮음: {low_count}")
    
    # CVE 정보 수집
    cve_count = len([v for v in vulnerabilities if "CVE" in str(v.get("rule_id", ""))])
    
    # 보고서 메타데이터
    report_metadata = {
        "report_date": datetime.now().strftime("%Y년 %m월 %d일 %H시 %M분"),
        "scan_range": scan_info.get("ip_range", f"{total_hosts}개 호스트") if scan_info else f"{total_hosts}개 호스트",
        "total_hosts": total_hosts,
        "critical_issues": critical_count,
        "high_issues": high_count,
        "medium_issues": medium_count,
        "low_issues": low_count,
        "total_cves": cve_count
    }

    print(f"📈 HTML 생성 데이터:")
    print(f"   호스트: {total_hosts}, 취약점: {total_vulns}")
    print(f"   심각도별 - 높음: {high_count}, 중간: {medium_count}, 낮음: {low_count}")

    # HTML 생성
    html_content = generate_html_template(
        hosts=hosts,
        vulnerabilities=vulnerabilities,
        recommendations=recommendations,
        eval_db=eval_db,
        metadata=report_metadata
    )

    # 출력 경로 생성 및 저장
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html_content, encoding="utf-8")

    print(f"✅ 강화된 HTML 보고서 생성 완료 → {output_path}")
    return str(output_file.absolute())


def generate_html_template(hosts, vulnerabilities, recommendations, eval_db, metadata):
    """HTML 템플릿 생성"""
    
    html_content = f'''<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GovScan 보안점검결과</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Malgun Gothic', sans-serif; 
            line-height: 1.6;
            background-color: #f8f9fa;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding: 30px 0;
            border-bottom: 3px solid #007bff;
        }}
        .header h1 {{
            font-size: 28px;
            color: #007bff;
            margin-bottom: 10px;
        }}
        .summary-section {{
            margin-bottom: 40px;
            padding: 20px;
            background-color: #f8f9fa;
            border-left: 4px solid #007bff;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{ font-size: 24px; margin-bottom: 10px; }}
        .critical {{ color: #dc3545; }}
        .warning {{ color: #ffc107; }}
        .info {{ color: #17a2b8; }}
        .success {{ color: #28a745; }}
        .host-section {{
            margin-bottom: 40px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
        }}
        .host-header {{
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            padding: 20px;
            font-size: 18px;
            font-weight: bold;
        }}
        .host-content {{ padding: 20px; }}
        table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin-bottom: 20px;
            background: white;
        }}
        th, td {{ 
            border: 1px solid #dee2e6; 
            padding: 12px; 
            vertical-align: top;
            text-align: left;
        }}
        th {{ 
            background-color: #f8f9fa; 
            font-weight: bold;
            color: #495057;
        }}
        .severity-critical {{ background-color: #f8d7da; border-left: 4px solid #dc3545; }}
        .severity-high {{ background-color: #fff3cd; border-left: 4px solid #ffc107; }}
        .severity-medium {{ background-color: #d1ecf1; border-left: 4px solid #17a2b8; }}
        .severity-low {{ background-color: #d4edda; border-left: 4px solid #28a745; }}
        .recommendations-section {{
            background: #e7f3ff;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #007bff;
        }}
        .scripts-section {{
            background: #f0f8ff;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #28a745;
        }}
        .checklist-section {{
            background: #fff8e1;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #ff9800;
        }}
        .script-item {{
            background: white;
            margin: 10px 0;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #e0e0e0;
        }}
        .script-header {{
            font-weight: bold;
            color: #2e7d32;
            margin-bottom: 8px;
        }}
        .script-code {{
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            margin: 8px 0;
        }}
        .checklist-item {{
            background: white;
            margin: 8px 0;
            padding: 12px;
            border-radius: 4px;
            border-left: 3px solid #ff9800;
            display: flex;
            align-items: flex-start;
        }}
        .checklist-checkbox {{
            margin-right: 10px;
            margin-top: 3px;
        }}
        .download-section {{
            background: #e8f5e8;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            text-align: center;
        }}
        .download-btn {{
            display: inline-block;
            background: #28a745;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 6px;
            margin: 5px;
            transition: background-color 0.3s;
        }}
        .download-btn:hover {{
            background: #218838;
        }}
        .footer {{
            margin-top: 50px;
            padding: 20px 0;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #666;
            font-size: 12px;
        }}
        .collapsible {{
            background-color: #f1f1f1;
            color: #444;
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 15px;
            border-radius: 4px;
            margin: 5px 0;
        }}
        .collapsible:hover {{
            background-color: #ddd;
        }}
        .content-box {{
            padding: 0 18px;
            display: none;
            overflow: hidden;
            background-color: #f9f9f9;
            border-radius: 0 0 4px 4px;
        }}
        .content-box.active {{
            display: block;
            padding: 18px;
        }}
    </style>
    <script>
        function toggleContent(element) {{
            element.classList.toggle("active");
            var content = element.nextElementSibling;
            if (content.style.display === "block") {{
                content.style.display = "none";
            }} else {{
                content.style.display = "block";
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ GovScan 보안점검 결과보고서</h1>
            <div class="subtitle">
                생성일시: {metadata["report_date"]}<br>
                점검 범위: {metadata["scan_range"]}
            </div>
        </div>

        <div class="summary-section">
            <h2>📊 점검 결과 요약</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3 class="info">{metadata["total_hosts"]}</h3>
                    <p>점검 대상 호스트</p>
                </div>
                <div class="summary-card">
                    <h3 class="critical">{metadata["critical_issues"]}</h3>
                    <p>심각 위험</p>
                </div>
                <div class="summary-card">
                    <h3 class="warning">{metadata["high_issues"]}</h3>
                    <p>높은 위험</p>
                </div>
                <div class="summary-card">
                    <h3 class="info">{metadata["medium_issues"]}</h3>
                    <p>보통 위험</p>
                </div>
                <div class="summary-card">
                    <h3 class="success">{metadata["total_cves"]}</h3>
                    <p>탐지된 CVE</p>
                </div>
            </div>
        </div>
'''

    # 호스트별 상세 정보 추가
    if hosts and any(host.get("vulnerabilities") for host in hosts):
        for host in hosts:
            ip = str(host.get("ip", "Unknown"))
            hostname = host.get("hostname") or ""
            os_info = host.get("os") or "N/A"
            host_vulns = host.get("vulnerabilities", [])
            
            if not host_vulns:  # 호스트 취약점이 없으면 건너뛰기
                continue
                
            html_content += f'''
        <div class="host-section">
            <div class="host-header">
                🖥️ 호스트: {ip} {f"({hostname})" if hostname else ""}
            </div>
            <div class="host-content">
                <p><strong>운영체제:</strong> {os_info}</p>
                <p><strong>발견된 취약점:</strong> {len(host_vulns)}개</p>
                
                <h3>🔍 상세 취약점 목록</h3>
                <table>
                    <thead>
                        <tr>
                            <th>규칙 ID</th>
                            <th>취약점명</th>
                            <th>포트</th>
                            <th>심각도</th>
                            <th>설명</th>
                            <th>권장조치</th>
                        </tr>
                    </thead>
                    <tbody>
'''
            
            # 점검 스크립트와 체크리스트 수집
            unique_rules = set()
            for vuln in host_vulns:
                rule_id = str(vuln.get("rule_id", "N/A"))
                rule_name = str(vuln.get("rule_name", "N/A"))
                port = str(vuln.get("port", "N/A"))
                severity = str(vuln.get("severity", "info")).lower()
                description = str(vuln.get("description", "N/A"))
                details = str(vuln.get("details", ""))
                recommendation = str(vuln.get("recommendation", "N/A"))
                
                severity_class = f"severity-{severity}"
                unique_rules.add(rule_id)
                
                html_content += f'''
                    <tr class="{severity_class}">
                        <td><strong>{rule_id}</strong></td>
                        <td>{rule_name}</td>
                        <td>{port}</td>
                        <td><span class="{severity}">{severity.upper()}</span></td>
                        <td>
                            {description}
                            {f'<br><small><em>{details}</em></small>' if details and details != "N/A" and details.strip() else ''}
                        </td>
                        <td>{recommendation}</td>
                    </tr>
'''
            
            html_content += '''
                    </tbody>
                </table>
'''
            
            # 점검 스크립트 섹션 추가
            html_content += generate_scripts_section(unique_rules, eval_db, ip)
            
            # 체크리스트 섹션 추가
            html_content += generate_checklist_section(unique_rules, eval_db, ip)
            
            html_content += '</div></div>'
    
    elif vulnerabilities:
        # 호스트 정보가 없지만 취약점이 있는 경우
        html_content += f'''
        <div class="host-section">
            <div class="host-header">
                🔍 발견된 취약점 목록 ({len(vulnerabilities)}개)
            </div>
            <div class="host-content">
                <table>
                    <thead>
                        <tr>
                            <th>호스트</th>
                            <th>규칙 ID</th>
                            <th>취약점명</th>
                            <th>포트</th>
                            <th>심각도</th>
                            <th>설명</th>
                        </tr>
                    </thead>
                    <tbody>
'''
        
        unique_rules = set()
        for vuln in vulnerabilities:
            host_ip = str(vuln.get("host", "N/A"))
            rule_id = str(vuln.get("rule_id", "N/A"))
            rule_name = str(vuln.get("rule_name", "N/A"))
            port = str(vuln.get("port", "N/A"))
            severity = str(vuln.get("severity", "info")).lower()
            description = str(vuln.get("description", "N/A"))
            
            severity_class = f"severity-{severity}"
            unique_rules.add(rule_id)
            
            html_content += f'''
                    <tr class="{severity_class}">
                        <td>{host_ip}</td>
                        <td><strong>{rule_id}</strong></td>
                        <td>{rule_name}</td>
                        <td>{port}</td>
                        <td><span class="{severity}">{severity.upper()}</span></td>
                        <td>{description}</td>
                    </tr>
'''
        
        html_content += '</tbody></table>'
        
        # 통합 점검 스크립트 및 체크리스트 추가
        html_content += generate_scripts_section(unique_rules, eval_db, "전체")
        html_content += generate_checklist_section(unique_rules, eval_db, "전체")
        
        html_content += '</div></div>'
    
    # 권장사항 추가
    if recommendations:
        html_content += '''
        <div class="recommendations-section">
            <h2>💡 종합 권장사항</h2>
            <ul>
'''
        for rec in recommendations:
            html_content += f'<li>{str(rec)}</li>'
        
        html_content += '</ul></div>'
    
    # 다운로드 섹션 추가
    html_content += '''
        <div class="download-section">
            <h2>📥 추가 자료 다운로드</h2>
            <p>점검 스크립트와 체크리스트를 별도 파일로 다운로드할 수 있습니다.</p>
            <a href="#" class="download-btn" onclick="alert('점검 스크립트 생성 기능을 구현하세요.')">🔧 점검 스크립트 다운로드</a>
            <a href="#" class="download-btn" onclick="alert('체크리스트 문서 생성 기능을 구현하세요.')">📋 체크리스트 다운로드</a>
            <a href="#" class="download-btn" onclick="window.print()">🖨️ 보고서 인쇄</a>
        </div>
'''
    
    # 푸터
    html_content += f'''
        <div class="footer">
            <p>본 보고서는 GovScan 자동화 도구를 통해 생성되었습니다.</p>
            <p>생성 시간: {datetime.now().isoformat()}</p>
        </div>
    </div>
</body>
</html>'''
    
    return html_content


def generate_scripts_section(rule_ids, eval_db, host_info):
    """점검 스크립트 섹션 생성 (실제 스크립트 파일 기반)"""
    
    scripts_html = f'''
                <button class="collapsible" onclick="toggleContent(this)">🔧 점검 스크립트 ({host_info})</button>
                <div class="content-box">
                    <h4>자동화 점검 스크립트</h4>
                    <p>발견된 취약점에 대한 실제 점검 스크립트입니다. 스크립트를 다운로드하여 시스템에서 실행할 수 있습니다.</p>
'''
    
    # script_generator에서 매핑 정보 가져오기
    script_mapping = get_script_mapping()
    scripts_base_dir = Path("data/db/scripts")
    
    processed_scripts = set()  # 중복 스크립트 방지
    
    for rule_id in sorted(rule_ids):
        rule_info = eval_db.get(rule_id, {})
        if not rule_info:
            continue
            
        rule_name = rule_info.get("name", f"규칙 {rule_id}")
        check_script_name = rule_info.get("check_script", "")
        original_scripts = rule_info.get("original_script", "").split(",")
        
        # 실제 스크립트 파일 찾기
        actual_scripts = find_actual_scripts(rule_id, script_mapping, scripts_base_dir, original_scripts)
        
        if actual_scripts:
            for script_path, script_name in actual_scripts:
                if script_name in processed_scripts:
                    continue
                processed_scripts.add(script_name)
                
                script_content = load_script_content(script_path)
                scripts_html += f'''
                    <div class="script-item">
                        <div class="script-header">[{rule_id}] {rule_name} - {script_name}</div>
                        <div class="script-code">{script_content}</div>
                        <div style="margin-top: 10px;">
                            <small><strong>사용법:</strong> chmod +x {script_name} && ./{script_name} [target_ip]</small><br>
                            <small><em>※ root 권한으로 실행하며, 대상 IP를 인자로 전달하세요.</em></small>
                        </div>
                    </div>
'''
        else:
            # 기존 방식으로 폴백
            auto_script = generate_auto_script_content(rule_id, rule_info)
            scripts_html += f'''
                    <div class="script-item">
                        <div class="script-header">[{rule_id}] {rule_name} (자동생성)</div>
                        <div class="script-code">{auto_script}</div>
                        <small><em>기본 점검 스크립트가 생성되었습니다.</em></small>
                    </div>
'''
    
    scripts_html += '</div>'
    return scripts_html


def generate_checklist_section(rule_ids, eval_db, host_info):
    """체크리스트 섹션 생성 (eval_db의 실제 checklist_items 사용)"""
    
    checklist_html = f'''
                <button class="collapsible" onclick="toggleContent(this)">📋 점검 체크리스트 ({host_info})</button>
                <div class="content-box">
                    <h4>수동 점검 체크리스트</h4>
                    <p>다음 항목들을 수동으로 점검하여 보안 수준을 확인하세요. 각 항목은 실제 보안 가이드라인을 기반으로 작성되었습니다.</p>
'''
    
    checklist_items = []
    
    for rule_id in sorted(rule_ids):
        rule_info = eval_db.get(rule_id, {})
        if not rule_info:
            continue
            
        rule_name = rule_info.get("name", f"규칙 {rule_id}")
        description = rule_info.get("description", "")
        mitigation = rule_info.get("general_mitigation", "")
        original_script = rule_info.get("original_script", "")
        
        # eval_db에서 실제 체크리스트 항목 가져오기
        db_checklist_items = rule_info.get("checklist_items", [])
        
        if db_checklist_items:
            for item in db_checklist_items:
                checklist_items.append({
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "item": item,
                    "description": description,
                    "mitigation": mitigation,
                    "original_script": original_script
                })
        else:
            # 체크리스트가 없는 경우 기본 항목 생성
            default_item = f"{rule_name} 관련 보안 설정 확인"
            checklist_items.append({
                "rule_id": rule_id,
                "rule_name": rule_name,
                "item": default_item,
                "description": description,
                "mitigation": mitigation,
                "original_script": original_script
            })
    
    # 체크리스트 항목 출력
    for idx, item_info in enumerate(checklist_items, 1):
        original_ref = f" (참조: {item_info['original_script']})" if item_info['original_script'] else ""
        
        checklist_html += f'''
                    <div class="checklist-item">
                        <input type="checkbox" class="checklist-checkbox" id="check_{idx}">
                        <label for="check_{idx}">
                            <strong>[{item_info["rule_id"]}]</strong> {item_info["item"]}{original_ref}
                            <br><small style="color: #666;">{item_info["description"]}</small>
                            {f'<br><em style="color: #2e7d32;">💡 조치방법: {item_info["mitigation"]}</em>' if item_info["mitigation"] else ''}
                        </label>
                    </div>
'''
    
    # 체크리스트 진행률 표시 JavaScript 추가
    checklist_html += '''
                    <div style="margin-top: 20px; padding: 15px; background: #e8f5e8; border-radius: 6px;">
                        <strong>점검 진행률: <span id="progress">0</span>/{total_items} (0%)</strong>
                        <div style="width: 100%; background-color: #ddd; border-radius: 10px; margin-top: 5px;">
                            <div id="progressBar" style="width: 0%; height: 10px; background-color: #4CAF50; border-radius: 10px; transition: width 0.3s;"></div>
                        </div>
                        <small style="color: #666; margin-top: 5px; display: block;">체크박스를 클릭하여 점검 진행률을 확인하세요.</small>
                    </div>
                    
                    <script>
                        function updateProgress() {{
                            const checkboxes = document.querySelectorAll('.checklist-checkbox');
                            const checkedBoxes = document.querySelectorAll('.checklist-checkbox:checked');
                            const progress = checkedBoxes.length;
                            const total = checkboxes.length;
                            const percentage = total > 0 ? Math.round((progress / total) * 100) : 0;
                            
                            document.getElementById('progress').textContent = progress;
                            document.getElementById('progressBar').style.width = percentage + '%';
                            
                            // 진행률에 따른 색상 변경
                            const progressBar = document.getElementById('progressBar');
                            if (percentage < 30) {{
                                progressBar.style.backgroundColor = '#f44336';
                            }} else if (percentage < 70) {{
                                progressBar.style.backgroundColor = '#ff9800';
                            }} else {{
                                progressBar.style.backgroundColor = '#4CAF50';
                            }}
                        }}
                        
                        // 체크박스에 이벤트 리스너 추가
                        document.addEventListener('DOMContentLoaded', function() {{
                            const checkboxes = document.querySelectorAll('.checklist-checkbox');
                            checkboxes.forEach(checkbox => {{
                                checkbox.addEventListener('change', updateProgress);
                            }});
                            updateProgress(); // 초기 설정
                        }});
                    </script>
'''.replace('{total_items}', str(len(checklist_items)))
    
    checklist_html += '</div>'
    return checklist_html


def get_script_mapping():
    """script_generator.py의 매핑 정보 가져오기"""
    return {
        # 기본 보안 정책 매핑
        "11303": ["u-06.sh"],  # 관리대장 누락
        "20501": ["u-01.sh", "u-20.sh"],  # 접근통제 미흡
        "20502": ["u-01.sh"],  # SSH 약한 인증
        "20503": ["u-19.sh", "u-21.sh", "u-23.sh", "u-29.sh"],  # 취약한 서비스
        "30301": ["u-06.sh"],  # 네트워크 관리대장
        "30501": ["u-19.sh", "u-23.sh", "u-24.sh", "u-26.sh", "u-27.sh", "u-28.sh", "u-29.sh"],  # 불필요한 서비스
        "30601": [],  # SNMP 보안 (자동 생성)
        "30701": ["u-35.sh", "u-36.sh", "u-37.sh", "u-38.sh", "u-39.sh", "u-40.sh", "u-41.sh"],  # 웹 서버 보안
        "30802": [],  # 버전 정보 노출 (자동 생성)
        "40101": ["u-42.sh"],  # 패치 관리
        
        # 직접 매핑 (U-01 ~ U-43)
        "u-01": ["u-01.sh"], "u-02": ["u-02.sh"], "u-03": ["u-03.sh"], "u-04": ["u-04.sh"], "u-05": ["u-05.sh"],
        "u-06": ["u-06.sh"], "u-07": ["u-07.sh"], "u-08": ["u-08.sh"], "u-09": ["u-09.sh"], "u-10": ["u-10.sh"],
        "u-11": ["u-11.sh"], "u-12": ["u-12.sh"], "u-13": ["u-13.sh"], "u-14": ["u-14.sh"], "u-15": ["u-15.sh"],
        "u-16": ["u-16.sh"], "u-17": ["u-17.sh"], "u-18": ["u-18.sh"], "u-19": ["u-19.sh"], "u-20": ["u-20.sh"],
        "u-21": ["u-21.sh"], "u-22": ["u-22.sh"], "u-23": ["u-23.sh"], "u-24": ["u-24.sh"], "u-25": ["u-25.sh"],
        "u-26": ["u-26.sh"], "u-27": ["u-27.sh"], "u-28": ["u-28.sh"], "u-29": ["u-29.sh"], "u-30": ["u-30.sh"],
        "u-31": ["u-31.sh"], "u-32": ["u-32.sh"], "u-33": ["u-33.sh"], "u-34": ["u-34.sh"], "u-35": ["u-35.sh"],
        "u-36": ["u-36.sh"], "u-37": ["u-37.sh"], "u-38": ["u-38.sh"], "u-39": ["u-39.sh"], "u-40": ["u-40.sh"],
        "u-41": ["u-41.sh"], "u-42": ["u-42.sh"], "u-43": ["u-43.sh"]
    }


def find_actual_scripts(rule_id, script_mapping, scripts_base_dir, original_scripts):
    """실제 스크립트 파일 찾기"""
    found_scripts = []
    
    # 1. script_mapping에서 매핑된 스크립트 찾기
    if rule_id in script_mapping and script_mapping[rule_id]:
        for script_name in script_mapping[rule_id]:
            script_path = scripts_base_dir / script_name
            if script_path.exists():
                found_scripts.append((script_path, script_name))
    
    # 2. original_script에서 지정된 스크립트 찾기
    for script_ref in original_scripts:
        script_ref = script_ref.strip()
        if script_ref and script_ref.endswith('.sh'):
            script_path = scripts_base_dir / script_ref
            if script_path.exists():
                found_scripts.append((script_path, script_ref))
    
    # 3. rule_id로 직접 매핑 (u-xx 형태)
    if rule_id.startswith('u-'):
        script_path = scripts_base_dir / f"{rule_id}.sh"
        if script_path.exists():
            found_scripts.append((script_path, f"{rule_id}.sh"))
    
    # 중복 제거
    unique_scripts = []
    seen_names = set()
    for script_path, script_name in found_scripts:
        if script_name not in seen_names:
            unique_scripts.append((script_path, script_name))
            seen_names.add(script_name)
    
    return unique_scripts


def load_script_content(script_path, max_lines=30):
    """스크립트 파일 내용 로드 (미리보기용)"""
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 주석과 빈 줄 제거하여 핵심 내용만 표시
        core_lines = []
        for line in lines:
            stripped = line.strip()
            # 쉘 스크립트 헤더나 긴 주석 블록 건너뛰기
            if stripped.startswith('#') and ('=' in stripped or len(stripped) > 50):
                continue
            core_lines.append(line.rstrip())
        
        # 최대 라인 수 제한
        if len(core_lines) > max_lines:
            core_lines = core_lines[:max_lines-2] + ['...', f'# (전체 {len(lines)}줄 중 {max_lines}줄만 표시)']
        
        return '\n'.join(core_lines)
    
    except Exception as e:
        return f"# 스크립트 로드 실패: {e}\n# 파일 경로: {script_path}"


def generate_auto_script_content(rule_id, rule_info):
    """기존 스크립트가 없을 때 자동 생성하는 스크립트 내용"""
    
    name = rule_info.get("name", "")
    description = rule_info.get("description", "")
    
    # 규칙별 기본 스크립트 템플릿
    if rule_id == "30601":  # SNMP 보안
        return '''#!/bin/bash
# SNMP 보안 설정 점검 스크립트
TARGET_IP=${1:-localhost}

echo "=== SNMP 보안 점검 ==="
echo "대상: $TARGET_IP"

# SNMP 서비스 확인
nmap -sU -p 161 $TARGET_IP 2>/dev/null | grep -q "161/udp open"
if [ $? -eq 0 ]; then
    echo "✅ SNMP 서비스 실행 중"
    
    # 기본 커뮤니티 스트링 테스트
    for community in public private; do
        if command -v snmpwalk >/dev/null 2>&1; then
            timeout 5 snmpwalk -v2c -c $community $TARGET_IP 1.3.6.1.2.1.1.1.0 2>/dev/null | grep -q "STRING"
            [ $? -eq 0 ] && echo "❌ 기본 커뮤니티 '$community' 사용 중" || echo "✅ '$community' 비활성화"
        fi
    done
else
    echo "❌ SNMP 서비스 미실행"
fi'''
    
    elif rule_id == "30802":  # 버전정보 노출
        return '''#!/bin/bash
# 버전정보 노출 점검 스크립트
TARGET_IP=${1:-localhost}

echo "=== 버전정보 노출 점검 ==="
echo "대상: $TARGET_IP"

# HTTP 서버 버전 확인
echo "1. HTTP 서버 버전 정보:"
curl -I http://$TARGET_IP 2>/dev/null | grep -i "server:" || echo "HTTP 서비스 없음"

# SSH 서버 버전 확인  
echo "2. SSH 서버 버전 정보:"
timeout 3 ssh -o ConnectTimeout=3 $TARGET_IP exit 2>&1 | head -1 || echo "SSH 연결 실패"

# FTP 서버 버전 확인
echo "3. FTP 서버 버전 정보:"
timeout 3 telnet $TARGET_IP 21 2>/dev/null | head -2 || echo "FTP 서비스 없음"'''
    
    else:
        return f'''#!/bin/bash
# {name} 점검 스크립트 (자동생성)
TARGET_IP=${{1:-localhost}}

echo "=== {name} 점검 ==="
echo "대상: $TARGET_IP"
echo "설명: {description}"
echo ""
echo "⚠️  이 항목은 수동 점검이 필요합니다."
echo "📋 체크리스트를 참조하여 점검을 수행하세요."'''


def generate_default_checklist_items(rule_id, rule_info):
    """기본 체크리스트 항목 생성 (eval_db에 없는 경우 사용)"""
    
    rule_name = rule_info.get("name", "")
    
    # 규칙 ID별 기본 체크리스트 (간소화된 버전)
    checklist_templates = {
        "20501": [
            "FTP 익명 접속이 비활성화되어 있는지 확인",
            "Telnet 서비스가 비활성화되어 있는지 확인", 
            "SSH 키 기반 인증이 설정되어 있는지 확인"
        ],
        "20503": [
            "위험한 서비스(telnet, ftp, rsh 등)가 비활성화되어 있는지 확인",
            "방화벽에서 불필요한 포트가 차단되어 있는지 확인"
        ],
        "30802": [
            "서비스 배너에서 버전 정보가 숨겨져 있는지 확인",
            "웹 서버 응답 헤더에서 버전 정보가 제거되었는지 확인"
        ]
    }
    
    return checklist_templates.get(rule_id, [
        f"{rule_name} 관련 보안 정책이 수립되어 있는지 확인",
        f"{rule_name} 관련 설정이 보안 가이드라인에 따라 구성되었는지 확인"
    ])


def integrate_with_script_generator(eval_db_path: str, output_dir: str):
    """script_generator.py와 통합하여 실제 스크립트 생성"""
    try:
        # script_generator 모듈 import
        from backend.report.script_generator import generate_check_scripts
        
        print("🔧 점검 스크립트 생성 중...")
        generate_check_scripts(eval_db_path, output_dir)
        print(f"✅ 점검 스크립트 생성 완료: {output_dir}")
        
        return True
    except ImportError:
        print("⚠️  script_generator 모듈을 찾을 수 없습니다.")
        return False
    except Exception as e:
        print(f"❌ 스크립트 생성 실패: {e}")
        return False


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
        
        # eval_db에서 체크리스트 항목 가져오기 (없으면 기본 생성)
        checklist_items = rule_info.get('checklist_items', [])
        if not checklist_items:
            checklist_items = generate_default_checklist_items(rule_code, rule_info)
        
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