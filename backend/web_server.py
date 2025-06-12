import json
import os
import uuid
import shutil
from datetime import datetime
from pathlib import Path
from threading import Thread
from typing import Any, Dict, List

from flask import (Flask, jsonify, redirect, render_template, request,
                   send_file, url_for)
from werkzeug.utils import secure_filename

# GovScan 모듈 import
from backend.extract_ip.extractor import extract_ip_ranges
from backend.mmdb.mmdb_converter import parse_nmap_xml
from backend.report.enhanced_generator import generate_comprehensive_report
from backend.scanner.nmap_runner import run_nmap_scan

app = Flask(__name__)
app.config['SECRET_KEY'] = 'govscan-secret-key-2025'
app.config['UPLOAD_FOLDER'] = 'data/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# 전역 변수 - 스캔 작업 관리
active_scans: Dict[str, Dict[str, Any]] = {}
scan_history: List[Dict[str, Any]] = []


def run_vuln_analysis_with_file(scan_parsed_file: str):
    """
    특정 파일을 사용하여 취약점 분석 실행
    
    Args:
        scan_parsed_file: 분석할 scan_parsed JSON 파일 경로
    
    Returns:
        분석 결과 딕셔너리
    """
    try:
        # 1. 파일 존재 확인
        if not Path(scan_parsed_file).exists():
            raise FileNotFoundError(f"스캔 파일을 찾을 수 없습니다: {scan_parsed_file}")
        
        # 2. 파일 크기 확인
        file_size = Path(scan_parsed_file).stat().st_size
        if file_size == 0:
            raise ValueError("스캔 파일이 비어있습니다")
        
        # 3. 기본 파일로 임시 복사 (기존 core.py 호환성)
        default_file = "data/mmdb/scan_parsed.json"
        shutil.copy2(scan_parsed_file, default_file)
        
        # 4. 취약점 분석 실행
        from backend.vuln_checker.core import run_all_checks
        analysis_results = run_all_checks()
        
        # 5. 결과 검증
        if not analysis_results:
            # 빈 결과인 경우 기본 구조 생성
            analysis_results = {
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
                "recommendations": [
                    "스캔 결과를 확인하여 취약점을 분석하세요.",
                    "네트워크 보안 정책을 검토하세요."
                ],
                "status": "completed_with_empty_result",
                "timestamp": datetime.now().isoformat(),
                "source_file": scan_parsed_file
            }
        else:
            # 결과에 메타데이터 추가
            if isinstance(analysis_results, dict):
                analysis_results["timestamp"] = datetime.now().isoformat()
                analysis_results["source_file"] = scan_parsed_file
        
        return analysis_results
        
    except ImportError as e:
        return {
            "scan_summary": {"total_hosts": 0, "total_vulnerabilities": 0},
            "vulnerabilities": [],
            "status": "module_import_error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "scan_summary": {"total_hosts": 0, "total_vulnerabilities": 0},
            "vulnerabilities": [],
            "status": "analysis_error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


class ScanManager:
    """스캔 작업 관리 클래스"""
    
    def __init__(self):
        self.load_scan_history()
    
    def load_scan_history(self):
        """저장된 스캔 히스토리 로드"""
        global scan_history
        history_file = Path("data/scan_history.json")
        if history_file.exists():
            with open(history_file, 'r', encoding='utf-8') as f:
                scan_history = json.load(f)
    
    def save_scan_history(self):
        """스캔 히스토리 저장"""
        history_file = Path("data/scan_history.json")
        history_file.parent.mkdir(parents=True, exist_ok=True)
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(scan_history, f, indent=2, ensure_ascii=False)
    
    def start_scan(self, scan_config: Dict[str, Any]) -> str:
        """새로운 스캔 시작"""
        scan_id = str(uuid.uuid4())
        scan_info = {
            "id": scan_id,
            "name": scan_config["scan_name"],
            "status": "running",
            "progress": 0,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "input_file": scan_config["input_file"],
            "results": {},
            "error": None,
            "current_step": "초기화 중..."
        }
        
        active_scans[scan_id] = scan_info
        scan_history.append(scan_info)
        
        # 백그라운드에서 스캔 실행
        thread = Thread(target=self._execute_scan, args=(scan_id, scan_config))
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _execute_scan(self, scan_id: str, scan_config: Dict[str, Any]):
        """스캔 실행 (백그라운드)"""
        try:
            scan_info = active_scans[scan_id]
            
            # 1. IP 추출
            scan_info["progress"] = 20
            scan_info["current_step"] = "IP 대역 추출 중..."
            print(f"[{scan_id}] IP 추출 시작...")
            
            ip_count = extract_ip_ranges(
                file_path=scan_config["input_file"],
                output_path=f"data/ip_ranges/ip_list_{scan_id}.txt",
                cidr_output_path=f"data/ip_ranges/ip_cidr_{scan_id}.txt"
            )
            
            if ip_count == 0:
                raise Exception("추출된 IP가 없습니다")
            
            print(f"[{scan_id}] IP 추출 완료: {ip_count}개")
            
            # 2. Nmap 스캔
            scan_info["progress"] = 40
            scan_info["current_step"] = "네트워크 스캔 중..."
            print(f"[{scan_id}] Nmap 스캔 시작...")
            
            nmap_result = run_nmap_scan(
                input_file=f"data/ip_ranges/ip_cidr_{scan_id}.txt",
                output_dir=f"data/scan_results/{scan_id}",
                ports=scan_config.get("ports", "1-1024"),
                scan_type=scan_config.get("scan_type", "-sS"),
                additional_args=scan_config.get("additional_args", "-sV -sC -A -T4")
            )
            
            if not nmap_result:
                raise Exception("Nmap 스캔 실패")
            
            print(f"[{scan_id}] Nmap 스캔 완료")
            
            # 3. XML 파싱
            scan_info["progress"] = 60
            scan_info["current_step"] = "스캔 결과 분석 중..."
            print(f"[{scan_id}] XML 파싱 시작...")
            
            scan_parsed_file = f"data/mmdb/scan_parsed_{scan_id}.json"
            parse_nmap_xml(
                xml_path=f"{nmap_result}.xml",
                output_path=scan_parsed_file
            )
            
            # 파싱 결과 확인
            if not Path(scan_parsed_file).exists():
                raise Exception("XML 파싱 결과 파일이 생성되지 않았습니다")
            
            parsed_size = Path(scan_parsed_file).stat().st_size
            print(f"[{scan_id}] XML 파싱 완료: {parsed_size} bytes")
            
            # 4. 취약점 분석 (동적 파일 경로 사용)
            scan_info["progress"] = 80
            scan_info["current_step"] = "취약점 분석 중..."
            print(f"[{scan_id}] 취약점 분석 시작...")
            
            analysis_results = run_vuln_analysis_with_file(scan_parsed_file)
            
            # 결과 저장
            results_path = f"data/reports/analysis_results_{scan_id}.json"
            Path(results_path).parent.mkdir(parents=True, exist_ok=True)
            with open(results_path, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, indent=2, ensure_ascii=False)
            
            # 저장된 파일 크기 확인
            result_size = Path(results_path).stat().st_size
            print(f"[{scan_id}] 취약점 분석 완료: {result_size} bytes")
            
            # 5. 보고서 생성
            scan_info["progress"] = 90
            scan_info["current_step"] = "보고서 생성 중..."
            print(f"[{scan_id}] 보고서 생성 시작...")
            
            scan_info_data = {
                "ip_range": f"{ip_count}개 IP",
                "scan_date": scan_info["start_time"]
            }
            
            report_package = generate_comprehensive_report(
                results_path=results_path,
                eval_db_path="data/db/eval_db.json",
                output_dir=f"data/reports/{scan_id}",
                scan_info=scan_info_data
            )
            
            # 완료 처리
            scan_info["progress"] = 100
            scan_info["status"] = "completed"
            scan_info["current_step"] = "완료"
            scan_info["end_time"] = datetime.now().isoformat()
            scan_info["results"] = report_package
            
            print(f"[{scan_id}] 스캔 완료!")
            
        except Exception as e:
            print(f"[{scan_id}] 스캔 실패: {e}")
            scan_info["status"] = "failed"
            scan_info["error"] = str(e)
            scan_info["end_time"] = datetime.now().isoformat()
            scan_info["progress"] = 0
            scan_info["current_step"] = f"실패: {str(e)}"
        
        finally:
            # 스캔 히스토리 저장
            self.save_scan_history()
            
            # 완료된 스캔은 active_scans에서 제거 (24시간 후)
            # 실제로는 스케줄러를 사용해야 함


# 스캔 매니저 인스턴스
scan_manager = ScanManager()


@app.route('/')
def dashboard():
    """메인 대시보드"""
    # 최근 스캔 결과 요약
    recent_scans = sorted(scan_history, key=lambda x: x.get("start_time", ""), reverse=True)[:10]
    
    # 통계 계산
    total_scans = len(scan_history)
    completed_scans = len([s for s in scan_history if s.get("status") == "completed"])
    failed_scans = len([s for s in scan_history if s.get("status") == "failed"])
    running_scans = len([s for s in scan_history if s.get("status") == "running"])
    
    dashboard_data = {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "running_scans": running_scans,
        "recent_scans": recent_scans
    }
    
    return render_template('dashboard.html', data=dashboard_data)


@app.route('/api/scans')
def api_get_scans():
    """스캔 목록 API"""
    return jsonify(scan_history)


@app.route('/api/scan/<scan_id>')
def api_get_scan(scan_id):
    """특정 스캔 정보 API"""
    # active_scans와 scan_history에서 검색
    scan_info = active_scans.get(scan_id)
    if not scan_info:
        scan_info = next((s for s in scan_history if s.get("id") == scan_id), None)
    
    if scan_info:
        return jsonify(scan_info)
    else:
        return jsonify({"error": "Scan not found"}), 404


@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    """새 스캔 시작 API"""
    try:
        # 파일 업로드 처리
        if 'file' not in request.files:
            return jsonify({"error": "파일이 없습니다."}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "파일이 선택되지 않았습니다."}), 400
        
        # 파일 저장
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{filename}"
        
        upload_dir = Path(app.config['UPLOAD_FOLDER'])
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = upload_dir / filename
        file.save(file_path)
        
        # 스캔 설정
        scan_config = {
            "scan_name": request.form.get('scan_name', f'스캔_{timestamp}'),
            "input_file": str(file_path),
            "ports": request.form.get('ports', '1-1024'),
            "scan_type": request.form.get('scan_type', '-sS'),
            "additional_args": request.form.get('additional_args', '-sV -sC -A -T4')
        }
        
        # 스캔 시작
        scan_id = scan_manager.start_scan(scan_config)
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "message": "스캔이 시작되었습니다."
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/report/<scan_id>')
def view_report(scan_id):
    """보고서 보기"""
    scan_info = next((s for s in scan_history if s.get("id") == scan_id), None)
    
    if not scan_info:
        return "스캔을 찾을 수 없습니다.", 404
    
    if scan_info.get("status") != "completed":
        return "스캔이 완료되지 않았습니다.", 400
    
    # HTML 보고서 파일 경로
    html_report_path = scan_info.get("results", {}).get("html_report")
    
    if html_report_path and Path(html_report_path).exists():
        return send_file(html_report_path)
    else:
        return "보고서 파일을 찾을 수 없습니다.", 404


@app.route('/download/<scan_id>/<file_type>')
def download_file(scan_id, file_type):
    """파일 다운로드"""
    scan_info = next((s for s in scan_history if s.get("id") == scan_id), None)
    
    if not scan_info or scan_info.get("status") != "completed":
        return "파일을 찾을 수 없습니다.", 404
    
    results = scan_info.get("results", {})
    
    if file_type == "scripts":
        file_path = results.get("scripts_archive")
    elif file_type == "checklist":
        file_path = results.get("checklist_document")
    elif file_type == "json":
        file_path = results.get("json_results")
    else:
        return "잘못된 파일 타입입니다.", 400
    
    if file_path and Path(file_path).exists():
        return send_file(file_path, as_attachment=True)
    else:
        return "파일을 찾을 수 없습니다.", 404


@app.route('/download/script/<script_name>')
def download_script(script_name):
    """개별 스크립트 다운로드"""
    script_path = Path("data/scripts") / secure_filename(script_name)
    
    if script_path.exists():
        return send_file(script_path, as_attachment=True)
    else:
        return "스크립트 파일을 찾을 수 없습니다.", 404


if __name__ == '__main__':
    # 필요한 디렉토리 생성
    for directory in ['data/uploads', 'data/reports', 'data/scan_results', 'data/scripts']:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    # Flask 애플리케이션 실행
    app.run(host='0.0.0.0', port=5000, debug=True)