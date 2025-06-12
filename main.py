#!/usr/bin/env python3
"""
GovScan - 정부기관 네트워크 보안점검 자동화 도구
메인 실행 파일

사용법:
    python main.py web                          # 웹 GUI 실행
    python main.py scan <csv_file>              # CLI 스캔 실행
    python main.py scan <csv_file> --single    # 단일 IP만 스캔 (확장 안함)
    python main.py scan <csv_file> --tcp       # TCP Connect 스캔 사용
    python main.py report <results_file>        # 보고서만 생성
    python main.py generate-scripts            # 점검 스크립트 생성
"""

import argparse
import json
import os
import socket
import sys
from pathlib import Path

# 프로젝트 루트를 Python 경로에 추가
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port

def run_web_gui():
    """웹 GUI 실행"""
    print("🌐 GovScan 웹 서버를 시작합니다...")
    
    port = find_free_port()
    print(f"   접속 주소: http://localhost:{port}")  # 실제 포트 번호 표시
    print("   종료하려면 Ctrl+C를 누르세요")
    print()
    
    try:
        # 현재 디렉토리 구조에 맞게 import 경로 수정
        import sys
        from pathlib import Path

        # web_server.py가 있는 위치 확인
        web_server_path = Path(__file__).parent / "web_server.py"
        backend_web_server_path = Path(__file__).parent / "backend" / "web_server.py"
        
        if web_server_path.exists():
            # 현재 디렉토리에 web_server.py가 있는 경우
            from web_server import app
            print(f"✅ 웹 서버 모듈 로드 완료: {web_server_path}")
        elif backend_web_server_path.exists():
            # backend 디렉토리에 있는 경우
            from backend.web_server import app
            print(f"✅ 웹 서버 모듈 로드 완료: {backend_web_server_path}")
        else:
            print("❌ web_server.py 파일을 찾을 수 없습니다.")
            print("   다음 위치 중 하나에 파일이 있는지 확인하세요:")
            print(f"   - {web_server_path}")
            print(f"   - {backend_web_server_path}")
            return False
        
        # Flask 앱 실행
        app.run(host='0.0.0.0', port=port, debug=False)
        return True
        
    except ImportError as e:
        print(f"❌ 웹 서버 모듈 import 오류: {e}")
        print("   다음 사항을 확인하세요:")
        print("   1. Flask가 설치되어 있는지: pip install Flask")
        print("   2. 필요한 backend 모듈들이 존재하는지")
        print("   3. 파일 권한 및 경로 문제")
        return False
        
    except Exception as e:
        print(f"❌ 웹 서버 실행 오류: {e}")
        print(f"   오류 유형: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False


def run_cli_scan(input_file: str, scan_name: str = None, single_ip: bool = False, 
                 use_tcp: bool = False, ports: str = "1-1024"):
    """CLI 모드로 전체 스캔 실행 - 동적 파일 경로 지원"""
    from datetime import datetime
    import shutil
    
    if not Path(input_file).exists():
        print(f"❌ 입력 파일을 찾을 수 없습니다: {input_file}")
        return False
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_id = scan_name or f"cli_scan_{timestamp}"
    
    print(f"🚀 CLI 스캔을 시작합니다: {scan_id}")
    print(f"   입력 파일: {input_file}")
    if single_ip:
        print("   모드: 단일 IP만 스캔 (확장 안함)")
    if use_tcp:
        print("   스캔 타입: TCP Connect 스캔")
    print()
    
    try:
        # 1. IP 추출
        print("📥 1단계: IP 대역 추출 중...")
        from backend.extract_ip.extractor import extract_ip_ranges
        
        ip_count = extract_ip_ranges(
            file_path=input_file,
            output_path=f"data/ip_ranges/ip_list_{scan_id}.txt",
            cidr_output_path=f"data/ip_ranges/ip_cidr_{scan_id}.txt",
            expand_single_ip=not single_ip  # single_ip가 True면 확장 안함
        )
        
        if ip_count == 0:
            print("❌ 추출된 IP가 없습니다.")
            return False
            
        print(f"   ✅ {ip_count}개 IP 추출 완료")
        
        # CIDR 파일이 비어있는지 확인
        cidr_file = f"data/ip_ranges/ip_cidr_{scan_id}.txt"
        if not Path(cidr_file).exists() or Path(cidr_file).stat().st_size == 0:
            print("❌ CIDR 파일이 비어있습니다. IP 추출을 확인하세요.")
            return False
        
        # 2. Nmap 스캔
        print("🔍 2단계: Nmap 스캔 중...")
        from backend.scanner.nmap_runner import run_nmap_scan
        
        scan_type = "-sT" if use_tcp else "-sS"
        
        nmap_result = run_nmap_scan(
            input_file=cidr_file,
            output_dir=f"data/scan_results/{scan_id}",
            ports=ports,
            scan_type=scan_type,
            additional_args="-sV -sC -A -T4"
        )
        
        if not nmap_result:
            print("❌ Nmap 스캔 실패")
            return False
        print("   ✅ Nmap 스캔 완료")
        
        # 3. XML 파싱
        print("🧠 3단계: 스캔 결과 분석 중...")
        from backend.mmdb.mmdb_converter import parse_nmap_xml
        
        xml_file = f"{nmap_result}.xml"
        if not Path(xml_file).exists():
            print(f"❌ XML 파일을 찾을 수 없습니다: {xml_file}")
            return False
        
        # XML 파일 크기 확인
        xml_size = Path(xml_file).stat().st_size
        print(f"   📏 XML 파일 크기: {xml_size} bytes")
        
        # 스캔별 파싱 파일 생성
        scan_parsed_file = f"data/mmdb/scan_parsed_{scan_id}.json"
        parse_nmap_xml(
            xml_path=xml_file,
            output_path=scan_parsed_file
        )
        
        # 파싱 결과 확인
        if not Path(scan_parsed_file).exists():
            print("❌ XML 파싱 실패 - 결과 파일이 생성되지 않았습니다.")
            return False
        
        parsed_size = Path(scan_parsed_file).stat().st_size
        print(f"   ✅ XML 파싱 완료 - 결과 파일 크기: {parsed_size} bytes")
        
        if parsed_size == 0:
            print("   ⚠️  파싱 결과가 비어있습니다!")
        
        # 4. 취약점 분석 (동적 파일 사용)
        print("🔒 4단계: 취약점 분석 중...")
        
        try:
            # 스캔별 파일을 기본 파일로 복사 (기존 core.py 호환성)
            default_parsed_file = "data/mmdb/scan_parsed.json"
            shutil.copy2(scan_parsed_file, default_parsed_file)
            print(f"   📋 파싱 파일 복사: {scan_parsed_file} → scan_parsed.json")
            
            from backend.vuln_checker.core import run_all_checks
            analysis_results = run_all_checks()
            
            # 결과 검증 및 처리
            if not analysis_results:
                print("   ⚠️  분석 결과가 비어있어 기본 구조를 생성합니다...")
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
                # 분석 결과에 메타데이터 추가
                if isinstance(analysis_results, dict):
                    analysis_results["timestamp"] = datetime.now().isoformat()
                    analysis_results["source_file"] = scan_parsed_file
                    print(f"   📊 분석 결과 키 개수: {len(analysis_results)}")
                elif isinstance(analysis_results, list):
                    print(f"   📊 분석 결과 항목 개수: {len(analysis_results)}")
            
        except ImportError as e:
            print(f"   ❌ 취약점 분석 모듈 import 오류: {e}")
            analysis_results = {
                "scan_summary": {"total_hosts": 0, "total_vulnerabilities": 0},
                "vulnerabilities": [],
                "status": "module_import_error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            print(f"   ❌ 취약점 분석 오류: {e}")
            analysis_results = {
                "scan_summary": {"total_hosts": 0, "total_vulnerabilities": 0},
                "vulnerabilities": [],
                "status": "analysis_error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        
        # 분석 결과 저장
        results_path = f"data/reports/analysis_results_{scan_id}.json"
        Path(results_path).parent.mkdir(parents=True, exist_ok=True)
        with open(results_path, 'w', encoding='utf-8') as f:
            json.dump(analysis_results, f, indent=2, ensure_ascii=False)
        
        # 저장된 파일 크기 확인
        result_size = Path(results_path).stat().st_size
        print(f"   ✅ 취약점 분석 완료 - 결과 파일 크기: {result_size} bytes")
        
        # 5. 보고서 생성
        print("📊 5단계: 보고서 생성 중...")
        from backend.report.generator import generate_comprehensive_report
        
        scan_info = {
            "ip_range": f"{ip_count}개 IP",
            "scan_date": datetime.now().isoformat()
        }
        
        report_package = generate_comprehensive_report(
            results_path=results_path,
            eval_db_path="data/db/eval_db.json",
            output_dir=f"data/reports/{scan_id}",
            scan_info=scan_info
        )
        print("   ✅ 보고서 생성 완료")
        
        print()
        print("🎉 스캔이 완료되었습니다!")
        print("📄 생성된 파일들:")
        print(f"   - 스캔 파싱 결과: {scan_parsed_file}")
        print(f"   - 취약점 분석 결과: {results_path}")
        for key, path in report_package.items():
            if key != "timestamp":
                print(f"   - {key}: {path}")
        
        return True
        
    except Exception as e:
        print(f"❌ 스캔 실행 오류: {e}")
        import traceback
        traceback.print_exc()
        return False


def generate_report_only(results_file: str, output_dir: str = None):
    """기존 분석 결과로 보고서만 생성"""
    if not Path(results_file).exists():
        print(f"❌ 결과 파일을 찾을 수 없습니다: {results_file}")
        return False
    
    from datetime import datetime
    
    if not output_dir:
        output_dir = f"data/reports/report_only_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print(f"📊 보고서를 생성합니다...")
    print(f"   입력: {results_file}")
    print(f"   출력: {output_dir}")
    
    try:
        from backend.report.generator import generate_comprehensive_report
        
        scan_info = {
            "ip_range": "기존 스캔 결과",
            "scan_date": datetime.now().isoformat()
        }
        
        report_package = generate_comprehensive_report(
            results_path=results_file,
            eval_db_path="data/db/eval_db.json",
            output_dir=output_dir,
            scan_info=scan_info
        )
        
        print("🎉 보고서 생성이 완료되었습니다!")
        print("📄 생성된 파일들:")
        for key, path in report_package.items():
            if key != "timestamp":
                print(f"   - {key}: {path}")
        
        return True
        
    except Exception as e:
        print(f"❌ 보고서 생성 오류: {e}")
        return False


def generate_scripts():
    """점검 스크립트 생성"""
    print("🔧 점검 스크립트를 생성합니다...")
    
    try:
        from backend.report.script_generator import generate_check_scripts
        
        generate_check_scripts(
            eval_db_path="data/db/eval_db.json",
            output_dir="data/scripts"
        )
        
        print("🎉 점검 스크립트 생성이 완료되었습니다!")
        print("📂 생성 위치: data/scripts/")
        
        return True
        
    except Exception as e:
        print(f"❌ 스크립트 생성 오류: {e}")
        return False


def setup_directories():
    """필요한 디렉토리 생성"""
    directories = [
        "data/input",
        "data/ip_ranges", 
        "data/scan_results",
        "data/mmdb",
        "data/reports",
        "data/scripts",
        "data/uploads"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)


def check_dependencies():
    """필수 의존성 확인"""
    required_modules = [
        ("jinja2", "Jinja2"),
        ("pandas", "pandas"),
        ("packaging", "packaging")
    ]
    
    missing_modules = []
    
    for module_name, pip_name in required_modules:
        try:
            __import__(module_name)
        except ImportError:
            missing_modules.append(pip_name)
    
    if missing_modules:
        print("❌ 다음 Python 패키지가 필요합니다:")
        for module in missing_modules:
            print(f"   - {module}")
        print(f"\n설치 명령: pip install {' '.join(missing_modules)}")
        return False
    
    return True


def check_nmap():
    """Nmap 설치 확인"""
    import subprocess
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"✅ Nmap 확인: {version_line}")
            return True
        else:
            return False
    except:
        return False


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description="GovScan - 정부기관 네트워크 보안점검 자동화 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python main.py web                                      # 웹 GUI 실행
  python main.py scan data/input/network.csv              # CLI 스캔 실행
  python main.py scan network.csv --single               # 단일 IP만 (확장 안함)
  python main.py scan network.csv --tcp                  # TCP Connect 스캔
  sudo python main.py scan network.csv                   # SYN 스캔 (권한 필요)
  python main.py report data/reports/results.json        # 보고서만 생성
  python main.py generate-scripts                        # 점검 스크립트 생성
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='실행할 명령')
    
    # 웹 GUI 명령
    web_parser = subparsers.add_parser('web', help='웹 GUI 실행')
    
    # CLI 스캔 명령
    scan_parser = subparsers.add_parser('scan', help='CLI 모드로 스캔 실행')
    scan_parser.add_argument('input_file', help='IP 관리대장 CSV/Excel 파일')
    scan_parser.add_argument('-n', '--name', help='스캔 이름')
    scan_parser.add_argument('--single', action='store_true', 
                           help='단일 IP만 스캔 (C클래스로 확장하지 않음)')
    scan_parser.add_argument('--tcp', action='store_true', 
                           help='TCP Connect 스캔 사용 (권한 불필요)')
    scan_parser.add_argument('-p', '--ports', default='1-1024',
                           help='스캔할 포트 범위 (기본: 1-1024)')
    
    # 보고서 생성 명령
    report_parser = subparsers.add_parser('report', help='기존 결과로 보고서 생성')
    report_parser.add_argument('results_file', help='분석 결과 JSON 파일')
    report_parser.add_argument('-o', '--output', help='출력 디렉토리')
    
    # 스크립트 생성 명령
    scripts_parser = subparsers.add_parser('generate-scripts', help='점검 스크립트 생성')
    scripts_parser.add_argument('--backup', action='store_true', help='기존 43개 스크립트 백업')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # 기본 설정
    setup_directories()
    
    print("=" * 60)
    print("🛡️  GovScan - 정부기관 네트워크 보안점검 자동화 도구")
    print("=" * 60)
    print()
    
    # 의존성 확인
    if not check_dependencies():
        sys.exit(1)
    
    # Nmap 확인 (스캔 명령어인 경우에만)
    if args.command == 'scan':
        if not check_nmap():
            print("❌ Nmap이 설치되어 있지 않습니다.")
            print("🔧 설치 방법:")
            print("   Ubuntu/Debian: sudo apt-get install nmap")
            print("   CentOS/RHEL: sudo yum install nmap") 
            print("   macOS: brew install nmap")
            print("   Windows: https://nmap.org/download.html")
            sys.exit(1)
        
        # 권한 확인 및 안내
        if not args.tcp and os.name != 'nt':  # Windows가 아니고 TCP 옵션이 아닌 경우
            if os.geteuid() != 0:  # root가 아닌 경우
                print("⚠️  현재 관리자 권한이 없습니다.")
                print("🔧 권한 해결 방법:")
                print("   1. 관리자 권한으로 실행: sudo python main.py scan ...")
                print("   2. TCP Connect 스캔 사용: python main.py scan ... --tcp")
                print("   3. 계속 진행하면 자동으로 TCP 스캔으로 변경됩니다.")
                print()
    
    success = False
    
    try:
        if args.command == 'web':
            success = run_web_gui()
        
        elif args.command == 'scan':
            success = run_cli_scan(
                input_file=args.input_file, 
                scan_name=args.name,
                single_ip=args.single,
                use_tcp=args.tcp,
                ports=args.ports
            )
        
        elif args.command == 'report':
            success = generate_report_only(args.results_file, args.output)
        
        elif args.command == 'generate-scripts':
            # --backup 옵션 처리
            if hasattr(args, 'backup') and args.backup:
                from backend.report.script_generator import \
                    copy_all_existing_scripts
                copy_all_existing_scripts()
            
            success = generate_scripts()
        
        else:
            print(f"❌ 알 수 없는 명령: {args.command}")
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n\n⏹️  사용자에 의해 중단되었습니다.")
        success = True  # 정상 종료로 처리
        
    except Exception as e:
        print(f"\n❌ 예상치 못한 오류가 발생했습니다: {e}")
        import traceback
        traceback.print_exc()
        success = False
    
    print("\n" + "=" * 60)
    if success:
        print("✅ 작업이 성공적으로 완료되었습니다.")
    else:
        print("❌ 작업이 실패했습니다.")
    print("=" * 60)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()