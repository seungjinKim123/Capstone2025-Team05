import argparse
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def run_nmap_scan(
    input_file: str = "data/ip_ranges/ip_cidr.txt",
    output_dir: str = "data/scan_results",
    ports: str = "1-1024",
    scan_type: str = "-sS",
    additional_args: str = "-sV -sC -A -T4",
    fallback_to_tcp: bool = True
) -> str:
    """
    지정된 IP 목록에 대해 Nmap 스캔을 수행하고 결과 파일 경로를 반환한다.
    
    Args:
        fallback_to_tcp: SYN 스캔 실패 시 TCP Connect 스캔으로 자동 변경
    """

    # 1. CIDR 대상 로딩
    with open(input_file, "r") as f:
        targets = [line.strip() for line in f if line.strip()]
    if not targets:
        raise ValueError("❌ 대상 IP가 없습니다.")

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_base = os.path.join(output_dir, f"scan_{timestamp}")

    # 2. 권한 확인 및 스캔 타입 조정
    original_scan_type = scan_type
    
    # Windows나 권한이 없는 경우 TCP Connect 스캔 사용
    if scan_type == "-sS":
        if os.name == 'nt':  # Windows
            print("🖥️  Windows 환경: TCP Connect 스캔으로 변경")
            scan_type = "-sT"
        elif os.geteuid() != 0:  # Linux/macOS에서 root가 아닌 경우
            if fallback_to_tcp:
                print("⚠️  관리자 권한 없음: TCP Connect 스캔으로 변경")
                scan_type = "-sT"
            else:
                print("❌ SYN 스캔을 위해 관리자 권한이 필요합니다.")
                print("   해결 방법:")
                print("   1. sudo python main.py scan ...")
                print("   2. 또는 --tcp 옵션 사용")
                return ""

    # 3. Nmap 명령어 구성
    cmd = [
        "nmap",
        scan_type,
        "-p", ports,
        *targets,
        *additional_args.split(),
        "-oA", output_base,  # .nmap, .xml, .gnmap
    ]

    print(f"🚀 실행 명령어: {' '.join(cmd)}")
    if original_scan_type != scan_type:
        print(f"📝 스캔 타입 변경: {original_scan_type} → {scan_type}")

    # 4. 실행
    try:
        subprocess.run(cmd, check=True)
        print(f"✅ 스캔 완료: {output_base}.[nmap|gnmap|xml]")
        return output_base
    except subprocess.CalledProcessError as e:
        if scan_type == "-sS" and fallback_to_tcp:
            print(f"⚠️  SYN 스캔 실패, TCP Connect 스캔으로 재시도...")
            return run_nmap_scan(
                input_file=input_file,
                output_dir=output_dir,
                ports=ports,
                scan_type="-sT",
                additional_args=additional_args,
                fallback_to_tcp=False  # 무한 재귀 방지
            )
        else:
            print(f"❌ Nmap 실행 실패: {e}")
            print("🔧 해결 방법:")
            print("   1. Nmap이 설치되어 있는지 확인: nmap --version")
            print("   2. 관리자 권한으로 실행: sudo python main.py scan ...")
            print("   3. TCP Connect 스캔 사용: --scan-type -sT")
            return ""
    except FileNotFoundError:
        print("❌ Nmap을 찾을 수 없습니다.")
        print("🔧 Nmap 설치 방법:")
        print("   Ubuntu/Debian: sudo apt-get install nmap")
        print("   CentOS/RHEL: sudo yum install nmap")
        print("   macOS: brew install nmap")
        print("   Windows: https://nmap.org/download.html")
        return ""


def check_nmap_privileges():
    """Nmap 실행 권한 확인"""
    try:
        # 간단한 권한 테스트
        result = subprocess.run(
            ["nmap", "-sS", "--help"], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        return result.returncode == 0
    except:
        return False


# 단독 실행 가능하게 CLI 모드 추가
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🔎 Nmap CIDR 스캐너")
    parser.add_argument("input_file", help="CIDR 대상 IP 파일 경로")
    parser.add_argument("-o", "--output_dir", default="data/scan_results", help="결과 저장 디렉토리")
    parser.add_argument("-p", "--ports", default="1-1024", help="스캔할 포트 범위")
    parser.add_argument("-t", "--scan_type", default="-sS", help="Nmap 스캔 타입 (예: -sS, -sT 등)")
    parser.add_argument("-a", "--additional_args", default="-sV -sC -A -T4", help="추가 Nmap 인자")
    parser.add_argument("--tcp", action="store_true", help="TCP Connect 스캔 강제 사용")

    args = parser.parse_args()

    if args.tcp:
        args.scan_type = "-sT"
        print("🔄 TCP Connect 스캔 모드로 설정")

    try:
        run_nmap_scan(
            input_file=args.input_file,
            output_dir=args.output_dir,
            ports=args.ports,
            scan_type=args.scan_type,
            additional_args=args.additional_args
        )
    except Exception as e:
        print(f"❌ 오류 발생: {e}")