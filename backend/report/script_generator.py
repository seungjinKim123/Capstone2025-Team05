import json
import os
import shutil
from pathlib import Path


def generate_check_scripts(eval_db_path: str = "data/db/eval_db.json", 
                          output_dir: str = "data/scripts",
                          existing_scripts_dir: str = "data/db/scripts") -> None:
    """
    eval_db.json을 기반으로 점검 스크립트 파일들을 생성
    기존 43개 스크립트(U-01~U-43)를 활용하고, 없으면 자동 생성
    """
    with open(eval_db_path, 'r', encoding='utf-8') as f:
        eval_db = json.load(f)
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    existing_scripts_path = Path(existing_scripts_dir)
    
    # 전체 스크립트 매핑 (U-01 ~ U-43)
    script_mapping = create_complete_script_mapping()
    
    copied_count = 0
    generated_count = 0
    
    print("🔍 기존 스크립트 검색 중...")
    available_scripts = list(existing_scripts_path.glob("u-*.sh")) if existing_scripts_path.exists() else []
    print(f"📁 발견된 스크립트: {len(available_scripts)}개")
    
    for rule_code, rule_info in eval_db.items():
        script_name = rule_info.get("check_script", f"check_{rule_code}.sh")
        script_path = output_path / script_name
        
        # 1. 기존 스크립트가 있는지 확인
        existing_script = find_existing_script(rule_code, existing_scripts_path, script_mapping)
        
        if existing_script and existing_script.exists():
            # 기존 스크립트를 복사하고 헤더 추가
            copy_and_enhance_existing_script(existing_script, script_path, rule_code, rule_info)
            copied_count += 1
            print(f"✅ 기존 스크립트 활용: {rule_code} → {existing_script.name}")
        else:
            # 자동 생성
            script_content = generate_script_content(rule_code, rule_info)
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(script_content)
            generated_count += 1
            print(f"🔧 자동 생성: {rule_code} → {script_name}")
        
        # 실행 권한 부여 (Unix 계열)
        try:
            os.chmod(script_path, 0o755)
        except:
            pass
    
    print(f"\n✅ 점검 스크립트 생성 완료: {output_dir}")
    print(f"   📋 기존 스크립트 활용: {copied_count}개")
    print(f"   🔧 자동 생성: {generated_count}개")
    print(f"   📂 총 스크립트: {copied_count + generated_count}개")


def create_complete_script_mapping():
    """
    전체 43개 스크립트와 GovScan 규칙의 완전한 매핑 관계
    """
    return {
        # 기본 보안 정책 매핑
        "11303": ["u-06.sh"],  # 관리대장 누락 ← 파일 소유자 관련
        "20501": ["u-01.sh", "u-20.sh"],  # 접근통제 미흡 ← SSH/Telnet + 익명 FTP
        "20502": ["u-01.sh"],  # SSH 약한 인증 ← SSH 루트 접속
        "20503": ["u-19.sh", "u-21.sh", "u-23.sh", "u-29.sh"],  # 취약한 서비스 ← finger, r-command, DoS취약서비스, tftp/talk
        "30301": ["u-06.sh"],  # 네트워크 관리대장 ← 파일 소유자 관련
        "30501": ["u-19.sh", "u-23.sh", "u-24.sh", "u-26.sh", "u-27.sh", "u-28.sh", "u-29.sh"],  # 불필요한 서비스
        "30601": [],  # SNMP 보안 (자동 생성)
        "30701": ["u-35.sh", "u-36.sh", "u-37.sh", "u-38.sh", "u-39.sh", "u-40.sh", "u-41.sh"],  # 웹 서버 보안
        "30802": [],  # 버전 정보 노출 (자동 생성)
        "40101": ["u-42.sh"],  # 패치 관리

        # 직접 매핑 (U-01 ~ U-43)
        "u-01": ["u-01.sh"],   # root 계정 원격 접속 제한
        "u-02": ["u-02.sh"],   # 패스워드 복잡성 설정
        "u-03": ["u-03.sh"],   # 계정 잠금 임계값 설정
        "u-04": ["u-04.sh"],   # 패스워드 파일 보호
        "u-05": ["u-05.sh"],   # root 권한 및 패스 설정
        "u-06": ["u-06.sh"],   # 파일 및 디렉터리 소유자 설정
        "u-07": ["u-07.sh"],   # /etc/passwd 파일 권한
        "u-08": ["u-08.sh"],   # /etc/shadow 파일 권한
        "u-09": ["u-09.sh"],   # /etc/hosts 파일 권한
        "u-10": ["u-10.sh"],   # /etc/inetd.conf 파일 권한
        "u-11": ["u-11.sh"],   # /etc/syslog 파일 권한
        "u-12": ["u-12.sh"],   # /etc/services 파일 권한
        "u-13": ["u-13.sh"],   # SUID/SGID 설정 파일 점검
        "u-14": ["u-14.sh"],   # 사용자 홈 디렉터리 파일 점검
        "u-15": ["u-15.sh"],   # world writable 파일 점검
        "u-16": ["u-16.sh"],   # /dev에 존재하지 않는 device 파일
        "u-17": ["u-17.sh"],   # rhosts, hosts.equiv 사용 금지
        "u-18": ["u-18.sh"],   # 접속 IP 및 포트 제한
        "u-19": ["u-19.sh"],   # finger 서비스 비활성화
        "u-20": ["u-20.sh"],   # 익명 FTP 접속 허용 여부
        "u-21": ["u-21.sh"],   # r-command 서비스 비활성화
        "u-22": ["u-22.sh"],   # Cron 관련 파일의 권한
        "u-23": ["u-23.sh"],   # DoS 공격 취약 서비스 실행 여부
        "u-24": ["u-24.sh"],   # 불필요한 NFS 서비스 사용 여부
        "u-25": ["u-25.sh"],   # NFS everyone 공유 제한 설정
        "u-26": ["u-26.sh"],   # automountd 서비스 데몬 실행 여부
        "u-27": ["u-27.sh"],   # 불필요한 RPC 서비스 실행 여부
        "u-28": ["u-28.sh"],   # NIS 서비스 비활성화
        "u-29": ["u-29.sh"],   # tftp, talk, ntalk 서비스 활성화 여부
        "u-30": ["u-30.sh"],   # Sendmail 서비스 취약 버전
        "u-31": ["u-31.sh"],   # SMTP 릴레이 제한 설정
        "u-32": ["u-32.sh"],   # SMTP 일반사용자 q 옵션 제한
        "u-33": ["u-33.sh"],   # BIND 최신 버전 사용 및 패치
        "u-34": ["u-34.sh"],   # DNS Zone Transfer 제한 설정
        "u-35": ["u-35.sh"],   # 웹 디렉터리 검색 기능 제한
        "u-36": ["u-36.sh"],   # Apache 데몬 root 권한 구동
        "u-37": ["u-37.sh"],   # 상위 디렉터리 접근 제한 설정
        "u-38": ["u-38.sh"],   # Apache 불필요한 기본 파일/디렉터리
        "u-39": ["u-39.sh"],   # 심볼릭 링크 사용 제한
        "u-40": ["u-40.sh"],   # 파일 업로드/다운로드 사이즈 제한
        "u-41": ["u-41.sh"],   # 웹 루트 디렉터리 분리 설정
        "u-42": ["u-42.sh"],   # 최신 패치 적용 여부
        "u-43": ["u-43.sh"],   # 로그 정기 검토 여부

        # 그룹별 매핑
        "password_security": ["u-02.sh", "u-03.sh", "u-04.sh", "u-05.sh"],
        "file_permissions": ["u-07.sh", "u-08.sh", "u-09.sh", "u-10.sh", "u-11.sh", "u-12.sh"],
        "access_control": ["u-01.sh", "u-17.sh", "u-18.sh", "u-20.sh"],
        "network_services": ["u-19.sh", "u-21.sh", "u-23.sh", "u-24.sh", "u-25.sh", "u-26.sh", "u-27.sh", "u-28.sh", "u-29.sh"],
        "mail_dns_services": ["u-30.sh", "u-31.sh", "u-32.sh", "u-33.sh", "u-34.sh"],
        "web_security": ["u-35.sh", "u-36.sh", "u-37.sh", "u-38.sh", "u-39.sh", "u-40.sh", "u-41.sh"],
        "system_management": ["u-13.sh", "u-14.sh", "u-15.sh", "u-16.sh", "u-22.sh", "u-42.sh", "u-43.sh"]
    }


def find_existing_script(rule_code: str, scripts_dir: Path, mapping: dict):
    """
    규칙 코드에 해당하는 기존 스크립트를 찾기
    """
    if rule_code in mapping and mapping[rule_code]:
        # 첫 번째 매핑된 스크립트를 우선 사용
        script_name = mapping[rule_code][0]
        script_path = scripts_dir / script_name
        if script_path.exists():
            return script_path
    
    # U-XX 형태의 직접 매핑 확인
    if rule_code.startswith('u-'):
        script_path = scripts_dir / f"{rule_code}.sh"
        if script_path.exists():
            return script_path
    
    # 패턴으로 찾기
    patterns = [
        f"{rule_code.lower()}.sh",
        f"u-{rule_code[-2:]}.sh" if len(rule_code) >= 2 else f"u-{rule_code}.sh",
        f"check_{rule_code}.sh"
    ]
    
    for pattern in patterns:
        script_path = scripts_dir / pattern
        if script_path.exists():
            return script_path
    
    return None


def copy_and_enhance_existing_script(source_script: Path, target_script: Path, 
                                   rule_code: str, rule_info: dict):
    """
    기존 스크립트를 복사하고 GovScan 형식에 맞게 헤더 추가
    """
    with open(source_script, 'r', encoding='utf-8') as f:
        original_content = f.read()
    
    # GovScan 헤더 생성
    header = generate_govscan_header(rule_code, rule_info, source_script.name)
    
    # 체크리스트 섹션 생성
    checklist_section = generate_checklist_section(rule_info)
    
    # 조치방법 섹션 생성
    mitigation_section = generate_mitigation_section(rule_info)
    
    # 최종 스크립트 내용 구성
    enhanced_content = f"""{header}

{original_content}

{checklist_section}

{mitigation_section}

echo "🎯 GovScan 점검 완료: {rule_code} - {rule_info.get('name', '')}"
echo "📅 실행 시간: $(date)"
"""
    
    with open(target_script, 'w', encoding='utf-8') as f:
        f.write(enhanced_content)


def generate_govscan_header(rule_code: str, rule_info: dict, original_filename: str):
    """
    GovScan 형식의 헤더 생성
    """
    name = rule_info.get("name", "")
    description = rule_info.get("description", "")
    
    return f"""#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: {rule_code} - {name}
# 설명: {description}
# 원본 스크립트: {original_filename}
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: {rule_code} - {name}"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="
"""


def generate_checklist_section(rule_info: dict):
    """
    체크리스트 섹션 생성
    """
    checklist_items = rule_info.get("checklist_items", [])
    if not checklist_items:
        return ""
    
    section = "\necho \"📋 점검 체크리스트:\"\n"
    for i, item in enumerate(checklist_items, 1):
        section += f'echo "   {i}. {item}"\n'
    
    return section


def generate_mitigation_section(rule_info: dict):
    """
    조치방법 섹션 생성
    """
    mitigation = rule_info.get("general_mitigation", "")
    if not mitigation:
        return ""
    
    return f"""
echo ""
echo "🛠️  조치 방법:"
echo "   {mitigation}"
"""


def generate_script_content(rule_code: str, rule_info: dict) -> str:
    """
    기존 스크립트가 없을 때 자동 생성하는 스크립트 내용
    """
    name = rule_info.get("name", "")
    description = rule_info.get("description", "")
    mitigation = rule_info.get("general_mitigation", "")
    checklist = rule_info.get("checklist_items", [])
    
    script_content = f"""#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트 (자동생성)
# ==========================================
# 점검 항목: {rule_code} - {name}
# 설명: {description}
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: {rule_code} - {name}"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="

# 점검 대상 정보 수집
if [ "$#" -ne 1 ]; then
    echo "사용법: $0 <target_ip>"
    echo "예시: $0 192.168.1.100"
    exit 1
fi

TARGET_IP=$1
echo "🎯 점검 대상 IP: $TARGET_IP"
echo

"""

    # 규칙별 특화된 점검 로직 추가
    if rule_code in ["11303", "30301"]:
        script_content += """
# 관리대장 점검
echo "1. 자산 관리대장 점검"
nmap -sn $TARGET_IP > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ 호스트 $TARGET_IP가 활성 상태입니다."
    echo "❌ 관리대장 등록 여부를 수동으로 확인하세요."
else
    echo "❌ 호스트 $TARGET_IP에 접근할 수 없습니다."
fi
echo
"""

    elif rule_code == "30601":
        script_content += """
# SNMP 보안 설정 점검
echo "1. SNMP 서비스 확인"
nmap -sU -p 161 $TARGET_IP 2>/dev/null | grep -q "161/udp open"
if [ $? -eq 0 ]; then
    echo "✅ SNMP 서비스가 실행 중입니다."
    
    echo "2. 기본 커뮤니티 스트링 테스트"
    for community in public private admin manager; do
        if command -v snmpwalk >/dev/null 2>&1; then
            snmpwalk -v2c -c $community $TARGET_IP 1.3.6.1.2.1.1.1.0 2>/dev/null | grep -q "STRING"
            if [ $? -eq 0 ]; then
                echo "❌ 기본 커뮤니티 스트링 '$community'가 사용 중입니다."
            else
                echo "✅ 커뮤니티 스트링 '$community'는 사용되지 않습니다."
            fi
        else
            echo "⚠️  snmpwalk 명령어가 설치되지 않았습니다."
        fi
    done
else
    echo "❌ SNMP 서비스가 실행되지 않습니다."
fi
echo
"""

    elif rule_code == "30802":
        script_content += """
# 버전 정보 노출 점검
echo "1. HTTP 서버 버전 정보 확인"
if command -v curl >/dev/null 2>&1; then
    http_header=$(curl -I http://$TARGET_IP 2>/dev/null | grep -i "server:")
    if [ ! -z "$http_header" ]; then
        echo "❌ HTTP 서버 버전 정보가 노출됩니다: $http_header"
    else
        echo "✅ HTTP 서버 버전 정보가 숨겨져 있습니다."
    fi
else
    echo "⚠️  curl 명령어가 설치되지 않았습니다."
fi

echo "2. SSH 서버 버전 정보 확인"
if command -v ssh >/dev/null 2>&1; then
    ssh_version=$(timeout 3 ssh -o ConnectTimeout=3 $TARGET_IP exit 2>&1 | head -1)
    if [[ $ssh_version == *"OpenSSH"* ]]; then
        echo "❌ SSH 서버 버전 정보가 노출됩니다: $ssh_version"
    else
        echo "✅ SSH 서버 버전 정보가 적절히 설정되어 있습니다."
    fi
else
    echo "⚠️  ssh 명령어가 설치되지 않았습니다."
fi
echo
"""

    # 공통 체크리스트 추가
    if checklist:
        script_content += f"""
echo "📋 점검 체크리스트:"
"""
        for i, item in enumerate(checklist, 1):
            script_content += f'echo "   {i}. {item}"\n'
    
    # 조치방법 추가
    if mitigation:
        script_content += f"""
echo ""
echo "🛠️  조치 방법:"
echo "   {mitigation}"
"""

    script_content += f"""
echo ""
echo "🎯 GovScan 점검 완료: {rule_code} - {name}"
echo "📅 실행 시간: $(date)"
"""

    return script_content


def copy_all_existing_scripts(existing_scripts_dir: str = "data/db/scripts",
                             output_dir: str = "data/scripts") -> None:
    """
    기존 43개 스크립트를 모두 복사 (백업용)
    """
    existing_path = Path(existing_scripts_dir)
    output_path = Path(output_dir)
    
    if not existing_path.exists():
        print(f"⚠️  기존 스크립트 디렉토리가 없습니다: {existing_scripts_dir}")
        return
    
    output_path.mkdir(parents=True, exist_ok=True)
    backup_dir = output_path / "original_scripts"
    backup_dir.mkdir(exist_ok=True)
    
    copied_files = 0
    for script_file in existing_path.glob("u-*.sh"):
        target_file = backup_dir / script_file.name
        shutil.copy2(script_file, target_file)
        try:
            os.chmod(target_file, 0o755)
        except:
            pass
        copied_files += 1
    
    print(f"📋 기존 스크립트 백업 완료: {copied_files}개 → {backup_dir}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="🔧 GovScan 보안 점검 스크립트 생성기 (U-01~U-43 지원)")
    parser.add_argument("-e", "--eval_db", default="data/db/eval_db.json", help="평가 기준 JSON 파일")
    parser.add_argument("-o", "--output", default="data/scripts", help="스크립트 출력 디렉토리")
    parser.add_argument("-s", "--existing", default="data/db/scripts", help="기존 스크립트 디렉토리")
    parser.add_argument("--backup", action="store_true", help="기존 43개 스크립트 백업")
    
    args = parser.parse_args()
    
    if args.backup:
        copy_all_existing_scripts(args.existing, args.output)
    
    generate_check_scripts(args.eval_db, args.output, args.existing)