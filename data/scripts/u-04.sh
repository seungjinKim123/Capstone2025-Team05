#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-04 - 패스워드 파일 보호
# 설명: Shadow 패스워드 사용 여부 및 패스워드 파일 보호 상태 점검
# 원본 스크립트: u-04.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-04 - 패스워드 파일 보호"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-04 패스워드 파일 보호 점검 시작===="

OS=$(uname -s)
shadow_file="/etc/shadow"
passwd_file="/etc/passwd"
hpux_passwd="/etc/security/passwd"

status="Safe"

# ===== SOLARIS / LINUX =====
if [[ "$OS" == "Linux" || "$OS" == "SunOS" ]]; then
    echo "[+] OS: $OS"

    if [ ! -f "$shadow_file" ]; then
        echo "[!] Shadow 파일이 존재하지 않습니다: $shadow_file"
        status="Vulnerable"
    else
        echo "[+] Shadow 파일 존재 확인됨"
    fi

    if [ -f "$passwd_file" ]; then
        plaintext=$(awk -F: '$2 !~ /^[x*]$/' "$passwd_file")
        if [ -n "$plaintext" ]; then
            status="Vulnerable"
            echo "[!] /etc/passwd 파일 내 일부 계정이 평문 또는 해시된 패스워드를 포함함"
        else
            echo "[+] /etc/passwd 파일 내 패스워드 필드가 적절하게 보호됨 (x)"
        fi
    else
        echo "[!] /etc/passwd 파일을 찾을 수 없습니다"
        status="Vulnerable"
    fi

# ===== HP-UX =====
elif [[ "$OS" == "HP-UX" ]]; then
    echo "[+] OS: HP-UX"
    if [ -f "$hpux_passwd" ]; then
        # 단순 파일 존재 여부 점검 (정교한 정규식 파싱 필요 시 추가 가능)
        encrypted_count=$(grep -E 'password.*=.*' "$hpux_passwd" | wc -l)
        if [ "$encrypted_count" -eq 0 ]; then
            echo "[!] 패스워드 설정이 누락되었거나 평문일 수 있음"
            status="Vulnerable"
        else
            echo "[+] /etc/security/passwd 내 패스워드 항목 존재 및 암호화 가능성 확인됨"
        fi
    else
        echo "[!] /etc/security/passwd 파일이 존재하지 않음"
        status="Vulnerable"
    fi

# ===== 기타 OS =====
else
    echo "[!] Unknown OS: $OS (점검 스크립트 미지원)"
    status="Unknown"
fi

echo ""

# ===== 결과 출력 =====
if [ "$status" == "Safe" ]; then
    echo "[U-04] Safe"
else
    echo "[U-04] Vulnerable"
fi

echo "====[Info] U-04 done===="



echo "📋 점검 체크리스트:"
echo "   1. /etc/shadow 파일 존재 확인"
echo "   2. /etc/passwd 파일에서 패스워드 필드 'x' 확인"
echo "   3. 패스워드 파일 권한 적절성 확인"
echo "   4. 평문 패스워드 사용 금지"



echo ""
echo "🛠️  조치 방법:"
echo "   Shadow 패스워드를 사용하고 패스워드 파일의 적절한 권한을 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-04 - 패스워드 파일 보호"
echo "📅 실행 시간: $(date)"
