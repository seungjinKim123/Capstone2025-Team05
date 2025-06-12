#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-11 - /etc/syslog 파일 소유자 및 권한 설정
# 설명: 시스템 로그 설정 파일의 소유자가 root가 아니거나 권한이 부적절한 경우
# 원본 스크립트: u-11.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-11 - /etc/syslog 파일 소유자 및 권한 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-11 /etc/syslog 파일 점검 시작===="

FILES=("/etc/syslog.conf" "/etc/rsyslog.conf")
missing_count=0

for FILE in "${FILES[@]}"; do
    echo ""
    echo "→ 점검 대상 파일: $FILE"

    if [ ! -f "$FILE" ]; then
        echo "[!] 파일이 존재하지 않음 → 생략"
        missing_count=$((missing_count + 1))
        continue
    fi

    PERM=$(stat -c %a "$FILE")
    OWNER=$(stat -c %U "$FILE")
    GROUP=$(stat -c %G "$FILE")

    echo "   - 소유자: $OWNER"
    echo "   - 그룹: $GROUP"
    echo "   - 권한: $PERM"

    # 기준: 소유자 root/bin/sys 이고, 권한은 640 이하
    if { [ "$OWNER" = "root" ] || [ "$OWNER" = "bin" ] || [ "$OWNER" = "sys" ]; } && [ "$PERM" -le 640 ]; then
        echo -e "[U-11] Safe"
    else
        echo -e "[U-11] Vulnerable"
        if ! { [ "$OWNER" = "root" ] || [ "$OWNER" = "bin" ] || [ "$OWNER" = "sys" ]; }; then
            echo -e "\t- [경고] 소유자가 root/bin/sys 아님: $OWNER"
        fi
        if [ "$PERM" -gt 640 ]; then
            echo -e "\t- [경고] 권한이 640 초과: $PERM"
        fi
    fi
done

if [ "$missing_count" -eq "${#FILES[@]}" ]; then
    echo ""
    echo "[U-11] Vulnerable"
    echo -e "\t ↳ 로그 설정 파일이 모두 존재하지 않음."
    echo -e "\t ↳ 시스템 로그 설정이 누락되어 있을 수 있음."
    echo -e "\t ↳ 로깅 데몬 설치 및 설정 필요"
fi

echo ""
echo "====[Info] U-11 done===="


echo "📋 점검 체크리스트:"
echo "   1. /etc/syslog.conf 파일 소유자 및 권한 확인"
echo "   2. /etc/rsyslog.conf 파일 보안 설정"
echo "   3. 로그 파일 순환 정책 설정"
echo "   4. 로그 무결성 보호 방안 수립"



echo ""
echo "🛠️  조치 방법:"
echo "   로그 설정 파일의 소유자를 root로 설정하고 권한을 640 이하로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-11 - /etc/syslog 파일 소유자 및 권한 설정"
echo "📅 실행 시간: $(date)"
