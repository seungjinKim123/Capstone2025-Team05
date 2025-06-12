#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-08 - /etc/shadow 파일 소유자 및 권한 설정
# 설명: /etc/shadow 파일의 소유자가 root가 아니거나 권한이 부적절한 경우
# 원본 스크립트: u-08.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-08 - /etc/shadow 파일 소유자 및 권한 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-08 /etc/shadow 파일 소유자 및 권한 설정 점검 시작===="

SHADOW_FILE="/etc/shadow"

if [ ! -f "$SHADOW_FILE" ]; then
    echo "[U-08] /etc/shadow 파일이 존재하지 않습니다. → 점검 불가"
    exit 1
fi

owner=$(stat -c %U "$SHADOW_FILE")
perm=$(stat -c %a "$SHADOW_FILE")

is_safe=true

if [ "$owner" != "root" ]; then
    echo "[!] 소유자: $owner → root 아님"
    is_safe=false
fi

if [ "$perm" -gt 400 ]; then
    echo "[!] 권한: $perm → 400 초과"
    is_safe=false
fi

echo ""
if [ "$is_safe" = true ]; then
    echo -e "[U-08] Safe"
else
    echo -e "[U-08] Vulnerable"
    if [ "$owner" != "root" ]; then
        echo -e "\t ↳ 소유자가 root가 아님"
    fi
    if [ "$perm" -gt 400 ]; then
        echo -e "\t ↳ 권한이 400 초과"
    fi
fi

echo "====[Info] U-08 done===="



echo "📋 점검 체크리스트:"
echo "   1. /etc/shadow 파일 소유자 root 확인"
echo "   2. /etc/shadow 파일 권한 400 이하 확인"
echo "   3. 패스워드 파일 백업 관리"
echo "   4. 파일 접근 로그 모니터링"



echo ""
echo "🛠️  조치 방법:"
echo "   /etc/shadow 파일의 소유자를 root로 설정하고 권한을 400 이하로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-08 - /etc/shadow 파일 소유자 및 권한 설정"
echo "📅 실행 시간: $(date)"
