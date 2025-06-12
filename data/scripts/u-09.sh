#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-09 - /etc/hosts 파일 소유자 및 권한 설정
# 설명: /etc/hosts 파일의 소유자가 root가 아니거나 권한이 부적절한 경우
# 원본 스크립트: u-09.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-09 - /etc/hosts 파일 소유자 및 권한 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-09 /etc/host 파일 소유자 및 권한 설정 점검 시작===="

TARGET_FILE="/etc/hosts"

# 파일 존재 여부 확인
if [ ! -f "$TARGET_FILE" ]; then
    echo "[U-09] 대상 파일이 존재하지 않습니다: $TARGET_FILE"
    echo "→ [U-09] 점검 불가"
    exit 1
fi

# 소유자 확인
owner=$(ls -l "$TARGET_FILE" | awk '{print $3}')
# 권한 확인 (8진수 형태로 추출)
perm=$(stat -c %a "$TARGET_FILE")

echo "파일 소유자: $owner"
echo "파일 권한: $perm"

vulnerable=0

# 조건 판단
if [ "$owner" != "root" ]; then
    echo -e "\t ↳ 소유자가 root가 아님"
    vulnerable=1
fi

if [ "$perm" -gt 600 ]; then
    echo -e "\t ↳ 권한이 600 초과"
    vulnerable=1
fi

echo ""

# 결과 출력
if [ $vulnerable -eq 0 ]; then
    echo "[U-09] Safe"
else
    echo "[U-09] Vulnerable"
fi

echo "====[Info] U-09 done===="



echo "📋 점검 체크리스트:"
echo "   1. /etc/hosts 파일 소유자 root 확인"
echo "   2. /etc/hosts 파일 권한 600 이하 확인"
echo "   3. hosts 파일 무단 수정 방지"
echo "   4. DNS 설정과 일치성 확인"



echo ""
echo "🛠️  조치 방법:"
echo "   /etc/hosts 파일의 소유자를 root로 설정하고 권한을 600 이하로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-09 - /etc/hosts 파일 소유자 및 권한 설정"
echo "📅 실행 시간: $(date)"
