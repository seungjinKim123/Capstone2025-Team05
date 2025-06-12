#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-12 - /etc/services 파일 소유자 및 권한 설정
# 설명: /etc/services 파일의 소유자가 적절하지 않거나 권한이 부적절한 경우
# 원본 스크립트: u-12.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-12 - /etc/services 파일 소유자 및 권한 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-12 /etc/services 권한 점검 시작===="

file="/etc/services"
is_safe=1

if [ ! -e "$file" ]; then
    echo "[U-12] $file 파일이 존재하지 않습니다."
    echo "[U-12] 점검 불가"
    exit 1
fi

# 소유자 및 권한 확인
perm=$(stat -c %a "$file")
owner=$(stat -c %U "$file")
group=$(stat -c %G "$file")

echo "파일 권한: $perm"
echo "소유자: $owner"
echo "그룹: $group"

# 조건 1: 소유자 (root 또는 bin 또는 sys)
if [[ "$owner" != "root" && "$owner" != "bin" && "$owner" != "sys" ]]; then
    echo -e "\t ↳ 소유자가 root/bin/sys가 아님"
    is_safe=0
fi

# 조건 2: 권한이 644 이하인지 확인
if [ "$perm" -gt 644 ]; then
    echo -e "\t ↳ 권한이 644 초과"
    is_safe=0
fi

# 최종 결과
if [ "$is_safe" -eq 1 ]; then
    echo -e "[U-12] Safe"
else
    echo -e "[U-12] Vulnerable"
fi

echo "====[Info] U-12 /etc/services 권한 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. /etc/services 파일 소유자 root/bin/sys 확인"
echo "   2. /etc/services 파일 권한 644 이하 확인"
echo "   3. 서비스 포트 정의 검토"
echo "   4. 불필요한 서비스 항목 제거"



echo ""
echo "🛠️  조치 방법:"
echo "   /etc/services 파일의 소유자를 root/bin/sys로 설정하고 권한을 644 이하로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-12 - /etc/services 파일 소유자 및 권한 설정"
echo "📅 실행 시간: $(date)"
