#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-10 - /etc/inetd.conf 파일 소유자 및 권한 설정
# 설명: inetd 관련 설정 파일의 소유자가 root가 아니거나 권한이 부적절한 경우
# 원본 스크립트: u-10.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-10 - /etc/inetd.conf 파일 소유자 및 권한 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-10 /etc/inetd.conf 파일 점검 시작===="

safe=0
vulnerable_list=()

# 점검 함수
check_permission() {
    file_path=$1
    if [ -f "$file_path" ]; then
        owner=$(stat -c %U "$file_path")
        perm=$(stat -c %a "$file_path")
        if [ "$owner" != "root" ] || [ "$perm" -gt 600 ]; then
            vulnerable_list+=("$file_path → owner: $owner / perm: $perm")
        fi
    fi
}

# 1. /etc/inetd.conf
check_permission "/etc/inetd.conf"

# 2. /etc/xinetd.conf
check_permission "/etc/xinetd.conf"

# 3. /etc/xinetd.d/*
if [ -d /etc/xinetd.d ]; then
    for f in /etc/xinetd.d/*; do
        [ -f "$f" ] && check_permission "$f"
    done
fi

# 결과 출력
echo ""
if [ ${#vulnerable_list[@]} -eq 0 ]; then
    echo -e "[U-10] Safe"
else
    echo -e "[U-10] Vulnerable"
    for item in "${vulnerable_list[@]}"; do
        echo -e "\t ↳ $item"
    done
fi

echo "====[Info] U-10 done===="



echo "📋 점검 체크리스트:"
echo "   1. /etc/inetd.conf 파일 소유자 root 확인"
echo "   2. /etc/xinetd.conf 및 /etc/xinetd.d/* 파일 권한 확인"
echo "   3. 불필요한 서비스 비활성화"
echo "   4. inetd 서비스 보안 설정"



echo ""
echo "🛠️  조치 방법:"
echo "   inetd 관련 설정 파일의 소유자를 root로 설정하고 권한을 600 이하로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-10 - /etc/inetd.conf 파일 소유자 및 권한 설정"
echo "📅 실행 시간: $(date)"
