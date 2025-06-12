#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-07 - /etc/passwd 파일 소유자 및 권한 설정
# 설명: /etc/passwd 파일의 소유자가 root가 아니거나 권한이 부적절한 경우
# 원본 스크립트: u-07.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-07 - /etc/passwd 파일 소유자 및 권한 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-07 /etc/passwd파일 소유자 및 권한 설정 점검 시작===="

passwd_file="/etc/passwd"

if [ -e $passwd_file ]; then
    # 파일의 권한과 소유자 정보 가져오기
    file_stat=$(stat -c "%a %U" $passwd_file 2>/dev/null)
    file_perm=$(echo $file_stat | awk '{print $1}')
    file_owner=$(echo $file_stat | awk '{print $2}')

    echo "[+] /etc/passwd 권한 : $file_perm"
    echo "[+] /etc/passwd 소유자 : $file_owner"

    # 판단 기준: 소유자 root && 권한 644 이하
    if [ "$file_owner" == "root" ] && [ "$file_perm" -le 644 ]; then
        echo "[U-07] Safe"
    else
        echo "[U-07] Vulnerable"
        if [ "$file_owner" != "root" ]; then
            echo -e "\t ↳ 소유자가 root가 아님"
        fi
        if [ "$file_perm" -gt 644 ]; then
            echo -e "\t ↳ 권한이 644 초과"
        fi
    fi
else
    echo "[U-07] Vulnerable"
    echo "[!] /etc/passwd 파일이 존재하지 않습니다."
fi

echo "====[Info] U-07 done===="



echo "📋 점검 체크리스트:"
echo "   1. /etc/passwd 파일 소유자 root 확인"
echo "   2. /etc/passwd 파일 권한 644 이하 확인"
echo "   3. 파일 무결성 모니터링 설정"
echo "   4. 정기적인 파일 권한 점검"



echo ""
echo "🛠️  조치 방법:"
echo "   /etc/passwd 파일의 소유자를 root로 설정하고 권한을 644 이하로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-07 - /etc/passwd 파일 소유자 및 권한 설정"
echo "📅 실행 시간: $(date)"
