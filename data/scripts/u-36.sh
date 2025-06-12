#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-36 - Apache 데몬 root 권한 구동
# 설명: Apache 웹 서버가 root 권한으로 구동되는 경우
# 원본 스크립트: u-36.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-36 - Apache 데몬 root 권한 구동"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-36 Apache 데몬 root 권한 구동 여부 점검 시작===="

vulnerable=0

# Apache 설정 파일 위치 예시 (환경에 따라 조정 필요)
apache_conf="/etc/httpd/conf/httpd.conf"
[ ! -f "$apache_conf" ] && apache_conf="/usr/local/apache2/conf/httpd.conf"

if [ -f "$apache_conf" ]; then
    user_line=$(grep -i '^User' "$apache_conf" | grep -v '^#')
    group_line=$(grep -i '^Group' "$apache_conf" | grep -v '^#')

    user=$(echo "$user_line" | awk '{print $2}')
    group=$(echo "$group_line" | awk '{print $2}')

    echo "설정된 User: $user"
    echo "설정된 Group: $group"

    if [ "$user" = "root" ] || [ "$group" = "root" ]; then
        vulnerable=1
    fi
else
    echo "Apache 설정 파일을 찾을 수 없습니다: $apache_conf"
    vulnerable=-1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-36] Safe"
else
    echo "[U-36] Vulnerable"
    if [ "$vulnerable" -eq -1 ]; then
        echo -e "\t ↳ Apache 설정 파일을 찾을 수 없습니다: $apache_conf"
    else
        echo -e "\t ↳ Apache 데몬이 root 권한(User/Group)으로 설정되어 있습니다."
    fi
fi

echo "====[Info] U-36 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. Apache User/Group을 root 이외로 설정"
echo "   2. apache 전용 계정 생성 및 사용"
echo "   3. 웹 서버 프로세스 권한 최소화"
echo "   4. 웹 서버 보안 강화 설정"



echo ""
echo "🛠️  조치 방법:"
echo "   Apache를 전용 사용자 계정으로 실행해야 합니다."


echo "🎯 GovScan 점검 완료: u-36 - Apache 데몬 root 권한 구동"
echo "📅 실행 시간: $(date)"
