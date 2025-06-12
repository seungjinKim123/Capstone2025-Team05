#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-39 - 심볼릭 링크 사용 제한
# 설명: 웹 서버에서 심볼릭 링크 사용이 제한되지 않은 경우
# 원본 스크립트: u-39.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-39 - 심볼릭 링크 사용 제한"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-39 심볼릭 링크(FollowSymLinks) 사용 제한 여부 점검 시작===="

vulnerable=0

# Apache 설정 파일 경로 예시 (환경에 따라 조정 가능)
apache_conf="/etc/httpd/conf/httpd.conf"
[ ! -f "$apache_conf" ] && apache_conf="/usr/local/apache2/conf/httpd.conf"

if [ -f "$apache_conf" ]; then
    # FollowSymLinks 설정 여부 확인 (주석 제외)
    if grep -E '^\s*Options\s+.*FollowSymLinks' "$apache_conf" | grep -v '^#' > /dev/null; then
        echo "심볼릭 링크 허용 옵션(FollowSymLinks)이 설정되어 있습니다."
        vulnerable=1
    else
        echo "FollowSymLinks 옵션이 설정되어 있지 않거나 주석 처리되어 있습니다."
    fi
else
    echo "Apache 설정 파일을 찾을 수 없습니다: $apache_conf"
    vulnerable=1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-39] Safe"
else
    echo "[U-39] Vulnerable"
    echo -e "\t ↳ httpd.conf에 FollowSymLinks 옵션이 활성화되어 있어 심볼릭 링크를 허용하는 설정입니다."
fi

echo "====[Info] U-39 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. Options에서 FollowSymLinks 제거"
echo "   2. SymLinksIfOwnerMatch 사용 검토"
echo "   3. 웹 디렉터리 심볼릭 링크 점검"
echo "   4. 파일 시스템 접근 제어 강화"



echo ""
echo "🛠️  조치 방법:"
echo "   FollowSymLinks 옵션을 비활성화하여 심볼릭 링크 사용을 제한해야 합니다."


echo "🎯 GovScan 점검 완료: u-39 - 심볼릭 링크 사용 제한"
echo "📅 실행 시간: $(date)"
