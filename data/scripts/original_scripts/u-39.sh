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
