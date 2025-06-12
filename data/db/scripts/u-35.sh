#!/bin/bash

echo "====[Info] U-35 디렉터리 검색 기능(Indexes 옵션) 점검 시작===="

vulnerable=0

# Apache 설정 파일 위치 예시 (환경에 따라 변경 가능)
apache_conf="/etc/httpd/conf/httpd.conf"
[ ! -f "$apache_conf" ] && apache_conf="/usr/local/apache2/conf/httpd.conf"

if [ -f "$apache_conf" ]; then
    # Indexes 옵션이 설정된 라인 검색 (주석 제외)
    if grep -E '^\s*Options\s+.*Indexes' "$apache_conf" | grep -v '^#' > /dev/null; then
        echo "디렉터리 검색 기능(Indexes)이 설정되어 있습니다."
        vulnerable=1
    else
        echo "디렉터리 검색 기능(Indexes)이 설정되어 있지 않습니다."
    fi
else
    echo "Apache 설정 파일을 찾을 수 없습니다: $apache_conf"
    vulnerable=1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-35] Safe"
else
    echo "[U-35] Vulnerable"
    echo -e "\t ↳ httpd.conf에 Indexes 옵션이 설정되어 있어 디렉터리 검색 기능이 활성화된 상태입니다."
fi

echo "====[Info] U-35 점검 완료===="
