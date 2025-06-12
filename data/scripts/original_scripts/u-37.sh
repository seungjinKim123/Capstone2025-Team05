#!/bin/bash

echo "====[Info] U-37 상위 디렉터리 접근 제한 설정 점검 시작===="

vulnerable=0

# Apache 설정 파일 경로 예시 (환경에 따라 변경 가능)
apache_conf="/etc/httpd/conf/httpd.conf"
[ ! -f "$apache_conf" ] && apache_conf="/usr/local/apache2/conf/httpd.conf"

if [ -f "$apache_conf" ]; then
    # AllowOverride None 설정 확인
    override_lines=$(grep -i 'AllowOverride' "$apache_conf" | grep -v '^#')

    if echo "$override_lines" | grep -q -i 'AllowOverride\s\+None'; then
        echo "AllowOverride 설정이 None으로 되어 있어, .htaccess 설정을 통한 접근 제어가 불가능합니다."
        vulnerable=1
    else
        echo "AllowOverride 설정이 제한 없이 설정되어 있지 않습니다 (Some override 허용)."
    fi
else
    echo "Apache 설정 파일을 찾을 수 없습니다: $apache_conf"
    vulnerable=1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-37] Safe"
else
    echo "[U-37] Vulnerable"
    echo -e "\t ↳ 상위 디렉터리로 이동을 제한하기 위한 AllowOverride 설정이 부적절하거나 확인되지 않았습니다."
fi

echo "====[Info] U-37 점검 완료===="
