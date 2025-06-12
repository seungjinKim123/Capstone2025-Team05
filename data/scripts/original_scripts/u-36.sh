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
