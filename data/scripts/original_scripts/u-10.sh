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
