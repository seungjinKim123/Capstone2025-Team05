#!/bin/bash

echo "====[Info] U-08 /etc/shadow 파일 소유자 및 권한 설정 점검 시작===="

SHADOW_FILE="/etc/shadow"

if [ ! -f "$SHADOW_FILE" ]; then
    echo "[U-08] /etc/shadow 파일이 존재하지 않습니다. → 점검 불가"
    exit 1
fi

owner=$(stat -c %U "$SHADOW_FILE")
perm=$(stat -c %a "$SHADOW_FILE")

is_safe=true

if [ "$owner" != "root" ]; then
    echo "[!] 소유자: $owner → root 아님"
    is_safe=false
fi

if [ "$perm" -gt 400 ]; then
    echo "[!] 권한: $perm → 400 초과"
    is_safe=false
fi

echo ""
if [ "$is_safe" = true ]; then
    echo -e "[U-08] Safe"
else
    echo -e "[U-08] Vulnerable"
    if [ "$owner" != "root" ]; then
        echo -e "\t ↳ 소유자가 root가 아님"
    fi
    if [ "$perm" -gt 400 ]; then
        echo -e "\t ↳ 권한이 400 초과"
    fi
fi

echo "====[Info] U-08 done===="
