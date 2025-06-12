#!/bin/bash

echo "====[Info] U-12 /etc/services 권한 점검 시작===="

file="/etc/services"
is_safe=1

if [ ! -e "$file" ]; then
    echo "[U-12] $file 파일이 존재하지 않습니다."
    echo "[U-12] 점검 불가"
    exit 1
fi

# 소유자 및 권한 확인
perm=$(stat -c %a "$file")
owner=$(stat -c %U "$file")
group=$(stat -c %G "$file")

echo "파일 권한: $perm"
echo "소유자: $owner"
echo "그룹: $group"

# 조건 1: 소유자 (root 또는 bin 또는 sys)
if [[ "$owner" != "root" && "$owner" != "bin" && "$owner" != "sys" ]]; then
    echo -e "\t ↳ 소유자가 root/bin/sys가 아님"
    is_safe=0
fi

# 조건 2: 권한이 644 이하인지 확인
if [ "$perm" -gt 644 ]; then
    echo -e "\t ↳ 권한이 644 초과"
    is_safe=0
fi

# 최종 결과
if [ "$is_safe" -eq 1 ]; then
    echo -e "[U-12] Safe"
else
    echo -e "[U-12] Vulnerable"
fi

echo "====[Info] U-12 /etc/services 권한 점검 완료===="
