#!/bin/bash

echo "====[Info] U-09 /etc/host 파일 소유자 및 권한 설정 점검 시작===="

TARGET_FILE="/etc/hosts"

# 파일 존재 여부 확인
if [ ! -f "$TARGET_FILE" ]; then
    echo "[U-09] 대상 파일이 존재하지 않습니다: $TARGET_FILE"
    echo "→ [U-09] 점검 불가"
    exit 1
fi

# 소유자 확인
owner=$(ls -l "$TARGET_FILE" | awk '{print $3}')
# 권한 확인 (8진수 형태로 추출)
perm=$(stat -c %a "$TARGET_FILE")

echo "파일 소유자: $owner"
echo "파일 권한: $perm"

vulnerable=0

# 조건 판단
if [ "$owner" != "root" ]; then
    echo -e "\t ↳ 소유자가 root가 아님"
    vulnerable=1
fi

if [ "$perm" -gt 600 ]; then
    echo -e "\t ↳ 권한이 600 초과"
    vulnerable=1
fi

echo ""

# 결과 출력
if [ $vulnerable -eq 0 ]; then
    echo "[U-09] Safe"
else
    echo "[U-09] Vulnerable"
fi

echo "====[Info] U-09 done===="
