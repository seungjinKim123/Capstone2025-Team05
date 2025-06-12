#!/bin/bash

echo "====[Info] U-25 NFS everyone 공유 제한 설정 여부 점검 시작===="

vulnerable=0

# 점검 대상 파일 목록
files_to_check=(
  "/etc/exports"
  "/etc/dfs/dfstab"
  "/etc/dfs/sharetab"
)

# 파일 내에 "everyone" 공유 설정이 존재하는지 확인
for file in "${files_to_check[@]}"; do
  if [ -f "$file" ]; then
    if grep -i "everyone" "$file" | grep -v '^#' > /dev/null; then
      vulnerable=1
      break
    fi
  fi
done

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-25] Safe"
else
    echo "[U-25] Vulnerable"
    echo -e "\t ↳ NFS 설정 파일에서 'everyone' 공유가 제한되지 않은 항목이 존재합니다."
fi

echo "====[Info] U-25 점검 완료===="
