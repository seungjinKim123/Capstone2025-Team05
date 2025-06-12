#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-25 - NFS everyone 공유 제한 설정
# 설명: NFS에서 everyone 공유가 제한되지 않은 경우
# 원본 스크립트: u-25.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-25 - NFS everyone 공유 제한 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


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



echo "📋 점검 체크리스트:"
echo "   1. /etc/exports에서 everyone 공유 제거"
echo "   2. 특정 IP/네트워크만 접근 허용"
echo "   3. NFS 공유 권한 최소화"
echo "   4. 정기적인 NFS 설정 검토"



echo ""
echo "🛠️  조치 방법:"
echo "   NFS everyone 공유를 제한하고 특정 호스트만 접근할 수 있도록 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-25 - NFS everyone 공유 제한 설정"
echo "📅 실행 시간: $(date)"
