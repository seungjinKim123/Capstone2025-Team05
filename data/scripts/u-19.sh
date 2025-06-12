#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-19 - finger 서비스 비활성화
# 설명: finger 서비스가 활성화되어 사용자 정보 노출 위험이 있는 경우
# 원본 스크립트: u-19.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-19 - finger 서비스 비활성화"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-19 finger 서비스 비활성화 여부 점검 시작===="

vulnerable=0

# OS별 finger 서비스 점검
OS=$(uname -s)

case "$OS" in
  Linux|SunOS|AIX|HP-UX)
    # finger 서비스가 활성화되어 있는지 확인 (xinetd 또는 서비스 확인)
    if grep -qiE '^[^#]*finger' /etc/inetd.conf 2>/dev/null || \
       grep -ril 'finger' /etc/xinetd.d/ 2>/dev/null | grep -q . ; then
        vulnerable=1
    fi
    ;;
  *)
    echo "지원되지 않는 운영체제입니다: $OS"
    exit 1
    ;;
esac

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-19] Safe"
else
    echo "[U-19] Vulnerable"
    echo -e "\t ↳ finger 서비스가 활성화되어 있습니다."
fi

echo "====[Info] U-19 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. finger 서비스 실행 상태 확인"
echo "   2. inetd/xinetd에서 finger 서비스 비활성화"
echo "   3. 사용자 정보 노출 방지"
echo "   4. 대체 사용자 정보 제공 방안 검토"



echo ""
echo "🛠️  조치 방법:"
echo "   finger 서비스를 비활성화하고 사용자 정보 노출을 방지해야 합니다."


echo "🎯 GovScan 점검 완료: u-19 - finger 서비스 비활성화"
echo "📅 실행 시간: $(date)"
