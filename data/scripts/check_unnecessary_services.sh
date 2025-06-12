#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: 30501 - 불필요한 서비스 운영
# 설명: 업무와 무관한 불필요한 서비스가 실행 중인 경우
# 원본 스크립트: u-19.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: 30501 - 불필요한 서비스 운영"
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
echo "   1. finger 서비스 비활성화 (u-19.sh)"
echo "   2. DoS 취약 서비스 비활성화 (u-23.sh)"
echo "   3. 불필요한 NFS 서비스 비활성화 (u-24.sh)"
echo "   4. automountd 서비스 비활성화 (u-26.sh)"
echo "   5. 불필요한 RPC 서비스 비활성화 (u-27.sh)"
echo "   6. NIS 서비스 비활성화 (u-28.sh)"
echo "   7. tftp/talk 서비스 비활성화 (u-29.sh)"



echo ""
echo "🛠️  조치 방법:"
echo "   업무에 필요하지 않은 서비스는 중지하고 필요한 서비스만 운영해야 합니다."


echo "🎯 GovScan 점검 완료: 30501 - 불필요한 서비스 운영"
echo "📅 실행 시간: $(date)"
