#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: 20503 - 기본포트 사용 및 취약한 서비스 운용
# 설명: Telnet, FTP, rlogin 등 보안성이 취약한 서비스가 기본 포트로 운용되는 경우
# 원본 스크립트: u-19.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: 20503 - 기본포트 사용 및 취약한 서비스 운용"
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
echo "   1. Telnet 서비스 비활성화 및 SSH로 대체"
echo "   2. FTP 서비스 비활성화 및 SFTP/SCP로 대체"
echo "   3. finger 서비스 비활성화 (u-19.sh 참조)"
echo "   4. r-command 서비스 비활성화 (u-21.sh 참조)"
echo "   5. DoS 취약 서비스 비활성화 (u-23.sh 참조)"



echo ""
echo "🛠️  조치 방법:"
echo "   보안성이 낮은 서비스를 사용하지 않거나, VPN 내에서 사용하며 SSH 등 보안 대체 수단을 사용해야 합니다."


echo "🎯 GovScan 점검 완료: 20503 - 기본포트 사용 및 취약한 서비스 운용"
echo "📅 실행 시간: $(date)"
