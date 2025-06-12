#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-29 - tftp, talk, ntalk 서비스 활성화 여부
# 설명: tftp, talk, ntalk 등 취약한 서비스가 활성화된 경우
# 원본 스크립트: u-29.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-29 - tftp, talk, ntalk 서비스 활성화 여부"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-29 tftp, talk, ntalk 서비스 활성화 여부 점검 시작===="

vulnerable=0
OS=$(uname -s)

# 점검 대상 서비스 목록
services=("tftp" "talk" "ntalk")

case "$OS" in
  Linux)
    # xinetd 기반 서비스 설정 확인
    if [ -d /etc/xinetd.d ]; then
      for svc in "${services[@]}"; do
        if grep -ril "$svc" /etc/xinetd.d/ 2>/dev/null | xargs grep -i "disable\s*=\s*no" | grep -q .; then
          vulnerable=1
          break
        fi
      done
    fi

    # inetd.conf 기반 점검 (레거시 시스템 대응)
    if [ -f /etc/inetd.conf ]; then
      if grep -E "tftp|talk|ntalk" /etc/inetd.conf | grep -v '^#' | grep -q .; then
        vulnerable=1
      fi
    fi
    ;;
  SunOS)
    # Solaris 10 이상: 서비스 상태 확인
    if command -v inetadm > /dev/null 2>&1; then
      if inetadm | egrep "tftp|talk" | grep -q enabled; then
        vulnerable=1
      fi
    # Solaris 9 이하: inetd.conf로 점검
    elif [ -f /etc/inetd.conf ]; then
      if grep -E "tftp|talk|ntalk" /etc/inetd.conf | grep -v '^#' | grep -q .; then
        vulnerable=1
      fi
    fi
    ;;
  AIX|HP-UX)
    if [ -f /etc/inetd.conf ]; then
      if grep -E "tftp|talk|ntalk" /etc/inetd.conf | grep -v '^#' | grep -q .; then
        vulnerable=1
      fi
    fi
    ;;
  *)
    echo "지원되지 않는 운영체제입니다: $OS"
    exit 1
    ;;
esac

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-29] Safe"
else
    echo "[U-29] Vulnerable"
    echo -e "\t ↳ tftp, talk, ntalk 등 불필요하거나 취약한 서비스가 활성화되어 있습니다."
fi

echo "====[Info] U-29 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. tftp 서비스 비활성화"
echo "   2. talk, ntalk 서비스 비활성화"
echo "   3. 보안 파일 전송 방법 사용 (SFTP 등)"
echo "   4. 대화 서비스 대안 검토"



echo ""
echo "🛠️  조치 방법:"
echo "   tftp, talk, ntalk 서비스를 비활성화해야 합니다."


echo "🎯 GovScan 점검 완료: u-29 - tftp, talk, ntalk 서비스 활성화 여부"
echo "📅 실행 시간: $(date)"
