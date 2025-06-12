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
