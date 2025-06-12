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
