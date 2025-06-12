#!/bin/bash

echo "====[Info] U-06 파일 및 디렉터리 소유자 설정 점검 시작===="

OS=$(uname -s)
status="Safe"

case "$OS" in
  Linux)
    echo "[+] OS: Linux"
    no_owner=$(find / -nouser -print 2>/dev/null | wc -l)
    no_group=$(find / -nogroup -print 2>/dev/null | wc -l)
    ;;
  SunOS|AIX)
    echo "[+] OS: $OS"
    no_owner=$(find / \( -nouser -o -nogroup \) -xdev -ls 2>/dev/null | wc -l)
    no_group=0  # 이미 포함되어 계산됨
    ;;
  HP-UX)
    echo "[+] OS: HP-UX"
    no_owner=$(find / \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2>/dev/null | wc -l)
    no_group=0  # 통합된 방식
    ;;
  *)
    echo "[!] Unknown OS: $OS (미지원)"
    status="Unknown"
    ;;
esac

echo ""
echo "[+] Files with no owner: $no_owner"
echo "[+] Files with no group: $no_group"

if [ "$status" != "Unknown" ]; then
  if [ "$no_owner" -eq 0 ] && [ "$no_group" -eq 0 ]; then
    status="Safe"
    echo "[U-06] Safe"
  else
    status="Vulnerable"
    echo "[U-06] Vulnerable"
    if [ "$no_owner" -ne 0 ]; then
      echo -e "\t ↳ Found files with no valid owner"
    fi
    if [ "$no_group" -ne 0 ]; then
      echo -e "\t ↳ Found files with no valid group"
    fi
  fi
fi

echo "====[Info] U-06 done===="
