#!/bin/bash

echo "====[Info] U-28 NIS 서비스 비활성화 및 NIS+ 사용 여부 점검 시작===="

vulnerable=0
OS=$(uname -s)

# 점검 대상 NIS 관련 데몬 목록
nis_daemons=(
  "ypserv" "ypbind" "ypxfrd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
  "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd" "rpc.yppasswdd"
)

case "$OS" in
  Linux|AIX|HP-UX)
    if ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.yppasswdd|rpc.yppasswdd|rpc.yppasswdd|rpc.yppasswdd|rpc.yppasswdd|rpc.yppasswdd" | grep -v grep > /dev/null; then
      vulnerable=1
    fi
    ;;
  SunOS)
    if command -v svcs > /dev/null 2>&1; then
      if svcs -a | grep nis | grep -q "online"; then
        vulnerable=1
      fi
    else
      if ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.yppasswdd" | grep -v grep > /dev/null; then
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
    echo "[U-28] Safe"
else
    echo "[U-28] Vulnerable"
    echo -e "\t ↳ NIS 관련 서비스(ypserv, ypbind 등)가 활성화되어 있습니다."
fi

echo "====[Info] U-28 점검 완료===="
