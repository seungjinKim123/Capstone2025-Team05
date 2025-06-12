#!/bin/bash

echo "====[Info] U-27 불필요한 RPC 서비스 실행 여부 점검 시작===="

vulnerable=0
OS=$(uname -s)

# 점검 대상 RPC 서비스 목록
rpc_services=(
  "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld"
  "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd"
  "rpc.yppasswdd" "rpc.quotad" "kcms_server" "cachefsd"
)

case "$OS" in
  Linux)
    # xinetd 환경: /etc/xinetd.d/ 내 서비스 파일에서 RPC 서비스 확인
    for svc in "${rpc_services[@]}"; do
      if grep -ril "$svc" /etc/xinetd.d/ 2>/dev/null | xargs grep -i "disable\s*=\s*no" | grep -q .; then
        vulnerable=1
        break
      fi
    done

    # /etc/inetd.conf (과거형 시스템 고려)
    if [ -f /etc/inetd.conf ]; then
      if grep -E "$(IFS=\|; echo "${rpc_services[*]}")" /etc/inetd.conf | grep -v '^#' | grep -q .; then
        vulnerable=1
      fi
    fi
    ;;
  SunOS)
    # Solaris 10 이상
    if command -v inetadm >/dev/null 2>&1; then
      if inetadm | egrep "ttdbserver|rexd|rstat|rusers|spray|wall|rquota" | grep -q "enabled"; then
        vulnerable=1
      fi
    # Solaris 9 이하
    elif [ -f /etc/inetd.conf ]; then
      if grep -E "$(IFS=\|; echo "${rpc_services[*]}")" /etc/inetd.conf | grep -v '^#' | grep -q .; then
        vulnerable=1
      fi
    fi
    ;;
  AIX|HP-UX)
    if [ -f /etc/inetd.conf ]; then
      if grep -E "$(IFS=\|; echo "${rpc_services[*]}")" /etc/inetd.conf | grep -v '^#' | grep -q .; then
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
    echo "[U-27] Safe"
else
    echo "[U-27] Vulnerable"
    echo -e "\t ↳ 불필요한 RPC 관련 서비스가 활성화되어 있습니다."
fi

echo "====[Info] U-27 점검 완료===="
