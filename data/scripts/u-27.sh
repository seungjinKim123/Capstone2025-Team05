#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-27 - 불필요한 RPC 서비스 실행 여부
# 설명: 불필요한 RPC 관련 서비스가 실행되는 경우
# 원본 스크립트: u-27.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-27 - 불필요한 RPC 서비스 실행 여부"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


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



echo "📋 점검 체크리스트:"
echo "   1. rpc.cmsd, rpc.ttdbserverd, sadmind 등 비활성화"
echo "   2. rusersd, walld, sprayd, rstatd 등 비활성화"
echo "   3. 필요한 RPC 서비스만 선별적 활성화"
echo "   4. RPC 서비스 보안 설정 적용"



echo ""
echo "🛠️  조치 방법:"
echo "   불필요한 RPC 서비스를 비활성화해야 합니다."


echo "🎯 GovScan 점검 완료: u-27 - 불필요한 RPC 서비스 실행 여부"
echo "📅 실행 시간: $(date)"
