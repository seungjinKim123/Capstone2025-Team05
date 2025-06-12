#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-23 - DoS 공격 취약 서비스 실행 여부
# 설명: echo, discard, daytime, chargen 등 DoS 공격에 취약한 서비스가 실행되는 경우
# 원본 스크립트: u-23.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-23 - DoS 공격 취약 서비스 실행 여부"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-23 사용하지 않는 DoS 공격 취약 서비스 실행 여부 점검 시작===="

vulnerable=0
OS=$(uname -s)

# 점검 대상 서비스 목록
services=(echo discard daytime chargen ntp snmp)

case "$OS" in
  Linux)
    for svc in "${services[@]}"; do
      if systemctl list-units --type=service 2>/dev/null | grep -i "$svc" | grep -q running; then
        vulnerable=1
        break
      fi
    done

    # xinetd 기반 여부도 점검
    if [ -d /etc/xinetd.d ]; then
      for svc in "${services[@]}"; do
        if grep -ril "$svc" /etc/xinetd.d 2>/dev/null | xargs grep -i "disable\s*=\s*no" | grep -q .; then
          vulnerable=1
          break
        fi
      done
    fi
    ;;
  SunOS)
    if command -v inetadm >/dev/null 2>&1; then
      # Solaris 10 이상
      if inetadm | grep -E "echo|discard|daytime|chargen" | grep -q enabled; then
        vulnerable=1
      fi
    else
      # Solaris 9 이하
      if grep -E "echo|discard|daytime|chargen" /etc/inetd.conf | grep -v "^#" | grep -q .; then
        vulnerable=1
      fi
    fi
    ;;
  AIX|HP-UX)
    if [ -f /etc/inetd.conf ]; then
      if grep -E "echo|discard|daytime|chargen" /etc/inetd.conf | grep -v "^#" | grep -q .; then
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
    echo "[U-23] Safe"
else
    echo "[U-23] Vulnerable"
    echo -e "\t ↳ echo, discard, daytime, chargen, ntp, snmp 등의 DoS 취약 서비스가 활성화되어 있습니다."
fi

echo "====[Info] U-23 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. echo, discard, daytime, chargen 서비스 비활성화"
echo "   2. xinetd/inetd 설정에서 해당 서비스 제거"
echo "   3. SNMP, NTP 서비스 보안 설정"
echo "   4. 불필요한 UDP 서비스 비활성화"



echo ""
echo "🛠️  조치 방법:"
echo "   DoS 공격에 취약한 서비스를 비활성화해야 합니다."


echo "🎯 GovScan 점검 완료: u-23 - DoS 공격 취약 서비스 실행 여부"
echo "📅 실행 시간: $(date)"
