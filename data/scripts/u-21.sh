#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-21 - r-command 서비스 비활성화
# 설명: rsh, rlogin, rexec 등 r-command 서비스가 활성화된 경우
# 원본 스크립트: u-21.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-21 - r-command 서비스 비활성화"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-21 r-command 서비스 비활성화 여부 점검 시작===="

vulnerable=0
OS=$(uname -s)

case "$OS" in
  Linux)
    # xinetd 기반 서비스 파일에서 r-command 서비스(rsh, rlogin, rexec 등) 확인
    if grep -rE "disable\s*=\s*no" /etc/xinetd.d/ 2>/dev/null | grep -E "rsh|rlogin|rexec" > /dev/null; then
      vulnerable=1
    fi
    ;;
  SunOS)
    # Solaris 10 이상: inetadm 명령 사용
    if command -v inetadm > /dev/null 2>&1; then
      if inetadm | grep -E "shell|login|exec" | grep -q "enabled"; then
        vulnerable=1
      fi
    # Solaris 9 이하: /etc/inetd.conf 확인
    elif [ -f /etc/inetd.conf ]; then
      if grep -E "^(rsh|rlogin|rexec)" /etc/inetd.conf | grep -v '^#' > /dev/null; then
        vulnerable=1
      fi
    fi
    ;;
  AIX|HP-UX)
    if [ -f /etc/inetd.conf ]; then
      if grep -E "^(rsh|rlogin|rexec)" /etc/inetd.conf | grep -v '^#' > /dev/null; then
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
    echo "[U-21] Safe"
else
    echo "[U-21] Vulnerable"
    echo -e "\t ↳ r-command 관련 서비스(rsh, rlogin, rexec 등)가 활성화되어 있습니다."
fi

echo "====[Info] U-21 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. rsh, rlogin, rexec 서비스 비활성화"
echo "   2. xinetd/inetd 설정에서 r-command 제거"
echo "   3. SSH 등 보안 대안 사용"
echo "   4. r-command 관련 파일 제거"



echo ""
echo "🛠️  조치 방법:"
echo "   r-command 서비스를 비활성화하고 SSH 등 보안 대안을 사용해야 합니다."


echo "🎯 GovScan 점검 완료: u-21 - r-command 서비스 비활성화"
echo "📅 실행 시간: $(date)"
