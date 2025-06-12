#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-28 - NIS 서비스 비활성화
# 설명: NIS(Network Information Service) 관련 서비스가 실행되는 경우
# 원본 스크립트: u-28.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-28 - NIS 서비스 비활성화"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


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



echo "📋 점검 체크리스트:"
echo "   1. ypserv, ypbind, ypxfrd 등 NIS 데몬 비활성화"
echo "   2. NIS+ 사용 검토"
echo "   3. LDAP 등 보안 디렉터리 서비스 검토"
echo "   4. NIS 관련 설정 파일 제거"



echo ""
echo "🛠️  조치 방법:"
echo "   NIS 서비스를 비활성화하고 LDAP 등 보안 대안을 사용해야 합니다."


echo "🎯 GovScan 점검 완료: u-28 - NIS 서비스 비활성화"
echo "📅 실행 시간: $(date)"
