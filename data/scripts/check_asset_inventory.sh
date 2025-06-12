#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: 11303 - 관리대장 누락
# 설명: 보안관리자용 기록관리 시스템에 등록되지 않은 호스트 또는 서비스
# 원본 스크립트: u-06.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: 11303 - 관리대장 누락"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


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



echo "📋 점검 체크리스트:"
echo "   1. 전체 IP 자산에 대한 관리대장 작성 여부 확인"
echo "   2. 관리대장과 실제 운영 자산의 일치성 검토"
echo "   3. 미등록 자산 발견 시 즉시 등록 절차 수행"
echo "   4. 주기적(월 1회) 자산 현황 점검 및 업데이트"



echo ""
echo "🛠️  조치 방법:"
echo "   모든 자산과 서비스에 대해 관리대장을 작성하고 주기적으로 검토해야 합니다."


echo "🎯 GovScan 점검 완료: 11303 - 관리대장 누락"
echo "📅 실행 시간: $(date)"
