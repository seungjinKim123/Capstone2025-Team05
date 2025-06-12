#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: 30301 - 관리대장 누락 (네트워크)
# 설명: 연결된 장비가 관리대장에 포함되지 않음 (물리 네트워크 추적 기준)
# 원본 스크립트: u-06.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: 30301 - 관리대장 누락 (네트워크)"
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
echo "   1. 네트워크 연결 장비의 MAC 주소 수집"
echo "   2. 물리적 네트워크 토폴로지 문서화"
echo "   3. 미등록 네트워크 장비 탐지 및 등록"
echo "   4. 네트워크 장비 관리대장 주기적 업데이트"



echo ""
echo "🛠️  조치 방법:"
echo "   물리적/논리적 연결 장비의 MAC 주소를 식별하고 자산 등록을 철저히 해야 합니다."


echo "🎯 GovScan 점검 완료: 30301 - 관리대장 누락 (네트워크)"
echo "📅 실행 시간: $(date)"
