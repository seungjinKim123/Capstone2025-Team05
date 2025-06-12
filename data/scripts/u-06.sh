#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-06 - 파일 및 디렉터리 소유자 설정
# 설명: 소유자가 없는 파일이나 디렉터리가 존재하는 경우
# 원본 스크립트: u-06.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-06 - 파일 및 디렉터리 소유자 설정"
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
echo "   1. 소유자 없는 파일/디렉터리 검색"
echo "   2. 발견된 파일의 적절한 소유자 설정"
echo "   3. 정기적인 파일 소유권 점검"
echo "   4. 파일 생성 시 기본 소유자 정책 수립"



echo ""
echo "🛠️  조치 방법:"
echo "   시스템의 모든 파일과 디렉터리가 적절한 소유자를 가지도록 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-06 - 파일 및 디렉터리 소유자 설정"
echo "📅 실행 시간: $(date)"
