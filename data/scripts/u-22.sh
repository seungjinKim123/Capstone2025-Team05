#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-22 - Cron 관련 파일의 권한
# 설명: crontab 및 cron 관련 파일의 권한이 부적절한 경우
# 원본 스크립트: u-22.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-22 - Cron 관련 파일의 권한"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-22 Cron 관련 파일의 권한 적절성 점검 시작===="

vulnerable=0

# 점검 대상 cron 관련 주요 파일
cron_files=(
  "/usr/bin/crontab"
  "/etc/crontab"
  "/etc/cron.allow"
  "/etc/cron.deny"
  "/etc/cron.d"
  "/etc/cron.hourly"
  "/etc/cron.daily"
  "/etc/cron.weekly"
  "/etc/cron.monthly"
  "/var/spool/cron"
  "/var/spool/cron/crontabs"
  "/var/adm/cron/cron.allow"
  "/var/adm/cron/cron.deny"
)

# crontab 실행 파일 권한 확인
if [ -f "/usr/bin/crontab" ]; then
  perm=$(stat -c "%a" /usr/bin/crontab 2>/dev/null)
  if [ "$perm" -gt 750 ]; then
    vulnerable=1
  fi
fi

# cron 설정 파일들의 권한 확인
for file in "${cron_files[@]}"; do
  if [ -e "$file" ]; then
    perm=$(stat -c "%a" "$file" 2>/dev/null)
    owner=$(stat -c "%U" "$file" 2>/dev/null)
    group=$(stat -c "%G" "$file" 2>/dev/null)

    if [ "$perm" -gt 640 ] || [ "$owner" != "root" ]; then
      vulnerable=1
      break
    fi
  fi
done

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-22] Safe"
else
    echo "[U-22] Vulnerable"
    echo -e "\t ↳ crontab 실행 파일 또는 cron 설정 파일의 권한/소유자가 부적절합니다."
fi

echo "====[Info] U-22 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. crontab 실행 파일 권한 750 이하 확인"
echo "   2. cron 설정 파일 소유자 root 확인"
echo "   3. cron 디렉터리 권한 640 이하 확인"
echo "   4. cron.allow/cron.deny 파일 관리"



echo ""
echo "🛠️  조치 방법:"
echo "   cron 관련 파일의 소유자를 root로 설정하고 적절한 권한을 부여해야 합니다."


echo "🎯 GovScan 점검 완료: u-22 - Cron 관련 파일의 권한"
echo "📅 실행 시간: $(date)"
