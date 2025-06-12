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
