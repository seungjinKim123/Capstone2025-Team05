#!/bin/bash

echo "====[Info] U-43 로그 정기 검토 여부 점검 시작===="

# 점검 설명 출력
echo "[설명] /var/log 디렉터리 내 주요 로그 파일에 대한 최근 수정일을 확인하고,"
echo "       최근 로그 검토 여부를 판단합니다."

# 확인 대상 로그 파일 목록
log_files=(
    "/var/log/messages"
    "/var/log/secure"
    "/var/log/auth.log"
    "/var/log/syslog"
    "/var/log/wtmp"
    "/var/log/lastlog"
)

echo ""
echo "[검토 기준] 최근 30일 이내 변경된 로그가 하나 이상 존재해야 안전"

# 기준 날짜 (30일 전)
date_threshold=$(date -d '-30 days' +%s)

safe_count=0
vuln_logs=()

for file in "${log_files[@]}"; do
    if [ -f "$file" ]; then
        mod_time=$(stat -c %Y "$file")
        if [ "$mod_time" -ge "$date_threshold" ]; then
            echo "[OK] $file : 최근 변경됨"
            ((safe_count++))
        else
            echo "[WARN] $file : 30일 이상 변경 없음"
            vuln_logs+=("$file")
        fi
    else
        echo "[INFO] $file : 파일 없음"
    fi
done

echo ""
# 결과 판단
if [ "$safe_count" -ge 1 ]; then
    echo "[U-43] Safe"
else
    echo "[U-43] Vulnerable"
    if [ "${#vuln_logs[@]}" -gt 0 ]; then
        echo -e "\t ↳ 취약 로그 파일 목록:"
        for vf in "${vuln_logs[@]}"; do
            echo -e "\t ↳ $vf"
        done
    fi
fi

echo "====[Info] U-43 로그 점검 완료===="
