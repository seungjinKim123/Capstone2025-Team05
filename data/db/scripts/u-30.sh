#!/bin/bash

echo "====[Info] U-30 Sendmail 서비스 취약 버전 점검 시작===="

vulnerable=0
latest_version="8.15.2"

# Sendmail 실행 여부 확인
if ps -ef | grep -i sendmail | grep -v grep > /dev/null; then
    # Sendmail 버전 확인 (telnet을 통해 배너 읽기 시도)
    banner=$(echo | timeout 3 telnet localhost 25 2>/dev/null | grep -i sendmail)

    if [[ -z "$banner" ]]; then
        echo "Sendmail 서비스가 실행 중이지만 버전을 확인할 수 없습니다."
        vulnerable=1
    else
        # 버전 문자열에서 숫자 추출하여 비교
        current_version=$(echo "$banner" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -n1)
        if [[ -n "$current_version" ]]; then
            # 버전 비교
            if [ "$(printf '%s\n' "$latest_version" "$current_version" | sort -V | head -n1)" != "$latest_version" ]; then
                echo "Sendmail 버전이 최신 버전 이상입니다: $current_version"
            else
                echo "Sendmail 버전이 최신 버전보다 낮습니다: $current_version"
                vulnerable=1
            fi
        else
            echo "버전 문자열이 파싱되지 않았습니다. 수동 확인 필요"
            vulnerable=1
        fi
    fi
else
    echo "Sendmail 서비스가 실행 중이지 않습니다."
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-30] Safe"
else
    echo "[U-30] Vulnerable"
    echo -e "\t ↳ Sendmail 서비스가 취약한 버전이거나 확인 불가능한 상태입니다."
fi

echo "====[Info] U-30 점검 완료===="
