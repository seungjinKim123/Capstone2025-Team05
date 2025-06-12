#!/bin/bash

echo "====[Info] U-33 BIND 최신 버전 사용 및 패치 여부 점검 시작===="

vulnerable=0
latest_version="9.10.3-P2"

# BIND(named) 서비스 실행 여부 확인
if ps -ef | grep named | grep -v grep > /dev/null; then
    # named 버전 확인
    if command -v named > /dev/null 2>&1; then
        version_output=$(named -v 2>/dev/null)
        bind_version=$(echo "$version_output" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-P[0-9]+)?')
        
        if [ -n "$bind_version" ]; then
            # 버전 비교
            if [ "$(printf '%s\n' "$latest_version" "$bind_version" | sort -V | head -n1)" != "$latest_version" ]; then
                echo "BIND 버전 최신 상태입니다: $bind_version"
            else
                echo "BIND 버전이 최신 버전보다 낮습니다: $bind_version"
                vulnerable=1
            fi
        else
            echo "버전 정보 파싱 실패: $version_output"
            vulnerable=1
        fi
    else
        echo "'named' 명령어를 찾을 수 없습니다."
        vulnerable=1
    fi
else
    echo "BIND(named) 서비스가 실행 중이지 않습니다."
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-33] Safe"
else
    echo "[U-33] Vulnerable"
    echo -e "\t ↳ BIND 서비스가 구버전이거나 버전 확인이 불가합니다. 최신 보안 패치 필요."
fi

echo "====[Info] U-33 점검 완료===="
