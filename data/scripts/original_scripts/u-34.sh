#!/bin/bash

echo "====[Info] U-34 DNS Zone Transfer 제한 설정 여부 점검 시작===="

vulnerable=0

# named 프로세스가 실행 중인지 확인
if ps -ef | grep named | grep -v grep > /dev/null; then
    # named.conf 내 allow-transfer 설정 점검
    if [ -f /etc/named.conf ]; then
        if grep -i "allow-transfer" /etc/named.conf | grep -q -v '//'; then
            echo "named.conf 파일에 allow-transfer 설정이 존재합니다."
        else
            echo "named.conf 파일에 allow-transfer 설정이 없습니다."
            vulnerable=1
        fi
    elif [ -f /etc/named.boot ]; then
        # named.boot 파일 사용 시 xfrnets 확인
        if grep -i "xfrnets" /etc/named.boot | grep -q -v '#'; then
            echo "named.boot 파일에 xfrnets 설정이 존재합니다."
        else
            echo "named.boot 파일에 xfrnets 설정이 없습니다."
            vulnerable=1
        fi
    else
        echo "DNS 설정 파일(named.conf 또는 named.boot)을 찾을 수 없습니다."
        vulnerable=1
    fi
else
    echo "named 프로세스가 실행 중이지 않습니다."
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-34] Safe"
else
    echo "[U-34] Vulnerable"
    echo -e "\t ↳ DNS 서버의 Zone Transfer 제한 설정이 없거나 확인할 수 없습니다."
fi

echo "====[Info] U-34 점검 완료===="
