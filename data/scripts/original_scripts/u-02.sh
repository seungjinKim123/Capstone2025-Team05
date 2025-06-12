#!/bin/bash

echo "====[Info] U-02 패스워드 복잡성 설정 점검 시작===="

CONFIG="/etc/security/pwquality.conf"

# 최소 길이 점검
minlen=$(grep -E '^\s*minlen' "$CONFIG" | awk -F '=' '{gsub(/[ \t]/,"",$2); print $2}')
if [ -z "$minlen" ]; then
    minlen=0
fi

# 복잡성 점검 (문자 유형 -1 개수)
credit_count=0
for item in dcredit ucredit lcredit ocredit; do
    value=$(grep -E "^\s*$item" "$CONFIG" | awk -F '=' '{gsub(/[ \t]/,"",$2); print $2}')
    if [ "$value" == "-1" ]; then
        credit_count=$((credit_count + 1))
    fi
done

# result
echo "minlen: $minlen"
echo "credit_count: $credit_count"

echo ""

if [ "$minlen" -ge 8 ] && [ "$credit_count" -ge 3 ]; then
    echo "[U-02] Safe"
else
    echo "[U-02] Vulnerable"
    if [ "$minlen" -lt 8 ]; then
        echo -e "\t ↳ 최소 길이(minlen) 미달: $minlen (필요: 8 이상)"
    fi
    if [ "$credit_count" -lt 3 ]; then
        echo -e "\t ↳ 문자 구성 요소 부족: -1 설정된 항목 $credit_count개 (필요: 3개 이상)"
    fi
fi

echo "====[Info] U-02 done===="
