#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-02 - 패스워드 복잡성 설정
# 설명: 패스워드 최소 길이, 복잡성 요구사항이 설정되지 않은 경우
# 원본 스크립트: u-02.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-02 - 패스워드 복잡성 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


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



echo "📋 점검 체크리스트:"
echo "   1. /etc/security/pwquality.conf에서 minlen >= 8 설정"
echo "   2. dcredit, ucredit, lcredit, ocredit 중 3개 이상 -1 설정"
echo "   3. 패스워드 정책 사용자 교육 실시"
echo "   4. 정기적인 패스워드 변경 정책 수립"



echo ""
echo "🛠️  조치 방법:"
echo "   패스워드 최소 길이 8자 이상, 영문 대소문자, 숫자, 특수문자 조합 사용을 강제해야 합니다."


echo "🎯 GovScan 점검 완료: u-02 - 패스워드 복잡성 설정"
echo "📅 실행 시간: $(date)"
