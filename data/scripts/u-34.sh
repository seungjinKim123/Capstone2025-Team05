#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-34 - DNS Zone Transfer 제한 설정
# 설명: DNS Zone Transfer가 제한되지 않은 경우
# 원본 스크립트: u-34.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-34 - DNS Zone Transfer 제한 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


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



echo "📋 점검 체크리스트:"
echo "   1. allow-transfer 설정으로 Zone Transfer 제한"
echo "   2. 보조 DNS 서버만 Transfer 허용"
echo "   3. DNS 설정 파일 보안 강화"
echo "   4. DNS 조회 로그 모니터링"



echo ""
echo "🛠️  조치 방법:"
echo "   DNS Zone Transfer를 특정 서버로만 제한해야 합니다."


echo "🎯 GovScan 점검 완료: u-34 - DNS Zone Transfer 제한 설정"
echo "📅 실행 시간: $(date)"
