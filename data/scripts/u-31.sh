#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-31 - SMTP 릴레이 제한 설정
# 설명: SMTP 릴레이가 제한되지 않은 경우
# 원본 스크립트: u-31.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-31 - SMTP 릴레이 제한 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-31 SMTP 릴레이 제한 설정 점검 시작===="

vulnerable=0

# Sendmail 프로세스 실행 여부 확인
if ps -ef | grep -i sendmail | grep -v grep > /dev/null; then
    # 설정 파일 확인
    if [ -f /etc/mail/sendmail.cf ]; then
        # 릴레이 제한 설정 확인
        if grep -E '^R\$*' /etc/mail/sendmail.cf | grep -q "Relaying denied"; then
            echo "릴레이 제한 설정이 적용되어 있습니다."
        else
            echo "릴레이 제한 설정이 적용되어 있지 않습니다."
            vulnerable=1
        fi
    else
        echo "Sendmail 설정 파일(/etc/mail/sendmail.cf)을 찾을 수 없습니다."
        vulnerable=1
    fi
else
    echo "Sendmail 서비스가 실행 중이지 않습니다."
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-31] Safe"
else
    echo "[U-31] Vulnerable"
    echo -e "\t ↳ SMTP 릴레이 제한이 설정되지 않았거나 설정 파일을 찾을 수 없습니다."
fi

echo "====[Info] U-31 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. Sendmail 릴레이 제한 설정 확인"
echo "   2. 허용된 호스트/네트워크만 릴레이 허용"
echo "   3. 오픈 릴레이 테스트 수행"
echo "   4. 메일 서버 액세스 제어 설정"



echo ""
echo "🛠️  조치 방법:"
echo "   SMTP 릴레이를 제한하여 스팸 메일 발송을 방지해야 합니다."


echo "🎯 GovScan 점검 완료: u-31 - SMTP 릴레이 제한 설정"
echo "📅 실행 시간: $(date)"
