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
