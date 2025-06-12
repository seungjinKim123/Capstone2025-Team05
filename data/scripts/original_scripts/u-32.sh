#!/bin/bash

echo "====[Info] U-32 SMTP 일반사용자 q 옵션 제한 여부 점검 시작===="

vulnerable=0

# Sendmail 실행 여부 확인
if ps -ef | grep -i sendmail | grep -v grep > /dev/null; then
    # restrictqrun 설정 확인
    if [ -f /etc/mail/sendmail.cf ]; then
        if grep -v '^#' /etc/mail/sendmail.cf | grep -q "PrivacyOptions" && \
           grep -v '^#' /etc/mail/sendmail.cf | grep "PrivacyOptions" | grep -q "restrictqrun"; then
            echo "restrictqrun 옵션이 설정되어 있어 일반 사용자의 q 옵션 사용이 제한되어 있습니다."
        else
            echo "restrictqrun 옵션이 설정되지 않았습니다."
            vulnerable=1
        fi
    else
        echo "/etc/mail/sendmail.cf 설정 파일이 존재하지 않습니다."
        vulnerable=1
    fi
else
    echo "Sendmail 서비스가 실행 중이지 않습니다."
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-32] Safe"
else
    echo "[U-32] Vulnerable"
    echo -e "\t ↳ 일반 사용자의 q 옵션 제한 설정(PrivacyOptions=restrictqrun)이 적용되어 있지 않거나 확인 불가합니다."
fi

echo "====[Info] U-32 점검 완료===="
