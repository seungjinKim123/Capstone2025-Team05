#!/bin/bash

echo "====[Info] U-20 익명 FTP 접속 허용 여부 점검 시작===="

vulnerable=0

# /etc/passwd에 ftp 계정이 존재하는지 확인
if grep -i "^ftp:" /etc/passwd > /dev/null 2>&1; then
    vulnerable=1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-20] Safe"
else
    echo "[U-20] Vulnerable"
    echo -e "\t ↳ /etc/passwd에 ftp 계정이 존재하여 익명 FTP 접속이 허용된 상태입니다."
fi

echo "====[Info] U-20 점검 완료===="
