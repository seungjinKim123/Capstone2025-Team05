#!/bin/bash

echo "====[Info] U-05 root 권한 및 패스 설정 점검 시작===="

# root 계정의 환경변수 PATH 추출
ROOT_PATH=$(sudo su - root -c 'echo $PATH' 2>/dev/null)

# 확인 메시지
echo "[+] root PATH: $ROOT_PATH"

status="Safe"

# '.' 이 PATH에 포함되어 있는지 앞, 중간 위치 확인
if [[ "$ROOT_PATH" =~ (^|:)\.(:|$) ]]; then
    status="Vulnerable"
fi

echo ""

# 결과 출력
if [ "$status" == "Safe" ]; then
    echo "[U-05] Safe"
else
    echo "[U-05] Vulnerable"
    echo -e "\t ↳ PATH 환경변수에 '.' 이 포함되어 있음"
fi

echo "====[Info] U-05 done===="
