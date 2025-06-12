#!/bin/bash

echo "====[Info] U-38 Apache 불필요한 기본 파일/디렉터리 존재 여부 점검 시작===="

vulnerable=0

# Apache 기본 경로 설정 (환경에 따라 조정 필요)
apache_root="/usr/local/apache2"

manual_path_1="$apache_root/htdocs/manual"
manual_path_2="$apache_root/manual"

# 불필요한 디렉터리 존재 여부 점검
if [ -d "$manual_path_1" ]; then
    echo "불필요한 디렉터리 존재: $manual_path_1"
    vulnerable=1
fi

if [ -d "$manual_path_2" ]; then
    echo "불필요한 디렉터리 존재: $manual_path_2"
    vulnerable=1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-38] Safe"
else
    echo "[U-38] Vulnerable"
    echo -e "\t ↳ Apache 설치 시 생성된 메뉴얼 디렉터리 등 불필요한 파일/디렉터리가 제거되지 않았습니다."
fi

echo "====[Info] U-38 점검 완료===="
