#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-38 - Apache 불필요한 기본 파일/디렉터리
# 설명: Apache 설치 시 생성된 불필요한 파일이나 디렉터리가 존재하는 경우
# 원본 스크립트: u-38.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-38 - Apache 불필요한 기본 파일/디렉터리"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


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



echo "📋 점검 체크리스트:"
echo "   1. Apache 매뉴얼 디렉터리 제거"
echo "   2. 기본 예제 파일 제거"
echo "   3. 불필요한 CGI 스크립트 제거"
echo "   4. 웹 루트 정리 및 보안 강화"



echo ""
echo "🛠️  조치 방법:"
echo "   Apache 기본 매뉴얼, 예제 파일 등 불필요한 파일을 제거해야 합니다."


echo "🎯 GovScan 점검 완료: u-38 - Apache 불필요한 기본 파일/디렉터리"
echo "📅 실행 시간: $(date)"
