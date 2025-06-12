#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-35 - 웹 디렉터리 검색 기능 제한
# 설명: 웹 서버에서 디렉터리 검색 기능(Indexes)이 활성화된 경우
# 원본 스크립트: u-35.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-35 - 웹 디렉터리 검색 기능 제한"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-35 디렉터리 검색 기능(Indexes 옵션) 점검 시작===="

vulnerable=0

# Apache 설정 파일 위치 예시 (환경에 따라 변경 가능)
apache_conf="/etc/httpd/conf/httpd.conf"
[ ! -f "$apache_conf" ] && apache_conf="/usr/local/apache2/conf/httpd.conf"

if [ -f "$apache_conf" ]; then
    # Indexes 옵션이 설정된 라인 검색 (주석 제외)
    if grep -E '^\s*Options\s+.*Indexes' "$apache_conf" | grep -v '^#' > /dev/null; then
        echo "디렉터리 검색 기능(Indexes)이 설정되어 있습니다."
        vulnerable=1
    else
        echo "디렉터리 검색 기능(Indexes)이 설정되어 있지 않습니다."
    fi
else
    echo "Apache 설정 파일을 찾을 수 없습니다: $apache_conf"
    vulnerable=1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-35] Safe"
else
    echo "[U-35] Vulnerable"
    echo -e "\t ↳ httpd.conf에 Indexes 옵션이 설정되어 있어 디렉터리 검색 기능이 활성화된 상태입니다."
fi

echo "====[Info] U-35 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. Apache Options에서 Indexes 제거"
echo "   2. 디렉터리별 접근 제어 설정"
echo "   3. 기본 인덱스 페이지 설정"
echo "   4. 웹 디렉터리 구조 보안 검토"



echo ""
echo "🛠️  조치 방법:"
echo "   웹 서버의 디렉터리 검색 기능을 비활성화해야 합니다."


echo "🎯 GovScan 점검 완료: u-35 - 웹 디렉터리 검색 기능 제한"
echo "📅 실행 시간: $(date)"
