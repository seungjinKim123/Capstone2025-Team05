#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-41 - 웹 루트 디렉터리 분리 설정
# 설명: 웹 루트 디렉터리가 시스템 기본 위치로 설정된 경우
# 원본 스크립트: u-41.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-41 - 웹 루트 디렉터리 분리 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-41 웹 루트 디렉터리(DocumentRoot) 분리 설정 점검 시작===="

vulnerable=0

# Apache 설정 파일 경로 예시
apache_conf="/etc/httpd/conf/httpd.conf"
[ ! -f "$apache_conf" ] && apache_conf="/usr/local/apache2/conf/httpd.conf"

# DocumentRoot 기준 경로 (취약 판단 기준)
default_paths=(
    "/usr/local/apache/htdocs"
    "/usr/local/apache2/htdocs"
    "/var/www/html"
)

if [ -f "$apache_conf" ]; then
    doc_root=$(grep -i '^DocumentRoot' "$apache_conf" | grep -v '^#' | awk '{print $2}' | tr -d '"')

    if [ -z "$doc_root" ]; then
        echo "DocumentRoot 설정이 명확히 지정되지 않았습니다."
        vulnerable=1
    else
        echo "DocumentRoot 경로: $doc_root"
        for path in "${default_paths[@]}"; do
            if [ "$doc_root" = "$path" ]; then
                echo "기본 디렉터리 경로로 설정되어 있습니다: $path"
                vulnerable=1
                break
            fi
        done
    fi
else
    echo "Apache 설정 파일을 찾을 수 없습니다: $apache_conf"
    vulnerable=1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-41] Safe"
else
    echo "[U-41] Vulnerable"
    echo -e "\t ↳ DocumentRoot가 시스템 기본 디렉터리로 설정되어 있어 보안상 분리 설정이 필요합니다."
fi

echo "====[Info] U-41 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. DocumentRoot를 기본 위치에서 변경"
echo "   2. 웹 컨텐츠 전용 디렉터리 생성"
echo "   3. 웹 루트 권한 최소화"
echo "   4. 시스템 파일과 웹 파일 분리"



echo ""
echo "🛠️  조치 방법:"
echo "   DocumentRoot를 시스템 기본 디렉터리가 아닌 별도 위치로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-41 - 웹 루트 디렉터리 분리 설정"
echo "📅 실행 시간: $(date)"
