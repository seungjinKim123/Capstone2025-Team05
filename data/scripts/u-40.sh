#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-40 - 파일 업로드/다운로드 사이즈 제한
# 설명: 웹 서버에서 파일 업로드/다운로드 크기가 제한되지 않은 경우
# 원본 스크립트: u-40.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-40 - 파일 업로드/다운로드 사이즈 제한"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-40 파일 업로드 및 다운로드 사이즈 제한 설정 점검 시작===="

vulnerable=0

# Apache 설정 파일 경로 예시 (환경에 따라 조정 필요)
apache_conf="/etc/httpd/conf/httpd.conf"
[ ! -f "$apache_conf" ] && apache_conf="/usr/local/apache2/conf/httpd.conf"

if [ -f "$apache_conf" ]; then
    # LimitRequestBody 설정 확인 (주석 제외)
    limit_line=$(grep -i 'LimitRequestBody' "$apache_conf" | grep -v '^#')

    if [ -n "$limit_line" ]; then
        # 숫자 추출 및 확인
        limit_value=$(echo "$limit_line" | grep -oE '[0-9]+')
        if [ "$limit_value" -le 5242880 ]; then  # 5MB = 5*1024*1024 = 5242880 bytes
            echo "파일 업로드/다운로드 용량이 $limit_value bytes 이하로 제한되어 있습니다."
        else
            echo "LimitRequestBody 값이 $limit_value bytes로, 5MB 초과입니다."
            vulnerable=1
        fi
    else
        echo "LimitRequestBody 설정이 없습니다."
        vulnerable=1
    fi
else
    echo "Apache 설정 파일을 찾을 수 없습니다: $apache_conf"
    vulnerable=1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-40] Safe"
else
    echo "[U-40] Vulnerable"
    echo -e "\t ↳ 파일 업로드/다운로드 크기에 대한 LimitRequestBody 설정이 없거나 5MB 초과로 설정되어 있습니다."
fi

echo "====[Info] U-40 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. LimitRequestBody 5MB 이하로 설정"
echo "   2. 업로드 파일 유형 제한"
echo "   3. 임시 파일 정리 정책 수립"
echo "   4. 파일 업로드 보안 검증"



echo ""
echo "🛠️  조치 방법:"
echo "   LimitRequestBody를 사용하여 파일 크기를 제한해야 합니다."


echo "🎯 GovScan 점검 완료: u-40 - 파일 업로드/다운로드 사이즈 제한"
echo "📅 실행 시간: $(date)"
