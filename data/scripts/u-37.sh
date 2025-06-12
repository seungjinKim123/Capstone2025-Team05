#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-37 - 상위 디렉터리 접근 제한 설정
# 설명: 웹 서버에서 상위 디렉터리 접근이 제한되지 않은 경우
# 원본 스크립트: u-37.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-37 - 상위 디렉터리 접근 제한 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-37 상위 디렉터리 접근 제한 설정 점검 시작===="

vulnerable=0

# Apache 설정 파일 경로 예시 (환경에 따라 변경 가능)
apache_conf="/etc/httpd/conf/httpd.conf"
[ ! -f "$apache_conf" ] && apache_conf="/usr/local/apache2/conf/httpd.conf"

if [ -f "$apache_conf" ]; then
    # AllowOverride None 설정 확인
    override_lines=$(grep -i 'AllowOverride' "$apache_conf" | grep -v '^#')

    if echo "$override_lines" | grep -q -i 'AllowOverride\s\+None'; then
        echo "AllowOverride 설정이 None으로 되어 있어, .htaccess 설정을 통한 접근 제어가 불가능합니다."
        vulnerable=1
    else
        echo "AllowOverride 설정이 제한 없이 설정되어 있지 않습니다 (Some override 허용)."
    fi
else
    echo "Apache 설정 파일을 찾을 수 없습니다: $apache_conf"
    vulnerable=1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-37] Safe"
else
    echo "[U-37] Vulnerable"
    echo -e "\t ↳ 상위 디렉터리로 이동을 제한하기 위한 AllowOverride 설정이 부적절하거나 확인되지 않았습니다."
fi

echo "====[Info] U-37 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. AllowOverride 설정 적절히 구성"
echo "   2. 디렉터리 접근 권한 제한"
echo "   3. .htaccess 파일 보안 설정"
echo "   4. 웹 루트 외부 접근 차단"



echo ""
echo "🛠️  조치 방법:"
echo "   상위 디렉터리 접근을 제한하고 AllowOverride 설정을 적절히 구성해야 합니다."


echo "🎯 GovScan 점검 완료: u-37 - 상위 디렉터리 접근 제한 설정"
echo "📅 실행 시간: $(date)"
