#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: 30701 - 웹 서버 보안 설정 미흡
# 설명: 웹 서버에서 디렉토리 리스팅, 불필요한 HTTP 메소드 허용 등
# 원본 스크립트: u-35.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: 30701 - 웹 서버 보안 설정 미흡"
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
echo "   1. 디렉토리 브라우징 비활성화 (u-35.sh)"
echo "   2. Apache 데몬 root 권한 제한 (u-36.sh)"
echo "   3. 상위 디렉터리 접근 제한 (u-37.sh)"
echo "   4. 불필요한 기본 파일 제거 (u-38.sh)"
echo "   5. 심볼릭 링크 사용 제한 (u-39.sh)"
echo "   6. 파일 업로드 크기 제한 (u-40.sh)"
echo "   7. 웹 루트 디렉터리 분리 (u-41.sh)"



echo ""
echo "🛠️  조치 방법:"
echo "   웹 서버 보안 설정을 강화하고 불필요한 기능을 비활성화해야 합니다."


echo "🎯 GovScan 점검 완료: 30701 - 웹 서버 보안 설정 미흡"
echo "📅 실행 시간: $(date)"
