#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-15 - world writable 파일 점검
# 설명: 모든 사용자가 쓰기 가능한 파일이 존재하는 경우
# 원본 스크립트: u-15.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-15 - world writable 파일 점검"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-15 world writable 파일 점검 시작===="

# World writable 파일 검색
vulnerable_files=$(find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null)

if [ -z "$vulnerable_files" ]; then
    echo "[U-15] Safe"
else
    echo "[U-15] Vulnerable"
    echo -e "\t ↳ World Writable Files Found:"
    echo "$vulnerable_files" | while read line; do
        echo -e "\t ↳ $line"
    done
fi

echo "====[Info] U-15 done===="



echo "📋 점검 체크리스트:"
echo "   1. 시스템 전체 world writable 파일 검색"
echo "   2. 불필요한 world writable 권한 제거"
echo "   3. 임시 디렉터리 보안 설정"
echo "   4. 파일 권한 정책 수립"



echo ""
echo "🛠️  조치 방법:"
echo "   world writable 권한을 제거하고 필요한 경우에만 최소 권한으로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-15 - world writable 파일 점검"
echo "📅 실행 시간: $(date)"
