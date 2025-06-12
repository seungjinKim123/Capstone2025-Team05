#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-16 - /dev에 존재하지 않는 device 파일 점검
# 설명: /dev 디렉터리에 일반 파일이 존재하는 경우
# 원본 스크립트: u-16.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-16 - /dev에 존재하지 않는 device 파일 점검"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-16 /dev 에 존재하지 않는 devices 파일 점검 시작===="

vulnerable_files=()

while IFS= read -r line; do
    # 파일 정보 추출
    file_type=$(echo "$line" | awk '{print $1}')
    file_path=$(echo "$line" | awk '{for (i=9; i<=NF; i++) printf $i " "; print ""}' | sed 's/ *$//')

    # 일반 파일이고 major/minor 번호가 없는 경우
    if [[ $file_type != b* && $file_type != c* ]]; then
        vulnerable_files+=("$file_path")
    fi
done < <(find /dev -type f -exec ls -l {} \; 2>/dev/null)

echo ""

if [ ${#vulnerable_files[@]} -eq 0 ]; then
    echo "[U-16] Safe"
else
    echo "[U-16] Vulnerable"
    for file in "${vulnerable_files[@]}"; do
        echo -e "\t ↳ $file"
    done
fi

echo "====[Info] U-16 done===="



echo "📋 점검 체크리스트:"
echo "   1. /dev 디렉터리 내 일반 파일 확인"
echo "   2. 불필요한 일반 파일 제거"
echo "   3. device 파일 무결성 확인"
echo "   4. /dev 디렉터리 접근 권한 관리"



echo ""
echo "🛠️  조치 방법:"
echo "   /dev 디렉터리에서 device 파일이 아닌 일반 파일을 제거해야 합니다."


echo "🎯 GovScan 점검 완료: u-16 - /dev에 존재하지 않는 device 파일 점검"
echo "📅 실행 시간: $(date)"
