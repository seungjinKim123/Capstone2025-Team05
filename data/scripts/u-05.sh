#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-05 - root 권한 및 패스 설정
# 설명: root 계정의 PATH 환경변수에 '.' 이 포함된 경우
# 원본 스크립트: u-05.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-05 - root 권한 및 패스 설정"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


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



echo "📋 점검 체크리스트:"
echo "   1. root 계정 PATH 환경변수 확인"
echo "   2. PATH에서 '.' 제거"
echo "   3. 안전한 PATH 설정"
echo "   4. 환경변수 보안 정책 수립"



echo ""
echo "🛠️  조치 방법:"
echo "   root 계정의 PATH에서 현재 디렉토리('.')를 제거해야 합니다."


echo "🎯 GovScan 점검 완료: u-05 - root 권한 및 패스 설정"
echo "📅 실행 시간: $(date)"
