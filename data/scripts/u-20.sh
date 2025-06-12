#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-20 - 익명 FTP 접속 허용 여부
# 설명: FTP 서비스에서 익명 접속이 허용되어 있는 경우
# 원본 스크립트: u-20.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-20 - 익명 FTP 접속 허용 여부"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-20 익명 FTP 접속 허용 여부 점검 시작===="

vulnerable=0

# /etc/passwd에 ftp 계정이 존재하는지 확인
if grep -i "^ftp:" /etc/passwd > /dev/null 2>&1; then
    vulnerable=1
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-20] Safe"
else
    echo "[U-20] Vulnerable"
    echo -e "\t ↳ /etc/passwd에 ftp 계정이 존재하여 익명 FTP 접속이 허용된 상태입니다."
fi

echo "====[Info] U-20 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. /etc/passwd에서 ftp 계정 존재 여부 확인"
echo "   2. FTP 서비스 익명 접속 설정 확인"
echo "   3. FTP 서비스 보안 설정 강화"
echo "   4. SFTP/SCP 등 보안 대안 검토"



echo ""
echo "🛠️  조치 방법:"
echo "   익명 FTP 접속을 비활성화하고 인증된 사용자만 접근할 수 있도록 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-20 - 익명 FTP 접속 허용 여부"
echo "📅 실행 시간: $(date)"
