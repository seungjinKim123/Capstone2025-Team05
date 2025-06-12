#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-24 - 불필요한 NFS 서비스 사용 여부
# 설명: 불필요한 NFS 관련 데몬이 실행되는 경우
# 원본 스크립트: u-24.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-24 - 불필요한 NFS 서비스 사용 여부"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-24 불필요한 NFS 서비스 사용 여부 점검 시작===="

vulnerable=0
OS=$(uname -s)

# NFS 관련 프로세스가 실행 중인지 확인
if ps -ef | grep -E "nfs|statd|lockd" | grep -v grep > /dev/null; then
    vulnerable=1
fi

# Solaris 10 이상일 경우 inetadm으로 점검
if [ "$OS" = "SunOS" ]; then
    if command -v inetadm > /dev/null 2>&1; then
        if inetadm | egrep "nfs|statd|lockd" | grep -q enabled; then
            vulnerable=1
        fi
    fi
fi

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-24] Safe"
else
    echo "[U-24] Vulnerable"
    echo -e "\t ↳ 불필요한 NFS 관련 데몬(nfsd, statd, lockd 등)이 활성화되어 있습니다."
fi

echo "====[Info] U-24 점검 완료===="



echo "📋 점검 체크리스트:"
echo "   1. nfsd, statd, lockd 등 NFS 데몬 비활성화"
echo "   2. NFS 서비스 필요성 검토"
echo "   3. NFS 사용 시 보안 설정 적용"
echo "   4. /etc/exports 파일 권한 관리"



echo ""
echo "🛠️  조치 방법:"
echo "   불필요한 NFS 서비스를 비활성화하고 필요한 경우에만 보안 설정을 적용해야 합니다."


echo "🎯 GovScan 점검 완료: u-24 - 불필요한 NFS 서비스 사용 여부"
echo "📅 실행 시간: $(date)"
