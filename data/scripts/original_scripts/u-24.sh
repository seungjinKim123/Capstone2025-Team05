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
