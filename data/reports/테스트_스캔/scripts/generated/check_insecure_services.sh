#!/bin/bash
# 점검 스크립트: 20503 - 기본포트 사용 및 취약한 서비스 운용
# 설명: Telnet, FTP, rlogin 등 보안성이 취약한 서비스가 기본 포트로 운용되는 경우
# 생성일: $(date +"%Y-%m-%d")

echo "======================================"
echo "점검 항목: 20503 - 기본포트 사용 및 취약한 서비스 운용"
echo "======================================"
echo

# 점검 대상 정보 수집
if [ "$#" -ne 1 ]; then
    echo "사용법: $0 <target_ip>"
    echo "예시: $0 192.168.1.100"
    exit 1
fi

TARGET_IP=$1
echo "점검 대상 IP: $TARGET_IP"
echo


# 취약한 서비스 점검
echo "1. 취약한 서비스 실행 여부 점검"

services=("telnet:23" "ftp:21" "rlogin:513" "rsh:514")
for service in "${services[@]}"; do
    svc_name=$(echo $service | cut -d: -f1)
    svc_port=$(echo $service | cut -d: -f2)
    
    echo "   - $svc_name 서비스 점검 (포트 $svc_port)"
    nmap -p $svc_port $TARGET_IP 2>/dev/null | grep -q "open"
    if [ $? -eq 0 ]; then
        echo "❌ $svc_name 서비스가 실행 중입니다."
        echo "   조치: $svc_name 서비스를 중지하고 보안 대안 사용"
    else
        echo "✅ $svc_name 서비스가 비활성화되어 있습니다."
    fi
done
echo

echo "======================================"
echo "점검 체크리스트"
echo "======================================"
echo "1. Telnet 서비스 비활성화 및 SSH로 대체"
echo "2. FTP 서비스 비활성화 및 SFTP/SCP로 대체"
echo "3. rlogin, rsh 등 r-command 서비스 비활성화"
echo "4. 필요시 VPN 내에서만 접근 가능하도록 구성"

echo
echo "======================================"
echo "조치 방법"
echo "======================================"
echo "보안성이 낮은 서비스를 사용하지 않거나, VPN 내에서 사용하며 SSH 등 보안 대체 수단을 사용해야 합니다."
echo

echo "점검 완료: $(date)"
