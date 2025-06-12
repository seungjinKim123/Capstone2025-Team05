#!/bin/bash
# 점검 스크립트: 30802 - 버전정보 노출
# 설명: 서비스에서 버전 정보가 노출될 경우 공격자가 취약점을 파악할 수 있음
# 생성일: $(date +"%Y-%m-%d")

echo "======================================"
echo "점검 항목: 30802 - 버전정보 노출"
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


# 버전 정보 노출 점검
echo "1. 서비스 버전 정보 노출 점검"

echo "   - HTTP 서버 버전 정보 확인"
curl -I http://$TARGET_IP 2>/dev/null | grep -i "server:"
if [ $? -eq 0 ]; then
    echo "❌ HTTP 서버 버전 정보가 노출되어 있습니다."
    echo "   조치: 웹 서버 설정에서 버전 정보 숨김 설정"
else
    echo "✅ HTTP 서버 버전 정보가 숨겨져 있습니다."
fi

echo "   - SSH 서버 버전 정보 확인"
ssh -o ConnectTimeout=5 $TARGET_IP exit 2>&1 | head -1 | grep -q "OpenSSH"
if [ $? -eq 0 ]; then
    echo "❌ SSH 서버 버전 정보가 노출되어 있습니다."
    echo "   조치: SSH 배너 설정 수정"
else
    echo "✅ SSH 서버 버전 정보가 적절히 설정되어 있습니다."
fi
echo

echo "======================================"
echo "점검 체크리스트"
echo "======================================"
echo "1. 웹 서버 버전 정보 숨김 설정"
echo "2. SSH 배너 정보 최소화"
echo "3. FTP 환영 메시지에서 버전 정보 제거"
echo "4. 에러 메시지에서 시스템 정보 노출 방지"

echo
echo "======================================"
echo "조치 방법"
echo "======================================"
echo "서비스 배너, 오류 메시지 등을 통해 버전 정보가 노출되지 않도록 설정합니다."
echo

echo "점검 완료: $(date)"
