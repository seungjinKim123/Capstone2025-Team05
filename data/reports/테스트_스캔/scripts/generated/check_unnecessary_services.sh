#!/bin/bash
# 점검 스크립트: 30501 - 불필요한 서비스 운영
# 설명: 업무와 무관한 불필요한 서비스가 실행 중인 경우
# 생성일: $(date +"%Y-%m-%d")

echo "======================================"
echo "점검 항목: 30501 - 불필요한 서비스 운영"
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


# 불필요한 서비스 점검
echo "1. 불필요한 서비스 실행 여부 점검"

unnecessary_ports=("7" "9" "13" "19" "79")
unnecessary_services=("echo" "discard" "daytime" "chargen" "finger")

for i in "${!unnecessary_ports[@]}"; do
    port=${unnecessary_ports[$i]}
    service=${unnecessary_services[$i]}
    
    echo "   - $service 서비스 점검 (포트 $port)"
    nmap -p $port $TARGET_IP 2>/dev/null | grep -q "open"
    if [ $? -eq 0 ]; then
        echo "❌ $service 서비스가 실행 중입니다."
        echo "   조치: 불필요한 $service 서비스 중지"
    else
        echo "✅ $service 서비스가 비활성화되어 있습니다."
    fi
done
echo

echo "======================================"
echo "점검 체크리스트"
echo "======================================"
echo "1. 실행 중인 모든 서비스 목록 작성"
echo "2. 업무 필요성에 따른 서비스 분류"
echo "3. 불필요한 서비스 중지 및 비활성화"
echo "4. 주기적 서비스 현황 점검"

echo
echo "======================================"
echo "조치 방법"
echo "======================================"
echo "업무에 필요하지 않은 서비스는 중지하고 필요한 서비스만 운영해야 합니다."
echo

echo "점검 완료: $(date)"
