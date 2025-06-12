#!/bin/bash
# 점검 스크립트: 30601 - SNMP 보안 설정 미흡
# 설명: SNMP 서비스에서 기본 커뮤니티 스트링 사용 또는 읽기/쓰기 권한 부여
# 생성일: $(date +"%Y-%m-%d")

echo "======================================"
echo "점검 항목: 30601 - SNMP 보안 설정 미흡"
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


# SNMP 보안 설정 점검
echo "1. SNMP 커뮤니티 스트링 점검"
echo "   - 기본 커뮤니티 스트링 사용 여부 확인"

communities=("public" "private" "admin" "manager")
for community in "${communities[@]}"; do
    echo "   - 커뮤니티 스트링 '$community' 테스트"
    snmpwalk -v2c -c $community $TARGET_IP 1.3.6.1.2.1.1.1.0 2>/dev/null | grep -q "STRING"
    if [ $? -eq 0 ]; then
        echo "❌ 기본 커뮤니티 스트링 '$community'가 사용 중입니다."
        echo "   조치: 강력한 커뮤니티 스트링으로 변경"
    else
        echo "✅ 커뮤니티 스트링 '$community'는 사용되지 않습니다."
    fi
done
echo

echo "======================================"
echo "점검 체크리스트"
echo "======================================"
echo "1. SNMP 기본 커뮤니티 스트링(public, private) 변경"
echo "2. SNMP 읽기 전용 권한 설정"
echo "3. SNMP 접근 IP 제한 설정"
echo "4. SNMPv3 사용 검토"

echo
echo "======================================"
echo "조치 방법"
echo "======================================"
echo "SNMP 커뮤니티 스트링을 변경하고 읽기 전용으로 설정해야 합니다."
echo

echo "점검 완료: $(date)"
