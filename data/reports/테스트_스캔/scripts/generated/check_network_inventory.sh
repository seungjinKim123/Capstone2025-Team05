#!/bin/bash
# 점검 스크립트: 30301 - 관리대장 누락
# 설명: 연결된 장비가 관리대장에 포함되지 않음 (물리 네트워크 추적 기준)
# 생성일: $(date +"%Y-%m-%d")

echo "======================================"
echo "점검 항목: 30301 - 관리대장 누락"
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


# 관리대장 점검
echo "1. 자산 관리대장 점검"
echo "   - 현재 IP가 관리대장에 등록되어 있는지 확인"
echo "   - 관리대장 파일 위치: /etc/asset_inventory.txt"
echo

if [ -f "/etc/asset_inventory.txt" ]; then
    if grep -q "$TARGET_IP" /etc/asset_inventory.txt; then
        echo "✅ IP $TARGET_IP가 관리대장에 등록되어 있습니다."
    else
        echo "❌ IP $TARGET_IP가 관리대장에 등록되어 있지 않습니다."
        echo "   조치: 관리대장에 해당 IP 정보를 등록하세요."
    fi
else
    echo "❌ 관리대장 파일이 존재하지 않습니다."
    echo "   조치: /etc/asset_inventory.txt 파일을 생성하고 자산 정보를 등록하세요."
fi
echo

echo "======================================"
echo "점검 체크리스트"
echo "======================================"
echo "1. 네트워크 연결 장비의 MAC 주소 수집"
echo "2. 물리적 네트워크 토폴로지 문서화"
echo "3. 미등록 네트워크 장비 탐지 및 등록"
echo "4. 네트워크 장비 관리대장 주기적 업데이트"

echo
echo "======================================"
echo "조치 방법"
echo "======================================"
echo "물리적/논리적 연결 장비의 MAC 주소를 식별하고 자산 등록을 철저히 해야 합니다."
echo

echo "점검 완료: $(date)"
