#!/bin/bash
# 점검 스크립트: 11303 - 관리대장 누락
# 설명: 보안관리자용 기록관리 시스템에 등록되지 않은 호스트 또는 서비스
# 생성일: $(date +"%Y-%m-%d")

echo "======================================"
echo "점검 항목: 11303 - 관리대장 누락"
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
echo "1. 전체 IP 자산에 대한 관리대장 작성 여부 확인"
echo "2. 관리대장과 실제 운영 자산의 일치성 검토"
echo "3. 미등록 자산 발견 시 즉시 등록 절차 수행"
echo "4. 주기적(월 1회) 자산 현황 점검 및 업데이트"

echo
echo "======================================"
echo "조치 방법"
echo "======================================"
echo "모든 자산과 서비스에 대해 관리대장을 작성하고 주기적으로 검토해야 합니다."
echo

echo "점검 완료: $(date)"
