#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: 40101 - 패치 관리 미흡
# 설명: 시스템 및 애플리케이션의 보안 패치가 적용되지 않은 경우
# 원본 스크립트: u-42.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: 40101 - 패치 관리 미흡"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-42 최신 패치 적용 여부 점검 시작===="

os_type=$(uname -s)
echo "[*] OS Type: $os_type"

case "$os_type" in
    Linux)
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            distro=$ID
        else
            echo "[U-42] 배포판 정보를 확인할 수 없습니다."
            exit 1
        fi

        echo "[*] Linux Distribution: $distro"

        case "$distro" in
            ubuntu|debian)
                echo "[*] Checking with apt"
                apt update > /dev/null 2>&1
                updates=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
                ;;
            centos|rhel|rocky|almalinux)
                echo "[*] Checking with yum"
                yum check-update > /dev/null 2>&1
                updates=$(yum check-update --security 2>/dev/null | grep -v "^Security:" | wc -l)
                ;;
            *)
                echo "[U-42] 지원되지 않는 Linux 배포판입니다."
                exit 1
                ;;
        esac

        if [ "$updates" -eq 0 ]; then
            echo "[U-42] Safe"
        else
            echo "[U-42] Vulnerable"
            echo -e "\t ↳ $updates개의 패치가 미적용 상태입니다."
        fi
        ;;
    
    SunOS)
        echo "[*] Detected OS: Solaris"
        echo "[*] 패치 정보 확인 중..."
        patch_num=$(showrev -p | wc -l)
        if [ "$patch_num" -gt 0 ]; then
            echo "[U-42] Safe"
        else
            echo "[U-42] Vulnerable"
            echo -e "\t ↳ 적용된 패치 정보를 확인할 수 없습니다."
        fi
        ;;
    
    AIX)
        echo "[*] Detected OS: AIX"
        echo "[*] 적용된 패치 목록 확인..."
        instfix_output=$(instfix -i | grep -i "All filesets")
        if [ -n "$instfix_output" ]; then
            echo "[U-42] Safe"
        else
            echo "[U-42] Vulnerable"
            echo -e "\t ↳ 일부 필수 패치가 누락되었거나 확인 불가."
        fi
        ;;
    
    HP-UX)
        echo "[*] Detected OS: HP-UX"
        echo "[*] 적용된 패치 목록 확인..."
        patch_count=$(swlist -l patch 2>/dev/null | wc -l)
        if [ "$patch_count" -gt 1 ]; then
            echo "[U-42] Safe"
        else
            echo "[U-42] Vulnerable"
            echo -e "\t ↳ 적용된 패치가 없거나 정보를 확인할 수 없습니다."
        fi
        ;;

    *)
        echo "[U-42] 지원되지 않는 운영체제입니다."
        ;;
esac

echo "====[Info] U-42 Done ===="



echo "📋 점검 체크리스트:"
echo "   1. 운영체제 최신 보안 패치 적용 여부 확인 (u-42.sh)"
echo "   2. 애플리케이션 보안 업데이트 적용 여부 확인"
echo "   3. 패치 적용 전 테스트 절차 수립"
echo "   4. 긴급 패치 적용 절차 수립"



echo ""
echo "🛠️  조치 방법:"
echo "   정기적인 보안 패치 적용 및 패치 관리 정책을 수립해야 합니다."


echo "🎯 GovScan 점검 완료: 40101 - 패치 관리 미흡"
echo "📅 실행 시간: $(date)"
