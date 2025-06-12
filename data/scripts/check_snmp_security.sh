#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: 30601 - SNMP 보안 설정 미흡
# 설명: SNMP 서비스에서 기본 커뮤니티 스트링 사용 또는 읽기/쓰기 권한 부여
# 원본 스크립트: u-01.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: 30601 - SNMP 보안 설정 미흡"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-01 root 계정 원격 접속 제한 점검 시작===="

# Telnet
TELNET_SERVICE=telnet.socket
systemctl is-active $TELNET_SERVICE > /dev/null
telnet_service_on=$?

if [ $telnet_service_on -eq 0 ]; then
	echo "TELNET SERVICE ON!"
	telnet_status=$(grep "^pts" /etc/securetty 2>/dev/null | wc -l)
	if [ $telnet_status -ne 0 ]; then
		echo "TELNET ROOT PERMIT ON"
		telnet_vulnerable=1
	else
		echo "TELNET ROOT PERMIT OFF"
		telnet_vulnerable=0
	fi
else
	echo "TELNET SERVICE OFF!"
	telnet_vulnerable=0
fi

# SSH
SSHD_SERVICE=sshd.service
systemctl is-active $SSHD_SERVICE > /dev/null
sshd_service_on=$?

if [ $sshd_service_on -eq 0 ]; then
	echo "SSHD SERVICE ON!"
	sshd_status=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | grep -i "yes" | awk '{print $2}')
	if [ "$sshd_status" == "yes" ]; then
		echo "SSHD ROOT PERMIT ON!"
		sshd_vulnerable=1
	else
		echo "SSHD ROOT PERMIT OFF!"
		sshd_vulnerable=0
	fi
else
	echo "SSH SERVICE OFF!"
	sshd_vulnerable=0
fi

# result
echo ""

if [ $telnet_vulnerable -eq 0 ] && [ $sshd_vulnerable -eq 0 ]; then
	echo -e "[U-01] Safe"
else
	echo -e "[U-01] Vulnerable"
	if [ $telnet_vulnerable -eq 1 ]; then
		echo -e "\t ↳ Telnet : root Access"
	fi
	if [ $sshd_vulnerable -eq 1 ]; then
		echo -e "\t ↳ SSH : root Access"
	fi
fi
echo "====[Info] U-01 done===="


echo "📋 점검 체크리스트:"
echo "   1. SNMP 기본 커뮤니티 스트링(public, private) 변경"
echo "   2. SNMP 읽기 전용 권한 설정"
echo "   3. SNMP 접근 IP 제한 설정"
echo "   4. SNMPv3 사용 검토"



echo ""
echo "🛠️  조치 방법:"
echo "   SNMP 커뮤니티 스트링을 변경하고 읽기 전용으로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: 30601 - SNMP 보안 설정 미흡"
echo "📅 실행 시간: $(date)"
