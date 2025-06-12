#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-01 - root 계정 원격 접속 제한
# 설명: SSH, Telnet을 통한 root 계정 원격 접속이 허용된 경우
# 원본 스크립트: u-01.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-01 - root 계정 원격 접속 제한"
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
echo "   1. SSH PermitRootLogin 설정을 no로 변경"
echo "   2. Telnet 서비스에서 root 접속 차단"
echo "   3. sudo 또는 su를 통한 권한 상승 사용"
echo "   4. 원격 접속 로그 모니터링"



echo ""
echo "🛠️  조치 방법:"
echo "   SSH/Telnet에서 root 계정 직접 로그인을 비활성화해야 합니다."


echo "🎯 GovScan 점검 완료: u-01 - root 계정 원격 접속 제한"
echo "📅 실행 시간: $(date)"
