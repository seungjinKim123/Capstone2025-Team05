#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: 20501 - 접근통제 미흡
# 설명: 익명 FTP, PostgreSQL 등 서비스에 기본 계정/익명 접근이 가능한 경우
# 원본 스크립트: u-01.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: 20501 - 접근통제 미흡"
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
echo "   1. FTP 익명 접속 비활성화 확인 (u-20.sh 참조)"
echo "   2. SSH/Telnet 루트 로그인 비활성화 확인 (u-01.sh 참조)"
echo "   3. 데이터베이스 기본 계정 비활성화 또는 패스워드 변경"
echo "   4. 서비스별 강력한 인증 정책 적용 확인"



echo ""
echo "🛠️  조치 방법:"
echo "   서비스 접근 시 인증체계를 적용하고 기본 계정 및 익명 접근을 제한해야 합니다."


echo "🎯 GovScan 점검 완료: 20501 - 접근통제 미흡"
echo "📅 실행 시간: $(date)"
