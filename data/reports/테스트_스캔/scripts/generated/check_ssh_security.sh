#!/bin/bash
# 점검 스크립트: 20502 - SSH 약한 인증
# 설명: SSH 서비스에서 약한 패스워드 사용 또는 루트 로그인 허용
# 생성일: $(date +"%Y-%m-%d")

echo "======================================"
echo "점검 항목: 20502 - SSH 약한 인증"
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


# SSH 보안 설정 점검
echo "1. SSH 설정 파일 점검"
if [ -f "/etc/ssh/sshd_config" ]; then
    echo "   - SSH 루트 로그인 설정 확인"
    root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
    if [ "$root_login" = "no" ]; then
        echo "✅ SSH 루트 로그인이 비활성화되어 있습니다."
    else
        echo "❌ SSH 루트 로그인이 허용되어 있습니다."
        echo "   조치: /etc/ssh/sshd_config에서 'PermitRootLogin no' 설정"
    fi
    
    echo "   - SSH 패스워드 인증 설정 확인"
    pass_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
    if [ "$pass_auth" = "no" ]; then
        echo "✅ SSH 패스워드 인증이 비활성화되어 있습니다."
    else
        echo "⚠️  SSH 패스워드 인증이 활성화되어 있습니다."
        echo "   권장: 키 기반 인증 사용"
    fi
else
    echo "⚠️  SSH 설정 파일을 찾을 수 없습니다."
fi
echo

echo "======================================"
echo "점검 체크리스트"
echo "======================================"
echo "1. SSH 루트 로그인 비활성화 (PermitRootLogin no)"
echo "2. SSH 키 기반 인증 사용"
echo "3. SSH 접속 시도 제한 설정"
echo "4. SSH 기본 포트 변경 고려"

echo
echo "======================================"
echo "조치 방법"
echo "======================================"
echo "SSH 루트 로그인을 비활성화하고 키 기반 인증을 사용해야 합니다."
echo

echo "점검 완료: $(date)"
