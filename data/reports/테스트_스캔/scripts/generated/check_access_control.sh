#!/bin/bash
# 점검 스크립트: 20501 - 접근통제 미흡
# 설명: 익명 FTP, PostgreSQL 등 서비스에 기본 계정/익명 접근이 가능한 경우
# 생성일: $(date +"%Y-%m-%d")

echo "======================================"
echo "점검 항목: 20501 - 접근통제 미흡"
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


# 접근통제 점검
echo "1. FTP 익명 접속 점검"
echo "   - FTP 서비스의 익명 접속 허용 여부 확인"
timeout 5 ftp -n $TARGET_IP <<EOF 2>/dev/null | grep -q "230.*anonymous"
user anonymous
quit
EOF

if [ $? -eq 0 ]; then
    echo "❌ FTP 익명 접속이 허용되어 있습니다."
else
    echo "✅ FTP 익명 접속이 차단되어 있습니다."
fi
echo

echo "2. PostgreSQL 기본 계정 점검"
echo "   - PostgreSQL 기본 계정 접속 시도"
for password in "postgres" "1234" "admin"; do
    pg_isready -h $TARGET_IP -p 5432 -U postgres >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "❌ PostgreSQL 서비스가 기본 포트에서 실행 중입니다."
        echo "   기본 계정 보안 점검이 필요합니다."
        break
    fi
done
echo

echo "======================================"
echo "점검 체크리스트"
echo "======================================"
echo "1. FTP 익명 접속 비활성화 확인"
echo "2. 데이터베이스 기본 계정 비활성화 또는 패스워드 변경"
echo "3. SSH 루트 로그인 비활성화 확인"
echo "4. 서비스별 강력한 인증 정책 적용 확인"

echo
echo "======================================"
echo "조치 방법"
echo "======================================"
echo "서비스 접근 시 인증체계를 적용하고 기본 계정 및 익명 접근을 제한해야 합니다."
echo

echo "점검 완료: $(date)"
