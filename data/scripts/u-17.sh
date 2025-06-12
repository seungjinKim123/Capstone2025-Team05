#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-17 - rhosts, hosts.equiv 사용 금지
# 설명: rhosts나 hosts.equiv 파일이 부적절하게 설정된 경우
# 원본 스크립트: u-17.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-17 - rhosts, hosts.equiv 사용 금지"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


#!/bin/bash

echo "====[Info] U-17 rhosts, hosts.equiv 사용 금지 점검 시작===="

vulnerable=0
output=""

# 1. /etc/hosts.equiv 점검
if [ -f /etc/hosts.equiv ]; then
    perm=$(stat -c "%a" /etc/hosts.equiv)
    owner=$(stat -c "%U" /etc/hosts.equiv)
    plus_check=$(grep '^+' /etc/hosts.equiv 2>/dev/null)

    echo "[*] /etc/hosts.equiv found: owner=$owner, perm=$perm"
    if [ "$owner" != "root" ]; then
        output+="\t- /etc/hosts.equiv 파일 소유자 비정상 (현재: $owner)\n"
        vulnerable=1
    fi
    if [ "$perm" -gt 600 ]; then
        output+="\t- /etc/hosts.equiv 파일 권한 과도 (현재: $perm)\n"
        vulnerable=1
    fi
    if [ ! -z "$plus_check" ]; then
        output+="\t- /etc/hosts.equiv 파일 내 '+' 설정 존재\n"
        vulnerable=1
    fi
else
    echo "[*] /etc/hosts.equiv not found"
fi

# 2. $HOME/.rhosts 점검 (사용자 홈 디렉토리 전체 탐색)
for home in $(awk -F: '{if($3 >= 1000 && $1 != "nobody") print $6}' /etc/passwd); do
    file="$home/.rhosts"
    if [ -f "$file" ]; then
        perm=$(stat -c "%a" "$file")
        owner=$(stat -c "%U" "$file")
        plus_check=$(grep '^+' "$file" 2>/dev/null)
        
        echo "[*] $file found: owner=$owner, perm=$perm"
        if [ "$owner" != "root" ] && [ "$owner" != "$(basename $home)" ]; then
            output+="\t ↳ $file 파일 소유자 비정상 (현재: $owner)\n"
            vulnerable=1
        fi
        if [ "$perm" -gt 600 ]; then
            output+="\t ↳ $file 파일 권한 과도 (현재: $perm)\n"
            vulnerable=1
        fi
        if [ ! -z "$plus_check" ]; then
            output+="\t ↳ $file 파일 내 '+' 설정 존재\n"
            vulnerable=1
        fi
    fi
done

echo ""
# 결과 출력
if [ "$vulnerable" -eq 1 ]; then
    echo -e "[U-17] Vulnerable"
    echo -e "$output"
else
    echo "[U-17] Safe"
fi

echo "====[Info] U-17 done===="



echo "📋 점검 체크리스트:"
echo "   1. /etc/hosts.equiv 파일 존재 여부 및 내용 확인"
echo "   2. 사용자 홈 디렉터리 .rhosts 파일 확인"
echo "   3. '+' 설정 제거"
echo "   4. r-command 서비스 비활성화"



echo ""
echo "🛠️  조치 방법:"
echo "   rhosts와 hosts.equiv 파일을 제거하거나 적절한 권한으로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-17 - rhosts, hosts.equiv 사용 금지"
echo "📅 실행 시간: $(date)"
