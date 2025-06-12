#!/bin/bash

echo "====[Info] U-07 /etc/passwd파일 소유자 및 권한 설정 점검 시작===="

passwd_file="/etc/passwd"

if [ -e $passwd_file ]; then
    # 파일의 권한과 소유자 정보 가져오기
    file_stat=$(stat -c "%a %U" $passwd_file 2>/dev/null)
    file_perm=$(echo $file_stat | awk '{print $1}')
    file_owner=$(echo $file_stat | awk '{print $2}')

    echo "[+] /etc/passwd 권한 : $file_perm"
    echo "[+] /etc/passwd 소유자 : $file_owner"

    # 판단 기준: 소유자 root && 권한 644 이하
    if [ "$file_owner" == "root" ] && [ "$file_perm" -le 644 ]; then
        echo "[U-07] Safe"
    else
        echo "[U-07] Vulnerable"
        if [ "$file_owner" != "root" ]; then
            echo -e "\t ↳ 소유자가 root가 아님"
        fi
        if [ "$file_perm" -gt 644 ]; then
            echo -e "\t ↳ 권한이 644 초과"
        fi
    fi
else
    echo "[U-07] Vulnerable"
    echo "[!] /etc/passwd 파일이 존재하지 않습니다."
fi

echo "====[Info] U-07 done===="
