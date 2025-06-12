#!/bin/bash

echo "====[Info] U-14 홈 디렉터리 점검 시작===="

# 점검 대상 환경변수 파일 목록
target_files=(".profile" ".kshrc" ".cshrc" ".bashrc" ".bash_profile" ".login" ".exrc" ".netrc")

# 결과 변수
vulnerable=0

# 사용자 목록에서 일반 사용자만 대상으로 한다 (UID >= 1000, 시스템 사용자 제외)
user_list=$(awk -F: '$3 >= 1000 && $1 != "nobody" { print $1":"$6 }' /etc/passwd)

# 사용자별 점검
while IFS=":" read -r username homedir; do
    for file in "${target_files[@]}"; do
        filepath="${homedir}/${file}"

        if [ -f "$filepath" ]; then
            # 파일 소유자 확인
            owner=$(stat -c %U "$filepath" 2>/dev/null)
            perm=$(stat -c %A "$filepath" 2>/dev/null)
            others_write=$(echo "$perm" | cut -c9)

            if [ "$owner" != "$username" ] && [ "$owner" != "root" ]; then
                echo "[!] $filepath - 소유자가 $username 또는 root가 아님 → 취약"
                vulnerable=1
            fi

            if [ "$others_write" == "w" ]; then
                echo "[!] $filepath - 다른 사용자에게 쓰기 권한 존재 → 취약"
                vulnerable=1
            fi
        fi
    done
done <<< "$user_list"

# 최종 결과
echo ""
if [ $vulnerable -eq 0 ]; then
    echo "[U-14] Safe"
else
    echo "[U-14] Vulnerable"
fi

echo "====[Info] U-14 Done===="
