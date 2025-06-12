#!/bin/bash

echo "====[Info] U-16 /dev 에 존재하지 않는 devices 파일 점검 시작===="

vulnerable_files=()

while IFS= read -r line; do
    # 파일 정보 추출
    file_type=$(echo "$line" | awk '{print $1}')
    file_path=$(echo "$line" | awk '{for (i=9; i<=NF; i++) printf $i " "; print ""}' | sed 's/ *$//')

    # 일반 파일이고 major/minor 번호가 없는 경우
    if [[ $file_type != b* && $file_type != c* ]]; then
        vulnerable_files+=("$file_path")
    fi
done < <(find /dev -type f -exec ls -l {} \; 2>/dev/null)

echo ""

if [ ${#vulnerable_files[@]} -eq 0 ]; then
    echo "[U-16] Safe"
else
    echo "[U-16] Vulnerable"
    for file in "${vulnerable_files[@]}"; do
        echo -e "\t ↳ $file"
    done
fi

echo "====[Info] U-16 done===="
