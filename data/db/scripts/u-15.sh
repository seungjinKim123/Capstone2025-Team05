#!/bin/bash

echo "====[Info] U-15 world writable 파일 점검 시작===="

# World writable 파일 검색
vulnerable_files=$(find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null)

if [ -z "$vulnerable_files" ]; then
    echo "[U-15] Safe"
else
    echo "[U-15] Vulnerable"
    echo -e "\t ↳ World Writable Files Found:"
    echo "$vulnerable_files" | while read line; do
        echo -e "\t ↳ $line"
    done
fi

echo "====[Info] U-15 done===="
