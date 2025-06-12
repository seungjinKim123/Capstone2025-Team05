#!/bin/bash

echo "====[Info] U-18 접속 IP 및 포트 제한 점검 시작===="

# 기본값
vulnerable=0

# TCP Wrapper 관련 파일 점검
deny_file="/etc/hosts.deny"
allow_file="/etc/hosts.allow"

echo "[*] Checking TCP Wrapper configuration..."

# Step 1: /etc/hosts.deny 확인 (all deny 설정 유무)
if grep -q -i "ALL:ALL" "$deny_file"; then
    echo "✔ ALL:ALL deny 설정이 존재합니다."
else
    echo "✘ [주의] ALL:ALL deny 설정이 존재하지 않습니다."
    vulnerable=1
fi

# Step 2: /etc/hosts.allow 허용된 IP 설정 확인
allow_ip_entries=$(grep -vE '^\s*#|^\s*$' "$allow_file" | wc -l)

if [ "$allow_ip_entries" -gt 0 ]; then
    echo "✔ 허용된 접근 설정이 $allow_ip_entries개 존재합니다."
else
    echo "✘ [주의] 허용된 접근 설정이 존재하지 않습니다."
    vulnerable=1
fi

# Step 3: inetd 데몬 상태 확인 (Solaris 등에서 tcp_wrappers 적용 여부 확인)
if command -v inetadm >/dev/null 2>&1; then
    tcp_wrapper_status=$(inetadm -p | grep tcp_wrappers)
    echo "[*] inetadm 설정: $tcp_wrapper_status"
    if echo "$tcp_wrapper_status" | grep -q "false"; then
        echo "✘ [주의] TCP Wrappers 기능이 중지되어 있습니다."
        vulnerable=1
    fi
else
    echo "[*] inetadm 명령을 사용할 수 없습니다. (일반 Linux 환경에서는 무시 가능)"
fi

echo ""

# 결과 출력
if [ $vulnerable -eq 0 ]; then
    echo -e "[U-18] Safe"
else
    echo -e "[U-18] Vulnerable"
    echo -e "\t ↳ TCP Wrapper 또는 접근 제어 설정 미흡"
fi

echo "====[Info] U-18 done===="
