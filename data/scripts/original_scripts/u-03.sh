#!/bin/bash

echo "====[Info] U-03 계정 잠금 임계값 설정 점검 시작===="

OS=$(uname -s)
LOCK_THRESHOLD=10
lock_value=""
status="Safe"

# ===== LINUX =====
if [ "$OS" = "Linux" ]; then
    echo "[+] OS: Linux"
    if grep -q "pam_tally" /etc/pam.d/system-auth 2>/dev/null; then
        lock_value=$(grep "pam_tally" /etc/pam.d/system-auth | grep -o "deny=[0-9]*" | cut -d= -f2 | head -n1)
    elif grep -q "^deny" /etc/security/faillock.conf 2>/dev/null; then
        lock_value=$(grep "^deny" /etc/security/faillock.conf | awk -F= '{gsub(/[ \t]/,"",$2); print $2}')
    fi

# ===== SOLARIS =====
elif [[ "$OS" == "SunOS" ]]; then
    echo "[+] OS: Solaris"
    if [ -f /etc/default/login ]; then
        lock_value=$(grep "^RETRIES=" /etc/default/login | cut -d= -f2)
    fi
    if [ -z "$lock_value" ] && [ -f /etc/security/policy.conf ]; then
        lock_value=$(grep "^LOCK_AFTER_RETRIES=" /etc/security/policy.conf | cut -d= -f2)
    fi

# ===== AIX =====
elif [[ "$OS" == "AIX" ]]; then
    echo "[+] OS: AIX"
    if [ -f /etc/security/user ]; then
        lock_value=$(grep "^loginretries=" /etc/security/user | head -n1 | cut -d= -f2)
    fi

# ===== HP-UX =====
elif [[ "$OS" == "HP-UX" ]]; then
    echo "[+] OS: HP-UX"
    if [ -f /tcb/files/auth/system/default ]; then
        lock_value=$(grep "^u_maxtries=" /tcb/files/auth/system/default | cut -d= -f2)
    fi
    if [ -z "$lock_value" ] && [ -f /etc/default/security ]; then
        lock_value=$(grep "^AUTH_MAXTRIES=" /etc/default/security | cut -d= -f2)
    fi

else
    echo "[!] Unknown OS: $OS"
    status="Unknown"
fi

echo "계정 잠금 임계값: $lock_value"

# ===== 판단 =====
if [ -z "$lock_value" ]; then
    status="Vulnerable"
    echo "[U-03] Vulnerable"
    echo -e "\t ↳ 계정 잠금 임계값이 설정되어 있지 않음"
elif [ "$lock_value" -le "$LOCK_THRESHOLD" ]; then
    status="Safe"
    echo "[U-03] Safe"
else
    status="Vulnerable"
    echo "[U-03] Vulnerable"
    echo -e "\t ↳ 임계값 설정이 $lock_value회로 기준($LOCK_THRESHOLD회 이하)을 초과함"
fi

echo "====[Info] U-03 done===="
