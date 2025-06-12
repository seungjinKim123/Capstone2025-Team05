#!/bin/bash

echo "====[Info] U-13 SUID/SGID 설정 점검 시작===="
vulnerable=0

# 점검 대상 파일 목록 (SOLARIS, LINUX, AIX, HP-UX 통합)
target_files=(
"/usr/bin/admintool" "/usr/bin/at" "/usr/bin/atq" "/usr/bin/atrm" "/usr/bin/lpset"
"/usr/bin/newgrp" "/usr/bin/nisspasswd" "/usr/bin/rdist" "/usr/bin/yppasswd"
"/usr/bin/dtappgather" "/usr/bin/dtprintinfo" "/usr/bin/sdtcm_convert" "/usr/lib/fs/ufs/ufsdump"
"/usr/lib/fs/ufs/ufsrestore" "/usr/lib/lp/bin/netpr" "/usr/openwin/bin/ff.core" "/usr/openwin/bin/kcms_cali"
"/usr/openwin/bin/kcms_configure" "/usr/openwin/bin/xlock" "/usr/platform/sun4u/sbin/prtdiag"
"/usr/sbin/arp" "/usr/sbin/lpmove" "/usr/sbin/prtconf" "/usr/sbin/sysdef" "/usr/sbin/syseventd"
"/usr/sbin/swap -l" "/usr/sbin/swapadd" "/usr/sbin/swapon" "/usr/sbin/swapctl"
"/usr/sbin/dump" "/usr/sbin/restore" "/sbin/unix_chkpwd" "/usr/bin/lpq"
"/usr/bin/lpr" "/usr/bin/lprm" "/usr/bin/lpc" "/usr/bin/traceroute"
"/usr/bin/dtaction" "/usr/sbin/mount" "/usr/sbin/chuser" "/usr/sbin/chgroup"
"/usr/sbin/chrole" "/usr/sbin/traceroute" "/opt/perf/bin/glance" "/opt/perf/bin/gpm"
"/opt/video/bin/camServer" "/usr/bin/lpalt" "/usr/bin/mediainit" "/usr/sbin/landamin"
"/usr/sbin/landiag" "/usr/sbin/lpsched" "/usr/sbin/swconfig" "/usr/sbin/swinstall"
"/usr/sbin/swremove" "/usr/sbin/swlist" "/usr/contrib/bin/traceroute"
)

vulnerable_files=()

for file in "${target_files[@]}"; do
    if [ -e "$file" ]; then
        perms=$(ls -l "$file" 2>/dev/null | awk '{print $1}')
        echo "$file => $perms"
        if echo "$perms" | grep -q '[sS]'; then
            echo -e "\t ↳ SUID/SGID 설정됨"
            vulnerable_files+=("$file")
            vulnerable=1
        fi
    fi
done

echo ""
if [ "$vulnerable" -eq 0 ]; then
    echo "[U-13] Safe"
else
    echo "[U-13] Vulnerable"
    echo "\t ↳ 불필요하거나 위험한 파일에 SUID/SGID 설정이 존재합니다."
    echo "\t ↳ 발견된 파일 수: ${#vulnerable_files[@]}개"
    for vfile in "${vulnerable_files[@]:0:5}"; do  # 최대 5개까지만 표시
        echo "\t ↳ $vfile"
    done
    if [ ${#vulnerable_files[@]} -gt 5 ]; then
        echo "\t ↳ ... 외 $((${#vulnerable_files[@]} - 5))개 파일"
    fi
fi

echo "====[Info] U-13 점검 완료===="