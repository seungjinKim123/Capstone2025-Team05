#!/bin/bash
# ==========================================
# GovScan 보안점검 스크립트
# ==========================================
# 점검 항목: u-13 - SUID/SGID 설정 파일 점검
# 설명: 불필요하거나 위험한 파일에 SUID/SGID가 설정된 경우
# 원본 스크립트: u-13.sh
# 생성일: $(date +"%Y-%m-%d %H:%M:%S")
# ==========================================

echo "🛡️  GovScan 점검 시작: u-13 - SUID/SGID 설정 파일 점검"
echo "📋 점검 대상: $(hostname)"
echo "⏰ 시작 시간: $(date)"
echo "=================================="


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


echo "📋 점검 체크리스트:"
echo "   1. 시스템 전체 SUID/SGID 파일 목록 작성"
echo "   2. 불필요한 SUID/SGID 권한 제거"
echo "   3. 위험한 SUID 프로그램 대체 방안 검토"
echo "   4. 정기적인 SUID/SGID 파일 모니터링"



echo ""
echo "🛠️  조치 방법:"
echo "   불필요한 SUID/SGID 설정을 제거하고 필요한 경우에만 최소 권한으로 설정해야 합니다."


echo "🎯 GovScan 점검 완료: u-13 - SUID/SGID 설정 파일 점검"
echo "📅 실행 시간: $(date)"
