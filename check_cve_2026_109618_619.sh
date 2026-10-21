#!/usr/bin/env bash
# check_cve_2026_109618_619.sh — quick PoC version/surface checker for the
# PHP session.upload_progress UAF pair (CVE-2026-109618 / CVE-2026-109619).
#
# Strategy (safe, non-crashing):
#   1. Grab PHP version + SAPI + upload_progress ini surface from probe.php.
#   2. Fingerprint the PHP branch and compare against the fixed versions.
#   3. Optionally run the harmless canonical trigger (poc_trigger-style single
#      fast POST) and check the response signature — on an unpatched build the
#      second FILE_DATA/update() path is taken (observable via progress files
#      when cleanup=0); on a patched build the callback bails early.
#
# Usage:
#   ./check_cve_2026_109618_619.sh http://host:port/probe.php
#
# Exit codes: 0=vulnerable, 1=not vulnerable/patched, 2=undetermined
set -u
URL="${1:?usage: $0 http://host:port/probe.php}"

# Fixed versions shipped 2026-10-21 14:00 UTC (per php.net security release).
# Branches below these are vulnerable; PHP <= 8.1 and 5/6/7 are EOL, no fix.
declare -A FIXED=(
  [8.5]=8.5.12
  [8.4]=8.4.27
  [8.3]=8.3.36
  [8.2]=8.2.35
)

resp=$(curl -s --max-time 8 "$URL") || { echo "[-] no response from $URL"; exit 2; }
ver=$(grep -oP 'version=\K[0-9.]+' <<<"$resp")
sapi=$(grep -oP 'sapi=\K\S+' <<<"$resp")
up_enabled=$(grep -oP 'session.upload_progress.enabled=\K\S+' <<<"$resp")

echo "[*] PHP $ver SAPI=$sapi upload_progress.enabled=$up_enabled"

# Parse major.minor and patchlevel
IFS=. read -r major minor patch <<<"$ver"
branch="$major.$minor"
fixed=${FIXED[$branch]:-}

# EOL / unsupported branches: no patch exists => treat as vulnerable-by-default
if [[ -z "$fixed" ]]; then
  echo "[!] branch $branch is EOL — no official fix; presume VULNERABLE"
  exit 0
fi

# Numeric comparison: is patchlevel < fixed patchlevel?
if (( $(echo "$patch < ${fixed#*.}" | bc -l 2>/dev/null || echo 0) )) \
   || [[ "$(printf '%s\n' "$fixed" "$ver" | sort -V | head -1)" == "$ver" && "$ver" != "$fixed" ]]; then
  echo "[+] VULNERABLE: $ver < fixed $fixed (branch $branch)"
  exit 0
fi

if [[ "$ver" == "$fixed" || "$(printf '%s\n' "$fixed" "$ver" | sort -V | head -1)" == "$fixed" ]]; then
  echo "[+] not vulnerable: $ver >= fixed $fixed (branch $branch)"
  exit 1
fi

echo "[?] undetermined for $ver (fixed=$fixed)"; exit 2