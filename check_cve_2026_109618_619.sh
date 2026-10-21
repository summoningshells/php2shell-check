#!/usr/bin/env bash
# check_cve_2026_109618_619.sh — PoC version/surface checker for the
# PHP session.upload_progress UAF pair (CVE-2026-109618 / CVE-2026-109619).
#
# Works with or without a phpinfo()/probe endpoint. Version discovery cascade:
#   1. explicit URL/path you pass (e.g. /probe.php, /phpinfo.php)
#   2. X-Powered-By: PHP/x.y.z   (expose_php=On default)
#   3. Server: ... PHP/x.y.z ... (cli-server, some FastCGI setups)
#   4. body patterns: "PHP Version x.y.z", "PHP/x.y.z", "PHP x.y.z"
#   5. common info endpoints: probe.php, phpinfo.php, info.php, test.php, php.php
#   6. PHP confirmed but version hidden (PHPSESSID cookie / PHP header) -> UNKNOWN
#
# Safe: GETs only. No trigger body is sent.
#
# Usage:
#   ./check_cve_2026_109618_619.sh [opts] URL [URL...]
# Opts:
#   --no-common   skip step 5
#   --insecure    curl -k (self-signed TLS)
#   --timeout N   per-request timeout (default 8)
#   --ua STR      override the default Windows 11 / Chrome user agent
#
# Exit: 0=vulnerable, 1=patched/safe, 2=no PHP detected, 3=PHP but version hidden
set -u

# Default UA: stock Windows 11 + current Chrome. A scanner UA on a bare
# X-Powered-By check is fine, but waf/CDN rules sometimes vary the surface.
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

# Fixed versions shipped 2026-10-21 14:00 UTC (per php.net security release).
# Branches below these are vulnerable; PHP <= 8.1 and 5/6/7 are EOL, no fix.
declare -A FIXED=(
  [8.5]=8.5.12
  [8.4]=8.4.27
  [8.3]=8.3.36
  [8.2]=8.2.35
)
COMMON=(probe.php phpinfo.php info.php test.php php.php)

CURL_OPTS=(-sS)
TIMEOUT=8
USE_COMMON=1
URLS=()
while (($#)); do
  case "$1" in
    --no-common) USE_COMMON=0;;
    --insecure) CURL_OPTS+=(-k);;
    --timeout) TIMEOUT="$2"; shift;;
    --ua) UA="$2"; shift;;
    -*) echo "unknown option: $1" >&2; exit 2;;
    *) URLS+=("$1");;
  esac
  shift
done
((${#URLS[@]})) || { echo "usage: $0 [--no-common] [--insecure] [--timeout N] [--ua STR] URL [URL...]" >&2; exit 2; }

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

# --- helpers -----------------------------------------------------------------
fetch() { # fetch URL -> sets RESP_CODE, HD (headers, CR stripped), BD (body)
  local url=$1 hdr="$tmp/h" body="$tmp/b"
  RESP_CODE=$(curl "${CURL_OPTS[@]}" --max-time "$TIMEOUT" \
                      -A "$UA" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
                      -o "$body" -D "$hdr" -w '%{http_code}' "$url" 2>"$tmp/err") || {
    echo "[-] $url: $(tr -d '\n' <"$tmp/err")"; RESP_CODE=000; HD=""; BD=""; return 1; }
  HD=$(tr -d '\r' <"$hdr")
  BD=$(head -c 500000 "$body" 2>/dev/null | tr -d '\r')
  [[ "$RESP_CODE" == 000 ]] && { echo "[-] $url: connection failed"; return 1; }
  return 0
}

ver_from_headers() { # echoes one version found in headers, if any
  { grep -i '^x-powered-by:.*PHP/' <<<"$HD"
    grep -i '^server:.*PHP/'       <<<"$HD"
  } | grep -oiE 'PHP/[0-9]+(\.[0-9]+)*' | head -1 | cut -d/ -f2
}

ver_from_body() { # one version from body: "PHP 8.4.4", "PHP/8.4.4", "version=8.4.4"
  grep -aoiE '(PHP[ /]v?|^version=)[0-9]+\.[0-9]+(\.[0-9]+)?' <<<"$BD" \
    | head -1 | grep -aoE '[0-9]+\.[0-9]+(\.[0-9]+)?'
}

php_present() { # $1 = url
  grep -qi '^x-powered-by:.*PHP' <<<"$HD" && return 0
  grep -qi '^server:.*PHP'       <<<"$HD" && return 0
  grep -qi '^set-cookie:.*PHPSESSID' <<<"$HD" && return 0
  grep -qa 'PHPSESSID' <<<"$BD" && return 0
  # masked headers but the script itself is a .php path AND the request was
  # actually served (2xx/3xx); a generic 404 from a static server is not PHP
  [[ "${1%%\?*}" =~ \.php(/|$) && "$RESP_CODE" =~ ^[23] ]] && return 0
  return 1
}

base_of() { # base URL for common endpoints
  local u=${1%%\?*}; u=${u%%#*}
  [[ "$u" =~ ^https?://[^/]+/?$ ]] && { echo "${u%/}/"; return; }
  echo "${u%/*}/"
}

verdict() { # version -> prints verdict, returns 0 vuln / 1 safe / 3 unknown
  local ver=$1 major minor rest patch
  IFS=. read -r major minor rest <<<"$ver"
  patch=${rest:-0}
  local branch="$major.$minor" fixed
  fixed=${FIXED[$branch]:-}
  if [[ -z "$fixed" ]]; then
    echo "[!] branch $branch is EOL — no official fix; presume VULNERABLE"
    return 0
  fi
  local fpatch=${fixed##*.}
  if (( patch < fpatch )); then
    echo "[+] VULNERABLE: $ver < fixed $fixed (branch $branch)"
    return 0
  fi
  echo "[+] not vulnerable: $ver >= fixed $fixed (branch $branch)"
  return 1
}

any_vuln=0 any_hidden=0 any_php=0 any_reached=0

for url in "${URLS[@]}"; do
  echo "[*] target: $url"
  ver=''; src=''
  if fetch "$url"; then
    any_reached=1
    ver=$(ver_from_headers); [[ -n "$ver" ]] && src="headers"
    if [[ -z "$ver" ]]; then ver=$(ver_from_body); [[ -n "$ver" ]] && src="body"; fi
    php_present "$url" && any_php=1
  fi

  # fallback: common info endpoints (only if version still unknown)
  if [[ -z "$ver" && $USE_COMMON == 1 ]]; then
    base=$(base_of "$url")
    for p in "${COMMON[@]}"; do
      fetch "$base$p" || continue
      ver=$(ver_from_headers); [[ -n "$ver" ]] && src="/$p headers" && break
      ver=$(ver_from_body);   [[ -n "$ver" ]] && src="/$p body"   && break
    done
  fi

  if [[ -n "$ver" ]]; then
    echo "[*] fingerprint: PHP $ver (via $src)"
    verdict "$ver"; rc=$?
    ((rc == 0)) && any_vuln=1
  elif php_present "$url" || ((any_php)); then
    echo "[?] PHP detected but version not disclosed (X-Powered-By/phpinfo hidden)"
    echo "    Cannot confirm patch level from the outside. Every PHP build released"
    echo "    before the 2026-10-21 14:00 UTC fix is affected; treat as VULNERABLE"
    echo "    unless your inventory says otherwise. To get an exact version, serve"
    echo "    lab/poc-check/webroot/probe.php temporarily, or check the package manager."
    any_hidden=1
  else
    echo "[-] no PHP fingerprint — not a PHP endpoint, or headers fully masked"
  fi
  echo
done

if ((any_vuln)); then exit 0
elif ((any_hidden)); then exit 3
elif ((any_reached)); then exit 1      # reached, but no PHP fingerprint
else exit 2                             # nothing reachable at all
fi
