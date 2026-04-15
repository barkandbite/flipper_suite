#!/bin/bash
# Verify the dist/ folder has a .fap for each app and warn about stale builds.
# A .fap is "stale" when any .c or .h file in the app directory is newer than
# the corresponding .fap in dist/.
#
# Usage: ./check_dist.sh

set -euo pipefail

APPS=(
    badusb_pro
    ble_scanner
    ccid_emulator
    evil_ble
    flipperpwn
    hid_exfil
    nfc_fuzzer
    rayhunter_client
    rogue_ap_detector
    spi_flash_dump
    subghz_jammer
    subghz_spectrum
    uart_sniff
)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"

MISSING=0
STALE=0
OK=0

for app in "${APPS[@]}"; do
    fap="$DIST_DIR/${app}.fap"
    printf "%-24s " "$app"

    if [[ ! -f "$fap" ]]; then
        echo "MISSING"
        MISSING=$((MISSING + 1))
        continue
    fi

    # Find the newest .c or .h file in the app directory
    newest_src=$(find "$SCRIPT_DIR/$app" -maxdepth 1 \( -name '*.c' -o -name '*.h' \) -printf '%T@\n' 2>/dev/null | sort -rn | head -1)
    fap_time=$(stat -c '%Y' "$fap" 2>/dev/null || echo 0)

    if [[ -n "$newest_src" ]] && (( $(echo "$newest_src > $fap_time" | bc -l 2>/dev/null || echo 0) )); then
        echo "STALE"
        STALE=$((STALE + 1))
    else
        echo "OK"
        OK=$((OK + 1))
    fi
done

echo ""
echo "Results: $OK current, $STALE stale, $MISSING missing out of ${#APPS[@]} apps"

if [[ $MISSING -gt 0 || $STALE -gt 0 ]]; then
    if [[ $STALE -gt 0 ]]; then
        echo "Rebuild stale apps with: cd <app> && ufbt && cp dist/<app>.fap ../dist/"
    fi
    exit 1
fi
