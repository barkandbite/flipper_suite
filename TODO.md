# Flipper Suite — Maintenance TODO

## Review Rotation Log

| Date       | App Reviewed     | Findings                                                    |
|------------|------------------|-------------------------------------------------------------|
| 2026-03-30 | uart_sniff       | Batch-read fix applied to worker thread. Code otherwise clean. |
| 2026-03-31 | subghz_jammer    | Added CC1101 hw error screen (was silent failure). Code otherwise clean. |
| 2026-03-31 | subghz_spectrum  | Removed stale fap_icon_assets. Logged HAL API migration. Code otherwise clean. |
| 2026-04-01 | flipperpwn       | Fixed EXFIL_USB COM port filtering bug (Windows 11). Logged marauder get_* race condition for future fix. |
| 2026-04-02 | nfc_fuzzer       | Fixed SD card log truncation (256-byte buf for 1555-char lines), progress bar uint32 overflow, volatile thread safety, redundant free(NULL). |
| 2026-04-03 | badusb_pro       | Added malloc NULL check in entry point, removed dead code in input handler. Code otherwise clean after thorough trace. |
| 2026-04-04 | hid_exfil        | Fixed USB config clobbered on repeated runs (usb_prev overwritten with HID config). Added malloc NULL check. Code otherwise clean after full trace. |
| 2026-04-05 | spi_flash_dump   | Fixed progress bar uint32 overflow for >37MB chips. Added malloc NULL checks. Fixed README dump path mismatch. Settings Back UX logged. |

## Open Items

### Cross-App Issues

- **Issue #6 — Empty `images/` directories**: RESOLVED 2026-03-31. Removed `fap_icon_assets="images"` from all 7 apps (badusb_pro, ccid_emulator, flipperpwn, hid_exfil, nfc_fuzzer, spi_flash_dump, subghz_spectrum). No app uses compiled icon assets. GitHub issue can be closed.
- **Issue #4 — CCID VID/PID customization**: SDK does not support custom USB descriptors for CCID. Dead preset UI was already removed (commit 7e63dca). Issue can likely be closed or kept for future SDK support.
- **Issue #3 — CI lint/format check**: ADDRESSED 2026-04-03. Added `.github/workflows/build.yml` using `flipperzero-ufbt-action` with matrix strategy (build + lint for all 13 FAPs). Added `build_all.sh` for local use. GitHub issue can be closed after verifying the workflow runs successfully.
- **SD card paths**: `nfc_fuzzer` uses `/ext/nfc_fuzzer/`, `spi_flash_dump` uses `/ext/spi_dumps/`, `badusb_pro` uses `/ext/badusb_pro/`, and `hid_exfil` uses `/ext/hid_exfil/` instead of the conventional `/ext/apps_data/<app_name>/`. Should migrate to avoid polluting SD card root. Coordinate change across apps in a dedicated session.
- **malloc NULL checks**: 4 app entry points (ccid_emulator, subghz_spectrum, nfc_fuzzer, subghz_jammer) have no malloc check. 9 apps use `furi_assert(app)` (always-on, gives crash dump — idiomatic). badusb_pro uses `if(!app) return 1`. hid_exfil fixed 2026-04-04. spi_flash_dump worker/hex_viewer fixed 2026-04-05.

### Per-App Items

- **flipperpwn**: Reviewed 2026-04-01. Fixed EXFIL_USB Windows COM port filtering (parity with os_detect.c CDC fix). Race condition in `fpwn_marauder_get_*` accessors — `fpwn_wifi_save_results` and WIFI_* payload commands use unsafe getters that release the mutex before the caller reads the data. Need to add `fpwn_marauder_lock/unlock` API or refactor to use heap-allocated copy buffers. Low practical impact (scans are usually stopped before save/use), but technically a data race.
- **hid_exfil**: Reviewed 2026-04-04. Fixed USB config loss on DataViewer→Back→re-run path (usb_prev overwritten with HID). Added malloc NULL check. GUI thread blocks ~6.5s during USB HID setup in config_enter_callback (UX issue, not crash — user can't cancel during this). SD card path uses `/ext/hid_exfil/` (existing cross-app issue). `assembled_script[8192]` is a static global — not thread-safe but only accessed from worker thread, so no actual race. Linux payloads require X11 + xdotool/xset (Wayland won't work). Code otherwise clean.
- **badusb_pro**: Reviewed 2026-04-03. Added malloc NULL check. Removed dead code (unreachable InputKeyLeft/Back switch cases). REPEAT command doesn't support mouse/consumer/LED/VAR tokens (feature gap, not crash). Condition evaluator (`evaluate_condition`) can be confused by `==`/`!=` inside substituted variable values (edge case). SD card path uses `/ext/badusb_pro/` instead of `/ext/apps_data/badusb_pro/` (existing cross-app issue).
- **nfc_fuzzer**: Reviewed 2026-04-02. Fixed log truncation, progress bar overflow, volatile annotation, redundant free. Code otherwise clean — profiles well-bounded, mutex usage correct, all allocations freed on exit.
- **subghz_jammer**: Reviewed 2026-03-31. Clean after hw error fix.
- **subghz_spectrum**: Reviewed 2026-03-31. Needs HAL→subghz_devices API migration (non-trivial, dedicated session).
- **spi_flash_dump**: Reviewed 2026-04-05. Fixed progress bar uint32 overflow in read and verify views (cast to uint64_t). Added furi_assert after malloc in spi_worker_alloc and hex_viewer_alloc. Fixed README referencing wrong dump path (/ext/spi_flash_dump/ → /ext/spi_dumps/). UX issue: Settings Back always returns to WiringGuide even when entered from ChipInfo (needs return-view tracking; low priority). SD card path uses `/ext/spi_dumps/` instead of `/ext/apps_data/spi_flash_dump/` (existing cross-app issue). GPIO pins (PB3/PA6/PA7/PA4) verified — no conflicts. SPI Mode 0 bit-bang correct. 4-byte address mode for >16MB chips correct. Worker stack ~560 bytes in chip_verify (two 256-byte buffers) — fits within 4KB. All Storage API returns checked. View lifecycle clean.
- **evil_portal**: Non-FAP resource directory. HTML/Marauder script audit pending.

### Module/Payload Audit (2026-03-30)

**flipperpwn_modules/** — 21 `.fpwn` modules:

| Module | Status | Findings |
|--------|--------|----------|
| recon/sys_info | Audited | Clean. Linux `CTRL ALT t` only works in GNOME (known limitation). |
| recon/av_detect | **Fixed** | 3 lines exceeded 512-byte limit (942, 600, 515 chars). Split into multi-line. |
| recon/network_enum | Audited | Clean. Uses modern iproute2 commands on Linux. |
| recon/wifi_enum | Audited | Clean. |
| recon/wifi_scan_report | Audited | Clean. Requires ESP32. |
| recon/port_scan_report | Audited | Clean. Requires ESP32. |
| credential/wifi_harvest | Audited | Clean. Linux `sudo` commands will prompt (documented). |
| credential/ssh_keys | Audited | Clean. |
| credential/env_dump | Audited | Clean. |
| credential/browser_creds | **Fixed** | WIN line was 723 chars. Split into multi-line. |
| credential/fake_login | **Fixed** | Function def was 1736 chars. Split into multi-line PS block. |
| exploit/reverse_shell_tcp | Audited | Clean. Defaults safe (10.0.0.1). |
| exploit/reverse_shell_dns | Audited | Clean. Defaults safe (10.0.0.1:53). |
| exploit/download_exec | Audited | Clean. Defaults safe (10.0.0.1). |
| exploit/msfvenom_stager | Audited | Clean. WIN-only. Defaults safe. |
| exploit/uac_bypass_fodhelper | Audited | Clean. Registry cleanup included. WIN-only. |
| exploit/evil_twin | Audited | Clean. Requires ESP32. |
| post/add_user | Audited | Clean. Documents admin requirement. |
| post/disable_defender | Audited | Clean. Documents Tamper Protection limitation. |
| post/persist_schtask | Audited | Minor: double backslashes in PAYLOAD_PATH default (harmless on Windows). |
| post/persist_startup | **Fixed** | OPTION default had spaces — parser only stored first token "curl". Changed to /tmp/beacon.sh. |

- **badusb_pro_sample_scripts/**: 3 `.ds` files — audited 2026-03-30. Clean. Uses OS_DETECT, LED_CHECK, IF/END_IF correctly.
- **ccid_emulator_sample_cards/**: 2 `.ccid` files — audited 2026-03-30. Clean. TLV structures valid, PIV AID correct.
- **evil_portal/**: 9 HTML portals, 5 .fpwn scripts, 2 Python tools — audited 2026-03-30. All clean.

### Documentation Status (2026-04-04)

- **Per-app READMEs**: All 13 FAPs + evil_portal now have READMEs. Completed 2026-04-04 (added rogue_ap_detector, ble_scanner, evil_ble, subghz_jammer, uart_sniff, rayhunter_client).
- **CHANGELOG.md**: Not yet created. Retroactive entries from 74+ commits needed.
- **Per-file header comments**: Not yet audited across all apps.

## Review Priority Queue

Priority by complexity (review more complex apps more frequently):

1. `flipperpwn` (~8,200 lines) — review every 2-3 sessions
2. `nfc_fuzzer` (~3,350 lines) — review every 3-4 sessions
3. `badusb_pro` (~2,900 lines) — review every 3-4 sessions
4. `hid_exfil` (~2,000 lines)
5. `spi_flash_dump` (~1,900 lines)
6. `ccid_emulator` (~1,600 lines)
7. `rogue_ap_detector` (~1,400 lines)
8. `ble_scanner` (~1,300 lines)
9. `rayhunter_client` (~1,200 lines)
10. `evil_ble` (~1,150 lines)
11. `subghz_spectrum` (~860 lines) — reviewed 2026-03-31
12. `uart_sniff` (~790 lines) — reviewed 2026-03-30
13. `subghz_jammer` (~730 lines) — reviewed 2026-03-31
