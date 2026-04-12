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
| 2026-04-06 | ccid_emulator    | Added malloc NULL check. Fixed log_count uint16 overflow (wraps after 65535 APDUs → display shows 0 entries). Widened to uint32. Full trace clean otherwise. |
| 2026-04-08 | rogue_ap_detector | Wired up dead min_rssi setting (value was set in UI but never applied to worker filtering). Added NULL context guard in UART callback to prevent crash on race during scan stop. Updated README. Full trace clean otherwise. |
| 2026-04-09 | ble_scanner      | Added NULL context guard in worker_rx_line for teardown race (same pattern as rogue_ap_detector). Added volatile to scanning field for cross-thread visibility (same fix as nfc_fuzzer). Full trace clean otherwise — buffer sizes correct, mutex usage correct, view lifecycle clean, stack usage safe. |
| 2026-04-10 | rayhunter_client | Added NULL context guard in rh_worker_rx_line for teardown race (same class as rogue_ap_detector/ble_scanner). Added volatile to connected field for cross-thread visibility (UART worker writes, timer daemon reads). Full trace clean otherwise — buffer sizes verified (counters[32] tight but safe), stack usage safe (832/2048 on UART thread), view lifecycle clean, no SD card I/O, settings mutex usage correct, poll timer blocking acceptable (~1.3ms at 115200). Dead defines RH_PORT_MIN/MAX noted but not worth removing. |
| 2026-04-11 | evil_ble         | Added NULL context guard in evil_ble_scanner_rx_cb for teardown race (same class as rogue_ap_detector/ble_scanner/rayhunter_client). Added volatile to scanning field (scanner struct, cross-thread: GUI writes, UART worker reads without mutex) and connected field (UART struct, worker writes, API reads). Full trace clean otherwise — buffer sizes verified (device_labels[64] fits 40-char max, status_buf[256] fits 109-char max, clone_menu_label[48] fits 27-char max), stack usage safe (145/4096 main, 520/2048 UART worker), view lifecycle clean (3 views: submenu×2 + textbox, correct add/remove/free order), back-button handling correct for all views, clone engine extra_beacon config/start/stop correct, scanner mutex usage correct, dedup by MAC correct, djb2 placeholder MAC generation correct, adv payload construction bounded. evil_ble_uart_is_connected declared but never called (same as rogue_ap_detector). No SD card I/O. No cross-app consistency issues. |
| 2026-04-12 | flipperpwn       | **Fixed marauder get_\* race condition** — migrated all 14 callers (5 in wifi_views.c, 9 in payload_engine.c) from unsafe `get_*` to `copy_*` with heap-allocated temporary buffers. Removed dead `get_*` API from marauder.h/marauder.c. Added volatile to wifi_uart.c `connected` field (cross-thread: UART worker writes, GUI reads). Full trace clean — flipperpwn.c view lifecycle correct (17 views), os_detect.c LED restore + CDC bounded, payload_engine.c substitution bounded, wifi_uart.c clean after volatile fix. No new cross-app issues. |

## Open Items

### Cross-App Issues

- **Issue #6 — Empty `images/` directories**: RESOLVED 2026-03-31. Removed `fap_icon_assets="images"` from all 7 apps (badusb_pro, ccid_emulator, flipperpwn, hid_exfil, nfc_fuzzer, spi_flash_dump, subghz_spectrum). No app uses compiled icon assets. GitHub issue can be closed.
- **Issue #4 — CCID VID/PID customization**: SDK does not support custom USB descriptors for CCID. Dead preset UI was already removed (commit 7e63dca). Issue can likely be closed or kept for future SDK support.
- **Issue #3 — CI lint/format check**: ADDRESSED 2026-04-03. Added `.github/workflows/build.yml` using `flipperzero-ufbt-action` with matrix strategy (build + lint for all 13 FAPs). Added `build_all.sh` for local use. GitHub issue can be closed after verifying the workflow runs successfully.
- **SD card paths**: `nfc_fuzzer` uses `/ext/nfc_fuzzer/`, `spi_flash_dump` uses `/ext/spi_dumps/`, `badusb_pro` uses `/ext/badusb_pro/`, and `hid_exfil` uses `/ext/hid_exfil/` instead of the conventional `/ext/apps_data/<app_name>/`. Should migrate to avoid polluting SD card root. Coordinate change across apps in a dedicated session.
- **malloc NULL checks**: 3 app entry points (subghz_spectrum, nfc_fuzzer, subghz_jammer) have no malloc check. 10 apps use `furi_assert(app)` (always-on, gives crash dump — idiomatic). badusb_pro uses `if(!app) return 1`. hid_exfil fixed 2026-04-04. spi_flash_dump worker/hex_viewer fixed 2026-04-05. ccid_emulator fixed 2026-04-06.

### Per-App Items

- **flipperpwn**: Reviewed 2026-04-12. RESOLVED: Marauder `get_*` race condition — migrated all 14 callers to `copy_*`, removed dead `get_*` API. Added volatile to `wifi_uart.c:connected`. Previous fixes: EXFIL_USB Windows COM port filtering (2026-04-01). Full trace clean: view lifecycle correct, os_detect LED/CDC handling bounded, payload_engine substitution bounded, wifi_uart ISR/worker clean. No open items.
- **ccid_emulator**: Reviewed 2026-04-06. Added furi_assert after malloc in app_alloc. Widened log_count from uint16_t to uint32_t to prevent ring buffer display reset after 65535 APDU exchanges. SD card path uses `/ext/ccid_emulator/` (existing cross-app issue). USB VID/PID customization not possible with current SDK (Issue #4 — documented in settings_build). discover_card_files doesn't check second storage_dir_open return (no crash, just 0 results — not worth fixing). APDU monitor draw holds log_mutex with FuriWaitForever — brief freeze possible during log export, but user-initiated so acceptable. Code otherwise clean.
- **hid_exfil**: Reviewed 2026-04-04. Fixed USB config loss on DataViewer→Back→re-run path (usb_prev overwritten with HID). Added malloc NULL check. GUI thread blocks ~6.5s during USB HID setup in config_enter_callback (UX issue, not crash — user can't cancel during this). SD card path uses `/ext/hid_exfil/` (existing cross-app issue). `assembled_script[8192]` is a static global — not thread-safe but only accessed from worker thread, so no actual race. Linux payloads require X11 + xdotool/xset (Wayland won't work). Code otherwise clean.
- **badusb_pro**: Reviewed 2026-04-03. Added malloc NULL check. Removed dead code (unreachable InputKeyLeft/Back switch cases). REPEAT command doesn't support mouse/consumer/LED/VAR tokens (feature gap, not crash). Condition evaluator (`evaluate_condition`) can be confused by `==`/`!=` inside substituted variable values (edge case). SD card path uses `/ext/badusb_pro/` instead of `/ext/apps_data/badusb_pro/` (existing cross-app issue).
- **nfc_fuzzer**: Reviewed 2026-04-02. Fixed log truncation, progress bar overflow, volatile annotation, redundant free. Code otherwise clean — profiles well-bounded, mutex usage correct, all allocations freed on exit.
- **subghz_jammer**: Reviewed 2026-03-31. Clean after hw error fix.
- **subghz_spectrum**: Reviewed 2026-03-31. Needs HAL→subghz_devices API migration (non-trivial, dedicated session).
- **spi_flash_dump**: Reviewed 2026-04-05. Fixed progress bar uint32 overflow in read and verify views (cast to uint64_t). Added furi_assert after malloc in spi_worker_alloc and hex_viewer_alloc. Fixed README referencing wrong dump path (/ext/spi_flash_dump/ → /ext/spi_dumps/). UX issue: Settings Back always returns to WiringGuide even when entered from ChipInfo (needs return-view tracking; low priority). SD card path uses `/ext/spi_dumps/` instead of `/ext/apps_data/spi_flash_dump/` (existing cross-app issue). GPIO pins (PB3/PA6/PA7/PA4) verified — no conflicts. SPI Mode 0 bit-bang correct. 4-byte address mode for >16MB chips correct. Worker stack ~560 bytes in chip_verify (two 256-byte buffers) — fits within 4KB. All Storage API returns checked. View lifecycle clean.
- **rogue_ap_detector**: Reviewed 2026-04-08. Wired up min_rssi setting — was dead (UI stored value but worker never filtered). Added int8_t min_rssi to RogueApResults, settings callback writes it, worker applies it after mutex acquire. Added NULL context guard in rogue_uart_line_cb to prevent crash from race condition during callback teardown (set_rx_callback clears ctx before cb — narrow window but real). `rogue_uart_is_connected()` declared/implemented but never called — scan view uses scanning flag, not actual ESP32 presence. UX enhancement for future. SSID parser strips trailing digit tokens (beacon bytes) — could truncate SSIDs ending in numbers (e.g., "WiFi 5"); inherent Marauder format limitation, documented in README. Refresh timer runs continuously even when not on scan view — negligible CPU, not worth fixing. View lifecycle, memory management, mutex usage all clean. No resource leaks. Stack usage safe (512-byte line_buf on 2048 UART thread stack). All code paths free properly.
- **ble_scanner**: Reviewed 2026-04-09. Added NULL context guard in worker_rx_line to prevent crash from UART callback teardown race (same class as rogue_ap_detector fix). Added volatile annotation to scanning field for correct cross-thread visibility (GUI writes, UART worker reads). `ble_uart_is_connected()` is called from refresh timer (no_esp32 flag) — used correctly. Refresh timer runs continuously even when on main menu (malloc+free every 500ms when idle — negligible, same as rogue_ap_detector). SD card path uses `/ext/ble_scanner/` (existing cross-app issue). Deterministic placeholder MACs for named devices use FNV-1a hash — ~0.01% collision risk at 64 max devices, acceptable. AirTag heuristic covers Apple OUI list + name substring. All buffer sizes verified. All code paths free properly. View lifecycle and back-button handling clean.
- **rayhunter_client**: Reviewed 2026-04-10. Added NULL context guard in rh_worker_rx_line for teardown race (same class as rogue_ap_detector/ble_scanner). Added volatile to connected field for cross-thread visibility (UART worker writes, timer thread reads via rh_uart_is_connected). No SD card I/O — pure in-memory display app. Settings use preset cycling (4 host IPs, 4 ports, 5 poll intervals) — no free-text input. config_mutex protects app->config but config is only written from GUI thread (settings callbacks) — mutex is defensive, not strictly needed. Dead defines RH_PORT_MIN/RH_PORT_MAX from removed text-input approach — not worth removing. counters[32] buffer tight (31-char max + NUL) but snprintf protects. Stack usage on UART thread: ~832/2048 bytes at worst case. All buffer sizes verified. View lifecycle clean. Back button handled correctly. No resource leaks. Poll timer acceptable (~1.3ms blocking for 15-byte TX at 115200).
- **evil_ble**: Reviewed 2026-04-11. Added NULL context guard in evil_ble_scanner_rx_cb for UART teardown race (same class as rogue_ap_detector/ble_scanner/rayhunter_client). Added volatile to scanning (scanner struct) and connected (UART struct) for cross-thread visibility. evil_ble_uart_is_connected() declared/implemented but never called (same as rogue_ap_detector). No SD card I/O. Marauder scanbt parser uses " Device: " anchor with MAC/name disambiguation — MAC parsed directly, names get djb2-hashed placeholder MACs (DE:AD:xx:xx:xx:xx prefix). Synthetic adv payload uses AD type 0x09 (Complete Local Name). Clone engine uses extra_beacon API correctly — config/start/stop lifecycle clean, stopped on both explicit user action and app exit. Dedup check against "(unknown)" is vestigial (never generated) but harmless. All buffer sizes verified with margin. Stack usage well within limits. View lifecycle (3 views: 2 submenus + textbox) correct. Back-button navigates cleanly from all views. No cross-app consistency issues found.
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
- **CHANGELOG.md**: Created 2026-04-05. Retroactive entries from all 50 commits, organized by date with fix/feat/refactor/chore/docs categories.
- **Per-file header comments**: Completed 2026-04-05. All 39 `.c` files now have header comments explaining module purpose.

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
