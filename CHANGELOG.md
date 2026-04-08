# Changelog

All notable changes to the Flipper Suite project are documented in this file.

Format: grouped by date, categorized as **fix**, **feat**, **refactor**, **chore**, or **docs**.

---

## 2026-04-08

### fix
- **rogue_ap_detector**: Wire up min RSSI filter — Settings UI stored the value but the worker thread never applied it; APs below threshold are now dropped before detection analysis
- **rogue_ap_detector**: Add NULL context guard in `rogue_uart_line_cb` to prevent crash from race condition during UART callback teardown

### docs
- **rogue_ap_detector**: Update README — min RSSI filter now active, document SSID digit-truncation limitation

---

## 2026-04-06

### fix
- **ccid_emulator**: Add `furi_assert` after `malloc` in `ccid_emulator_app_alloc` entry point
- **ccid_emulator**: Widen `log_count` from `uint16_t` to `uint32_t` — APDU monitor and log export showed 0 entries after 65,535 APDU exchanges due to integer wrap

---

## 2026-04-05

### fix
- **spi_flash_dump**: Fix progress bar integer overflow for chips >37 MB — cast to `uint64_t` in read and verify progress views (`spi_flash_dump.c`)
- **spi_flash_dump**: Add `furi_assert` after `malloc` in `spi_worker_alloc` and `hex_viewer_alloc`

### docs
- **spi_flash_dump**: Fix README dump path (`/ext/spi_flash_dump/` → `/ext/spi_dumps/`) to match actual code

---

## 2026-04-04

### fix
- **hid_exfil**: Fix USB config loss on repeated runs — `usb_prev` was being overwritten with the HID config on DataViewer→Back→re-run path (`hid_exfil.c`)
- **hid_exfil**: Add `malloc` NULL check in app entry point

### docs
- **rogue_ap_detector**: Add README with hardware setup, wiring, usage, and detection algorithm docs
- **ble_scanner, evil_ble, subghz_jammer, uart_sniff, rayhunter_client**: Add per-app READMEs — all 13 FAPs now documented

---

## 2026-04-03

### fix
- **badusb_pro**: Add `malloc` NULL check in app entry point (`badusb_pro.c`)

### refactor
- **badusb_pro**: Remove dead code — unreachable `InputKeyLeft`/`InputKeyBack` switch cases in input handler

### chore
- Add `.github/workflows/build.yml` CI workflow using `flipperzero-ufbt-action` with matrix strategy for all 13 FAPs (Issue #3)
- Add `build_all.sh` local build script

---

## 2026-04-02

### fix
- **nfc_fuzzer**: Fix SD card log truncation — 256-byte buffer was too small for 1555-char fuzz result lines (`nfc_fuzzer.c`)
- **nfc_fuzzer**: Fix progress bar `uint32` overflow on large fuzz runs
- **nfc_fuzzer**: Add `volatile` annotation for thread-safety on shared worker state
- **nfc_fuzzer**: Remove redundant `free(NULL)` call

---

## 2026-04-01

### fix
- **flipperpwn**: Fix EXFIL_USB Windows COM port filtering for Windows 11 — parity with `os_detect.c` CDC device enumeration fix

---

## 2026-03-31

### fix
- **subghz_jammer**: Show CC1101 hardware error on screen instead of silent failure (`subghz_jammer.c`)

### chore
- Remove stale `fap_icon_assets="images"` from 7 apps that had empty `images/` directories (Issue #6): badusb_pro, ccid_emulator, flipperpwn, hid_exfil, nfc_fuzzer, spi_flash_dump, subghz_spectrum

---

## 2026-03-30

### fix
- **uart_sniff**: Batch-read worker stream buffer to reduce mutex overhead (`uart_sniff_worker.c`)
- **flipperpwn**: Fix 3 `.fpwn` payload lines exceeding 512-byte parser limit (av_detect, browser_creds, fake_login modules)
- **flipperpwn**: Fix `persist_startup` OPTION default truncated by whitespace parser — changed default from path with spaces to `/tmp/beacon.sh`

### chore
- Add Python bytecode (`*.pyc`, `__pycache__/`) to `.gitignore`

### docs
- Add `TODO.md` for daily maintenance session tracking
- Complete Tier 1 module audit: all 21 `.fpwn`, 3 `.ds`, 2 `.ccid`, and `evil_portal/` files verified

---

## 2026-03-29

### fix
- **spi_flash_dump**: Fix 24-bit address overflow when reading chips >16 MB — 4-byte address mode was not being entered (`spi_worker.c`)
- **spi_flash_dump**: Fix hex viewer column overlap — ASCII column was rendering over hex bytes
- **nfc_fuzzer**: Fix NFC poller crash on rapid fuzz cycles — poller was not stopped before reallocation
- **ble_scanner**: Add BLE hardware availability warning when radio is in use

---

## 2026-03-28

### fix
- **hid_exfil**: Fix CapsLock case inversion — typed characters were wrong case when CapsLock was active on host
- **ccid_emulator**: Fix crash on app exit — CCID handler was freed while USB callback was still registered
- **flipperpwn**: Fix CDC OS detection — port name filtering, case-insensitive matching, abort responsiveness (`os_detect.c`)
- **rayhunter_client**: Fix false-connected state — validate UART response content before marking ESP32 as connected
- **badusb_pro**: Fix dropped keystrokes under rapid typing — add inter-keystroke delay
- **ccid_emulator**: Fix crash when switching card profiles — parser state was not reset
- **badusb_pro**: Add parser diagnostics for malformed `.ds` files

### feat
- **hid_exfil**: Add LED channel pre-flight probe and firmware version warning

### refactor
- **rogue_ap_detector, ble_scanner, evil_ble**: Rewrite Marauder UART parsers to handle real ESP32 output formats instead of synthetic test data
- **badusb_pro**: Remove dead BLE mode setting (never implemented)
- **ccid_emulator**: Remove dead VID/PID customization UI (SDK doesn't support it)

### chore
- Remove GitHub Actions workflow — builds done locally with `ufbt`

---

## 2026-03-26

### fix
- **badusb_pro**: Fix integer overflow in variable arithmetic — `VAR` operations on large values wrapped silently
- **badusb_pro**: Fix silent `$var` dropping — undefined variable references in `STRING` lines were removed instead of producing an error

---

## 2026-03-25

### fix
- **flipperpwn**: Fix WiFi scan/connect failures — Marauder command sequencing was not waiting for scan completion before issuing connect
- Cross-app: Fix 20+ bugs from full codebase code review (buffer overflows, null derefs, resource leaks, race conditions)
- Cross-app: Fix 14 bugs from second review pass (edge cases in parsers, protocol handlers, view lifecycle)
- Cross-app: Fix 10 consensus bugs from triple-agent chain-of-thought verification

---

## 2026-03-23

### fix
- Cross-app: Fix 20+ bugs found during first full codebase code review — buffer overflows, null pointer dereferences, resource leaks, unchecked return values across all 13 apps

---

## 2026-03-16

### fix
- Fix 5 device crashes found during on-device testing — stack overflows, GPIO conflicts, view lifecycle issues
- Fix GitHub issues #1 and #2

### docs
- Update README: fix app count (7 → 13), add project status note

---

## 2026-03-15

### fix
- **flipperpwn**: Fix payload execution engine — commands were not dispatched to correct OS handler
- **flipperpwn**: Fix Marauder scan state machine — scan results were lost on state transitions

---

## 2026-03-09

### feat
- **flipperpwn**: Add EXFIL_USB command for high-bandwidth USB CDC serial exfiltration — enables data extraction at ~115 KB/s vs HID channel's ~30 B/s

### fix
- **flipperpwn**: Fix EXFIL_USB memory barrier, drain loop, and buffer truncation issues
- **flipperpwn**: Reduce memory footprint by ~50 KB to fix OOM crash on device — pre-allocated buffers were oversized
- **hid_exfil**: Fix clang-format lint failure
