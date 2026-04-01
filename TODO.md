# Flipper Suite — Maintenance TODO

## Review Rotation Log

| Date       | App Reviewed     | Findings                                                    |
|------------|------------------|-------------------------------------------------------------|
| 2026-03-30 | uart_sniff       | Batch-read fix applied to worker thread. Code otherwise clean. |
| 2026-03-31 | subghz_jammer    | Added CC1101 hw error screen (was silent failure). Code otherwise clean. |
| 2026-03-31 | subghz_spectrum  | Removed stale fap_icon_assets. Logged HAL API migration. Code otherwise clean. |
| 2026-04-01 | flipperpwn       | Fixed EXFIL_USB COM port filtering bug (Windows 11). Logged marauder get_* race condition for future fix. |

## Open Items

### Cross-App Issues

- **Issue #6 — Empty `images/` directories**: RESOLVED 2026-03-31. Removed `fap_icon_assets="images"` from all 7 apps (badusb_pro, ccid_emulator, flipperpwn, hid_exfil, nfc_fuzzer, spi_flash_dump, subghz_spectrum). No app uses compiled icon assets. GitHub issue can be closed.
- **Issue #4 — CCID VID/PID customization**: SDK does not support custom USB descriptors for CCID. Dead preset UI was already removed (commit 7e63dca). Issue can likely be closed or kept for future SDK support.
- **Issue #3 — CI lint/format check**: No GitHub Actions workflow. `ufbt lint` should be run per-app. Blocked on deciding whether to use `flipperzero-ufbt-action` or a local `ufbt` install in CI.

### Per-App Items

- **flipperpwn**: Reviewed 2026-04-01. Fixed EXFIL_USB Windows COM port filtering (parity with os_detect.c CDC fix). Race condition in `fpwn_marauder_get_*` accessors — `fpwn_wifi_save_results` and WIFI_* payload commands use unsafe getters that release the mutex before the caller reads the data. Need to add `fpwn_marauder_lock/unlock` API or refactor to use heap-allocated copy buffers. Low practical impact (scans are usually stopped before save/use), but technically a data race.
- **subghz_jammer**: Reviewed 2026-03-31. Clean after hw error fix.
- **subghz_spectrum**: Reviewed 2026-03-31. Needs HAL→subghz_devices API migration (non-trivial, dedicated session).
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
