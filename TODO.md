# Flipper Suite — Maintenance TODO

## Review Rotation Log

| Date       | App Reviewed     | Findings                                                    |
|------------|------------------|-------------------------------------------------------------|
| 2026-03-30 | uart_sniff       | Batch-read fix applied to worker thread. Code otherwise clean. |

## Open Items

### Cross-App Issues

- **Issue #6 — Empty `images/` directories**: 7 apps declare `fap_icon_assets="images"` (badusb_pro, ccid_emulator, flipperpwn, hid_exfil, nfc_fuzzer, spi_flash_dump, subghz_spectrum) but no actual image files exist. Either add icons or remove the field. 6 apps (ble_scanner, evil_ble, rayhunter_client, rogue_ap_detector, subghz_jammer, uart_sniff) correctly omit the field.
- **Issue #4 — CCID VID/PID customization**: SDK does not support custom USB descriptors for CCID. Dead preset UI was already removed (commit 7e63dca). Issue can likely be closed or kept for future SDK support.
- **Issue #3 — CI lint/format check**: No GitHub Actions workflow. `ufbt lint` should be run per-app. Blocked on deciding whether to use `flipperzero-ufbt-action` or a local `ufbt` install in CI.

### Per-App Items

- **subghz_jammer**: Not yet reviewed. Next in rotation (small, ~730 lines).
- **subghz_spectrum**: Not yet reviewed. After subghz_jammer.
- **evil_portal**: Non-FAP resource directory. HTML/Marauder script audit pending.

### Module/Payload Audit

- **flipperpwn_modules/**: 21 `.fpwn` modules — none audited yet.
- **badusb_pro_sample_scripts/**: 3 `.ds` files — not audited.
- **ccid_emulator_sample_cards/**: 2 `.ccid` files — not audited.

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
11. `subghz_spectrum` (~860 lines)
12. `uart_sniff` (~790 lines) — reviewed 2026-03-30
13. `subghz_jammer` (~730 lines)
