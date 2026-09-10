# Marauder Scripts

Attack chain modules and PC-side serial utilities for WiFi Marauder.

## FlipperPwn Modules (`fpwn/`)

Copy to Flipper SD: `/ext/flipperpwn/modules/credential/`

| Module | Phases | Novel Aspect |
|---|---|---|
| `evil_twin.fpwn` | Scan → Deauth → Portal | Full evil twin in one module |
| `probe_karma_portal.fpwn` | Probe sniff → Identify top SSID → Karma + portal | Targeted karma (not broadcast) |
| `pmkid_harvest.fpwn` | PMKID capture + parallel portal | Dual-vector: hash AND cleartext |
| `wifi_survey_report.fpwn` | Scan → Station scan → Probe sniff → HID report | Auto-generates pentest report via keyboard |
| `ble_chaos.fpwn` | iOS + SwiftPair + Samsung + AirTag in sequence | Full BLE coverage sweep |

These modules drive the ESP32 through FlipperPwn's `WIFI_CMD` command (added in
FlipperPwn 1.8), which sends Marauder CLI commands verbatim over the UART bridge
(`scanap`, `attack -t deauth`, `sniffpmkid`, `sniffprobe`, `evilportal -c …`,
`blespam -t …`). Marauder command names/flags vary between builds and forks, so
review the `WIFI_CMD` lines and adjust them to match the firmware flashed on
your ESP32 dev board. A board must be connected or the commands no-op with a log
warning. **Authorized testing only.**

## Python Tools (`serial_tools/`)

Requires: `pip install pyserial`

| Tool | Use |
|---|---|
| `marauder_serial.py` | Interactive shell with macros + auto PCAP save |
| `pcap_capture.py` | Dedicated PCAP capture with Wireshark-compatible output |

See [../README.md](../README.md) for full usage documentation.
