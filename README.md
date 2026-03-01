# Flipper Suite

A collection of 6 external applications (FAPs) for the [Flipper Zero](https://flipperzero.one/) multi-tool. Each app targets a different hardware interface on the Flipper Zero, covering USB HID, NFC, GPIO, and Sub-GHz radio.

## Applications

### BadUSB Pro (USB)
Advanced USB HID keystroke injection with an extended DuckyScript engine.

- **Extended DuckyScript**: `OS_DETECT` for cross-platform payloads, `IF`/`ELSE`/`ENDIF` branching, `LABEL`/`GOTO`/`GOSUB`/`RETURN` flow control, `LED_CHECK`/`LED_WAIT` feedback channel
- **Consumer Key Support**: `CONSUMER_KEY PLAY_PAUSE`, `CONSUMER_KEY VOL_UP`, etc. (50+ media/system keys, or raw hex like `CONSUMER_KEY 0xCD`)
- **Script Restart**: `RESTART` command to loop scripts from the beginning
- **Call Stack**: Up to 8 levels of nested `GOSUB`/`RETURN`

### CCID Emulator (USB)
Programmable USB smartcard (CCID) emulator.

- **Card Profiles**: Load `.ccid` card definition files from SD card with custom APDU response rules
- **APDU Monitor**: Real-time display of command/response pairs from connected readers
- **Log Export**: Press Right in the APDU monitor to export the full session log to `/ext/apps_data/ccid_emulator/logs/`
- **Sample Cards**: Includes VISA EMV test card, PIV applet, and Java Card profiles

### HID Exfil (USB)
HID-based data exfiltration via keyboard LED feedback channel.

- **7 Payload Types**: System info, WiFi credentials, clipboard contents, browser history, saved passwords, SSH keys, browser bookmarks
- **Cross-Platform**: Separate PowerShell (Windows), Bash (Linux), and osascript (macOS) payload variants
- **Automatic Encoding**: Data is encoded through the keyboard LED status bits feedback channel
- **SD Card Storage**: Exfiltrated data is saved to the Flipper's SD card

### NFC Fuzzer (NFC)
NFC protocol fuzzer for testing reader/tag robustness.

- **5 Fuzzing Profiles**: Randomize UID, corrupt ATQA/SAK, malformed NDEF, overflow length fields, rapid re-select
- **NFC-A Support**: Targets ISO 14443-A protocol
- **Configurable**: Adjustable iteration count and fuzzing parameters

### SPI Flash Dump (GPIO)
Read SPI NOR flash chips via the Flipper's GPIO header.

- **32 Chip Database**: Auto-detection via JEDEC ID for common chips (W25Q, MX25L, AT25, SST25, etc.)
- **Full Read with Verify**: Reads chip contents to SD card, then verifies by re-reading
- **CRC32 Checksum**: Calculates and displays CRC32 after successful read
- **Hex Preview**: Browse dumped data in a hex viewer on-device
- **Adjustable SPI Speed**: 1 MHz or 4 MHz clock

**Wiring (3.3V logic, directly to Flipper GPIO header):**

| Flash Pin | Flipper Pin |
|-----------|-------------|
| CS        | PA4         |
| CLK       | PB3         |
| MOSI      | PA7         |
| MISO      | PA6         |
| VCC       | 3V3         |
| GND       | GND         |

### SubGHz Spectrum (Sub-GHz)
Real-time Sub-GHz spectrum analyzer.

- **4 Frequency Bands**: 315 MHz (310-320), 433 MHz (425-445), 868 MHz (860-880), 915 MHz (900-930)
- **Bar & Waterfall Views**: Toggle between bar graph and waterfall display in Settings
- **Adjustable Step Size**: 10 / 25 / 50 / 100 / 200 kHz
- **Peak Hold**: Optional peak marker overlay
- **CSV Logging**: Scan data exported to `/ext/subghz_spectrum/` with timestamps

## Installation

### Prerequisites

- A [Flipper Zero](https://flipperzero.one/) running official firmware
- [ufbt](https://github.com/flipperdevices/flipperzero-ufbt) (micro Flipper Build Tool) installed on your computer
- Python 3.8+ (required by ufbt)

### Install ufbt

```bash
pip install ufbt
```

Or if you prefer pipx:

```bash
pipx install ufbt
```

### Build All Apps

Clone this repository and build each application:

```bash
git clone https://github.com/barkandbite/flipper_suite.git
cd flipper_suite

# Build each app individually
for app in badusb_pro ccid_emulator hid_exfil nfc_fuzzer spi_flash_dump subghz_spectrum; do
    cd "$app"
    ufbt
    cd ..
done
```

Each app builds to `<app_name>/dist/<app_name>.fap`.

### Install to Flipper Zero

Connect your Flipper Zero via USB, then deploy each app:

```bash
cd badusb_pro
ufbt launch     # Builds, installs, and launches on Flipper
cd ..
```

Or manually copy the `.fap` files:

1. Build the app with `ufbt` (inside the app directory)
2. Copy `dist/<app_name>.fap` to your Flipper's SD card under `/ext/apps/<category>/`
   - BadUSB Pro, CCID Emulator, HID Exfil: `/ext/apps/USB/`
   - NFC Fuzzer: `/ext/apps/NFC/`
   - SPI Flash Dump: `/ext/apps/GPIO/`
   - SubGHz Spectrum: `/ext/apps/Sub-GHz/`

### Sample Files

Copy the included sample files to your Flipper's SD card:

- `badusb_pro_sample_scripts/*.ds` &rarr; `/ext/badusb_pro/` on SD card
- `ccid_emulator_sample_cards/*.ccid` &rarr; `/ext/apps_data/ccid_emulator/cards/` on SD card

## FAQ

**Q: What firmware version do I need?**
A: These apps are built against the official Flipper Zero firmware SDK. They were developed and tested with API version 87.1 (firmware 1.4.x). If you're on a significantly older or newer firmware, rebuild from source with `ufbt` to match your version.

**Q: Do these work with custom firmware (Momentum, Unleashed, etc.)?**
A: They may work if the custom firmware maintains API compatibility with the official SDK. Rebuild from source with `ufbt` pointed at your firmware's SDK for best results. No guarantees are made for third-party firmware.

**Q: How do I update ufbt's SDK version?**
A: Run `ufbt update` to pull the latest SDK matching your Flipper's firmware. If you need a specific version: `ufbt update --channel=release`.

**Q: The app crashes or shows "API mismatch" on my Flipper.**
A: This means the `.fap` was built against a different firmware version than what's running on your Flipper. Rebuild from source: `cd <app_directory> && ufbt`.

**Q: Can I use BadUSB Pro over Bluetooth?**
A: BLE HID is not currently available in the official firmware SDK for external FAP applications. The app will automatically fall back to USB mode. This may change in future firmware releases.

**Q: Where does SPI Flash Dump save files?**
A: Dumps are saved to `/ext/apps_data/spi_flash_dump/` on the SD card, named by the detected chip and timestamp.

**Q: Can I add my own CCID card profiles?**
A: Yes. Create a `.ccid` file following the format in the sample cards and place it in `/ext/apps_data/ccid_emulator/cards/` on your SD card. The format uses `[Card]` headers with `AID`, `RULE`, and `DEFAULT_RESPONSE` directives.

**Q: What SPI flash chips are supported?**
A: The app includes a database of 32 common SPI NOR flash chips and will auto-detect via JEDEC ID. If your chip isn't recognized, the app will display the raw JEDEC ID so you can verify compatibility manually.

## Project Structure

```
flipper_suite/
├── badusb_pro/                  # BadUSB Pro application
├── ccid_emulator/               # CCID Emulator application
├── hid_exfil/                   # HID Exfil application
├── nfc_fuzzer/                  # NFC Fuzzer application
├── spi_flash_dump/              # SPI Flash Dump application
├── subghz_spectrum/             # SubGHz Spectrum application
├── badusb_pro_sample_scripts/   # Sample DuckyScript files
├── ccid_emulator_sample_cards/  # Sample CCID card profiles
└── README.md
```

Each application directory contains:
- `application.fam` &mdash; Build manifest (app name, category, entry point)
- `*.c` / `*.h` &mdash; Source code
- `images/` &mdash; Icon assets
- `dist/` &mdash; Build output (`.fap` file)

## Legal Disclaimer

**This software is provided for educational, entertainment, and research purposes only.**

The authors and contributors of Flipper Suite are **not responsible** for any actions taken by users of this software. By using these applications, you agree to the following:

- You will only use these tools on devices and systems that you own or have explicit written authorization to test.
- You are solely responsible for ensuring that your use of these tools complies with all applicable local, state, federal, and international laws and regulations.
- These tools are intended for legitimate security research, learning, and personal tinkering. Any misuse is entirely the responsibility of the user.
- The authors make no warranties, express or implied, regarding the functionality, safety, or legality of use in any specific jurisdiction.
- The Flipper Zero is a legal multi-tool in most jurisdictions. However, the legality of specific use cases varies by location. **Know your local laws.**

**No warranty.** This software is provided "as is" without warranty of any kind. Use at your own risk.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/barkandbite/flipper_suite).

When contributing code, please ensure it builds cleanly with `ufbt` and passes `ufbt lint`.

## License

See the repository for license details. All code in this repository is provided for educational and research purposes.
