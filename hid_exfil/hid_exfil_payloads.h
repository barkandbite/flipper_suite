#pragma once

#include "hid_exfil.h"

/**
 * Get the injection script for a given payload type and target OS.
 * Returns a pointer to a static C string containing the script to be typed.
 * The script collects data on the target and encodes it via keyboard LED toggles.
 *
 * LED encoding protocol:
 *   Each byte is sent as 4 dibits (2-bit pairs), MSB first.
 *   For each dibit:
 *     - Target sets Caps Lock = bit1, Num Lock = bit0
 *     - Target toggles Scroll Lock to clock the dibit
 *   End-of-transmission: target stops toggling Scroll Lock. The Flipper
 *   detects end-of-data when no clock edge arrives within the timeout
 *   (HID_EXFIL_CLOCK_TIMEOUT_MS).
 */
const char* hid_exfil_get_payload_script(PayloadType type, TargetOS os);

/**
 * Get a human-readable label for the payload type.
 */
const char* hid_exfil_get_payload_label(PayloadType type);
