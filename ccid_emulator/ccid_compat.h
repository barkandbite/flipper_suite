#pragma once

/* ccid_compat.h — firmware-compatibility shim for the USB CCID stack.
 *
 * Through SDK API 87.x the CCID USB device lived in the firmware HAL
 * (<furi_hal_usb_ccid.h>).  At API 88.0 the official firmware removed the CCID
 * layer from the HAL and requires each app to vendor its own copy
 * (flipperdevices/flipperzero-firmware#4407, tracked here as issue #62).
 *
 * We detect which world we are building against by header presence: the new
 * firmware physically deletes <furi_hal_usb_ccid.h>, so __has_include is an
 * exact 1:1 signal — it cannot false-positive in either direction.  There is
 * no app-visible firmware/API version macro to test instead (api_symbols.csv
 * is a build-tool manifest, not an includable header).
 *
 *   Old firmware (Momentum, current Unleashed, OFW <= 87.x):
 *     CCID in HAL — use <furi_hal_usb_ccid.h> and the firmware symbols.
 *   New firmware (OFW >= 88.0):
 *     CCID removed — use the vendored ccid_usb.c/.h in this app directory,
 *     which additionally exposes VID/PID/manufacturer/product customization
 *     (FuriHalUsbCcidConfig) — see issue #4.
 *
 * All CCID call sites use the ccid_compat_* names and CCID_USB_INTERFACE below
 * so the rest of the app is firmware-agnostic.  <furi_hal_usb.h> (which
 * provides FuriHalUsbInterface) must be included before this header — both
 * ccid_emulator.h and the vendored ccid_usb.h pull it in.
 */

#if defined(__has_include)
#if __has_include(<furi_hal_usb_ccid.h>)
#define CCID_HAL_IN_FIRMWARE 1
#endif
#endif

#ifdef CCID_HAL_IN_FIRMWARE

/* ---- Old firmware: CCID lives in the HAL (API < 88.0) ------------------- */
#include <furi_hal_usb_ccid.h>

#define CCID_USB_INTERFACE           (&usb_ccid)
#define ccid_compat_set_callbacks    furi_hal_usb_ccid_set_callbacks
#define ccid_compat_insert_smartcard furi_hal_usb_ccid_insert_smartcard
#define ccid_compat_remove_smartcard furi_hal_usb_ccid_remove_smartcard

#else

/* ---- New firmware: CCID removed from HAL (API >= 88.0), use vendored ----- */
#include "ccid_usb.h"

#define CCID_USB_INTERFACE           (&ccid_usb_interface)
#define ccid_compat_set_callbacks    ccid_usb_set_callbacks
#define ccid_compat_insert_smartcard ccid_usb_insert_smartcard
#define ccid_compat_remove_smartcard ccid_usb_remove_smartcard

/* The vendored stack accepts a FuriHalUsbCcidConfig as the set_config context,
 * enabling USB VID/PID and manufacturer/product string customization. */
#define CCID_USB_CONFIG_SUPPORTED 1

#endif
