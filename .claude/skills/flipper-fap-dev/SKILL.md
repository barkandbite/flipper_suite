---
name: flipper-fap-dev
description: >-
  Memory-safe coding rules for Flipper Zero external apps (FAPs) in this repo.
  Use whenever writing, reviewing, or debugging C for any app under this
  suite (badusb_pro, ccid_emulator, hid_exfil, nfc_fuzzer, ble_scanner,
  evil_ble, flipperpwn, rayhunter_client, rogue_ap_detector, spi_flash_dump,
  subghz_jammer, subghz_spectrum, uart_sniff) — especially for crashes,
  reboots, "out of memory", "app won't open", or stack-overflow bugs. The
  Flipper has ONE shared ~150 KB heap and malloc crashes (never returns NULL)
  on exhaustion, so memory discipline is mandatory, not optional.
---

# Flipper Zero FAP development — memory-safe coding

Full research & evidence: `docs/MEMORY_RESEARCH.md`. This skill is the actionable
distillation. Target is the STM32WB55 (firmware target `f7`).

## The model you MUST hold in your head

- **One shared heap, ~140–150 KB free** at idle. Your app's stack + every
  `malloc` + every static/global buffer all draw from it. No per-app sandbox.
- **`malloc` never returns NULL — it crashes + reboots the whole device on
  exhaustion.** You cannot "handle" OOM; you can only stay in budget. (`malloc`
  also zero-fills, so you never need `calloc` for zeroing.)
- **`aligned_malloc` DOES return NULL** on failure; free it **only** with
  `aligned_free`.
- Allocator is heap_4 → **fragmentation matters**: free heap can be big while the
  largest contiguous block is small.
- `malloc`/`free` in an **ISR or timer-ISR = instant crash.**
- A `.fap` is an ELF; its `.text`/`.data`/`.bss` are heap-allocated **at load**,
  and a section must fit (size + 1 KB) in the **largest free block** or the app
  **won't even open**. ⇒ keep static/global data small.

## Non-negotiable rules

1. **Big buffers go on the heap, allocated after launch, sized to need.** Never put
   large arrays/structs on the stack or in globals.
2. **Every `malloc` has exactly one `free` on every path, including error paths.**
3. **`app_free` tears down in reverse order of `app_alloc`:** stop workers → for
   each view `view_dispatcher_remove_view` / `view_holder_set_view(vh, NULL)`
   **before** freeing → free views/modules → free dispatcher → free heap buffers →
   close every record → `free(app)` last. **Removing a view before free is
   mandatory — not doing so crashes.**
4. **Balance every `furi_record_open` with a `furi_record_close` on the same
   thread.** (`RECORD_GUI`, `RECORD_NOTIFICATION`, `RECORD_STORAGE`,
   `RECORD_DIALOGS`.) Open blocks and never returns NULL.
5. **Allocate once, reuse** on hot/periodic paths. Guard with `if(!buf) buf =
   malloc(...)`; bounds-check writes; set the pointer to NULL after free. (See
   `flipperpwn` exfil buffer, `hid_exfil` recv buffer.)
6. **Clamp length AT the `memcpy`/`strncpy`/`snprintf` call site**, never trust an
   upstream producer to have capped it. Use `strncpy(dst, src, sizeof(dst)-1)` +
   explicit NUL.
7. **Prefer `FuriString`** over manual `char[]`; pair `furi_string_alloc` with
   `furi_string_free`; `furi_string_reserve` up front in loops.
8. **Stream large files**, never slurp. `buffered_file_stream_*` (1 KB cache) +
   `stream_read_line`/`stream_read`, or chunked `storage_file_read`. Close the
   stream even if open failed.
9. **`stack_size` in `application.fam`:** 4 KB is the suite default and is enough
   *because* big buffers are kept off the stack. Too small → stack-overflow crash;
   too big → wasted heap. Only raise it for genuinely deep call trees (e.g.
   `flipperpwn` 8 KB).

## Debugging memory crashes

- **Crash inside `free()`** → you double-freed or freed a bad/stack/global pointer
  (firmware asserts the block is heap-resident and currently allocated).
- **Random crash after a buffer write** → heap overflow caught by the canary; find
  the `memcpy`/loop that ran past its buffer.
- **"out of memory" reboot** → total budget exceeded; profile with on-device CLI
  **`free`** and **`top`**, and check `memmgr_get_minimum_free_heap()` (worst-case
  watermark).
- **App won't open at all** → a section (often large `.bss`/globals) can't fit the
  largest free block; shrink static data or allocate at runtime.

## Reference implementations in THIS repo (copy these patterns)

- `uart_sniff/uart_sniff.c:357` — model `app_free` lifecycle.
- `nfc_fuzzer/nfc_fuzzer.c:57-64` — safe `realloc`-into-temp with a hard cap.
- `flipperpwn` exfil / `hid_exfil` recv — allocate-once-and-reuse.
- `ccid_emulator/card_parser.c`, `spi_flash_dump/spi_worker.c` — streaming I/O.
- `rogue_ap_detector/rogue_ap_worker.c:217` — clamp-at-memcpy on untrusted input.

## Pre-commit checklist

Run through the checklist in `docs/MEMORY_RESEARCH.md` §8 before any FAP change.
The one-line test: *"Does every byte I allocate have a guaranteed path to being
freed, and is every write bounded at its call site?"*
