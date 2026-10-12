# Flipper Zero FAP Development — Memory & Coding Research Report

**Date:** 2026-10-12
**Scope:** Research only (no app code written). Produced by analyzing the official
Flipper Zero firmware and the 13 FAPs in this repo, cross-referenced with the
REA (Reverse Engineer Anything) reverse-engineering toolkit.

> **Why this exists:** We've repeatedly hit memory errors and crashes on-device.
> This report nails down the *actual* numbers and rules of the STM32WB55 so we
> stop guessing, then turns the firmware's own idioms + our codebase's good/bad
> habits into a checklist. A companion skill lives at
> `.claude/skills/flipper-fap-dev/SKILL.md`.

---

## 0. Materials gathered

| Item | Source | Why |
|---|---|---|
| **Official firmware** | `flipperdevices/flipperzero-firmware` (shallow clone) | Authoritative heap/stack model, ELF loader, example apps, dev docs |
| **REA toolkit** | `morluto/rea` (shallow clone) | Local-only RE agent wrapping Ghidra/IDA/binwalk/jadx/unblob/pwndbg via CLI+MCP; used to statically inspect `.fap` ELF footprints |

Both were cloned into the session scratchpad and treated as untrusted data (not
committed to this repo). The firmware is the primary research source; REA is a
tool we can point at our built `.fap` files to measure real `.text`/`.data`/`.bss`
sizes (see §7).

---

## 1. The hardware reality (STM32WB55, firmware target `f7`)

Your memory recollection of "16k or 64k" is the **per-app thread stack**, not a
hard app ceiling. The real picture:

| Resource | Value | Evidence |
|---|---|---|
| App SRAM (RAM1) | `0x2FFF8` ≈ **192 KB**, shared by firmware + services + GUI + your app | `targets/f7/stm32wb55xx_flash.ld:10` |
| **FreeRTOS heap** | `__heap_end__ − __heap_start__` — **one shared heap**, computed at link time (not a constant). Everything left over after firmware `.data`/`.bss`. In practice **~140–150 KB free at an idle main menu.** | `FreeRTOSConfig.h:36`; `...flash.ld:103-112` |
| Radio co-processor RAM | 2× **10 KB** (RAM2A/RAM2B) — reserved for the BLE stack mailbox, **not yours** | `...flash.ld:11-12` |
| ISR / main stack reserve | `0x400` = **1 KB** (separate from app thread stacks) | `...flash.ld:6` |
| `configMINIMAL_STACK_SIZE` | 128 words | `FreeRTOSConfig.h:32` |
| Per-app thread stack | `stack_size` in `application.fam`, a `uint16_t` (max 65535). Examples use 1–4 KB | `application_manifest.h:38`; `applications/examples/*/application.fam` |
| Flash | 1 MB | `...flash.ld:9` |

**The one sentence to remember:** your app's **stack** + every **`malloc`** +
every **static/global buffer** all come out of the *same* ~150 KB pool that the
rest of the OS is also using. There is no per-app memory sandbox.

---

## 2. The malloc model — and why we crash instead of getting NULL

The single most important behavioral fact for us:

> **`malloc` NEVER returns NULL. On exhaustion the firmware `furi_check`-halts the
> entire system (crash + reboot).** — `furi/core/memmgr_heap.c:466`
> (`furi_check(pvReturn, ... "out of memory")`)

Consequences and details:

- **You cannot defensively handle OOM** by checking `malloc`'s return — it either
  succeeds or the device bluescreens. The only defense is **staying within
  budget**. (`configUSE_MALLOC_FAILED_HOOK 0` — `FreeRTOSConfig.h:24`.)
- **`malloc` is zero-initialized** — the firmware `memset`s every allocation to 0
  (`memmgr_heap.c:467`). You don't need `calloc` for zeroing; and don't *assume*
  garbage for debugging either.
- `malloc`/`free` are thin wrappers over FreeRTOS `pvPortMalloc`/`vPortFree`
  (`memmgr.c:12-18`); newlib's reentrant allocators are redirected to the same
  heap (`memmgr.c:62-80`). **There is exactly one heap.**
- Allocator is **heap_4** (first-fit + coalescing) → **fragmentation is real**.
  "Free heap" can be large while the **largest contiguous block** is small.
- **`malloc`/`free` in an ISR = instant crash** (`memmgr_heap.c:320-322, 476-478`,
  `furi_crash("memmgt in ISR")`). Never allocate in interrupt/timer-ISR context.
- `aligned_malloc` **does** return NULL on failure (`memmgr.c:101-103`) and must be
  freed **only** with `aligned_free` — mixing it with plain `free` corrupts the heap.
- `realloc(ptr, 0)` frees and returns NULL (`memmgr.c:20-37`).

### Heap introspection (use these while profiling)
- `memmgr_get_free_heap()` — current free bytes.
- `memmgr_get_minimum_free_heap()` — low-watermark (the number that matters: your
  worst case since boot).
- `memmgr_heap_get_max_free_block()` — largest contiguous block (fragmentation).
- On-device CLI: **`free`** and **`top`** profile live usage per thread
  (`documentation/AppManifests.md:39`).

### Built-in corruption detection (it's on)
- **Heap canary / pointer protector enabled** (`configENABLE_HEAP_PROTECTOR 1`,
  `FreeRTOSConfig.h:22`): free-list pointers are XOR'd with a random canary; a
  heap overflow that smashes an adjacent block header is caught on the next
  malloc/free (`memmgr_heap.c:110-142`).
- **Double-free / wild-free / use-after-free guards** in `vPortFree`
  (`memmgr_heap.c:488-513`): the pointer must lie inside the heap, the block must
  currently be allocated, and freed memory is wiped. So a crash on `free()` almost
  always means *we* double-freed or freed a bad pointer — not a firmware bug.

---

## 3. How a FAP is loaded — and why big buffers are extra expensive

- A `.fap` is an **ELF executable + metadata/resources**
  (`documentation/AppsOnSDCard.md:3`). The MCU **cannot execute from the SD card**,
  so the App Loader copies it into RAM and relocates it (`AppsOnSDCard.md:54-60`).
- **Every allocatable ELF section (`.text`, `.data`, `.bss`) is `aligned_malloc`'d
  on the shared heap at load time** (`lib/flipper_application/elf/elf_file.c:488`).
  That means **a large global array or large `.bss` costs heap the moment the app
  is opened** — before any of your code runs.
- The loader pre-checks each section: **section size + 1 KB must fit in the largest
  free block** or load fails cleanly with `NoMemory`
  (`elf_file.c:478-486`). **This is the classic "app won't even open" symptom on a
  fragmented heap** — total free looks fine, but no single block is big enough.
- `stack_size` from the manifest is passed straight to the app thread
  (`flipper_application.c:266-268`); `0` is invalid.
- `fap_libs` entries increase both `.fap` size **and** RAM consumption
  (`AppManifests.md:53`).

**Takeaway:** keep static/global data small; allocate large buffers from the heap
*after* launch (so they're sized to need and don't block loading), and free them
when idle to reduce fragmentation pressure on the next app.

---

## 4. The canonical bounded-memory architecture

The firmware's own examples encode the pattern. From
`applications/examples/example_view_dispatcher/example_view_dispatcher.c`:

```
app_main():
    app = app_alloc();   // malloc struct ONCE; open records; alloc all views ONCE
    app_run(app);        // blocks in view_dispatcher_run(); NO per-frame alloc
    app_free(app);       // tear down in REVERSE order
    return 0;
```

Rules the examples make explicit (with crash warnings in their comments):

1. **Allocate each view/module exactly once** in `_alloc`, register with
   `view_dispatcher_add_view`, and **reuse** via `view_dispatcher_switch_to_view` —
   never realloc views to switch screens (`example_view_dispatcher.c:88-133`).
2. **Unregister before free.** In `_free`, call `view_dispatcher_remove_view` for
   *every* registered view **before** `view_dispatcher_free`
   (`:137-140` — "Failure to do so will result in a crash"). For `ViewHolder`,
   `view_holder_set_view(vh, NULL)` before freeing (`example_view_holder.c:69-75`).
3. **Free in reverse order of allocation**, then `free(app)` last.
4. **Balance every record.** `furi_record_open` is reference-counted, **blocks
   until available, and never returns NULL** (`record.h:51-55`). Close from the
   **same thread** (`record.h:57-63`). Common records: `RECORD_GUI` (`"gui"`),
   `RECORD_NOTIFICATION`, `RECORD_STORAGE`, `RECORD_DIALOGS`.

---

## 5. Strings & large data

- **`FuriString`** is the owning, bounded string type — use it instead of manual
  `char[]` math. `furi_string_alloc`/`furi_string_free` must pair
  (`string.h:34,97`). For hot loops, **`furi_string_reserve`** up front to avoid
  repeated realloc growth (`string.h:103-111`). `furi_string_cat*` each may grow
  the allocation (`string.h:272-291`).
- **Never slurp a whole file into RAM.** Use a **buffered file stream** — its cache
  is a **fixed 1 KB** (`lib/toolbox/stream/stream_cache.c:3`), so peak RAM stays
  flat regardless of file size:
  - `buffered_file_stream_alloc` / `_open` / `_close`
    (`buffered_file_stream.h`; **close even if open failed** — `:22`).
  - `stream_read_line(stream, FuriString*)` for line-at-a-time parsing
    (`stream.h:122`), or `stream_read` into a small fixed buffer (`stream.h:96`).
  - Or raw `storage_file_read(file, buf, n)` in chunks (`storage.h:126`).

---

## 6. What our 13 apps already do (audit results)

**Overall: the suite is markedly defensive.** Every app balances
`malloc`/`free`, `furi_record_open`/`close` (including error branches),
`view_alloc`/`view_free`, and `view_dispatcher_add_view`/`remove_view`. **No
leaks, double-frees, or unbounded copies were found.** Many files carry
"Issue N / Fix N" comments from a prior hardening pass.

**Reference implementations to copy from:**
- `uart_sniff/uart_sniff.c:357` — model `app_free`: stop worker → remove 3 views →
  free widgets → free dispatcher → free heap buffers → close GUI → free app.
- `nfc_fuzzer` — safe `realloc`-into-temp with a hard cap (`nfc_fuzzer.c:57-64`),
  free-before-reassign on rebuild.
- `flipperpwn` exfil buffer & `hid_exfil` recv buffer — **allocate-once-and-reuse**
  guarded by `if(!buf)`, bounds-checked writes, NULL-after-free.
- `ccid_emulator/card_parser.c` and `spi_flash_dump/spi_worker.c` — **streaming**
  file/flash I/O (page-by-page, 256 B buffers) instead of full-RAM loads.

**Things to watch (not bugs today, but the guide's cautions):**
1. **Per-event/per-refresh heap churn of large buffers.** `ble_scanner.c:106`
   (~3.5 KB every UI refresh), `nfc_fuzzer.c:179-188` (3 buffers every anomaly log).
   Deliberate (timer threads have ~1 KB stacks) but a fragmentation risk — prefer
   allocate-once-and-reuse where the path is truly hot.
2. **Large single buffers:** `hid_exfil_payloads.c:407` `static char
   assembled_script[8192]` (permanent 8 KB; also a non-reentrant shared static that
   returns an internal pointer); `badusb_pro.c:307` ~35 KB token array;
   `flipperpwn` 128-element port arrays. All freed/static, but large vs. ~150 KB.
3. **memcpy safety that relies on an upstream cap** rather than a local check:
   `evil_ble.c:264` (safe only because `build_adv_from_name` caps the producer).
   Prefer clamping **at the memcpy site** — the pattern most other parsers already
   use (`rogue_ap_worker.c:217/251/291`, `ccid_handler.c:104/137/147`).
4. **Stack right-sizing:** `rayhunter_client` 6 KB looks generous (no large stack
   arrays); `flipperpwn` 8 KB is justified (3600-line engine, 128–320 B stack
   buffers). Nothing is undersized — because big buffers are consistently kept
   **off the stack**, the single best habit in the codebase.

> `evil_portal/` is **not** a FAP (HTML templates + ESP32/Marauder scripts only), so
> it has no on-Flipper C memory surface.

---

## 7. Using REA on our own builds (optional, powerful)

REA (`morluto/rea`) is a local-only RE agent toolkit (Ghidra/IDA/binwalk/unblob/
jadx/pwndbg behind one CLI + MCP server; Ghidra/IDA are bring-your-own). Because a
`.fap` is just an ELF, we can point REA (or plain `arm-none-eabi-size` /
`readelf -S`) at `dist/*.fap` to measure the **real** load-time footprint:

- `.text` + `.rodata` → flash/RAM code size
- `.data` + `.bss` → the **static heap cost at load** (the §3 pre-check input)

Our built sizes today (on-disk, includes debug info): `flipperpwn.fap` 87 KB is the
outlier; most apps 12–30 KB. On-disk size ≠ RAM footprint — section analysis gives
the real number. (Deferred: a `make size` target per app would make this a CI check.)

---

## 8. Pre-flight checklist (the short version)

Full version in the skill. Before shipping any FAP change:

- [ ] All large buffers are **heap**, allocated **after** launch, sized to need.
- [ ] Each malloc has exactly one free on **every** path (incl. error paths).
- [ ] `malloc`/`FuriString`/record/view all freed in `app_free`, **reverse order**.
- [ ] **Every view `remove`d from dispatcher/holder before free.**
- [ ] Every `furi_record_open` has a `furi_record_close` on the **same thread**.
- [ ] No `malloc`/`free` in ISR or timer-ISR context.
- [ ] Hot/periodic paths **reuse** a buffer rather than malloc-per-iteration.
- [ ] Every `memcpy`/`strncpy` into a fixed buffer **clamps length at the call site**.
- [ ] Large files **streamed**, never slurped.
- [ ] `aligned_malloc` ⇄ `aligned_free` only (never mixed with `free`).
- [ ] Verified on-device with `free` / `top`; checked `memmgr_get_minimum_free_heap`.

---

*All firmware line references are to `flipperdevices/flipperzero-firmware`
(target `f7`) as of the 2026-10-12 clone. Repo references are to this
repository's current `research/memory-guide` branch.*
