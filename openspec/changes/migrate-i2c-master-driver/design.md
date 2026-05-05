## Context

The fork's HAL `cryptoauthlib/third_party/hal/esp32/hal_esp32_i2c.c` already contains both code paths — the legacy `driver/i2c.h` implementation and a newer `driver/i2c_master.h` implementation — gated by `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER`. Today consumer projects (`playfield-relay/sdkconfig.defaults.esp32` and `sdkconfig.defaults.esp32s3`) explicitly set `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER=y`, which forces the legacy path. That's the path that triggers `i2c_hw_fsm_reset` inside a critical section on the wake-pulse NACK and panics with the IWDT.

Two complications make this more than just flipping the Kconfig:

1. **The fork modified `calib_basic.c`** to do its own custom wake-pulse sequence inline (around line 90 of `cryptoauthlib/lib/calib/calib_basic.c`). That block calls `i2c_cmd_link_create` / `i2c_master_start` / `i2c_master_write_byte` / `i2c_master_cmd_begin` — pure legacy API — and bypasses the HAL's `hal_i2c_wake` entirely. Disabling `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER` will not migrate this block; it will keep using the legacy driver headers regardless of the Kconfig.
2. **The new-driver code path in the HAL is missing `hal_i2c_wake`.** The legacy section defines it at line 286, but the new section (lines 375–648) does not. Today this gap is hidden because the fork's inline wake-pulse in `calib_basic.c` substitutes for `hal_i2c_wake` — but if we remove the inline block (which we'd want to, to fully migrate off the legacy API), we need a real `hal_i2c_wake` in the new path.

Build environment is ESP-IDF v5.5 (Dagger container `espressif/idf:v5.5`), comfortably above the v5.2 floor where `driver/i2c_master.h` became available. Hardware is RAK11200 (ESP32-WROVER, ESP32 family, SDA/SCL configured at runtime) and Heltec WiFi LoRa 32 V3 (ESP32-S3, SDA=9, SCL=40). ATECC608A on I2C bus 0, 7-bit address `0x60`.

### Why the legacy driver was chosen originally

The fleet's docs preserve the actual history (`hermes-bridge/resources/esp-cryptoauthlib-fork.md`, `hermes-bridge/resources/ATECC608A_INTEGRATION.md`, `playfield-relay/resources/README-rak5814.md`). The constraint was **"the new path is untested on RAK hardware,"** not "the new path is broken."

When the team first integrated the ATECC608A on RAK11200 + RAK5814, upstream `espressif/esp-cryptoauthlib` had three real bugs that prevented basic communication:

1. I2C address shifting bug — the HAL passed the 7-bit address where ESP-IDF expected it pre-shifted to 8-bit.
2. Hardcoded 400 kHz baud rate that ignored `ATCAIfaceCfg`, but the ATECC wake pulse requires ≤ 100 kHz.
3. No write-to-0x00 wake sequence; the chip never woke.

The fix work was done against the legacy `driver/i2c.h` code path because that was where the existing bugs lived and where the engineers were actively debugging — not because the new driver couldn't have hosted the same fixes. The fork's commit message and the integration doc both record `Tested on ESP-IDF v5.5.1 with ATCA_I2C_USE_LEGACY_DRIVER enabled` as the validated configuration. `README-rak5814.md` lists the new driver's possibly-different timeout / clock-stretching behaviour as a *concern*, never as a confirmed problem.

The fork's HAL today already contains a complete new-driver implementation alongside the legacy one, gated by `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER`. That code path has just never been exercised on RAK hardware, which is the gap this proposal closes — not a fix for a known bug, but a validated migration of a path that already exists.

Bus exclusivity also turns out to be a non-issue: `flashback-fleet-esp-common/src/i2c_utils.c` does install the legacy driver via `i2c_param_config` + `i2c_driver_install`, but a grep across both `playfield-relay` and `hermes-bridge` shows zero callers of its `i2c_master_init` / `i2c_scan_for_devices` / `i2c_test_device` exports. It's dead code from an earlier prototype that hasn't been deleted.

## Goals / Non-Goals

**Goals:**
- ATECC wakeup NACK no longer enters a long critical section in the legacy driver, so the Interrupt WDT does not fire.
- Eliminate every legacy `driver/i2c.h` call site that the ATECC path touches (HAL plus the inline block in `calib_basic.c`), so the legacy code path is truly dead for our fleet.
- Be able to remove the workaround `CONFIG_ESP_INT_WDT_TIMEOUT_MS=600` from consumer `sdkconfig.defaults` and stay stable on ESP-IDF's default 300 ms IWDT.
- Preserve the fork's RAK-board-tuned timings: 3 ms post-wake-pulse delay, 5 ms post-wake settle delay, 10 ms / 100 ms / 10 s timeouts on the various transactions.
- Keep the `hal_i2c_*` function signatures unchanged so cryptoauthlib's higher layers keep working without changes.

**Non-Goals:**
- Reducing log-level noise from expected wake NACKs (`HAL_I2C: Send: Device not responding at address 0x60`). Tracked separately.
- Pinning the ESP-IDF Docker image to a specific patch version. Tracked separately in infrastructure.
- Adding new cryptoauthlib features or refactoring code paths that aren't on the I2C-touching call chain.
- Migrating non-ESP32 HALs (the fork carries SAM, Linux, Harmony, Zephyr HALs; out of scope).

## Decisions

### Decision 1: Do not just flip the Kconfig — fully migrate the inline wake block

**Choice**: Migrate both the HAL and the inline `calib_basic.c` wake-pulse block to the new API. Then remove `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER=y` from consumer `sdkconfig.defaults*` files.

**Alternative considered**: Only remove `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER=y` and rely on the existing new-driver code path in the HAL. **Rejected** because the fork's inline wake-pulse in `calib_basic.c` would still be linking against `driver/i2c.h`. That means the legacy driver gets initialised alongside the new bus driver on the same I2C peripheral, which ESP-IDF explicitly disallows (a single I2C port cannot host both drivers concurrently). The build would either fail to link or fail at runtime when the second `i2c_driver_install` call collides with the new bus instance.

### Decision 2: Send the wake pulse via a temporary `i2c_master_dev_handle_t` registered at address `0x00`

**Choice**: To wake the chip we need a NACKed write to address `0x00`. With the new API, every transaction goes through a registered device handle. We add a *second* device handle on the same bus configured for address `0x00` (in addition to the regular `0x60` handle), use it once for the wake pulse, then keep it allocated for subsequent wakeups.

**Alternative considered**: Tear down and recreate the bus around each wake attempt. **Rejected** because that defeats the point — bus init is the slow path we're trying to keep out of the critical loop, and tearing it down also drops any other devices sharing the bus.

**Alternative considered**: Use `i2c_master_probe()` for the wake pulse. **Rejected** because probe is intended for "is something there" detection and its NACK handling does not promise the timing window the ATECC requires (the wake pulse must hold the line low for ~60 µs and then release). `i2c_master_transmit` against a registered `0x00` device gives us deterministic behaviour and is what Espressif's own examples use for this pattern.

### Decision 3: Add `hal_i2c_wake` to the new-driver section, even though our fork doesn't strictly need it

**Choice**: Implement `hal_i2c_wake` in the new-driver code path so the HAL is feature-complete. It will use the `0x00` device handle from Decision 2, do the NACKed write, `vTaskDelay(pdMS_TO_TICKS(3))`, then read the 4-byte wake response from the regular device handle.

**Rationale**: The fork currently relies on the inline block in `calib_basic.c` to substitute for `hal_i2c_wake`. After this change we want to delete that inline block, which means upstream cryptoauthlib code paths that call `hal_i2c_wake` (some `calib_*` functions do) will no longer route through fork-specific code. Better to have a working `hal_i2c_wake` than to leave a function-shaped hole.

### Decision 4: Keep tick-style timeouts, translate to ms

**Choice**: The current code uses `pdMS_TO_TICKS(...)` to pass tick counts to `i2c_master_cmd_begin`. The new API takes a millisecond timeout argument directly (`int32_t xfer_timeout_ms`). For each call site we translate: `pdMS_TO_TICKS(N)` → `N` (ms). The 10 s clock-stretching timeout (1000 ticks at default 100 Hz tick rate = 10000 ms) becomes `10000` ms.

### Decision 5: Stage rollout via consumer submodule pointer bumps

**Choice**: Land the change on `main` of `flippin-balls/esp-cryptoauthlib`. Then tag a release. Then bump the pointer in `flashback-fleet-esp-common`. Then bump the `flashback-fleet-esp-common` pointer in `playfield-relay` and `hermes-bridge`, tag firmware on each, and flash a single test device per board type before fleet-wide rollout. Only after both boards are stable do we revert `CONFIG_ESP_INT_WDT_TIMEOUT_MS=600` (it stays as a belt-and-suspenders safety net during the rollout window).

## Risks / Trade-offs

- **[Risk] Other components on the same I2C bus use the legacy driver** → Audited: `flashback-fleet-esp-common/src/i2c_utils.c` calls `i2c_param_config` + `i2c_driver_install`, but a grep of both consumer repos finds zero callers of its exports. It's dead code. No live consumer outside the cryptoauthlib HAL touches I2C bus 0. Mitigation: delete `i2c_utils.c` (and its header) as part of this change to remove the phantom bus-exclusivity risk for good. If a future component genuinely needs I2C, it will register through `i2c_master_bus_add_device` against the HAL's bus handle.
- **[Risk] New I2C driver has different clock-stretching / timeout behaviour on RAK hardware** → Documented in `playfield-relay/resources/README-rak5814.md` as a concern from the original integration. Mitigation: capture per-transaction latency on the test relay during the soak step; if stretches exceed our timeout budgets, tune `i2c_device_config_t.scl_wait_us` rather than reverting.
- **[Risk] The fork's three original upstream bugs (address shifting, hardcoded 400 kHz, missing wake sequence) re-emerge on the new path** → Audited: address shifting in the new path uses `dev_addr_length = I2C_ADDR_BIT_LEN_7` and lets the driver shift internally, so that bug class doesn't apply. Speed comes from `ATCAIfaceCfg` via `i2c_hal_data[bus].speed` (defaulted to 100 kHz, not hardcoded 400 kHz). Wake is implemented as part of this change (Decisions 2 and 3). Mitigation: the test step (task 6.6) verifies all three behaviours.
- **[Risk] The new bus driver's default `glitch_ignore_cnt = 7` and pull-up settings differ from the legacy `i2c_param_config` defaults** → Mitigation: keep the existing `flags.enable_internal_pullup = true` (already in the new-driver init code) and document the chosen `glitch_ignore_cnt` so it can be tuned if RAK boards prove sensitive. Test on real hardware before fleet rollout.
- **[Risk] The custom 3 ms / 5 ms wake delays might need re-tuning under the new driver because total transaction latency changes** → Mitigation: keep the same delays initially; add temporary verbose logging on the test device to capture per-transaction latency on first boot; adjust if the first 1000 wake cycles show any failures.
- **[Risk] Bus-level reset on transaction error is no longer automatic with the new driver** → Trade-off: that's the whole point. The new driver does *not* enter a critical section to reset the FSM on every NACK. This is what fixes the IWDT. The cost is that genuine bus hangs (e.g., a stuck slave holding SDA low) won't be recovered automatically — they'll surface as repeated `ATCA_COMM_FAIL` returns. We rely on cryptoauthlib's own retry logic and the ATECC retry loop in `DeviceContext::initATECC` to handle this.
- **[Risk] Existing fleet devices have firmware built against the legacy HAL** → Trade-off: we are not changing the on-the-wire I2C signalling, just how the master schedules it. Existing chips and provisioned slot data are unaffected. No factory re-provisioning needed.
- **[Risk] Reverting is awkward once the IWDT workaround is removed** → Mitigation: keep `CONFIG_ESP_INT_WDT_TIMEOUT_MS=600` in `sdkconfig.defaults` for at least one full release cycle after this lands. Revert only after fleet rollout is confirmed stable.

## Migration Plan

1. **In `flippin-balls/esp-cryptoauthlib`**: implement the HAL `hal_i2c_wake` for the new driver, remove the inline wake block from `calib_basic.c` (replace with a call to `hal_i2c_wake` via the iface), tag a release.
2. **In `flippin-balls/flashback-fleet-esp-common`**: bump the `components/esp-cryptoauthlib` submodule pointer to the new tag, commit, push to `main`.
3. **In `flippin-balls/playfield-relay`**:
   - Bump the `components/flashback-fleet-esp-common` submodule pointer.
   - Remove `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER=y` from `sdkconfig.defaults.esp32` and `sdkconfig.defaults.esp32s3`.
   - Keep `CONFIG_ESP_INT_WDT_TIMEOUT_MS=600` as a safety net for this release.
   - Tag a new firmware version, flash one test relay, run for at least an hour through several heartbeat / wake / idle cycles.
4. **In `flippin-balls/hermes-bridge`**: same submodule and Kconfig changes as relay, flash one test bridge.
5. **After both boards prove stable for a full release cycle**: open a follow-up PR that removes `CONFIG_ESP_INT_WDT_TIMEOUT_MS=600` and confirms boot at the default 300 ms IWDT.
6. **Rollback strategy**: if the new HAL misbehaves, revert the submodule pointer in `flashback-fleet-esp-common` to the prior commit and re-tag firmware. The IWDT workaround still in place provides a graceful fallback.

## Open Questions

- **Do any non-ATECC consumers share I2C bus 0 on either board?** Need to grep `flashback-fleet-esp-common`, `playfield-relay`, and `hermes-bridge` for `i2c_driver_install`, `i2c_param_config`, `i2c_new_master_bus`, and any sensor driver imports. If yes, those must migrate too or move to a different bus before this lands.
- **What is the maximum acceptable critical-section duration on ESP32-S3 under our load?** Knowing this would let us calibrate whether keeping `CONFIG_ESP_INT_WDT_TIMEOUT_MS=600` is overkill or just right.
- **Do we want to delete the legacy code path from the fork once the new path is verified, or keep it for upstream-merge friendliness?** Leaning toward deleting after one stable release cycle, but worth confirming.
