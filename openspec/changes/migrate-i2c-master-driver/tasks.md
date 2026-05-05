## 1. Audit and pre-flight checks

- [x] 1.1 Re-grep audit complete. **Findings** — additional dead-code legacy-driver call sites surfaced beyond the original audit: (a) `flashback-fleet-esp-common/src/i2c_utils.c` — dead, no callers (matches earlier audit); (b) `flashback-fleet-esp-common/src/atecc_utils.c` lines 100–200 inside `atecc_check_status` and other `atecc_test_*` diagnostic functions also use `i2c_param_config` / `i2c_driver_install` directly, but these are public-API utilities never invoked by either firmware repo. Live consumers of bus 0 remain the cryptoauthlib HAL only. The diagnostic dead code in `atecc_utils.c` is a follow-up cleanup, NOT in scope for this change — it does not conflict at runtime as long as nothing calls those functions.
- [x] 1.2 ESP-IDF version confirmed: Dagger build container is `espressif/idf:v5.5`; HAL's new-driver gate is `>= 5.2.0`. `driver/i2c_master.h` is available.
- [ ] 1.3 **Deferred** — no hardware available this session. Baseline reference is the 0.1.62 boot log already captured in the conversation transcript above (ATECC Serial → Lock Status within ~10 ms, ATECC retry observed at heartbeat #0 wake recovering on attempt 2/5).

## 2. Implement hal_i2c_wake on the new-driver code path

- [x] 2.1 Added `wake_handle` field (with explanatory comment) to `ATCAI2CMaster_t` in the new-driver section.
- [x] 2.2 Registered `wake_handle` at address `0x00` in `hal_i2c_init`, with rollback (rm_device + del_master_bus) on registration failure.
- [x] 2.3 `hal_i2c_release` now tears down `wake_handle` before `dev_handle` before the bus.
- [x] 2.4 Implemented `hal_i2c_wake` for the new-driver path. Sends one byte to `wake_handle` (NACK expected, return code intentionally ignored), `vTaskDelay(3ms)`, reads 4 bytes via the standard `hal_i2c_receive` helper (reusing its error handling), `vTaskDelay(5ms)`, returns `ATCA_WAKE_FAILED` if first byte ≠ 0x11 else `ATCA_SUCCESS`.
- [x] 2.5 **Deferred to consumer build (task 6.5).** Standalone build needs an ESP-IDF sandbox not available locally; the firmware-builder pipeline already runs `idf.py build` against the cryptoauthlib component as part of the relay build, which exercises the same compile.

## 3. Remove the inline wake-pulse block from calib_basic.c

- [x] 3.1 Located the inline `if (atcab_is_ca_device(...))` wake block in `calib_wakeup_i2c`.
- [x] 3.2 Replaced the block with a single `atwake(iface)` call. `atwake` routes through the iface's `halwake` function pointer to our new `hal_i2c_wake`. Set `wake = 0x11` after success to satisfy the downstream `hal_check_wake(...)` call (since hal_i2c_wake already validated the response, this is just a token to make the existing post-validation pass). Removed the now-unused `#include "driver/i2c.h"`, `#include "driver/gpio.h"`, `#include "esp_rom_sys.h"`, and the local `I2C_MASTER_*` / `*ACK*` macros.
- [x] 3.3 Verified with `grep -n "i2c_master_cmd_begin\|i2c_cmd_link_create\|i2c_master_start\|i2c_master_write_byte\|i2c_master_read_byte\|i2c_cmd_link_delete\|driver/i2c\.h" cryptoauthlib/lib/calib/calib_basic.c` — zero matches.

## 4. Tag the cryptoauthlib fork release

- [ ] 4.1 Run a unit/integration sanity check if any exist in the fork; otherwise rely on the consumer-side test pass for verification.
- [ ] 4.2 Commit the HAL and `calib_basic.c` changes on `flippin-balls/esp-cryptoauthlib` `main` with a descriptive message that links to this proposal.
- [ ] 4.3 Tag the new release (next sequential version after the current `bea9767` snapshot — pick whatever the fork's tagging convention is).
- [ ] 4.4 Push tag and commits to origin.

## 5. Update flashback-fleet-esp-common (submodule bump + dead-code removal)

- [ ] 5.1 In `flippin-balls/flashback-fleet-esp-common`, run `git -C components/esp-cryptoauthlib fetch origin && git -C components/esp-cryptoauthlib checkout <new-tag-or-commit>`.
- [ ] 5.2 Delete `src/i2c_utils.c` and `include/i2c_utils.h`. These have zero callers in either firmware repo (verified in 1.1) and link in legacy-driver symbols that give the false impression bus 0 is shared. If `CMakeLists.txt` references `src/i2c_utils.c` in `idf_component_register(SRCS ...)`, remove that line too.
- [ ] 5.3 Commit both changes on `main` referencing this proposal.
- [ ] 5.4 Push to origin.

## 6. Test on relay (playfield-relay)

- [ ] 6.1 In `flippin-balls/playfield-relay`, bump the `components/flashback-fleet-esp-common` submodule pointer to the new commit.
- [ ] 6.2 Remove the line `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER=y` from `sdkconfig.defaults.esp32` and `sdkconfig.defaults.esp32s3`.
- [ ] 6.3 Keep `CONFIG_ESP_INT_WDT_TIMEOUT_MS=600` in `sdkconfig.defaults` for now (safety net during rollout).
- [ ] 6.4 Commit and tag the next firmware version.
- [ ] 6.5 Trigger a build via the device-requisition pipeline and flash a single test relay (the same physical unit used to capture the v0.1.61 crash, so we have a controlled comparison).
- [ ] 6.6 Confirm the boot log no longer prints the `This driver is an old driver` warning, ATECC init succeeds on the first attempt, lock-status check completes within ~10 ms of serial read (matching v0.1.50-rebuild timing), and the device transitions to ACTIVE.
- [ ] 6.7 Soak test: leave the relay running through at least 100 heartbeat-and-diagnostic cycles (~30 minutes at the current cadence) and confirm no IWDT panics, no `ATCA_COMM_FAIL` storms, and stable counter increments.

## 7. Test on bridge (hermes-bridge)

- [ ] 7.1 In `flippin-balls/hermes-bridge`, bump `components/flashback-fleet-esp-common` submodule pointer.
- [ ] 7.2 Remove `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER=y` from any `sdkconfig.defaults*` that has it.
- [ ] 7.3 Tag the next bridge firmware version (next after `v0.1.62`).
- [ ] 7.4 Build and flash a single test bridge.
- [ ] 7.5 Verify successful boot, ATECC init, and at least 30 minutes of stable operation including encrypted command flow with the test relay.

## 8. Cleanup and rollout

- [ ] 8.1 Once both test devices have run cleanly for at least one full release cycle (no IWDT panics, no I2C-related regressions reported), open a follow-up PR on each consumer that removes `CONFIG_ESP_INT_WDT_TIMEOUT_MS=600` and confirms boot at the default 300 ms IWDT.
- [ ] 8.2 If any regression appears during the release cycle, revert the `flashback-fleet-esp-common` submodule pointer to the prior commit and re-tag firmware on both boards. The IWDT workaround remains in place to keep devices booting during rollback.
- [ ] 8.3 Once cleanup is merged and stable, decide whether to delete the legacy code path from `hal_esp32_i2c.c` entirely (lines 68–374). Track that as a follow-up change rather than rolling it into this one.

## 9. Documentation

- [ ] 9.1 Add a CHANGELOG entry on the cryptoauthlib fork describing the migration and the empirically-tuned values that were preserved.
- [ ] 9.2 Update or add a brief note in `flashback-fleet-esp-common`'s README (if one exists) noting that consumers must NOT set `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER` and explaining why.
- [ ] 9.3 Update `hermes-bridge/resources/esp-cryptoauthlib-fork.md` and `hermes-bridge/resources/ATECC608A_INTEGRATION.md` to reflect the new validated config: replace every "`CONFIG_ATCA_I2C_USE_LEGACY_DRIVER=y` (required for compatibility)" line with a note that the new driver is now the validated path, and link this OpenSpec change as the migration record.
- [ ] 9.4 Update `playfield-relay/resources/README-rak5814.md`'s "Potential Issues with ESP-IDF esp-cryptoauthlib" section to mark the I2C-driver concerns as resolved by this migration.
- [ ] 9.3 Save a memory note via the agent-memory MCP capturing the diagnostic insight: "ATECC wake-pulse NACK + legacy ESP-IDF I2C driver = IWDT panic in `i2c_hw_fsm_reset`. Fix: migrate to `driver/i2c_master.h`."
