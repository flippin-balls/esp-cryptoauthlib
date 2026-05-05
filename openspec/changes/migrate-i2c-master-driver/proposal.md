## Why

The fork's ESP32 HAL talks to the ATECC608A through ESP-IDF's legacy `driver/i2c.h` API. Each ATECC wakeup sends an intentional NACK to address `0x00` (the documented wake protocol), and the legacy driver responds to NACK errors by running `i2c_hw_fsm_reset` inside a critical section that holds interrupts disabled long enough to blow the default 300 ms Interrupt Watchdog Timeout. Decoded crash backtraces from playfield-relay tag 0.1.61 show the exact path: `calib_wakeup_i2c → i2c_master_cmd_begin → i2c_hw_fsm_reset → i2c_hw_disable → vPortExitCritical → IWDT panic`. We shipped a workaround on tag 0.1.62 that doubles the IWDT budget to 600 ms, but the underlying timing fragility is still there — small binary-layout shifts can resurface the panic, and ESP-IDF v5.5 itself prints `This driver is an old driver, please migrate your application code to adapt 'driver/i2c_master.h'` on every boot.

The original reason to stay on the legacy driver was **untested-on-RAK-hardware**, not technical incompatibility (see `hermes-bridge/resources/esp-cryptoauthlib-fork.md` and `playfield-relay/resources/README-rak5814.md`). When the team first integrated the ATECC, upstream `espressif/esp-cryptoauthlib` had three real bugs (I2C 7-bit/8-bit address shifting, hardcoded 400 kHz that ignored config baud rate, missing write-to-0x00 wake sequence). Engineers fixed those bugs in the fork against the legacy code path because that's where they were debugging, validated `Tested on ESP-IDF v5.5.1 with ATCA_I2C_USE_LEGACY_DRIVER enabled`, and shipped. The fork's HAL today already contains a complete new-driver implementation (lines 375–648 of `hal_esp32_i2c.c`) — it just hasn't been exercised on RAK hardware. That validation gap is what this proposal closes.

## What Changes

- Switch consumer projects (`playfield-relay`, `hermes-bridge`) off `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER=y` so the existing new-driver path in the HAL takes effect.
- Add the missing `hal_i2c_wake` to the new-driver section of `cryptoauthlib/third_party/hal/esp32/hal_esp32_i2c.c` (today only the legacy section defines it; the new section relies on the fork-specific inline block in `calib_basic.c` to substitute).
- Migrate the fork-specific custom wake-pulse block in `cryptoauthlib/lib/calib/calib_basic.c` (around line 90, inside `calib_wakeup_i2c`) to the same new API. Preserve the existing 3 ms wake delay and 5 ms post-wake settle delay.
- Preserve all fork-specific timeout customizations currently expressed as `i2c_master_cmd_begin` tick counts (10/100/1000 ticks visible in `hal_esp32_i2c.c`) by translating them to the new API's millisecond timeout argument.
- Remove the now-unnecessary IWDT workaround from consumer projects (`playfield-relay/sdkconfig.defaults` line `CONFIG_ESP_INT_WDT_TIMEOUT_MS=600` and the matching change in `hermes-bridge` if it gets one) once the new HAL is in and verified.
- Delete `flashback-fleet-esp-common/src/i2c_utils.c` and `include/i2c_utils.h`. Audit shows zero callers in either consumer firmware repo; it's dead code that still pulls in legacy-driver symbols and gives a misleading impression that bus 0 is shared.
- **BREAKING** for any external consumer of `hal_esp32_i2c.c` that initialises an I2C bus through this HAL and then expects to share the bus via the legacy driver — the new API exposes a `i2c_master_bus_handle_t` instead, and bus sharing across legacy/new drivers is not supported.

## Capabilities

### New Capabilities
- `esp32-i2c-hal`: ATECC608A I2C transport for ESP32 family targets, covering bus init, ATECC wake protocol, and the read/write entry points cryptoauthlib's higher layers expect (`hal_i2c_init`, `hal_i2c_send`, `hal_i2c_receive`, `hal_i2c_wake`, `hal_i2c_idle`, `hal_i2c_sleep`).

### Modified Capabilities
<!-- None — there are no existing capability specs in this fork yet. -->

## Impact

- **Code**: `cryptoauthlib/third_party/hal/esp32/hal_esp32_i2c.c`, `cryptoauthlib/lib/calib/calib_basic.c` (the fork-specific block in `calib_wakeup_i2c`).
- **APIs**: ESP-IDF I2C driver API surface used by the HAL changes from `driver/i2c.h` to `driver/i2c_master.h`. The cryptoauthlib `hal_*` function signatures are unchanged.
- **Dependencies**: ESP-IDF v5.5 (already what we build against). No new third-party dependencies.
- **Consumers**:
  - `flashback-fleet-esp-common` — picks up the new behavior via its existing submodule pointer; once the new HAL is on a tagged commit, bump the submodule pointer.
  - `playfield-relay` and `hermes-bridge` — pick it up via their `flashback-fleet-esp-common` submodule pointer. Tag a new firmware version on each after merging, then revert the IWDT workaround.
- **Hardware in scope**: RAK11200 (ESP32-WROVER) and Heltec WiFi LoRa 32 V3 (ESP32-S3). ATECC608A on I2C bus 0 at 7-bit address `0x60`. ESP32-S3 pin map SDA=9, SCL=40.
- **Risk**: Bus sharing — if any other component on the relay or bridge uses the legacy I2C driver on the same bus, the new bus driver instance will conflict. Need to audit consumers before merging.
