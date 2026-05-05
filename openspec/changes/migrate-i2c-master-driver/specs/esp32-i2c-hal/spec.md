## ADDED Requirements

### Requirement: I2C HAL SHALL use the new ESP-IDF i2c_master driver
The ESP32 I2C HAL (`cryptoauthlib/third_party/hal/esp32/hal_esp32_i2c.c`) SHALL implement bus initialisation, transmit, receive, wake, idle, and sleep operations using the `driver/i2c_master.h` API (`i2c_new_master_bus`, `i2c_master_bus_add_device`, `i2c_master_transmit`, `i2c_master_receive`) when built against ESP-IDF v5.2 or later. The legacy `driver/i2c.h` API SHALL NOT be reachable from any code path that the ATECC608A communication chain executes during normal operation, except behind the explicit opt-in `CONFIG_ATCA_I2C_USE_LEGACY_DRIVER` Kconfig (which our consumer projects MUST leave unset).

#### Scenario: Bus initialisation creates a master bus and registers the ATECC device
- **WHEN** `hal_i2c_init` is called with a valid `ATCAIfaceCfg` for a previously uninitialised I2C bus
- **THEN** the HAL calls `i2c_new_master_bus` with the configured SDA/SCL pins, internal pull-ups enabled, and 100 kHz speed; then calls `i2c_master_bus_add_device` to register the ATECC at its 7-bit address; then stores the bus and device handles in the HAL's per-bus state and marks it `initialized`

#### Scenario: Send routes through i2c_master_transmit
- **WHEN** `hal_i2c_send` is invoked with a word_address byte and a payload
- **THEN** the HAL builds a single contiguous buffer (or uses `i2c_master_multi_buffer_transmit` on ESP-IDF ≥ v5.4) and submits it via the registered device handle, with a transaction timeout in milliseconds

#### Scenario: Receive routes through i2c_master_receive
- **WHEN** `hal_i2c_receive` is invoked with an output buffer and length pointer
- **THEN** the HAL calls `i2c_master_receive` against the registered device handle, fills the buffer, and updates the length pointer with the actual byte count; on transport error it returns `ATCA_COMM_FAIL` without entering a critical section to reset the I2C peripheral

#### Scenario: Release tears down both device and bus
- **WHEN** the HAL's reference count for a bus drops to zero via `hal_i2c_release`
- **THEN** the HAL calls `i2c_master_bus_rm_device` for each registered device handle on the bus, then `i2c_del_master_bus`, then clears the per-bus state including the `initialized` flag

### Requirement: I2C HAL SHALL implement hal_i2c_wake on the new-driver code path
The new-driver section of the HAL SHALL define `hal_i2c_wake` (it currently exists only in the legacy section). Wake SHALL execute a write to address `0x00` that is expected to NACK, hold the bus low long enough for the chip's internal wake-up timer (≥ 60 µs), then read the 4-byte wake-confirm response from the regular ATECC device handle. The wake operation SHALL NOT cause an Interrupt Watchdog Timeout panic regardless of how many times it is invoked back-to-back.

#### Scenario: Wake pulse via temporary 0x00 device handle
- **WHEN** `hal_i2c_wake` is called on an initialised bus
- **THEN** the HAL transmits a single zero-length (or one-byte, address-only) write to a device handle registered at address `0x00`, observes the expected NACK without bus reset, then `vTaskDelay(pdMS_TO_TICKS(3))`, then reads 4 bytes from the regular ATECC device handle into a wake-confirm buffer

#### Scenario: Wake handles the NACK without entering a critical section
- **WHEN** the wake-pulse write returns `ESP_ERR_INVALID_STATE` or `ESP_ERR_TIMEOUT` (the new driver's NACK indication)
- **THEN** the HAL treats it as an expected outcome of the wake pulse, does NOT attempt any FSM reset, and proceeds to the wake-confirm read

#### Scenario: Repeated wakes do not panic the watchdog
- **WHEN** `hal_i2c_wake` is invoked 100 times consecutively (representative of a heartbeat-loop burn-in)
- **THEN** no Interrupt WDT panic occurs, even with `CONFIG_ESP_INT_WDT_TIMEOUT_MS` at the ESP-IDF default of 300 ms

### Requirement: Custom wake-pulse block in calib_basic.c SHALL be removed
The fork-specific custom wake sequence currently inlined inside `calib_wakeup_i2c` in `cryptoauthlib/lib/calib/calib_basic.c` (calling `i2c_cmd_link_create`, `i2c_master_start`, `i2c_master_write_byte`, `i2c_master_cmd_begin`) SHALL be removed. `calib_wakeup_i2c` SHALL delegate the wake operation to `hal_i2c_wake` via the `ATCAIface` HAL function pointers, the same way upstream cryptoauthlib does.

#### Scenario: calib_wakeup_i2c contains no direct ESP-IDF I2C calls
- **WHEN** the file `cryptoauthlib/lib/calib/calib_basic.c` is searched for `i2c_master_cmd_begin`, `i2c_cmd_link_create`, `i2c_master_start`, or `i2c_master_write_byte`
- **THEN** zero matches are returned

#### Scenario: Wake delegates through the HAL
- **WHEN** `calib_wakeup_i2c` is invoked during a `calib_execute_command` flow on an ESP32-family target
- **THEN** the function calls into the HAL's wake entry point (via `iface->hal_data` or `atgetifacehal(iface)->halwake`) and returns whatever ATCA status the HAL produces, without performing any direct ESP-IDF I2C calls

### Requirement: Fork timing customisations SHALL be preserved
The fork's empirically-tuned timing values for RAK11200 / RAK13300 boards SHALL be preserved verbatim during the migration: 3 ms post-wake-pulse delay before the wake-confirm read, 5 ms post-wake settle delay before any subsequent command, and the existing per-call timeouts (10 ms / 100 ms / 10 s) on transmit and receive operations.

#### Scenario: Wake delays are unchanged
- **WHEN** the migrated `hal_i2c_wake` runs
- **THEN** `vTaskDelay(pdMS_TO_TICKS(3))` is called between the wake pulse and the wake-confirm read, and `vTaskDelay(pdMS_TO_TICKS(5))` is called after the wake-confirm read on success

#### Scenario: Transmit/receive timeouts match the pre-migration tick counts (translated to ms)
- **WHEN** any HAL transmit or receive call is issued
- **THEN** the timeout passed to `i2c_master_transmit` / `i2c_master_receive` is the millisecond equivalent of the legacy code's `pdMS_TO_TICKS(10)`, `pdMS_TO_TICKS(100)`, or `pdMS_TO_TICKS(1000)` arguments — that is, `10`, `100`, or `10000` ms respectively, depending on the call site

### Requirement: HAL SHALL retain its public ATCA function signatures
None of the HAL's externally visible cryptoauthlib entry points (`hal_i2c_init`, `hal_i2c_post_init`, `hal_i2c_send`, `hal_i2c_receive`, `hal_i2c_wake`, `hal_i2c_idle`, `hal_i2c_sleep`, `hal_i2c_release`, `hal_i2c_control`, `hal_i2c_change_baud`) SHALL change their function signatures or ATCA return-status semantics. Higher cryptoauthlib layers and consumers of the fork SHALL link unchanged.

#### Scenario: ABI is preserved
- **WHEN** `flashback-fleet-esp-common` and downstream firmware projects (`playfield-relay`, `hermes-bridge`) are rebuilt against the migrated HAL with no source changes outside the submodule pointer bump
- **THEN** the build succeeds without modifications to consumer code

### Requirement: Bus exclusivity SHALL be enforced
On each board, I2C bus 0 (which carries the ATECC608A) SHALL be initialised exclusively through the new-driver HAL. No other component or driver in `flashback-fleet-esp-common`, `playfield-relay`, or `hermes-bridge` SHALL call `i2c_driver_install` or `i2c_param_config` on bus 0. Components needing a second I2C device SHALL register through `i2c_master_bus_add_device` against the bus handle exposed by the HAL, OR move to a different bus.

#### Scenario: No legacy driver init on bus 0
- **WHEN** the consumer firmware repos are searched for `i2c_driver_install` or `i2c_param_config` calls referencing bus 0
- **THEN** zero matches are found outside of test/diagnostic code

#### Scenario: Additional devices share the new bus
- **WHEN** a future component needs to talk to a second I2C device on bus 0
- **THEN** it obtains the bus handle from the HAL and calls `i2c_master_bus_add_device` with its own device address, rather than installing a parallel driver instance
