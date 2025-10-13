# Diagnosis: Why Your Blank Chip Appeared Locked

## Problem Summary

You had a **blank TrustCustom ATECC608A chip**, but after running `init`, it showed as **LOCKED**. This prevented you from writing custom configuration.

## Root Cause

### The `init` Command Was Auto-Locking Zones!

**Location:** `esp_cryptoauth_utility/firmware/main/handlers.c:163-189` (OLD VERSION)

The original `init_atecc608a()` function had this code:

```c
if (!is_zone_locked) {
    ret = atcab_lock_config_zone();  // ← AUTOMATICALLY LOCKED!
    if (ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "error in locking config zone, ret = %02x", ret);
        goto exit;
    }
    ECU_DEBUG_LOG(TAG, "success in locking config zone");
}
// ... same for data zone ...
if (!is_zone_locked) {
    ret = atcab_lock_data_zone();    // ← AUTOMATICALLY LOCKED!
}
```

### What Happened to Your Chip

1. **You received a blank TrustCustom chip** - zones UNLOCKED ✓
2. **You ran `init 4 5`** to initialize I2C
3. **`init` checked**: "Is config locked? No"
4. **`init` executed**: `atcab_lock_config_zone()` ← **LOCKED YOUR CHIP!**
5. **`init` checked**: "Is data locked? No"
6. **`init` executed**: `atcab_lock_data_zone()` ← **LOCKED DATA TOO!**
7. **Result**: Chip locked with **factory default config** (not your custom config!)

### Why generate-pubkey Failed

Error: `0xfffffff4` = `ATCA_EXECUTION_ERROR`

From ATECC608 datasheet: **Status byte 0x0F = Command cannot execute**

Reasons:
- No private key exists in slot 0 yet
- `generate-pubkey` retrieves the PUBLIC key FROM an EXISTING private key
- You need to run `generate-keys 0` FIRST to create the private key

But you couldn't do that because the chip was already locked with wrong config!

## The Fix

### Changes Made

#### 1. Modified `init` Command (handlers.c:156-181)

**REMOVED** auto-locking code.

**NEW behavior:**
```c
// Check lock status but DO NOT auto-lock
if (!is_zone_locked) {
    ESP_LOGI(TAG, "Config zone is UNLOCKED - ready for write-config command");
} else {
    ESP_LOGI(TAG, "Config zone is LOCKED");
}
```

Now `init` **only initializes I2C** and **reports lock status** - it does NOT lock zones!

#### 2. Added Manual Lock Commands

**New commands:**
- `lock-config` - Manually lock config zone (after write-config)
- `lock-data` - Manually lock data zone (after provisioning)

**Files modified:**
- `handlers.h:45-46` - Added prototypes
- `handlers.c:693-769` - Added implementations
- `commands.c:63-64, 83-84` - Added registrations
- `commands.c:709-787` - Added command handlers

#### 3. Suppressed I2C NACK Logs (app_main.c:117)

Added:
```c
esp_log_level_set("i2c.master", ESP_LOG_WARN);
```

ESP-IDF 5.5.1 added verbose I2C error logging. NACK errors during ATECC608 wakeup/retry are normal, so we suppress them.

## Correct Workflow (NEW)

### For Blank TrustCustom Chips

```bash
# Step 1: Initialize I2C (does NOT lock!)
init 4 5

# Step 2: Verify zones are unlocked
is-config-locked   # Should return: Config Zone: UNLOCKED
is-data-locked     # Should return: Data Zone: UNLOCKED

# Step 3: Write custom configuration
write-config <CRC32>
# (Python script sends 128 bytes via UART)

# Step 4: Lock config zone (IRREVERSIBLE!)
lock-config

# Step 5: Generate private key in slot 0
generate-keys 0

# Step 6: Lock data zone (IRREVERSIBLE!)
lock-data

# Step 7: Continue provisioning...
generate-csr
# (sign CSR on host)
program-dev-cert 1 <CRC>
program-signer-cert 1 <CRC>
```

### Python Script Integration

```python
def provision_trustcustom(port, config_bytes):
    ser = serial.Serial(port, 115200, timeout=2)

    # Step 1: Initialize (does NOT lock anymore)
    send_command(ser, "init 21 22")

    # Step 2: Check if already locked
    send_command(ser, "is-config-locked")
    response = ser.read_until(b'\n').decode()

    if "UNLOCKED" in response:
        # Step 3: Write custom config
        crc32 = zlib.crc32(config_bytes) & 0xFFFFFFFF
        send_command(ser, f"write-config {crc32}")
        ser.write(config_bytes + b'\0')

        # Step 4: Lock config
        send_command(ser, "lock-config")
    else:
        print("⚠ Config already locked - cannot write custom config!")

    # Step 5: Generate keys
    send_command(ser, "generate-keys 0")

    # Step 6: Lock data zone
    send_command(ser, "lock-data")

    # Continue with CSR, certs, etc...
```

## What to Do Now

### Option 1: Get a New Blank Chip

Your current chip is **permanently locked** with factory default config.

**You cannot:**
- Unlock it (irreversible!)
- Overwrite the config (locked!)

**To start fresh:**
1. Get a new blank TrustCustom ATECC608A chip
2. Rebuild firmware with the fixes
3. Follow the NEW workflow above

### Option 2: Use the Locked Chip (If Config Works)

**If the factory default config happens to work for your use case:**

1. Check what slots are configured for ECC private keys
2. Try generating keys: `generate-keys 0` (or slot 1, 2, etc.)
3. If it works, continue with CSR generation and provisioning

**To check the current config:**
```bash
# The chip revision and serial number are still readable
print-chip-info
```

You can also read the config zone to see what settings it has (even though it's locked).

## Rebuild Instructions

```bash
cd esp_cryptoauth_utility/firmware

# Clean previous build
idf.py fullclean

# Build with fixes
idf.py build

# Convert to binary
esptool.py --chip esp32 elf2image build/ecu_firmware.elf

# Copy to Python script location
cp build/ecu_firmware.bin ../sample_bins/esp32/secure_cert_mfg_esp32.bin
# Or copy to your Python project's sample_bins directory
```

## New Firmware Features

✅ `init` - Initialize I2C, detect chip, **report lock status** (no longer locks!)
✅ `is-config-locked` - Check config zone lock status
✅ `is-data-locked` - Check data zone lock status
✅ `write-config <CRC32>` - Write 128-byte custom config (only if unlocked)
✅ `lock-config` - **Manually** lock config zone (irreversible!)
✅ `lock-data` - **Manually** lock data zone (irreversible!)
✅ Suppressed harmless I2C NACK errors

## Summary

| Issue | Cause | Fix |
|-------|-------|-----|
| Blank chip shows as LOCKED | `init` auto-locked zones | Modified `init` to NOT auto-lock |
| Can't write custom config | Config locked too early | Added manual `lock-config` command |
| I2C NACK errors clutter logs | ESP-IDF 5.5.1 verbose logging | Suppressed with `esp_log_level_set()` |
| generate-pubkey fails 0xF4 | No private key in slot yet | Run `generate-keys 0` first |

**The fix gives you full control over WHEN zones get locked!**
