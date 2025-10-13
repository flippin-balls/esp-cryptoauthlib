# ATECC608 Write-Data Command Guide

## Overview

The `write-data` command allows writing 32 bytes of arbitrary data to ATECC608 data slots. This is essential for:
- Writing IO protection secrets to slot 6
- Writing secret data to slot 5 (after slot 6 secret is in place)
- Storing symmetric keys in slots 7-9 (AES slots)
- Storing public keys or certificates in slots 10-13

## Slot Configuration Analysis

Based on your configuration:

### Slot 5 (Secret - Write Protected)
```
SlotCfg=0xF6C0
  Binary: 1111 0110 1100 0000

  Bits 15-12 (WriteConfig): 0b1111 = 0xF
    - Can be written by DeriveKey, GenKey, or Write commands
    - Can be written during ECDH operation
    - Can be signed internally
    - Can be signed externally

  Bits 11-8 (WriteKey): 0b0110 = 6
    ** IMPORTANT: Slot 5 is WRITE-PROTECTED by slot 6's secret! **
    - To write to slot 5 after data lock, you need the 32-byte secret from slot 6

  Bit 6 (EncRead): Set
    - Data can only be read encrypted (requires slot 6 secret)

  KeyCfg=0x003C (Other/Data)
```

### Slot 6 (IO Protection Secret)
```
SlotCfg=0xA080
  Binary: 1010 0000 1000 0000

  This slot stores the 32-byte secret used to protect slot 5
  Must be written BEFORE locking data zone

  KeyCfg=0x003C (Other/Data)
```

## Provisioning Workflow

### Phase 1: Before Locking Data Zone

**Step 1: Initialize and configure**
```
init 21 22                  # Initialize I2C
write-config <CRC32>        # Write custom config with slot 5/6 settings
lock-config                 # Lock config zone
```

**Step 2: Write slot 6 IO protection secret**
```python
import os
import serial

# Generate or load your 32-byte secret for slot 6
slot6_secret = os.urandom(32)  # Or use a specific secret

# Send command to firmware
ser.write(b"write-data 6\n")

# Wait for "Reading 32 bytes" response
response = ser.read_until(b"Reading 32 bytes")

# Send the 32 bytes + null terminator
ser.write(slot6_secret + b'\0')

# Check response
result = ser.read_until(b'\n')
```

**Step 3: Generate keys in slot 0**
```
generate-keys 0             # Generate ECC keypair in slot 0
```

**Step 4: Write data to slot 5 (BEFORE locking data zone)**
```python
# Slot 5 can be written without encryption before data lock
slot5_data = b"Your 32-byte secret data here..."

ser.write(b"write-data 5\n")
ser.read_until(b"Reading 32 bytes")
ser.write(slot5_data + b'\0')
```

**Step 5: Lock data zone**
```
lock-data                   # IRREVERSIBLE! Locks all data
```

### Phase 2: After Locking Data Zone

Once data zone is locked, slot 5 becomes write-protected and can only be written using **encrypted writes** with the slot 6 secret.

⚠️ **Current Limitation**: The current `write-data` command does NOT support encrypted writes. To write to slot 5 after locking, you would need:

1. Use `atcab_write_enc_bytes()` instead of `atcab_write_bytes_zone()`
2. Provide the slot 6 secret for encryption
3. This requires a new command like `write-data-enc <slot> <write_key_slot>`

## Command Usage

### write-data Command

**Syntax:**
```
write-data <slot>
```

**Arguments:**
- `slot`: Slot number (0-15)

**Data Input:**
- Must provide exactly 32 bytes via UART after the command
- Followed by a null terminator (`\0`)

**Example (Python):**
```python
import serial

ser = serial.Serial('/dev/ttyUSB0', 115200)

# Write to slot 6
slot_number = 6
data = b'A' * 32  # 32 bytes of data

# Send command
ser.write(f"write-data {slot_number}\n".encode())

# Wait for prompt
ser.read_until(b"Reading 32 bytes")

# Send data + null terminator
ser.write(data + b'\0')

# Read response
response = ser.read_until(b'\n')
print(response)
```

## Slot Write Restrictions

### Before Data Lock
- **Slots 0-4 (ECC Private)**: Cannot write directly (use `generate-keys`)
- **Slot 5 (Secret)**: ✅ Can write with `write-data`
- **Slot 6 (IO Protection)**: ✅ Can write with `write-data`
- **Slots 7-9 (AES)**: ✅ Can write with `write-data`
- **Slots 10-15 (Storage)**: ✅ Can write with `write-data`

### After Data Lock
- **Slots 0-4 (ECC Private)**: Cannot write (locked)
- **Slot 5 (Secret)**: ❌ Requires encrypted write with slot 6 secret
- **Slot 6 (IO Protection)**: Depends on SlotConfig
- **Slots 7-9 (AES)**: Depends on SlotConfig
- **Slots 10-15 (Storage)**: Usually ✅ writable

## Error Messages

### "Data zone is locked - write may fail if slot requires encryption"
This is a warning. The write will fail if:
- Slot has WriteKey configured (like slot 5)
- Data zone is locked
- You're using unencrypted write

**Solution**: Write to protected slots BEFORE locking data zone.

### "Failed to write data to slot X, returned 0x0F"
Error code `0x0F` = `ATCA_CHECKMAC_VERIFY_FAILED`
- Slot requires encrypted/authenticated write
- Data zone is locked
- You need to use encrypted write with the WriteKey secret

### "Data length must be 32 bytes"
ATECC608 data slots are 32 bytes (or 72 bytes for some public key slots).
Always send exactly 32 bytes.

## Recommendations

### For Your Use Case (Slots 5 & 6)

**Recommended Workflow:**
1. ✅ `init` - Initialize chip
2. ✅ `write-config` - Write config with slot 5 protected by slot 6
3. ✅ `lock-config` - Lock config
4. ✅ `write-data 6` - Write slot 6 IO protection secret (SAVE THIS!)
5. ✅ `write-data 5` - Write slot 5 protected data
6. ✅ `generate-keys 0` - Generate ECC key in slot 0
7. ✅ `lock-data` - Lock data zone (FINAL STEP!)

**Important:**
- **SAVE the slot 6 secret** somewhere secure! Without it:
  - You cannot update slot 5 after data lock
  - You cannot read slot 5 (EncRead requires slot 6 secret)
- Write to both slots 5 and 6 BEFORE locking data zone
- Once locked, slot 5 is read-only unless you implement encrypted writes

### Future Enhancement: Encrypted Writes

To write to slot 5 after locking data zone, you would need to add a command like:

```c
esp_err_t atecc_write_data_encrypted(
    int target_slot,        // Slot to write to (e.g., 5)
    int write_key_slot,     // Slot containing write key (e.g., 6)
    unsigned char *data,    // 32 bytes to write
    unsigned char *key      // 32-byte key from slot 6
);
```

This would use `atcab_write_enc_bytes()` from CryptoAuthLib.

## References

- ATECC608 Datasheet: Section 2.2 (Memory Organization)
- ATECC608 Datasheet: Section 9.17 (Write Command)
- SlotConfig bits: WRITE_CONFIG_GUIDE.md
- CryptoAuthLib: `atcab_write_bytes_zone()` and `atcab_write_enc_bytes()`

## Version History

- **v0.0.6**: Added `write-data` command for unencrypted slot writes
  - Location: `esp_cryptoauth_utility/firmware/main/`
  - Files: `handlers.c`, `handlers.h`, `commands.c`, `app_main.c`
