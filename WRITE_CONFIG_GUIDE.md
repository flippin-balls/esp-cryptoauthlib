# ATECC608 TrustCustom Configuration Guide

## Overview

This guide explains how to write custom configuration to ATECC608 TrustCustom chips using the new `write-config` command added to the ESP cryptoauth utility firmware.

## What Was Added

### New Firmware Command: `write-config`

**Location:** `esp_cryptoauth_utility/firmware/main/`

**Files Modified:**
- `commands.c` - Added `write_config()` and `register_write_config()` functions
- `handlers.c` - Added `atecc_write_config()` implementation
- `handlers.h` - Added function prototype

**Command Usage:**
```
write-config <CRC32>
```

**Command Flow:**
1. Accepts CRC32 checksum as argument
2. Reads 128 bytes of config data via UART
3. Validates data integrity using CRC32
4. Checks if config zone is unlocked
5. Writes config in 4 slots:
   - Slot 0: bytes 16-31 (skips read-only serial number/revision at 0-15)
   - Slot 1: bytes 32-63
   - Slot 2: bytes 64-95
   - Slot 3: bytes 96-127
6. Reports success/failure

## Building Custom Firmware

### Prerequisites
- ESP-IDF v5.4 or newer
- Environment variable `IDF_PATH` set
- esptool.py installed

### Build Steps

1. **Navigate to firmware directory:**
   ```powershell
   cd components\esp-cryptoauthlib\esp_cryptoauth_utility\firmware
   ```

2. **Set target chip (if needed):**
   ```bash
   idf.py set-target esp32
   # or esp32s3, esp32c3, esp32c6, etc.
   ```

3. **Configure I2C pins (optional):**
   ```bash
   idf.py menuconfig
   # Navigate to: Component config > esp-cryptoauthlib > I2C SDA/SCL pin
   ```

4. **Build the firmware:**
   ```bash
   idf.py build
   ```

5. **Convert ELF to BIN:**
   ```bash
   esptool.py --chip esp32 elf2image build/ecu_firmware.elf
   ```

6. **Replace sample binary:**
   ```bash
   # Copy to your target chip folder
   cp build/ecu_firmware.bin ../sample_bins/esp32/secure_cert_mfg_esp32.bin
   ```

## Using write-config Command

### Provisioning Workflow for TrustCustom Chips

**Correct order:**
1. `init` - Initialize ATECC (does NOT lock yet in modified firmware)
2. `write-config <CRC32>` - Write custom 128-byte config
3. Second call to lock zones (or modify init to lock after write-config)

### Python Script Integration

You'll need to modify `secure_cert_mfg.py` to call the new command. Example:

```python
import struct
import zlib

def write_atecc_config(serial_port, config_bytes):
    """
    Write 128 bytes of configuration to ATECC608 via write-config command.

    Args:
        serial_port: Serial port object
        config_bytes: 128 bytes of ATECC608 configuration
    """
    # Calculate CRC32
    crc32 = zlib.crc32(config_bytes) & 0xFFFFFFFF

    # Send write-config command with CRC
    command = f"write-config {crc32}\n"
    serial_port.write(command.encode())

    # Send 128 bytes of config data followed by null terminator
    serial_port.write(config_bytes + b'\0')

    # Wait for response
    response = serial_port.read_until(b'\n')

    if b"Success" in response:
        print("✓ Config written successfully")
        return True
    else:
        print(f"✗ Config write failed: {response}")
        return False
```

### ATECC608 Config Structure

The 128-byte config zone layout:
- **Bytes 0-15:** Read-only (Serial Number + Revision) - Cannot be written
- **Bytes 16-83:** SlotConfig (16 slots × 2 bytes each)
- **Bytes 84-87:** Counter[0]
- **Bytes 88-91:** Counter[1]
- **Bytes 92-95:** LastKeyUse
- **Bytes 96-127:** KeyConfig (16 slots × 2 bytes each)

**Important:** Your 128-byte config data should include bytes 0-15 (even though they won't be written), as the firmware uses proper offsets.

## Example Config for TLS Certificate Storage

```python
# Default ATECC608 TrustCustom config for TLS certificate storage
ATECC608_DEFAULT_CONFIG = bytes([
    # Bytes 0-15: Read-only (will be preserved from factory)
    0x01, 0x23, 0x00, 0x00,  # SN[0:3]
    0x00, 0x00, 0x50, 0x00,  # SN[4:7]
    0x04, 0x05, 0x06, 0x07,  # SN[8] + Reserved[4]
    0xEE, 0x00, 0x01, 0x00,  # Reserved[5:8]

    # Bytes 16-83: SlotConfig
    # Slot 0: Private key slot for TLS
    0x83, 0x20,  # SlotConfig[0] - ECC private key
    # ... (configure remaining slots)

    # Bytes 84-91: Counters
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,

    # Bytes 92-95: LastKeyUse
    0xFF, 0xFF, 0xFF, 0xFF,

    # Bytes 96-127: KeyConfig
    0x33, 0x00,  # KeyConfig[0] - Private key settings
    # ... (configure remaining key slots)
])
```

## Troubleshooting

### "Config zone is already locked"
- The chip has already been provisioned
- You cannot write config to a locked chip
- Use a fresh TrustCustom chip

### "CRC32 mismatch"
- Data corruption during UART transmission
- Verify baud rate and serial connection
- Check that exactly 128 bytes are being sent

### "Invalid config size"
- Ensure exactly 128 bytes are sent
- Include null terminator after config data
- Check UART buffer sizes

### Build Errors
- Ensure ESP-IDF v5.4+ is installed
- Run `idf.py fullclean` and rebuild
- Check that `IDF_PATH` is set correctly

## Testing

1. Connect ATECC608 TrustCustom to ESP32 via I2C
2. Load custom firmware with write-config command
3. Run provisioning script with custom config
4. Verify config was written: read config zone back
5. Lock zones with `init` command
6. Test TLS functionality

## Next Steps

After successful config writing:
1. Generate keypair in slot 0: `generate-keys 0`
2. Generate CSR: `generate-csr`
3. Sign certificate on host
4. Program device cert: `program-dev-cert 1 <CRC>`
5. Program signer cert: `program-signer-cert 1 <CRC>`

## References

- [ATECC608 Datasheet](https://www.microchip.com/en-us/product/atecc608b)
- [Cryptoauthlib Documentation](https://github.com/MicrochipTech/cryptoauthlib)
- Original context: `write-conf-context.txt`
