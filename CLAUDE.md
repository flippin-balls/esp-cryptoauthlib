# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a fork of esp-cryptoauthlib, a port of Microchip's CryptoAuthLib for ESP-IDF. It provides integration for ATECC608A/B cryptographic chips with ESP32 modules, along with a Python utility for configuration and provisioning.

**Key modifications in this fork:**
- Added `write-config` command to support writing custom configurations to ATECC608 TrustCustom chips before zone locking
- Added `is-config-locked` and `is-data-locked` commands to check zone lock status from Python provisioning scripts

## Build Commands

### Firmware Build (esp_cryptoauth_utility/firmware)

```bash
# Navigate to firmware directory
cd esp_cryptoauth_utility/firmware

# Set target chip (esp32, esp32s3, esp32c3, esp32c6, etc.)
idf.py set-target esp32

# Configure I2C pins (optional)
idf.py menuconfig
# Navigate to: Component config > esp-cryptoauthlib > I2C SDA/SCL pin

# Build firmware
idf.py build

# Convert ELF to binary
esptool.py --chip esp32 elf2image build/ecu_firmware.elf

# Output: build/ecu_firmware.bin
```

### Python Utility Installation

```bash
pip install esp-cryptoauth-utility
```

## Architecture

### Component Structure

- **cryptoauthlib/** - Microchip's CryptoAuthLib (subset generated via generate_component.sh)
  - lib/ - Core library (calib, atcacert, crypto, hal)
  - app/tng/ - Trust & Go support
  - third_party/ - Platform HALs (esp32 I2C/timer)

- **port/** - ESP-IDF specific configuration
  - atca_config.h - Build configuration
  - atca_cfgs_port.c - Interface configurations

- **esp_cryptoauth_utility/** - Provisioning utility
  - firmware/ - ESP32 firmware for UART-based provisioning
  - secure_cert_mfg.py - Python provisioning script
  - helper_scripts/ - Certificate tools (cert_sign.py, cert2certdef.py)

### Firmware Command Handler Architecture

The firmware uses a command registration pattern (esp_cryptoauth_utility/firmware/main/):

1. **commands.c** - Command registration and parsing
   - `register_command_handler()` - Registers all commands with ESP console
   - Each command has: command name, help text, handler function
   - Commands: init, write-config, is-config-locked, is-data-locked, generate-keys, generate-csr, program-dev-cert, etc.

2. **handlers.c** - Implementation of cryptographic operations
   - `init_atecc608a()` - Auto-detects chip type (TrustCustom 0xC0, Trust&Go 0x6A, TrustFlex 0x6C)
   - `atecc_write_config()` - Writes 128-byte config to unlocked zone (custom addition)
   - `atecc_is_config_locked()` - Checks if config zone is locked (custom addition)
   - `atecc_is_data_locked()` - Checks if data zone is locked (custom addition)
   - `atecc_input_cert()` - Programs certificates via UART with CRC32 validation
   - Uses global state tracking via `device_status_t` enum

3. **ecu_console_interface.c** - UART console integration

### ATECC608 Chip Types

- **TrustCustom (0xC0)** - Blank config, must be configured before provisioning
- **Trust&Go (0x6A)** - Pre-configured by Microchip, generates manifest only
- **TrustFlex (0x6C)** - Pre-configured, generates manifest only

### Provisioning Flow

**For TrustCustom chips:**
1. `init <SDA> <SCL>` - Initialize I2C, detect chip type (does NOT lock in modified firmware)
2. `is-config-locked` - Check if config zone is locked (returns "LOCKED" or "UNLOCKED")
3. `write-config <CRC32>` - Write 128-byte config via UART (only if unlocked)
4. Lock zones (via subsequent init or explicit command)
5. `is-data-locked` - Check if data zone is locked
6. `generate-keys 0` - Generate keypair in slot 0
7. `generate-csr` - Create certificate signing request
8. Sign CSR on host with signer cert
9. `program-dev-cert 1 <CRC>` - Program device certificate
10. `program-signer-cert 1 <CRC>` - Program signer certificate

**For Trust&Go/TrustFlex:**
1. `init` - Initialize and detect
2. Python script generates manifest file for cloud registration

### Firmware Commands for Python Scripts

**Lock Status Commands (NEW):**
```bash
is-config-locked  # Returns "Config Zone: LOCKED" or "Config Zone: UNLOCKED"
is-data-locked    # Returns "Data Zone: LOCKED" or "Data Zone: UNLOCKED"
```

Python script example:
```python
# Check config lock status before writing config
serial_port.write(b"is-config-locked\n")
response = serial_port.read_until(b'\n').decode()
if "UNLOCKED" in response:
    # Safe to write config
    serial_port.write(f"write-config {crc32}\n".encode())
else:
    print("Config zone already locked, cannot write")
```

**CRC32 Validation:**

Added to prevent UART transmission errors:
- `write-config <CRC32>` - Config data validated before writing
- `program-dev-cert <lock> <CRC32>` - Certificate validated before programming
- `program-signer-cert <lock> <CRC32>` - Signer cert validated

CRC calculation in Python:
```python
import zlib
crc32 = zlib.crc32(data_bytes) & 0xFFFFFFFF
```

## Important Configuration Notes

### I2C Pin Configuration

Default pins: SDA=21, SCL=22

Change via:
- Build-time: `idf.py menuconfig` → Component config → esp-cryptoauthlib
- Runtime: `init <SDA> <SCL>` command
- Python script: `--i2c-sda-pin <SDA> --i2c-scl-pin <SCL>`

### ATECC608 Config Zone Layout

128 bytes total:
- Bytes 0-15: Read-only (Serial Number + Revision) - cannot be written
- Bytes 16-83: SlotConfig (16 slots × 2 bytes)
- Bytes 84-91: Counters
- Bytes 92-95: LastKeyUse
- Bytes 96-127: KeyConfig (16 slots × 2 bytes)

The `write-config` command writes in 4 blocks:
- Slot 0: bytes 16-31 (skips read-only section)
- Slot 1: bytes 32-63
- Slot 2: bytes 64-95
- Slot 3: bytes 96-127

### Certificate Definitions

Firmware uses compile-time cert definitions:
- cert_def_1_signer.c - Signer cert template
- cert_def_2_device.c - Device cert template
- cert_def_3_device_csr.c - CSR template (defines slot, CN, O, etc.)

Generate new definitions with `helper_scripts/cert2certdef.py`

## Development Notes

### Debugging

Enable debug logs in menuconfig:
```
ECU Configurations → esp_cryptoauth_utility Debug
```

Defined via `CONFIG_ECU_DEBUGGING` macro in handlers.c and commands.c

### ESP-IDF Version Requirements

- Main component: ESP-IDF v5.0+ (per README.md)
- Firmware: ESP-IDF v4.3+ (per firmware/README.md)
- Component declared in idf_component.yml with `idf: version: ">=4.3"`

### Binary Replacement Workflow

After custom firmware build:
1. Build creates `build/ecu_firmware.elf`
2. Convert: `esptool.py --chip esp32 elf2image build/ecu_firmware.elf`
3. Replace: `cp build/ecu_firmware.bin ../sample_bins/esp32/secure_cert_mfg_esp32.bin`
4. Python script uses binary from sample_bins/

## File Locations

- Firmware commands:
  - esp_cryptoauth_utility/firmware/main/commands.c:606-617 (write-config)
  - esp_cryptoauth_utility/firmware/main/commands.c:619-660 (is-config-locked, is-data-locked)
- Firmware handlers:
  - esp_cryptoauth_utility/firmware/main/handlers.c:644-700 (lock status handlers)
  - esp_cryptoauth_utility/firmware/main/handlers.h:43-44 (function prototypes)
- Python provisioning: esp_cryptoauth_utility/secure_cert_mfg.py
- Component config: port/atca_config.h
- CMake build: CMakeLists.txt, esp_cryptoauth_utility/firmware/CMakeLists.txt
