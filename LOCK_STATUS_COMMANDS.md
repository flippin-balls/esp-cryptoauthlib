# Lock Status Commands for Python Provisioning

## Overview

Two new commands have been added to the firmware to check the lock status of ATECC608 zones:

1. **`is-config-locked`** - Check if config zone is locked
2. **`is-data-locked`** - Check if data zone is locked

These commands are designed to be called from Python provisioning scripts to determine the state of the chip before performing operations like writing config or programming certificates.

## Command Usage

### is-config-locked

**Command:**
```
is-config-locked
```

**Output:**
```
Config Zone: LOCKED
```
or
```
Config Zone: UNLOCKED
```

**Requirements:**
- Must be called after `init` command
- No arguments required

### is-data-locked

**Command:**
```
is-data-locked
```

**Output:**
```
Data Zone: LOCKED
```
or
```
Data Zone: UNLOCKED
```

**Requirements:**
- Must be called after `init` command
- No arguments required

## Python Script Integration

### Basic Example

```python
import serial
import time

def send_command(ser, command):
    """Send command and wait for response"""
    ser.write(f"{command}\n".encode())
    time.sleep(0.1)
    response = ser.read_until(b'\n').decode()
    return response

def check_config_locked(ser):
    """Check if config zone is locked"""
    response = send_command(ser, "is-config-locked")
    return "LOCKED" in response

def check_data_locked(ser):
    """Check if data zone is locked"""
    response = send_command(ser, "is-data-locked")
    return "LOCKED" in response

# Example usage
ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=1)

# Initialize device first
send_command(ser, "init 21 22")

# Check lock status
if check_config_locked(ser):
    print("Config zone is locked - cannot write config")
else:
    print("Config zone is unlocked - safe to write config")
    # Proceed with write-config command

if check_data_locked(ser):
    print("Data zone is locked - device is provisioned")
else:
    print("Data zone is unlocked - can write data slots")
```

### Advanced Example with Error Handling

```python
import serial
import time
import logging

class ATECC608Provisioner:
    def __init__(self, port, baudrate=115200):
        self.ser = serial.Serial(port, baudrate, timeout=2)
        self.logger = logging.getLogger(__name__)

    def send_command(self, command, wait_time=0.2):
        """Send command and read response"""
        self.logger.debug(f"Sending: {command}")
        self.ser.write(f"{command}\n".encode())
        time.sleep(wait_time)

        # Read until we get the status line
        response_lines = []
        while True:
            line = self.ser.readline().decode().strip()
            if not line:
                break
            response_lines.append(line)
            self.logger.debug(f"Received: {line}")

        return '\n'.join(response_lines)

    def is_config_locked(self):
        """Check if config zone is locked"""
        response = self.send_command("is-config-locked")

        if "Failure" in response:
            raise RuntimeError("Failed to check config lock status")

        if "Config Zone: LOCKED" in response:
            return True
        elif "Config Zone: UNLOCKED" in response:
            return False
        else:
            raise RuntimeError(f"Unexpected response: {response}")

    def is_data_locked(self):
        """Check if data zone is locked"""
        response = self.send_command("is-data-locked")

        if "Failure" in response:
            raise RuntimeError("Failed to check data lock status")

        if "Data Zone: LOCKED" in response:
            return True
        elif "Data Zone: UNLOCKED" in response:
            return False
        else:
            raise RuntimeError(f"Unexpected response: {response}")

    def provision_trustcustom(self, config_bytes, i2c_sda=21, i2c_scl=22):
        """Provision a TrustCustom ATECC608 chip"""
        import zlib

        # Step 1: Initialize
        self.logger.info("Initializing ATECC608...")
        response = self.send_command(f"init {i2c_sda} {i2c_scl}")
        if "Failure" in response:
            raise RuntimeError("Failed to initialize device")

        # Step 2: Check if config is already locked
        self.logger.info("Checking config lock status...")
        if self.is_config_locked():
            self.logger.warning("Config zone already locked, skipping config write")
        else:
            # Step 3: Write config
            self.logger.info("Config zone is unlocked, writing config...")
            crc32 = zlib.crc32(config_bytes) & 0xFFFFFFFF

            # Send write-config command with CRC
            self.send_command(f"write-config {crc32}")

            # Send config bytes
            self.ser.write(config_bytes)
            self.ser.write(b'\0')  # Null terminator
            time.sleep(0.5)

            # Read response
            response = self.ser.read_until(b'\n').decode()
            if "Success" not in response:
                raise RuntimeError(f"Failed to write config: {response}")

            self.logger.info("Config written successfully")

        # Step 4: Check data lock status
        self.logger.info("Checking data lock status...")
        if self.is_data_locked():
            self.logger.info("Data zone is locked - device already provisioned")
            return

        # Continue with key generation, CSR, etc...
        self.logger.info("Data zone is unlocked - proceeding with provisioning")
        # ... rest of provisioning workflow

# Usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    provisioner = ATECC608Provisioner('/dev/ttyUSB0')

    # Example: Load custom config
    with open('atecc608_config.bin', 'rb') as f:
        config_data = f.read()

    provisioner.provision_trustcustom(config_data)
```

## Integration into secure_cert_mfg.py

To integrate into the existing `secure_cert_mfg.py` script:

```python
def check_zone_lock_status(serial_obj, zone_type):
    """
    Check if a zone is locked

    Args:
        serial_obj: Serial port object
        zone_type: 'config' or 'data'

    Returns:
        bool: True if locked, False if unlocked
    """
    command = f"is-{zone_type}-locked\n"
    serial_obj.write(command.encode())

    # Wait for response
    time.sleep(0.2)
    response = serial_obj.read_until(b'\n').decode()

    if "LOCKED" in response and "UNLOCKED" not in response:
        return True
    elif "UNLOCKED" in response:
        return False
    else:
        raise Exception(f"Failed to check {zone_type} lock status: {response}")

# Example usage in main provisioning flow:
def provision_device(port, config_bytes=None):
    ser = serial.Serial(port, 115200, timeout=2)

    # Initialize
    ser.write(b"init 21 22\n")
    time.sleep(0.5)

    # Check config lock before writing
    if config_bytes:
        if check_zone_lock_status(ser, 'config'):
            print("⚠ Config zone already locked, cannot write config")
        else:
            print("✓ Config zone unlocked, writing custom config...")
            write_config(ser, config_bytes)

    # Check data lock to determine provisioning state
    if check_zone_lock_status(ser, 'data'):
        print("✓ Device already provisioned (data zone locked)")
        return
    else:
        print("→ Data zone unlocked, proceeding with provisioning...")
        # Continue with key generation, certificates, etc.
```

## Response Format

Both commands return responses in this format:

```
[DEBUG LOGS if enabled]
Status: Success

Config Zone: LOCKED  (or UNLOCKED)
```

Parse for either "LOCKED" or "UNLOCKED" in the response to determine status.

## Error Handling

If the command fails, you'll see:

```
Status: Failure
Please initialize device before calling this function
```

Always check for "Failure" in the response and ensure `init` was called first.

## Implementation Details

- **Location:** `esp_cryptoauth_utility/firmware/main/commands.c:619-703`
- **Handlers:** `esp_cryptoauth_utility/firmware/main/handlers.c:644-700`
- **Uses:** `atcab_is_locked(LOCK_ZONE_CONFIG, &is_locked)` and `atcab_is_locked(LOCK_ZONE_DATA, &is_locked)` from cryptoauthlib
- **Requirements:** Device must be initialized with `init` command before calling
