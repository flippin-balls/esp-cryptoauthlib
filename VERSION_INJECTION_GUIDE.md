# Firmware Version Injection Guide

## Overview

The firmware version is now automatically injected at build time from the release script. You no longer need to manually update the version string in `app_main.c`.

## How It Works

### 1. Build System Configuration

**CMakeLists.txt** (`firmware/main/CMakeLists.txt`):
- Reads `FIRMWARE_VERSION` environment variable
- Defaults to `"0.0.0-dev"` if not set
- Generates `version.h` from `version.h.in` template

### 2. Version Header Template

**version.h.in** (`firmware/main/version.h.in`):
```c
#define FIRMWARE_VERSION "@FIRMWARE_VERSION@"
```

At build time, CMake replaces `@FIRMWARE_VERSION@` with the actual version string.

### 3. Application Code

**app_main.c**:
```c
#include "version.h"

void app_main() {
    printf("  VERSION: %s\n", FIRMWARE_VERSION);
}
```

### 4. Release Script

**release.py**:
- Takes version as command-line argument
- Sets `FIRMWARE_VERSION` environment variable
- Passes it to ESP-IDF build via PowerShell

## Usage

### Building with release.py

```bash
# Build and upload version 0.0.7
doppler run -- poetry run python release.py 0.0.7

# Local build only (skip S3)
doppler run -- poetry run python release.py 0.0.7 --no-s3

# Clean build
doppler run -- poetry run python release.py 0.0.7 --clean
```

The version you specify on the command line will automatically appear in the firmware banner.

### Manual Building (for development)

If building manually with `idf.py`:

```bash
# Set version environment variable
export FIRMWARE_VERSION="0.0.7-dev"  # Linux/Mac
$env:FIRMWARE_VERSION="0.0.7-dev"    # PowerShell

# Build
idf.py build
```

Without setting `FIRMWARE_VERSION`, the firmware will show `"0.0.0-dev"`.

## File Structure

```
firmware/main/
├── CMakeLists.txt           # Reads FIRMWARE_VERSION env var
├── version.h.in             # Template for version.h
├── app_main.c               # Uses FIRMWARE_VERSION macro
└── build/
    └── version.h            # Generated at build time (gitignored)
```

## Benefits

1. **Single source of truth**: Version is specified once on the command line
2. **No manual updates**: No need to edit C code for version bumps
3. **Consistency**: Same version in firmware, S3 filenames, and release notes
4. **Development builds**: Auto-defaults to "0.0.0-dev" for manual builds

## Git Ignore

The generated `version.h` file should be gitignored (already in build directory, which is ignored).

## Troubleshooting

### "FIRMWARE_VERSION not defined" error

**Cause**: CMake couldn't find the environment variable.

**Solution**: Ensure you're using the release script, or set the env var manually:
```bash
$env:FIRMWARE_VERSION="0.0.6"
idf.py build
```

### Version shows "0.0.0-dev"

**Cause**: Built without setting `FIRMWARE_VERSION` environment variable.

**Solution**: This is expected for manual development builds. Use release.py for versioned builds.

### Build fails with "version.h.in not found"

**Cause**: Template file is missing.

**Solution**: Ensure `firmware/main/version.h.in` exists.

## Version Numbering

Recommended semantic versioning: `MAJOR.MINOR.PATCH`

Examples:
- `0.0.6` - Initial development
- `0.1.0` - First feature-complete version
- `1.0.0` - First production release
- `1.0.1` - Bug fix
- `1.1.0` - New feature
- `2.0.0` - Breaking change

## Files Modified (v0.0.6 → Dynamic)

1. **firmware/main/CMakeLists.txt** - Added version injection logic
2. **firmware/main/version.h.in** - Created template file
3. **firmware/main/app_main.c** - Changed from hardcoded version to `FIRMWARE_VERSION` macro
4. **release.py** - Added version env var to build command, made version argument required

## Previous Behavior

Before v0.0.7, the version was hardcoded in app_main.c:
```c
printf("  VERSION: 0.0.6\n");  // Had to manually update this
```

Now it's automatic:
```c
printf("  VERSION: %s\n", FIRMWARE_VERSION);  // Injected at build time
```
