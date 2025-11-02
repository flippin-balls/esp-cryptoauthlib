#!/usr/bin/env python3
"""
Release script for ATECC608 provisioning firmware

This script automates the firmware build, conversion, local copy, and S3 upload process.

Usage:
    doppler run -- poetry run python release.py <version> [--no-s3] [--clean]

Examples:
    doppler run -- poetry run python release.py 0.0.6              # Build and upload version 0.0.6
    doppler run -- poetry run python release.py 0.0.7 --no-s3      # Build locally only, skip S3 upload
    doppler run -- poetry run python release.py 0.1.0 --clean      # Clean build with version 0.1.0

Environment Variables (injected via Doppler):
    AWS_PINBALL_DEV_ACCESS_KEY         # AWS access key
    AWS_PINBALL_DEV_SECRET_KEY         # AWS secret key
    S3_BUCKET                          # S3 bucket name
    FIRMWARE_ATECC_PROVISION_BIN_S3_KEY # S3 key prefix
"""

import os
import subprocess
import sys
import shutil
import re
import tempfile
from pathlib import Path
from datetime import datetime
import argparse

# Configuration - AWS credentials from Doppler
AWS_ACCESS_KEY = os.environ.get("AWS_PINBALL_DEV_ACCESS_KEY")
AWS_SECRET_KEY = os.environ.get("AWS_PINBALL_DEV_SECRET_KEY")
S3_BUCKET = os.environ.get("S3_BUCKET")
S3_PREFIX = os.environ.get("FIRMWARE_ATECC_PROVISION_BIN_S3_PREFIX")
LOCAL_COPY_PATH = Path(r"C:\PyCharmProjects\pinball\device-config-management\src\sample_bins\esp32")

# ESP-IDF configuration
IDF_INIT_SCRIPT = Path(r"C:\Espressif\Initialize-Idf.ps1")
IDF_ID = "esp-idf-29323a3f5a0574597d6dbaa0af20c775"

# Paths (script is in esp_cryptoauth_utility directory)
PROJECT_ROOT = Path(__file__).parent
FIRMWARE_DIR = PROJECT_ROOT / "firmware"
BUILD_DIR = FIRMWARE_DIR / "build"
APP_MAIN_C = FIRMWARE_DIR / "main" / "app_main.c"


def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def run_command(cmd, description, cwd=None, use_idf_env=False, env_vars=None):
    """Run a shell command and handle errors"""
    print_section(description)
    print(f"Command: {cmd}\n")

    if use_idf_env:
        # Create a temporary PowerShell script to avoid command line issues
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
            script_path = f.name

            # Write PowerShell script
            f.write(f'& "{IDF_INIT_SCRIPT}" -IdfId {IDF_ID}\n')

            # Set environment variables AFTER sourcing ESP-IDF
            if env_vars:
                for key, value in env_vars.items():
                    f.write(f'$env:{key} = "{value}"\n')

            f.write(f'cd "{cwd or FIRMWARE_DIR}"\n')
            f.write(f'{cmd}\n')
            f.write(f'exit $LASTEXITCODE\n')

        try:
            full_cmd = f'powershell.exe -ExecutionPolicy Bypass -File "{script_path}"'

            result = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True
            )
        finally:
            # Clean up temp file
            try:
                os.unlink(script_path)
            except:
                pass
    else:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            cwd=cwd or FIRMWARE_DIR
        )

    if result.stdout:
        print(result.stdout)

    if result.returncode != 0:
        print(f"\n❌ ERROR: Command failed!")
        if result.stderr:
            print(f"Error output:\n{result.stderr}")
        sys.exit(1)

    return result




def build_firmware(version):
    """Build the firmware using idf.py with version injection"""
    env_vars = {"FIRMWARE_VERSION": version}

    # Reconfigure to regenerate version.h with new FIRMWARE_VERSION
    run_command(
        "idf.py reconfigure",
        f"Reconfiguring CMake with version {version}",
        use_idf_env=True,
        env_vars=env_vars
    )

    # Build with the updated configuration
    run_command(
        "idf.py build",
        f"Step 1/5: Building firmware with ESP-IDF (version {version})",
        use_idf_env=True,
        env_vars=env_vars
    )


def convert_to_binary():
    """Convert ELF to binary using esptool"""
    elf_file = BUILD_DIR / "ecu_firmware.elf"
    if not elf_file.exists():
        print(f"❌ ERROR: ELF file not found: {elf_file}")
        sys.exit(1)

    run_command(
        f'esptool.py --chip esp32 elf2image "{elf_file}"',
        "Step 2/5: Converting ELF to binary",
        use_idf_env=True
    )

    bin_file = BUILD_DIR / "ecu_firmware.bin"
    if not bin_file.exists():
        print(f"❌ ERROR: Binary file not created: {bin_file}")
        sys.exit(1)

    return bin_file


def copy_to_local(bin_file):
    """Copy binary to local Python project"""
    print_section("Step 3/5: Copying to Python project")

    # Create destination directory if it doesn't exist
    LOCAL_COPY_PATH.mkdir(parents=True, exist_ok=True)

    dest = LOCAL_COPY_PATH / "secure_cert_mfg_esp32.bin"
    shutil.copy2(bin_file, dest)

    # Get file size
    size_kb = dest.stat().st_size / 1024

    print(f"✓ Copied to: {dest}")
    print(f"✓ File size: {size_kb:.1f} KB")


def upload_to_s3(bin_file, version):
    """Upload binary to S3 with versioning"""
    print_section("Step 4/5: Uploading to S3")

    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        print("❌ ERROR: boto3 not installed. Install with: pip install boto3")
        sys.exit(1)

    # Validate AWS credentials
    if not AWS_ACCESS_KEY or not AWS_SECRET_KEY:
        print("❌ ERROR: AWS credentials not found in environment")
        print("Required: AWS_PINBALL_DEV_ACCESS_KEY and AWS_PINBALL_DEV_SECRET_KEY")
        print("Run with: doppler run -- poetry run python release.py")
        sys.exit(1)

    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY
        )

        # Test S3 access
        try:
            s3.head_bucket(Bucket=S3_BUCKET)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                print(f"❌ ERROR: S3 bucket '{S3_BUCKET}' does not exist")
            elif error_code == '403':
                print(f"❌ ERROR: Access denied to S3 bucket '{S3_BUCKET}'")
            else:
                print(f"❌ ERROR: Cannot access S3 bucket: {e}")
            sys.exit(1)

        metadata = {
            'version': version,
            'build_date': datetime.utcnow().isoformat() + 'Z',
            'chip': 'esp32',
            'firmware': 'atecc608_provisioning'
        }

        # Upload versioned file
        versioned_key = f"{S3_PREFIX}/ecu_firmware_v{version}.bin"
        print(f"Uploading versioned file: {versioned_key}...")
        s3.upload_file(
            str(bin_file),
            S3_BUCKET,
            versioned_key,
            ExtraArgs={'Metadata': metadata}
        )
        print(f"✓ Uploaded: s3://{S3_BUCKET}/{versioned_key}")

        # Update 'latest' pointer
        latest_key = f"{S3_PREFIX}/ecu_firmware_latest.bin"
        print(f"\nUpdating 'latest' pointer: {latest_key}...")
        s3.upload_file(
            str(bin_file),
            S3_BUCKET,
            latest_key,
            ExtraArgs={'Metadata': metadata}
        )
        print(f"✓ Updated: s3://{S3_BUCKET}/{latest_key}")

    except NoCredentialsError:
        print("❌ ERROR: AWS credentials not configured")
        print("Run 'aws configure' to set up credentials")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERROR: S3 upload failed: {e}")
        sys.exit(1)


def create_release_notes(version, bin_file):
    """Create and display release summary"""
    print_section("Step 5/5: Release Summary")

    size_kb = bin_file.stat().st_size / 1024
    build_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"""
Release Information:
--------------------
Version:      {version}
Build Date:   {build_time}
Binary Size:  {size_kb:.1f} KB
Chip Target:  ESP32

Local Paths:
--------------------
Source:       {bin_file}
Destination:  {LOCAL_COPY_PATH / 'secure_cert_mfg_esp32.bin'}

S3 Locations:
--------------------
Versioned:    s3://{S3_BUCKET}/{S3_PREFIX}/ecu_firmware_v{version}.bin
Latest:       s3://{S3_BUCKET}/{S3_PREFIX}/ecu_firmware_latest.bin

Download URL (if public):
--------------------
https://{S3_BUCKET}.s3.amazonaws.com/{S3_PREFIX}/ecu_firmware_v{version}.bin
""")


def main():
    parser = argparse.ArgumentParser(
        description="Build and release ATECC608 firmware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  doppler run -- poetry run python release.py 0.0.6              # Build and upload version 0.0.6
  doppler run -- poetry run python release.py 0.0.7 --no-s3      # Build locally only, skip S3
  doppler run -- poetry run python release.py 0.1.0 --clean      # Clean build with new version
        """
    )
    parser.add_argument(
        'version',
        help='Firmware version (e.g., 0.0.6)'
    )
    parser.add_argument(
        '--no-s3',
        action='store_true',
        help='Skip S3 upload (local build only)'
    )
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Clean build directory before building'
    )

    args = parser.parse_args()

    # Get version from argument
    version = args.version

    print(f"\n{'=' * 70}")
    print(f"  ATECC608 Firmware Release Tool")
    print(f"  Version: {version}")
    print(f"{'=' * 70}")

    # Validate paths
    if not FIRMWARE_DIR.exists():
        print(f"❌ ERROR: Firmware directory not found: {FIRMWARE_DIR}")
        sys.exit(1)

    # Clean if requested
    if args.clean:
        print_section("Cleaning build directory")
        run_command("idf.py fullclean", "Running fullclean...", use_idf_env=True)

    # Step 1: Build
    build_firmware(version)

    # Step 2: Convert to binary
    bin_file = convert_to_binary()

    # Step 3: Copy to local project
    copy_to_local(bin_file)

    # Step 4: Upload to S3 (if not disabled)
    if not args.no_s3:
        if S3_BUCKET == "your-bucket-name":
            print("\n⚠️  WARNING: S3_BUCKET not configured in script")
            print("Skipping S3 upload. Edit release.py to set S3_BUCKET")
        else:
            upload_to_s3(bin_file, version)
    else:
        print_section("Step 4/5: Skipping S3 upload (--no-s3)")

    # Step 5: Summary
    create_release_notes(version, bin_file)

    print_section("✓ Release Complete!")
    print(f"\nFirmware v{version} is ready to use")
    if not args.no_s3 and S3_BUCKET != "your-bucket-name":
        print("Binary uploaded to S3 and copied to local project")
    else:
        print("Binary copied to local project (S3 upload skipped)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Build cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
