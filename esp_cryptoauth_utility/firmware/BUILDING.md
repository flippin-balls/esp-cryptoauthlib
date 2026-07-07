# Building `ecu_firmware.bin` (the factory ATECC provisioning utility)

This is the firmware that provisioning sessions RAM-load onto the target device to talk to
its ATECC608A (published to S3 as
`firmware/factory/atecc_slot_provisioning/<target>/ecu_firmware_latest.bin`).
Recipe verified 2026-07-07 in `espressif/idf:v5.5` for esp32s3; it mirrors upstream's
`build:ecu-firmware-all-targets-latest-release` GitLab CI job.

## Recipe

```bash
# ⚠ The checkout directory MUST be named `esp-cryptoauthlib` — the firmware consumes the
# surrounding repo as a local component via override_path, and ESP-IDF resolves local
# components by DIRECTORY NAME. A checkout named anything else fails with
# "Failed to resolve component 'esp-cryptoauthlib' ... unknown name".
git clone --branch feature/i2c-master-driver-migration \
    https://github.com/flippin-balls/esp-cryptoauthlib.git esp-cryptoauthlib
cd esp-cryptoauthlib/esp_cryptoauth_utility/firmware

idf.py set-target esp32s3
FIRMWARE_VERSION=x.y.z idf.py build     # version is baked via main/version.h.in

esptool.py --chip esp32s3 elf2image build/ecu_firmware.elf \
    --output build/ecu_firmware.bin
```

Docker one-liner (no local ESP-IDF needed):

```bash
docker run --rm -v "$(pwd)/esp-cryptoauthlib:/w/esp-cryptoauthlib" \
    -w /w/esp-cryptoauthlib/esp_cryptoauth_utility/firmware \
    -e FIRMWARE_VERSION=x.y.z espressif/idf:v5.5 bash -lc \
    'idf.py set-target esp32s3 && idf.py build && \
     esptool.py --chip esp32s3 elf2image build/ecu_firmware.elf --output build/ecu_firmware.bin'
```

## Verify before publishing

1. `dependencies.lock` must show `esp-cryptoauthlib` with `source: type: local` pointing at
   the checkout — if it shows the `components.espressif.com` registry instead, the bin
   contains the **un-fixed upstream** I2C HAL, not this fork's ATECC fixes. (This was the
   silent failure mode before the `override_path` fix — see PR #6.)
2. `grep -ac "RETIRED (R1)" build/ecu_firmware.bin` → ≥1 (the gen-location-psk neuter,
   PR #5, must be present).
3. Bench-validate against a real ATECC (`secure_cert_mfg.py` / `fbf` provisioning flow) —
   `write-enc-data` must report a real `Status: Success/Failure`, and `gen-location-psk`
   must refuse.
4. Back up the currently-published S3 bin before overwriting `ecu_firmware_latest.bin` —
   every provisioning session RAM-loads it, so never auto-publish.
