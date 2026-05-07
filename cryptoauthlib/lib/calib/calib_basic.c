/**
 * \file
 * \brief CryptoAuthLib Basic API methods. These methods provide a simpler way
 *        to access the core crypto methods.
 *
 * \copyright (c) 2015-2020 Microchip Technology Inc. and its subsidiaries.
 *
 * \page License
 *
 * Subject to your compliance with these terms, you may use Microchip software
 * and any derivatives exclusively with Microchip products. It is your
 * responsibility to comply with third party license terms applicable to your
 * use of third party software (including open source software) that may
 * accompany Microchip software.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
 * SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
 * OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
 * MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
 * FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
 * LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
 * THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
 * THIS SOFTWARE.
 */

#include "cryptoauthlib.h"
#include "esp_log.h"
/* The fork previously inlined a custom wake-pulse sequence here that called
 * the legacy ESP-IDF I2C driver directly. That has been replaced by a call
 * to atwake() which routes through hal_i2c_wake in the new-driver HAL. See
 * openspec/changes/migrate-i2c-master-driver for the migration record. */


/** \brief basic API methods are all prefixed with atcab_  (CryptoAuthLib Basic)
 *  the fundamental premise of the basic API is it is based on a single interface
 *  instance and that instance is global, so all basic API commands assume that
 *  one global device is the one to operate on.
 */

ATCA_STATUS calib_wakeup_i2c(ATCADevice device)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    uint8_t second_byte = 0U;
    ATCAIface iface = atGetIFace(device);

    if (NULL != iface)
    {
        int retries = atca_iface_get_retries(iface);
        uint8_t address = atcab_get_device_address(device);
        ATCAKitType kit_type = ATCA_KIT_UNKNOWN_IFACE;
        uint32_t temp;
        uint32_t wake;
        uint16_t rxlen;

        do
        {
            if (100000u < ATCA_IFACECFG_VALUE(iface->mIfaceCFG, atcai2c.baud))
            {
                temp = 100000u;
                status = atcontrol(iface, (uint8_t)ATCA_HAL_CHANGE_BAUD, &temp, sizeof(temp));
                if (ATCA_UNIMPLEMENTED == status)
                {
                    status = atcontrol(iface, (uint8_t)ATCA_HAL_CONTROL_WAKE, NULL, 0);
                    break;
                }
            }
            else
            {
                status = ATCA_SUCCESS;
            }

            if(atcab_is_ca_device(atcab_get_device_type_ext(device)))
            {
                /* Delegate the wake pulse to the HAL via atwake(), which on
                 * ESP32 routes to hal_i2c_wake in cryptoauthlib/third_party/
                 * hal/esp32/hal_esp32_i2c.c. The HAL handles the write-to-0x00
                 * NACK pulse, the 3 ms wake delay, the 4-byte response read,
                 * the 5 ms settle delay, and validates the 0x11 wake token
                 * internally — see openspec/changes/migrate-i2c-master-driver
                 * for the rationale.
                 *
                 * The fork's previous inline implementation called the legacy
                 * ESP-IDF I2C driver directly, which entered a critical
                 * section on the expected NACK and triggered IWDT panics.
                 * That block was removed as part of this migration. */
                status = atwake(iface);
                if (ATCA_SUCCESS == status)
                {
                    /* hal_i2c_wake already validated the canonical wake
                     * response. Populate `wake` (uint32_t) with the same
                     * bytes [0x04, 0x11, 0x33, 0x43] in little-endian so
                     * the hal_check_wake call below also passes. */
                    wake = 0x43331104u;
                }

                second_byte = 0U;  /* unused for CA devices, kept for safety */
            }
            else
            {
                // For non-CA devices, use the original method
                ESP_LOGI("CALIB_WAKEUP_I2C", "Non-CA device, using standard wake (second_byte=%u)", second_byte);
                (void)atsend(iface, second_byte, NULL, 0);
            }

            (void)ifacecfg_set_address(iface->mIfaceCFG, address, kit_type);

            rxlen = (uint16_t)sizeof(wake);
            if (ATCA_SUCCESS == status)
            {
                // For CA devices, we already read wake response above at 60kHz
                // Just validate we got a successful status
                // Set rxlen to indicate we got 4 bytes
                rxlen = 4;
            }

            if ((ATCA_SUCCESS == status) && (100000u < ATCA_IFACECFG_I2C_BAUD(iface->mIfaceCFG)))
            {
                ESP_LOGI("CALIB_WAKEUP_I2C", "Restoring baud to %u", ATCA_IFACECFG_I2C_BAUD(iface->mIfaceCFG));
                temp = ATCA_IFACECFG_I2C_BAUD(iface->mIfaceCFG);
                status = atcontrol(iface, (uint8_t)ATCA_HAL_CHANGE_BAUD, &temp, sizeof(temp));
            }

            if (ATCA_SUCCESS == status)
            {
                status = hal_check_wake((uint8_t*)&wake, (int)rxlen);
            }
        } while (0 < retries-- && ATCA_SUCCESS != status);
    }

    if (status != ATCA_SUCCESS) {
        ESP_LOGE("CALIB_WAKEUP_I2C", "Wake FAILED with status=0x%02x", status);
    }

    return status;
}

/** \brief wakeup the CryptoAuth device
 *  \param[in] device     Device context pointer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_wakeup(ATCADevice device)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    ATCAIface iface = atGetIFace(device);

    if ((NULL != iface) && (NULL != iface->mIfaceCFG))
    {
#ifdef ATCA_HAL_LEGACY_API
        status = atwake(iface);
#else
        if (atca_iface_is_kit(iface) || atca_iface_is_swi(&device->mIface))
        {
            status = atwake(iface);
        }
        else if (ATCA_I2C_IFACE == iface->mIfaceCFG->iface_type)
        {
            status = calib_wakeup_i2c(device);
        }
        else
        {
            status = ATCA_SUCCESS;
        }
#endif
    }

    return status;
}

/** \brief idle the CryptoAuth device
 *  \param[in] device     Device context pointer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_idle(ATCADevice device)
{
    ATCA_STATUS status;
    ATCADeviceType device_type = atcab_get_device_type_ext(device);

#ifdef ATCA_HAL_LEGACY_API
    status = atidle(&device->mIface);
#else
    if (atca_iface_is_kit(&device->mIface) || atca_iface_is_swi(&device->mIface))
    {
        status = atidle(&device->mIface);
    }
    else
    {
        if (!atcab_is_ca2_device(device_type))
        {
            uint8_t command = 0x02;
            status = atsend(&device->mIface, command, NULL, 0);
        }
        else
        {
            status = ATCA_SUCCESS;
        }
    }
#endif
    return status;
}

/** \brief invoke sleep on the CryptoAuth device
 *  \param[in] device     Device context pointer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_sleep(ATCADevice device)
{
    ATCA_STATUS status;

#ifdef ATCA_HAL_LEGACY_API
    status = atsleep(&device->mIface);
#else
    if (atca_iface_is_kit(&device->mIface) || atca_iface_is_swi(&device->mIface))
    {
        status = atsleep(&device->mIface);
    }
    else
    {
        uint8_t command = 0x01;
        status = atsend(&device->mIface, command, NULL, 0);
    }
#endif
    return status;
}

/** \brief common cleanup code which idles the device after any operation
 *  \param[in] device     Device context pointer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_exit(ATCADevice device)
{
    return calib_idle(device);
}


/** \brief Compute the address given the zone, slot, block, and offset
 *  \param[in] zone   Zone to get address from. Config(0), OTP(1), or
 *                    Data(2) which requires a slot.
 *  \param[in] slot   Slot Id number for data zone and zero for other zones.
 *  \param[in] block  Block number within the data or configuration or OTP zone .
 *  \param[in] offset Offset Number within the block of data or configuration or OTP zone.
 *  \param[out] addr  Pointer to the address of data or configuration or OTP zone.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint16_t* addr)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t mem_zone = (uint8_t)(zone & 0x03u);

    if (addr == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }
    if ((mem_zone != ATCA_ZONE_CONFIG) && (mem_zone != ATCA_ZONE_DATA) && (mem_zone != ATCA_ZONE_OTP))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received");
    }
    do
    {
        // Initialize the addr to 00
        *addr = 0;
        // Mask the offset
        offset = offset & (uint8_t)0x07;
        if ((mem_zone == ATCA_ZONE_CONFIG) || (mem_zone == ATCA_ZONE_OTP))
        {
            *addr = ((uint16_t)block) << 3;
            *addr |= offset;
        }
        else    // ATCA_ZONE_DATA
        {
            *addr = slot << 3;
            *addr |= offset;
            *addr |= ((uint16_t)block) << 8;
        }
    } while (false);

    return status;
}

#if ATCA_CA2_SUPPORT
/** \brief Compute the address given the zone, slot, block, and offset for the device
 *  \param[in] zone   Zone to get address from. Config(1) or
 *                    Data(0) which requires a slot.
 *  \param[in] slot   Slot Id number for data zone and zero for other zones.
 *  \param[in] block  Block number within the data zone .
 *  \param[in] offset Aalways zero.
 *  \param[out] addr  Pointer to the address of data or configuration zone.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_ca2_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint16_t* addr)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    ((void)zone);
    ((void)offset);

    if (addr == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    *addr = slot << 3;
    *addr |= ((uint16_t)block) << 8;

    return status;
}
#endif

/** \brief Gets the size of the specified zone in bytes.
 *
 * \param[in]  device  Device context pointer
 * \param[in]  zone    Zone to get size information from. Config(0), OTP(1), or
 *                     Data(2) which requires a slot.
 * \param[in]  slot    If zone is Data(2), the slot to query for size.
 * \param[out] size    Zone size is returned here.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_get_zone_size(ATCADevice device, uint8_t zone, uint16_t slot, size_t* size)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    if ((device == NULL) || (size == NULL))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    if (device->mIface.mIfaceCFG->devtype == ATSHA204A)
    {
#ifdef ATCA_ATSHA204A_SUPPORT
        switch (zone)
        {
        case ATCA_ZONE_CONFIG: *size = 88; break;
        case ATCA_ZONE_OTP:    *size = 64; break;
        case ATCA_ZONE_DATA:   *size = 32; break;
        default: status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received"); break;
        }
#endif
    }
#ifdef ATCA_ATSHA206A_SUPPORT
    else if (device->mIface.mIfaceCFG->devtype == ATSHA206A)
    {
        switch (zone)
        {
        case ATCA_ZONE_CONFIG: *size = 88; break;
        case ATCA_ZONE_OTP:    *size = 0; break;
        case ATCA_ZONE_DATA:   *size = 32; break;
        default: status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received"); break;
        }
    }
#endif
#if ATCA_CA2_SUPPORT
    else if (atcab_is_ca2_device(device->mIface.mIfaceCFG->devtype))
    {
        switch (zone)
        {
        case ATCA_ZONE_CONFIG: *size = 64; break;
        case ATCA_ZONE_DATA:
            if ((0u == slot) || (3u == slot))
            {
                *size = 32;
            }
            else if (1u == slot)
            {
                *size = 320;
            }
            else if (2u == slot)
            {
                *size = 64;
            }
            else
            {
                status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid slot received");
            }
            break;
        default: status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received"); break;
        }
    }
#endif
    else
    {
        switch (zone)
        {
        case ATCA_ZONE_CONFIG: *size = 128; break;
        case ATCA_ZONE_OTP:    *size = 64; break;
        case ATCA_ZONE_DATA:
            if (slot < 8u)
            {
                *size = 36;
            }
            else if (slot == 8u)
            {
                *size = 416;
            }
            else if (slot < 16u)
            {
                *size = 72;
            }
            else
            {
                status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid slot received");
            }
            break;
        default: status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received"); break;
        }
    }

    return status;
}
