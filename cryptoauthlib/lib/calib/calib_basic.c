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
#include "driver/i2c.h"
#include "driver/gpio.h"
#include "esp_rom_sys.h"

// I2C constants for wake pulse
#define I2C_MASTER_WRITE 0
#define I2C_MASTER_READ  1
#define NACK_VAL         0x1
#define ACK_VAL          0x0
#define ACK_CHECK_EN     0x1


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
                // Send wake pulse: START, 0x00(W), STOP (no word address byte!)
                // Using direct HAL call to avoid the word_address byte that atsend() adds
                ATCAIfaceCfg *cfg = iface->mIfaceCFG;
                if (cfg) {
                    // Use standard wake-by-write-to-0x00 method
                    i2c_cmd_handle_t wake_cmd = i2c_cmd_link_create();
                    i2c_master_start(wake_cmd);
                    i2c_master_write_byte(wake_cmd, 0x00 | I2C_MASTER_WRITE, false);
                    i2c_master_stop(wake_cmd);
                    esp_err_t rc = i2c_master_cmd_begin(cfg->atcai2c.bus, wake_cmd, pdMS_TO_TICKS(10));
                    i2c_cmd_link_delete(wake_cmd);

                    // Wait wake delay (1.5ms minimum per datasheet, using 3ms for margin)
                    vTaskDelay(pdMS_TO_TICKS(3));

                    // Read wake response
                    uint8_t wake_resp[4] = {0};
                    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
                    i2c_master_start(cmd);
                    i2c_master_write_byte(cmd, (cfg->atcai2c.address << 1) | I2C_MASTER_READ, true);
                    for (int i = 0; i < 4; i++) {
                        i2c_master_read_byte(cmd, &wake_resp[i], (i == 3) ? I2C_MASTER_NACK : I2C_MASTER_ACK);
                    }
                    i2c_master_stop(cmd);
                    rc = i2c_master_cmd_begin(cfg->atcai2c.bus, cmd, pdMS_TO_TICKS(100));
                    i2c_cmd_link_delete(cmd);

                    if (rc == ESP_OK) {
                        wake = wake_resp[0] | (wake_resp[1] << 8) | (wake_resp[2] << 16) | (wake_resp[3] << 24);
                        // Give device extra time to fully wake before accepting commands
                        vTaskDelay(pdMS_TO_TICKS(5));
                    } else {
                        status = ATCA_COMM_FAIL;
                    }
                }

                second_byte = 0U;  // Not used anymore, but set to 0 for safety
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
